# cluster-admission-guard

A Kubernetes admission controller that blocks or automatically fixes workloads
which can escape their container: privileged mode, host namespaces, hostPath
mounts, dangerous capabilities/proc options, and untrusted images. It is
designed around three hard requirements:

1. **Per-team, per-namespace, time-limited exceptions.** Teams get scoped
   exemptions with an expiry; nobody edits the baseline to make them work.
2. **No bypass by indirection.** The same pod spec can arrive as a Pod,
   Deployment, CronJob, or a custom resource nobody has heard of. All are
   checked.
3. **Availability without silent gaps.** A webhook outage must not freeze the
   cluster, and must not let a dangerous workload through either.

## How it works

```
API server ──AdmissionReview──▶ /mutate (remediate) ──▶ /validate (enforce)
     ▲                                                          │
     └───────────── allow / deny / JSON patch ──────────────────┘
                              │
              ┌───────────────┴───────────────┐
     file policy (ConfigMap)        SecurityPolicy CRs + Namespaces
```

* **Policy documents** (`SecurityPolicy`) list rules, scope (namespaces, teams,
  label selectors) and exemptions. `TrustStore` lists trusted image digests.
* **The engine** extracts every pod template from the submitted object,
  evaluates rules, applies exemptions, produces a JSON patch for remediation,
  and verifies that patch before admitting anything.
* **The webhook** speaks AdmissionReview v1 over HTTPS and serves `/validate`,
  `/mutate`, `/healthz`, `/readyz` and `/metrics`.
* **`admissionctl`** validates policies in CI, renders the webhook
  configuration, and replays manifests either offline or through a real
  AdmissionReview round trip.

## The three hard problems

### 1. Exceptions with scope and expiry

An exemption is never a free pass. It must name:

* **who** asked and **why** (audit trail, enforced at compile time),
* **which rules** it covers (`scope.rules`, or `*`),
* **where** it applies (namespace, team, workload, kind — at least one),
* **when** it expires (`expiresAt` is mandatory; `notBefore` optional),
* and it cannot exceed `maxExemptionDuration` (default 30 days).

Expired exemptions are ignored automatically *and* cause
`validate-policies` to fail, so a stale exception cannot linger silently.

Exemptions live where the risk is owned. A team overlay declares its exemption;
the platform baseline opts in with `acceptExemptions: [id]`. The exemption still
has to match the baseline's scope and rules, so a team cannot exempt itself from
a rule it does not own.

### 2. The same settings through many resource types

`internal/workload` combines two strategies:

* a registry of known kinds with exact template paths (Pod, Deployment,
  StatefulSet, DaemonSet, ReplicaSet, ReplicationController, Job, CronJob,
  Rollout, Knative, Ray, Kubeflow, Tekton, …), and
* a **structural scan** that finds any pod-spec-shaped map anywhere under
  `spec`, even for CRDs. A map qualifies only if it has a non-empty
  `containers`/`initContainers`/`ephemeralContainers` list whose entries carry
  image *and* name, which keeps false positives down.

`ConfigMap`/`Secret` payloads are never scanned (they are user data, not
schemas). Scanning is bounded (32 templates, depth 24, 20k nodes) so a hostile
object cannot exhaust the controller. Objects with an unreadable template, or a
container with no image, are **denied** rather than skipped.

The webhook configuration intercepts CREATE/UPDATE for all the built-in kinds
above, plus the `pods/ephemeralcontainers` subresource (so `kubectl debug` cannot
attach a privileged debug container). For CRDs beyond that list the structural
scan only helps if the object actually reaches the webhook: pass
`render-webhook-config --wildcard-resources` if your platform creates workloads
through custom operators. The trade-off — evaluating every object in the cluster
— is documented rather than hidden.

### 3. Availability *and* safety

Kubernetes' `failurePolicy` is per webhook, not per namespace, so one
configuration cannot both "fail open in dev" and "fail closed in prod". The
generated configuration therefore contains **two webhooks** sharing one server:

| Webhook | Matches | failurePolicy |
|---|---|---|
| `guard.example.com.strict` | namespaces labelled `guard.example.com/enforcement=strict` | `Fail` |
| `guard.example.com.default` | everything else (except `disabled`) | `Ignore` |

* An outage never blocks ordinary namespaces; it does block strict ones.
* `enforcement=disabled` is excluded entirely, used for the guard's own
  namespace and break-glass. Changing a namespace to `disabled` is itself an
  intercepted, admin-only operation — a workload author cannot opt their
  namespace out.
* Inside the process, if policy files fail to parse or informers have not
  synced, the engine **fails closed for strict namespaces and open elsewhere**,
  marks the response degraded, writes an audit record and bumps a metric. The
  last known good policy set stays active; a broken edit never replaces working
  policy.
* Readiness (`/readyz`) goes 503 when policy is stale, which removes the pod
  from the Service so the API server applies `failurePolicy` instead of
  receiving evaluate-with-stale-policy answers. Liveness (`/healthz`) stays up.

## Rules

| Rule | Default action | Notes |
|---|---|---|
| `pod.privileged` | deny | also strips privileged-only capabilities when remediating |
| `pod.allowPrivilegeEscalation` | remediate | absent = true (Kubernetes default) is flagged |
| `pod.capabilities` | remediate | allow-list or dangerous-capability deny-list; `drop: ALL` + `add` flagged |
| `pod.seccompProfile` | remediate | container and pod-level `Unconfined` |
| `pod.runAsNonRoot` | remediate | non-zero `runAsUser` counts as compliant |
| `pod.readOnlyRootFilesystem` | remediate | |
| `pod.hostPathVolumes` | deny | configurable allowed path prefixes, traversal-safe |
| `pod.hostNamespaces` | deny (remediate optional) | hostNetwork / hostPID / hostIPC |
| `pod.hostUsers` | deny (remediate optional) | |
| `pod.hostPorts` | remediate | allow-list |
| `pod.volumeTypes` | deny | NFS, iSCSI, RBD, CSI, cloud disks, … |
| `pod.unsafeSysctls` | deny | namespaced safe list built in |
| `pod.ephemeralContainers` | deny | `kubectl debug` bypass |
| `pod.procMount` | remediate | |
| `pod.hostProcess` | deny | Windows host process |
| `pod.shareProcessNamespace` | remediate | |
| `pod.serviceAccountToken` | remediate | automount default |
| `image.provenance` | deny | registry allow-list; optional signature enforcement |
| `image.digestOrPullAlways` | remediate | pins `imagePullPolicy` when a digest cannot be inferred |
| `object.unknownWorkload` | advisory | never denies; records that a scan happened |
| `object.malformedWorkload` | deny | missing image, non-list containers, truncated scan |

Rules that cannot be safely rewritten (`pod.ephemeralContainers`, volume types,
image provenance) are rejected if a policy tries to set `action: remediate`.

### Remediation is verified, not trusted

A remediation rule mutates the object in place. The engine diffs the object
before/after to build an exact RFC 6902 patch, then **applies its own patch and
re-runs evaluation**. If any deny-level violation remains, the request is denied
instead of admitted with a false "fixed" message. The validating endpoint runs
with mutation disabled, so it can never report a fix it did not apply: in a real
cluster the mutating webhook runs first and validation sees the patched object.

### Updates to existing objects

On UPDATE the guard compares against the stored object. A violation that already
existed is **reported but does not block** an unrelated edit (otherwise a
legacy privileged Deployment would freeze its own rollout forever); a *newly
introduced* violation still denies.

## Quick start

```bash
go build ./cmd/...
go test ./...

# Validate policy in CI.
go run ./cmd/admissionctl validate-policies --policy-dir testdata/policies

# Offline replay of the example corpus.
go run ./cmd/admissionctl simulate --policy-dir testdata/policies \
  --manifest testdata/manifests/workloads.yaml \
  --namespace-labels "team-payments=payments:strict,team-web=web,team-analytics=analytics,ci-builders=ci"

# Full AdmissionReview round trip: real webhook, real HTTP, mutate then validate,
# plus a simulated webhook outage demonstrating strict vs standard behaviour.
go run ./cmd/admissionctl e2e --policy-dir testdata/policies \
  --manifest testdata/manifests/workloads.yaml \
  --namespace-labels "team-payments=payments:strict,team-web=web,team-analytics=analytics,ci-builders=ci"

# Render the split webhook configuration.
go run ./cmd/admissionctl render-webhook-config \
  --service admission-guard --namespace admission-guard --ca-bundle ca.crt
```

Deploy:

```bash
kubectl apply -f deploy/crds/
kubectl apply -f deploy/manifests/namespace-and-rbac.yaml
kubectl apply -f deploy/manifests/deployment.yaml   # build image first
kubectl apply -f deploy/manifests/pdb.yaml
./deploy/scripts/gen-certs.sh && ./deploy/generated/apply.sh
```

Label namespaces:

```bash
kubectl label namespace payments guard.example.com/team=payments
kubectl label namespace prod-payments guard.example.com/team=payments \
  guard.example.com/enforcement=strict
```

## Testing

No cluster is required. Three levels:

* **Unit tests** — `internal/workload` (extraction, scan bounds, determinism),
  `internal/policy` (validation, expiry, scope), `internal/rules`,
  `internal/admission` (decisions, patches, pre-existing, degradation),
  `internal/store` (atomic reload, last-good retention),
  `internal/webhookconfig` (strict/default split),
  `internal/simulator` (failure policies, UID mismatch, mutate→validate order).
* **HTTP tests** — `internal/webhook` drives real `httptest` listeners with
  AdmissionReview payloads.
* **Cluster-backed end-to-end** — `internal/admission/e2e_test.go` starts
  client-go **fake clients**, runs the real `ClusterStore` informers against
  `SecurityPolicy` objects, serves the real webhook over HTTP, and drives it
  with the simulated API server. The offline/e2e CLI corpora live in
  `testdata/`.

Run everything, including the race detector:

```bash
go test -race ./...
```

## Operational notes and limits

* **Metrics** (`/metrics`): decision counts, degraded decisions by enforcement
  class, audit write failures, in-flight requests. Alert on
  `admission_guard_degraded_total` and on any `failurePolicy=Fail` webhook outage.
* **Audit** (`--audit-log`): one JSON object per decision, including honoured
  exemption IDs and their expiry so returning risk is visible before it returns.
* **Image attestation** is metadata matching only: `TrustStore` lists
  image+signer. This service does **not** verify cosign/notation signatures. Point
  `requireSignatures` at a store populated by a real verifier, or keep registry
  allow-listing as the barrier and treat the trust store as provenance metadata.
* The structural scan finds *pod-spec-shaped* maps. An operator that stores a
  pod template under an unusual shape (no `image` in the container entries) will
  not be detected — add its kind to `internal/workload`'s registry.
* The webhook does not intercept DELETE. `pods/ephemeralcontainers` is in the
  default rule set, so debug-container attachment is checked on UPDATE; objects
  that already carry ephemeral containers are also flagged by
  `pod.ephemeralContainers`.
* `--policy-reload-interval` polls files. There is no inotify dependency on
  purpose; a 30s poll is cheaper than a stuck watcher.
