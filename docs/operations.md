# Operations runbook

## Enforcement classes

| Namespace label | Webhook failurePolicy | Engine on policy outage | Use for |
|---|---|---|---|
| `enforcement=strict` | `Fail` | closed | production, regulated workloads |
| (absent) / `standard` | `Ignore` | open | development, internal tooling |
| `enforcement=disabled` | excluded | n/a | `kube-system`, the guard's own namespace, break-glass |

Changing a namespace to `disabled`, or removing `strict`, is intercepted and
requires membership in `--admin-groups` (default `system:masters`).

## Alerts

| Metric | Condition | Meaning |
|---|---|---|
| `admission_guard_decisions_total{decision="deny"}` | spike | policy change or an attack; check audit |
| `admission_guard_degraded_total` | any increase | policy store unhealthy; strict namespaces are failing closed |
| `admission_guard_audit_write_errors_total` | any increase | audit sink is down — decisions are no longer recorded |
| `admission_guard_inflight_requests` | sustained high | policy evaluation is slow; check object size/bounds |

`/readyz` returning 503 means the pod has been removed from the Service and the
API server is applying `failurePolicy`. That is expected during a policy fault;
the fix is the policy, not the pod.

## Recovering from a bad policy

1. `admissionctl validate-policies --policy-dir <dir>` in CI should have caught
   it; if it reached the cluster, the daemon keeps the last good snapshot and
   reports unhealthy.
2. Correct the ConfigMap/SecurityPolicy. The daemon polls every
   `--policy-reload-interval` (default 30s in the manifest).
3. `kubectl -n admission-guard get pods` — a 503 on `/readyz` is normal until the
   store is healthy again.

## Break-glass

A strict namespace is unavailable only if every replica is down *and* the
failure policy is `Fail`. To restore service without weakening policy:

1. Scale the guard back up; two replicas with anti-affinity and a PDB should
   make this unnecessary.
2. If the guard itself is broken, the `admission-guard` namespace is
   `enforcement=disabled`, so the fix can be applied from there.
3. Deleting the ValidatingWebhookConfiguration is the last resort; re-apply it
   from `admissionctl render-webhook-config` immediately, because it is not in
   GitOps otherwise.

## Rollout

The deployment uses `maxUnavailable` implicitly from the Deployment defaults plus
a `preStop` sleep; a PDB keeps one replica available. Because the webhook
Service load-balances across replicas, at least one ready replica is enough for
non-strict namespaces. Strict namespaces need any one replica to answer, which
the PDB guarantees for voluntary disruptions.

## Auditing exemptions

```bash
# Exemptions expiring soon (also enforced by validate-policies in CI)
admissionctl validate-policies --policy-dir policies --expiry-warning-window 336h

# What applies to a namespace right now
admissionctl explain --policy-dir policies --namespace payments \
  --labels "guard.example.com/team=payments,guard.example.com/enforcement=strict"

# Honoured exemptions in the audit stream
jq -r 'select(.exemptions) | [.namespace, .name, (.exemptions[] | .id)] | @tsv' audit.jsonl
```
