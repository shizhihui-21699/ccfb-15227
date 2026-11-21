# Policy reference

A policy is one `SecurityPolicy` document (`guard.example.com/v1alpha1`).
Policies are additive: every policy whose scope matches a request is evaluated,
and a deny from any of them rejects the object. There is no "policy priority";
use `scope` and exemptions, not ordering.

```yaml
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata:
  name: payments-overlay
  namespace: platform          # only used for cluster-sourced policies
spec:
  description: "what this policy is for"
  mode: enforce                # enforce | audit (default enforce)
  failureMode: closed          # closed | open (default closed)
  teamLabel: guard.example.com/team
  maxExemptionDuration: 720h   # default 720h (30 days)
  scope: {...}
  rules: [...]
  acceptExemptions: [...]
  exemptions: [...]
```

## `scope`

Every field is optional; an omitted list means "all".

```yaml
scope:
  namespaces: [prod-a, prod-*]      # glob patterns allowed
  excludeNamespaces: [prod-a-sandbox]
  teams: [payments, "web-*"]
  excludeTeams: [payments-contractors]
  namespaceSelector:                 # standard Kubernetes selector on Namespace labels
    matchLabels: {tier: prod}
```

Exclusions always win. A policy with `teams: [payments]` does not apply to a
namespace whose team label does not include `payments`.

Teams come from the namespace label named by `teamLabel` (default
`guard.example.com/team`) and are comma-separated for shared namespaces:
`guard.example.com/team: payments, shared-platform`.

## `rules`

```yaml
rules:
  - id: pod.privileged
  - id: pod.capabilities
    action: remediate            # deny (default) | remediate | audit | warn
    severity: high               # critical | high | medium | low | info
    enabled: true
    config:
      allowed: [NET_BIND_SERVICE]
```

* `action: remediate` is only accepted for rules that can be rewritten safely
  (`policy.Remediable`). A deny-only rule set to remediate fails policy
  compilation rather than silently denying.
* `action: audit` and `warn` always admit; `audit` is silent, `warn` surfaces an
  admission warning.
* `mode: audit` at the policy level downgrades every rule to audit regardless of
  its action.

### Rule configs

| Rule | Config | Meaning |
|---|---|---|
| `pod.capabilities` | `allowed: [CAP]` | capabilities permitted in `add`; empty = dangerous deny-list |
| `pod.hostPathVolumes` | `allowedPaths: [/prefix]` | host paths permitted (prefix match, traversal-safe) |
| `pod.hostPorts` | `allowedPorts: [8080]` | host ports permitted |
| `pod.volumeTypes` | `allowed: [configMap, …]` | volume source types permitted |
| `image.provenance` | `allowedRegistries: [host/path]`, `requireSignatures: bool` | registry prefix match; signature enforcement opt-in |

## `exemptions`

```yaml
exemptions:
  - id: analytics-validator-image      # unique within the policy
    reason: "vendor image not mirrored yet"   # required, min length 1
    requestedBy: analytics-team               # required
    ticket: INFRA-88
    notBefore: "2027-01-01T00:00:00Z"         # optional
    expiresAt: "2027-02-01T00:00:00Z"         # required, RFC3339
    scope:
      rules: [image.provenance]               # required; "*" allows all
      namespaces: [team-analytics]            # at least one of
      teams: [analytics]                      # namespaces / teams /
      workloads: [analytics-validator]        # workloads / kinds required
      kinds: [Deployment]
```

Compile-time guarantees:

* `reason`, `requestedBy`, `expiresAt` are mandatory.
* `scope.rules` must be present and name known rules (or `*`).
* at least one of namespaces/teams/workloads/kinds must be set.
* `expiresAt` may not exceed `maxExemptionDuration` from now.
* a policy containing an already-expired exemption fails to compile, so stale
  exceptions must be removed rather than forgotten.

Runtime behaviour:

* expired (or not-yet-active) exemptions are ignored automatically;
* a matched exemption suppresses *only* the rules it lists — every other rule
  still applies to the same object;
* honoured exemptions are recorded in the audit stream with their expiry time.

## Cross-policy exemptions (`acceptExemptions`)

Exemptions are declared where the risk is owned. When another policy's rule
would catch the same object, that policy must explicitly opt in:

```yaml
# team overlay declares the exemption
spec:
  scope: {teams: [analytics]}
  exemptions:
    - id: analytics-validator-image
      ...
---
# platform baseline honours it
spec:
  acceptExemptions: [analytics-validator-image]
  rules:
    - id: image.provenance
      config: {allowedRegistries: [registry.example.com]}
```

The exemption still has to match the accepting policy's namespace, team,
workload/kind and rule selectors. A team cannot exempt itself from a rule it does
not own, and cannot widen another policy's exemption.

## TrustStore

```yaml
apiVersion: guard.example.com/v1alpha1
kind: TrustStore
metadata: {name: platform-signatures}
spec:
  signatures:
    - image: registry.example.com/platform/api@sha256:1111...
      signer: platform-release
      expiresAt: "2027-01-01T00:00:00Z"     # optional
```

Only the first TrustStore object/document is used; a second is a load error.
Digest references match exactly; tags match only if pinned and not `:latest`.
Enforcement requires `image.provenance` with `config.requireSignatures: true`, so
attestations can be collected before they are required.
