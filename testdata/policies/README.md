# Example policies

- `baseline.yaml` — platform baseline applied to every namespace. Denies
  privileged/host-access workloads, remediates the "sloppy but fixable" fields,
  and restricts images to the internal registry.
- `shared-cache-exemption.yaml` — a team overlay. It owns a team-scoped,
  expiring exemption and opts the platform baseline into honouring it via
  `acceptExemptions`. This is how an exception is granted where the risk is
  owned without weakening the baseline for everyone.
- `truststore.yaml` — trusted image attestations. Enforced only when a rule sets
  `config.requireSignatures: true`, so signatures can be staged gradually.

Validate the whole directory before committing:

    admissionctl validate-policies --policy-dir testdata/policies

`validate-policies` also warns about exemptions expiring within 14 days, which
is meant to be wired into CI so temporary exceptions get reviewed.
