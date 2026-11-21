# Example workloads

`workloads.yaml` is a replay corpus. Each document demonstrates a distinct
bypass route or policy feature:

| Object | Expected outcome | What it proves |
|---|---|---|
| `Deployment/web` | allow | A compliant workload passes untouched |
| `Deployment/escape-attempt` | deny | privileged + hostNetwork + hostPID + hostPath |
| `TrainingJob/sneaky` | deny | Unknown CRD with an embedded pod template is still checked |
| `CronJob/nightly` | deny | `jobTemplate.spec.template.spec` is checked |
| `Deployment/sloppy` | remediated | Dangerous capabilities are removed, then admitted |
| `Deployment/unknown-image` | deny | Registry allow-list and mutable tag |
| `Deployment/analytics-validator` | remediated | Team-scoped expiring exemption for a vendor image |
| `Job/image-build` | remediated | Namespace-scoped exemption for privileged CI builds |
| `Pod/debugme` | deny | Ephemeral (debug) containers |
| `Deployment/no-image` | deny | Malformed container fails closed |

Replay offline:

    admissionctl simulate --policy-dir testdata/policies \
      --manifest testdata/manifests/workloads.yaml \
      --namespace-labels "team-payments=payments:strict,team-web=web,team-analytics=analytics,ci-builders=ci"

Replay through a real AdmissionReview HTTP round trip (mutate then validate,
including a simulated webhook outage):

    admissionctl e2e --policy-dir testdata/policies \
      --manifest testdata/manifests/workloads.yaml \
      --namespace-labels "team-payments=payments:strict,team-web=web,team-analytics=analytics,ci-builders=ci"
