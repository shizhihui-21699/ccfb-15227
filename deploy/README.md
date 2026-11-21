# Deployment

Apply in order:

```bash
# 1. API types
kubectl apply -f crds/

# 2. Namespace (labelled enforcement=disabled), RBAC, default policy
kubectl apply -f manifests/namespace-and-rbac.yaml
kubectl apply -f manifests/policies-configmap.yaml

# 3. Build and publish the image, then point the Deployment at it
make build
kubectl apply -f manifests/deployment.yaml
kubectl apply -f manifests/pdb.yaml
kubectl apply -f manifests/networkpolicy.yaml   # adjust CIDRs first

# 4. TLS + webhook configuration (two webhooks: strict=Fail, default=Ignore)
./scripts/gen-certs.sh
./generated/apply.sh
```

Order matters: the guard must be running and reachable before the
ValidatingWebhookConfiguration is created, otherwise strict namespaces cannot
be created while every replica is still starting.

`kubectl label namespace <name> guard.example.com/team=<team>` opts a namespace
into team-scoped policy; add `guard.example.com/enforcement=strict` to make it
fail closed on webhook outages.
