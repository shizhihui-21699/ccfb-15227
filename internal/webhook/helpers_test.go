package webhook_test

import (
	"os"
	"path/filepath"

	"github.com/example/cluster-admission-guard/internal/policy"
)

const validPolicy = `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: test}
spec:
  rules:
    - id: pod.privileged
    - id: pod.hostNamespaces
    - id: pod.allowPrivilegeEscalation
      action: remediate
    - id: pod.runAsNonRoot
      action: remediate
    - id: pod.readOnlyRootFilesystem
      action: remediate
    - id: pod.seccompProfile
      action: remediate
    - id: pod.serviceAccountToken
      action: remediate
    - id: object.malformedWorkload
`

func writeFile(dir, name, content string) error {
	return os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600)
}

// staticStore is a Store with no namespaces and no health problems.
type staticStore struct{}

func (staticStore) Policies() []*policy.CompiledPolicy { return nil }
func (staticStore) TrustStore() *policy.TrustStore     { return nil }
func (staticStore) Health() error                      { return nil }
func (staticStore) Namespace(string) (policy.NamespaceInfo, bool) {
	return policy.NamespaceInfo{}, false
}

// brokenStore reports a policy failure so degradation paths are exercised.
type brokenStore struct{ inner staticStore }

func (b *brokenStore) Policies() []*policy.CompiledPolicy { return b.inner.Policies() }
func (b *brokenStore) TrustStore() *policy.TrustStore     { return nil }
func (b *brokenStore) Namespace(name string) (policy.NamespaceInfo, bool) {
	return policy.NamespaceInfo{Name: name, Enforcement: policy.EnforcementStandard}, true
}
func (b *brokenStore) Health() error { return errBroken }

type brokenErr struct{}

func (brokenErr) Error() string { return "simulated policy failure" }

var errBroken = brokenErr{}
