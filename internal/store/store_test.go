package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const goodPolicy = `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p1}
spec:
  rules: [{id: pod.privileged}]
`

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", goodPolicy)
	writeFile(t, dir, "b.yml", `
apiVersion: guard.example.com/v1alpha1
kind: TrustStore
metadata: {name: t}
spec:
  signatures:
    - image: registry.example.com/a@sha256:1111111111111111111111111111111111111111111111111111111111111111
      signer: s
`)
	// Multi-document file.
	writeFile(t, dir, "c.yaml", goodPolicyReplaceName("p2")+"\n---\n"+goodPolicyReplaceName("p3"))
	// Ignored extensions.
	writeFile(t, dir, "notes.txt", "not policy")

	loaded, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(loaded.Policies) != 3 {
		t.Fatalf("expected 3 policies, got %d", len(loaded.Policies))
	}
	if loaded.TrustStore == nil {
		t.Fatal("trust store not loaded")
	}
}

func goodPolicyReplaceName(name string) string {
	return strings.Replace(goodPolicy, "name: p1", "name: "+name, 1)
}

func TestLoadDirRejectsWholeDirectoryOnOneBadFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "good.yaml", goodPolicy)
	writeFile(t, dir, "bad.yaml", `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: broken}
spec:
  rules: [{id: pod.not-a-rule}]
`)
	loaded, err := LoadDir(dir)
	if err == nil {
		t.Fatal("expected an error")
	}
	// The good policy is still returned so the caller can decide; the file store
	// keeps the last good snapshot instead of applying a partial set.
	if len(loaded.Errors) == 0 {
		t.Fatal("expected errors on the snapshot")
	}
}

func TestFileStoreKeepsLastGoodOnReloadFailure(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "good.yaml", goodPolicy)
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs.Policies()) != 1 || fs.Health() != nil {
		t.Fatal("initial load failed")
	}
	before := fs.Policies()[0].Metadata.Name

	// Break the directory.
	writeFile(t, dir, "bad.yaml", `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: broken}
spec:
  rules: [{id: nope}]
`)
	if err := fs.Reload(); err == nil {
		t.Fatal("reload should report the error")
	}
	if fs.Health() == nil {
		t.Fatal("health must report the failure so strict namespaces fail closed")
	}
	// Last good policy stays active.
	if len(fs.Policies()) != 1 || fs.Policies()[0].Metadata.Name != before {
		t.Fatalf("last good policy was not preserved: %v", fs.Policies())
	}

	// Fixing the file makes health recover.
	os.Remove(filepath.Join(dir, "bad.yaml"))
	if err := fs.Reload(); err != nil {
		t.Fatal(err)
	}
	if fs.Health() != nil {
		t.Fatalf("health should recover, got %v", fs.Health())
	}
}

func TestFileStoreNamespaceResolver(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "p.yaml", goodPolicy)
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	fs.NamespaceLabels["team-a"] = map[string]string{"guard.example.com/team": "payments", "guard.example.com/enforcement": "strict"}
	info, ok := fs.Namespace("team-a")
	if !ok || info.Enforcement != "strict" || len(info.Teams("guard.example.com/team")) != 1 {
		t.Fatalf("unexpected namespace info: %+v ok=%v", info, ok)
	}
	if _, ok := fs.Namespace("missing"); ok {
		t.Fatal("unknown namespace must report not found")
	}
}

func TestDuplicatePolicyNameRejected(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", goodPolicyReplaceName("same"))
	writeFile(t, dir, "b.yaml", goodPolicyReplaceName("same"))
	_, err := LoadDir(dir)
	if err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("expected duplicate-name error, got %v", err)
	}
}

func TestLoadedFromObjects(t *testing.T) {
	objs := []unstructured.Unstructured{
		{Object: map[string]any{
			"apiVersion": "guard.example.com/v1alpha1",
			"kind":       "SecurityPolicy",
			"metadata":   map[string]any{"name": "a", "namespace": "platform"},
			"spec":       map[string]any{"rules": []any{map[string]any{"id": "pod.privileged"}}},
		}},
		{Object: map[string]any{
			"apiVersion": "guard.example.com/v1alpha1",
			"kind":       "SecurityPolicy",
			"metadata":   map[string]any{"name": "bad", "namespace": "platform"},
			"spec":       map[string]any{"rules": []any{map[string]any{"id": "nope"}}},
		}},
	}
	loaded := LoadedFromObjects(objs)
	if len(loaded.Policies) != 1 {
		t.Fatalf("expected 1 valid policy, got %d", len(loaded.Policies))
	}
	if len(loaded.Errors) != 1 || !strings.Contains(loaded.Errors[0].Error(), "nope") {
		t.Fatalf("expected an error naming the bad rule, got %v", loaded.Errors)
	}
}
