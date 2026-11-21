package admission

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/example/cluster-admission-guard/internal/policy"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// testStore is a configurable Store for engine tests.
type testStore struct {
	policies []*policy.CompiledPolicy
	trust    *policy.TrustStore
	ns       map[string]policy.NamespaceInfo
	health   error
}

func (s *testStore) Policies() []*policy.CompiledPolicy { return s.policies }
func (s *testStore) TrustStore() *policy.TrustStore     { return s.trust }
func (s *testStore) Health() error                      { return s.health }
func (s *testStore) Namespace(name string) (policy.NamespaceInfo, bool) {
	info, ok := s.ns[name]
	return info, ok
}

func mustPolicy(t *testing.T, yamlText string) *policy.CompiledPolicy {
	t.Helper()
	p, err := policy.ParsePolicy([]byte(yamlText))
	if err != nil {
		t.Fatalf("policy did not compile: %v", err)
	}
	return p
}

func at(d time.Duration) string { return time.Now().Add(d).UTC().Format(time.RFC3339) }

func newStore(namespaces map[string]map[string]string, policies ...*policy.CompiledPolicy) *testStore {
	ns := map[string]policy.NamespaceInfo{}
	for name, labels := range namespaces {
		if labels == nil {
			labels = map[string]string{}
		}
		ns[name] = policy.NamespaceInfo{Name: name, Labels: labels, Enforcement: policy.EnforcementOf(labels)}
	}
	return &testStore{policies: policies, ns: ns}
}

// --- object builders ---------------------------------------------------------------

func privilegedDeployment(ns, name string) map[string]any {
	return map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"containers": []any{map[string]any{
						"name":  "c",
						"image": "registry.example.com/app@sha256:" + strings.Repeat("a", 64),
						"securityContext": map[string]any{
							"privileged": true,
						},
					}},
				},
			},
		},
	}
}

func safeDeployment(ns, name string) map[string]any {
	return map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": map[string]any{
					"automountServiceAccountToken": false,
					"containers": []any{map[string]any{
						"name":  "c",
						"image": "registry.example.com/app@sha256:" + strings.Repeat("a", 64),
						"securityContext": map[string]any{
							"privileged":               false,
							"allowPrivilegeEscalation": false,
							"runAsNonRoot":             true,
							"readOnlyRootFilesystem":   true,
							"seccompProfile":           map[string]any{"type": "RuntimeDefault"},
							"capabilities":             map[string]any{"drop": []any{"ALL"}},
						},
					}},
				},
			},
		},
	}
}

var deployGVK = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}

func createReq(gvk schema.GroupVersionKind, obj map[string]any) Request {
	ns, _ := obj["metadata"].(map[string]any)["namespace"].(string)
	name, _ := obj["metadata"].(map[string]any)["name"].(string)
	return Request{Operation: Create, GVK: gvk, Namespace: ns, Name: name, Object: obj}
}

// --- tests -------------------------------------------------------------------------

const baselinePolicy = `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: baseline}
spec:
  failureMode: closed
  rules:
    - id: pod.privileged
      severity: critical
    - id: pod.hostNamespaces
      severity: critical
    - id: pod.allowPrivilegeEscalation
      action: remediate
    - id: pod.runAsNonRoot
      action: remediate
    - id: pod.seccompProfile
      action: remediate
    - id: pod.readOnlyRootFilesystem
      action: remediate
    - id: pod.serviceAccountToken
      action: remediate
    - id: pod.ephemeralContainers
      severity: high
    - id: object.malformedWorkload
      severity: high
    - id: object.unknownWorkload
      severity: high
`

func TestDeniesPrivileged(t *testing.T) {
	store := newStore(nil, mustPolicy(t, baselinePolicy))
	e := NewEngine(store)
	resp := e.Evaluate(createReq(deployGVK, privilegedDeployment("team-a", "bad")))
	if resp.Allowed {
		t.Fatal("privileged deployment must be denied")
	}
	if len(resp.Reasons) == 0 || !strings.Contains(resp.Reasons[0], "privileged") {
		t.Fatalf("denial reasons missing detail: %v", resp.Reasons)
	}
}

func TestAllowsSafe(t *testing.T) {
	store := newStore(nil, mustPolicy(t, baselinePolicy))
	e := NewEngine(store)
	resp := e.Evaluate(createReq(deployGVK, safeDeployment("team-a", "good")))
	if !resp.Allowed {
		t.Fatalf("safe deployment denied: %v", resp.Reasons)
	}
	if len(resp.Patch) != 0 {
		t.Fatalf("safe deployment should not be patched: %s", resp.Patch)
	}
}

// TestRemediationProducesCompliantObject checks the whole round trip: the patch
// applies to the submitted object, and the result passes a fresh evaluation.
func TestRemediationProducesCompliantObject(t *testing.T) {
	store := newStore(nil, mustPolicy(t, baselinePolicy))
	e := NewEngine(store)

	submitted := map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "sloppy", "namespace": "team-a"},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{
				"name":  "c",
				"image": "registry.example.com/app@sha256:" + strings.Repeat("a", 64),
			}},
		}}},
	}
	submittedJSON, _ := json.Marshal(submitted)
	resp := e.Evaluate(createReq(deployGVK, submitted))
	if !resp.Allowed {
		t.Fatalf("remediable object denied: %v", resp.Reasons)
	}
	if len(resp.Patch) == 0 {
		t.Fatal("expected a remediation patch")
	}
	patch, err := jsonpatch.DecodePatch(resp.Patch)
	if err != nil {
		t.Fatalf("patch does not decode: %v", err)
	}
	patchedJSON, err := patch.Apply(submittedJSON)
	if err != nil {
		t.Fatalf("patch does not apply: %v", err)
	}
	var patched map[string]any
	if err := json.Unmarshal(patchedJSON, &patched); err != nil {
		t.Fatal(err)
	}
	again := e.Evaluate(createReq(deployGVK, patched))
	if !again.Allowed {
		t.Fatalf("remediated object still denied: %v", again.Reasons)
	}
	if len(again.Patch) != 0 {
		t.Fatalf("remediated object still needs patching: %s", again.Patch)
	}
}

// TestValidationOnlyModeDeniesInsteadOfPatching ensures /validate can never
// answer "allowed, fixed" for something it did not fix.
func TestValidationOnlyModeDeniesInsteadOfPatching(t *testing.T) {
	store := newStore(nil, mustPolicy(t, baselinePolicy))
	e := NewEngine(store).WithoutMutation()

	submitted := map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "sloppy", "namespace": "team-a"},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{
				"name":  "c",
				"image": "registry.example.com/app@sha256:" + strings.Repeat("a", 64),
			}},
		}}},
	}
	resp := e.Evaluate(createReq(deployGVK, submitted))
	if resp.Allowed {
		t.Fatal("validate-only must not allow an object it cannot fix")
	}
	if len(resp.Patch) != 0 {
		t.Fatal("validate-only must not return a patch")
	}
	if !strings.Contains(strings.Join(resp.Reasons, " "), "mutating webhook") {
		t.Fatalf("denial should explain the mutation route: %v", resp.Reasons)
	}
}

func TestExemptionScopedAndExpiring(t *testing.T) {
	p := mustPolicy(t, `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec:
  rules: [{id: pod.privileged}, {id: pod.hostNamespaces}]
  exemptions:
    - id: ci-priv
      reason: ci builds need privileged
      requestedBy: platform
      expiresAt: "`+at(48*time.Hour)+`"
      scope:
        namespaces: [ci]
        rules: [pod.privileged]
`)
	store := newStore(nil, p)
	e := NewEngine(store)

	// Exempted: only the privileged finding is exempted.
	obj := privilegedDeployment("ci", "job")
	obj["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["hostNetwork"] = true
	resp := e.Evaluate(createReq(deployGVK, obj))
	if resp.Allowed {
		t.Fatal("hostNetwork is not exempted, so the request must be denied")
	}
	for _, r := range resp.Reasons {
		if strings.Contains(r, "privileged") {
			t.Fatalf("privileged finding should have been exempted: %v", resp.Reasons)
		}
	}

	// Outside the namespace the exemption does not apply.
	resp = e.Evaluate(createReq(deployGVK, privilegedDeployment("team-a", "x")))
	if resp.Allowed {
		t.Fatal("exemption must be namespace-scoped")
	}

	// After expiry it no longer applies.
	e.Now = func() time.Time { return time.Now().Add(72 * time.Hour) }
	resp = e.Evaluate(createReq(deployGVK, privilegedDeployment("ci", "job")))
	if resp.Allowed {
		t.Fatal("exemption must stop applying after expiry")
	}
	if !strings.Contains(strings.Join(resp.Reasons, " "), "privileged") {
		t.Fatalf("expected privileged denial after expiry: %v", resp.Reasons)
	}
}

func TestPreExistingViolationDoesNotBlockUnrelatedUpdate(t *testing.T) {
	store := newStore(nil, mustPolicy(t, baselinePolicy))
	e := NewEngine(store)

	oldObj := privilegedDeployment("team-a", "legacy")
	newObj := privilegedDeployment("team-a", "legacy")
	// Unrelated change: add a label.
	newObj["metadata"].(map[string]any)["labels"] = map[string]any{"touched": "true"}

	req := Request{Operation: Update, GVK: deployGVK, Namespace: "team-a", Name: "legacy", Object: newObj, OldObject: oldObj}
	resp := e.Evaluate(req)
	if !resp.Allowed {
		t.Fatalf("pre-existing violation must not block an unrelated update: %v", resp.Reasons)
	}
	foundPreExisting := false
	for _, f := range resp.Findings {
		if f.Disposition == policy.DispositionPreExisting {
			foundPreExisting = true
		}
	}
	if !foundPreExisting {
		t.Fatal("pre-existing finding should be reported with its disposition")
	}
}

func TestNewViolationOnUpdateIsDenied(t *testing.T) {
	store := newStore(nil, mustPolicy(t, baselinePolicy))
	e := NewEngine(store)

	oldObj := safeDeployment("team-a", "app")
	newObj := safeDeployment("team-a", "app")
	newObj["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["hostPID"] = true

	req := Request{Operation: Update, GVK: deployGVK, Namespace: "team-a", Name: "app", Object: newObj, OldObject: oldObj}
	resp := e.Evaluate(req)
	if resp.Allowed {
		t.Fatal("newly introduced hostPID must be denied")
	}
}

func TestUnknownKindWithTemplate(t *testing.T) {
	store := newStore(nil, mustPolicy(t, baselinePolicy))
	e := NewEngine(store)

	obj := map[string]any{
		"apiVersion": "example.com/v1",
		"kind":       "TrainingJob",
		"metadata":   map[string]any{"name": "job", "namespace": "team-a"},
		"spec": map[string]any{"worker": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{
				"name":            "c",
				"image":           "registry.example.com/app@sha256:" + strings.Repeat("a", 64),
				"securityContext": map[string]any{"privileged": true},
			}},
		}}}},
	}
	gvk := schema.GroupVersionKind{Group: "example.com", Version: "v1", Kind: "TrainingJob"}
	resp := e.Evaluate(createReq(gvk, obj))
	if resp.Allowed {
		t.Fatal("privileged container inside an unknown CRD must be denied")
	}
	if !strings.Contains(strings.Join(resp.Reasons, " "), "privileged") {
		t.Fatalf("denial should name the violation: %v", resp.Reasons)
	}
}

func TestMalformedWorkloadDenied(t *testing.T) {
	store := newStore(nil, mustPolicy(t, baselinePolicy))
	e := NewEngine(store)
	obj := safeDeployment("team-a", "broken")
	c := obj["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	delete(c, "image")
	resp := e.Evaluate(createReq(deployGVK, obj))
	if resp.Allowed {
		t.Fatal("container without an image must be denied")
	}
}

func TestNamespaceDisabledRequiresAdmin(t *testing.T) {
	store := newStore(nil, mustPolicy(t, baselinePolicy))
	e := NewEngine(store)
	e.AdminGroups = []string{"system:masters"}
	nsObj := map[string]any{
		"apiVersion": "v1", "kind": "Namespace",
		"metadata": map[string]any{"name": "escape", "labels": map[string]any{policy.EnforcementLabel: "disabled"}},
	}
	gvk := schema.GroupVersionKind{Version: "v1", Kind: "Namespace"}
	req := Request{Operation: Create, GVK: gvk, Name: "escape", Object: nsObj}

	if resp := e.Evaluate(req); resp.Allowed {
		t.Fatal("non-admin must not be able to disable admission review for a namespace")
	}
	req.Groups = []string{"system:authenticated", "system:masters"}
	resp := e.Evaluate(req)
	if !resp.Allowed {
		t.Fatalf("admin should be allowed: %v", resp.Reasons)
	}
	if len(resp.Warnings) == 0 {
		t.Fatal("admin bypass should produce a warning")
	}
}

func TestFailClosedVersusOpenOnStoreFailure(t *testing.T) {
	// A Namespace lookup resolves enforcement; strict → closed.
	policyText := mustPolicy(t, baselinePolicy)
	store := newStore(map[string]map[string]string{
		"strict-ns": {policy.EnforcementLabel: "strict"},
		"normal":    {},
	}, policyText)
	store.health = fmt.Errorf("policy directory unreadable")

	e := NewEngine(store)
	resp := e.Evaluate(createReq(deployGVK, safeDeployment("strict-ns", "x")))
	if resp.Allowed {
		t.Fatal("strict namespace must fail closed when policy is unavailable")
	}
	if !resp.Degraded {
		t.Fatal("response must be marked degraded")
	}

	resp = e.Evaluate(createReq(deployGVK, safeDeployment("normal", "x")))
	if !resp.Allowed {
		t.Fatal("normal namespace must fail open so deployments keep working")
	}
	if !resp.Degraded {
		t.Fatal("fail-open decision must still be marked degraded")
	}

	// StrictWhenUnlabelled extends the closed posture to unknown namespaces.
	e.StrictWhenUnlabelled = true
	resp = e.Evaluate(createReq(deployGVK, safeDeployment("unknown", "x")))
	if resp.Allowed {
		t.Fatal("unknown namespace must fail closed when StrictWhenUnlabelled is set")
	}
}

func TestAuditModeReportsWithoutDenying(t *testing.T) {
	p := mustPolicy(t, strings.Replace(baselinePolicy, "failureMode: closed", "mode: audit\n  failureMode: closed", 1))
	store := newStore(nil, p)
	e := NewEngine(store)
	resp := e.Evaluate(createReq(deployGVK, privilegedDeployment("team-a", "x")))
	if !resp.Allowed {
		t.Fatalf("audit mode must not deny: %v", resp.Reasons)
	}
	seen := false
	for _, f := range resp.Findings {
		if f.Rule == policy.RulePrivileged && f.Disposition == policy.DispositionAudited {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("expected an audited privileged finding, got %+v", resp.Findings)
	}
}

func TestCrossPolicyExemption(t *testing.T) {
	owner := mustPolicy(t, `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: team-overlay}
spec:
  scope: {teams: [analytics]}
  rules: [{id: pod.runAsNonRoot, action: remediate}]
  exemptions:
    - id: analytics-image
      reason: vendor not mirrored
      requestedBy: analytics
      expiresAt: "`+at(24*time.Hour)+`"
      scope: {teams: [analytics], rules: [image.provenance]}
`)
	consumer := mustPolicy(t, `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: baseline}
spec:
  acceptExemptions: [analytics-image]
  rules:
    - id: image.provenance
      config: {allowedRegistries: [registry.example.com]}
`)
	store := newStore(map[string]map[string]string{
		"analytics": {policy.DefaultTeamLabel: "analytics"},
		"other":     {policy.DefaultTeamLabel: "other"},
	}, owner, consumer)

	e := NewEngine(store)
	obj := map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "v", "namespace": "analytics"},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"automountServiceAccountToken": false,
			"containers": []any{map[string]any{
				"name":  "v",
				"image": "vendor.example.net/validator@sha256:" + strings.Repeat("b", 64),
				"securityContext": map[string]any{
					"runAsNonRoot":             true,
					"allowPrivilegeEscalation": false,
				},
			}},
		}}},
	}
	if resp := e.Evaluate(createReq(deployGVK, obj)); !resp.Allowed {
		t.Fatalf("team-scoped exemption should allow the vendor image: %v", resp.Reasons)
	}
	// Another team does not get the exemption.
	obj["metadata"].(map[string]any)["namespace"] = "other"
	if resp := e.Evaluate(createReq(deployGVK, obj)); resp.Allowed {
		t.Fatal("exemption must be team-scoped")
	}
}

func TestTrustStoreRequiresOptIn(t *testing.T) {
	p := mustPolicy(t, `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: images}
spec:
  rules:
    - id: image.provenance
`)
	ts, err := policy.ParseTrustStore([]byte(`
apiVersion: guard.example.com/v1alpha1
kind: TrustStore
metadata: {name: t}
spec:
  signatures:
    - image: registry.example.com/other@sha256:` + strings.Repeat("c", 64) + `
      signer: release
`))
	if err != nil {
		t.Fatal(err)
	}
	store := newStore(nil, p)
	store.trust = ts
	e := NewEngine(store)

	// A trust store alone must not deny images: enforcement is opt-in.
	resp := e.Evaluate(createReq(deployGVK, safeDeployment("team-a", "x")))
	if !resp.Allowed {
		t.Fatalf("trust store without requireSignatures must not deny: %v", resp.Reasons)
	}

	p2 := mustPolicy(t, `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: images}
spec:
  rules:
    - id: image.provenance
      config: {requireSignatures: true}
`)
	store2 := newStore(nil, p2)
	store2.trust = ts
	e2 := NewEngine(store2)
	if resp := e2.Evaluate(createReq(deployGVK, safeDeployment("team-a", "x"))); resp.Allowed {
		t.Fatal("with requireSignatures, an unsigned image must be denied")
	}
}

func TestPolicyScopeExcludedNamespace(t *testing.T) {
	p := mustPolicy(t, `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec:
  scope:
    excludeNamespaces: [kube-system]
  rules: [{id: pod.privileged}]
`)
	store := newStore(nil, p)
	e := NewEngine(store)
	if resp := e.Evaluate(createReq(deployGVK, privilegedDeployment("kube-system", "x"))); !resp.Allowed {
		t.Fatal("excluded namespace must not be evaluated by this policy")
	}
	if resp := e.Evaluate(createReq(deployGVK, privilegedDeployment("team-a", "x"))); resp.Allowed {
		t.Fatal("non-excluded namespace must be evaluated")
	}
}

// reformat round-trips an object through JSON so pointer/aliasing quirks in the
// test builder cannot mask a bug.
func reformat(m map[string]any) map[string]any {
	data, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return out
}

func TestDisabledNamespaceIsSkippedByEngine(t *testing.T) {
	// Even if a directly-addressed request reaches the engine (wildcard rule,
	// manual call), the disabled label must be honoured consistently with the
	// webhook's namespaceSelector.
	store := newStore(map[string]map[string]string{
		"kube-system": {policy.EnforcementLabel: "disabled"},
	}, mustPolicy(t, baselinePolicy))
	e := NewEngine(store)
	resp := e.Evaluate(createReq(deployGVK, privilegedDeployment("kube-system", "x")))
	if !resp.Allowed {
		t.Fatalf("disabled namespace must be exempt: %v", resp.Reasons)
	}
	if len(resp.Warnings) == 0 {
		t.Fatal("skipping a namespace should say so")
	}
}

func TestDowngradingStrictNamespaceRequiresAdmin(t *testing.T) {
	store := newStore(map[string]map[string]string{
		"prod": {policy.EnforcementLabel: "strict"},
	}, mustPolicy(t, baselinePolicy))
	e := NewEngine(store)
	e.AdminGroups = []string{"system:masters"}
	gvk := schema.GroupVersionKind{Version: "v1", Kind: "Namespace"}
	oldObj := map[string]any{"metadata": map[string]any{"name": "prod", "labels": map[string]any{policy.EnforcementLabel: "strict"}}}
	newObj := map[string]any{"metadata": map[string]any{"name": "prod", "labels": map[string]any{}}}
	req := Request{Operation: Update, GVK: gvk, Name: "prod", Object: newObj, OldObject: oldObj}
	if resp := e.Evaluate(req); resp.Allowed {
		t.Fatal("non-admin must not downgrade a strict namespace")
	}
	req.Groups = []string{"system:masters"}
	if resp := e.Evaluate(req); !resp.Allowed {
		t.Fatalf("admin should be able to downgrade: %v", resp.Reasons)
	}
}

func TestNilObjectDenied(t *testing.T) {
	store := newStore(nil, mustPolicy(t, baselinePolicy))
	e := NewEngine(store)
	resp := e.Evaluate(Request{Operation: Create, GVK: deployGVK, Namespace: "a", Name: "x"})
	if resp.Allowed {
		t.Fatal("a request with no object must never be admitted")
	}
}
