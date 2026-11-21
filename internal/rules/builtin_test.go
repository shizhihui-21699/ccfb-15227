package rules

import (
	"strings"
	"testing"

	"github.com/example/cluster-admission-guard/internal/policy"
	"github.com/example/cluster-admission-guard/internal/workload"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func extract(t *testing.T, spec map[string]any) *workload.Workload {
	t.Helper()
	obj := map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "p", "namespace": "n"},
		"spec":     spec,
	}
	return workload.Extract(schema.GroupVersionKind{Version: "v1", Kind: "Pod"}, obj)
}

func container(name string, extra map[string]any) map[string]any {
	c := map[string]any{"name": name, "image": "registry.example.com/x@sha256:" + strings.Repeat("a", 64)}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func run(t *testing.T, ruleID string, spec map[string]any, cfg map[string]any, mutate bool) Result {
	t.Helper()
	w := extract(t, spec)
	impl := Get(ruleID)
	if impl == nil {
		t.Fatalf("no rule %s", ruleID)
	}
	var out Result
	for _, ps := range w.PodSpecs {
		Merge(&out, impl.Evaluate(&Context{}, ps, cfg, mutate))
	}
	return out
}

func TestPrivileged(t *testing.T) {
	spec := map[string]any{"containers": []any{
		container("bad", map[string]any{"securityContext": map[string]any{"privileged": true}}),
		container("good", nil),
	}}
	res := run(t, policy.RulePrivileged, spec, nil, false)
	if len(res.Findings) != 1 || res.Findings[0].Container != "bad" {
		t.Fatalf("findings = %+v", res.Findings)
	}
	// Remediation flips the flag.
	res = run(t, policy.RulePrivileged, spec, nil, true)
	if res.Remediated != 1 {
		t.Fatalf("remediated = %d", res.Remediated)
	}
	w := extract(t, spec)
	sc := w.PodSpecs[0].Containers[0].Obj["securityContext"].(map[string]any)
	if sc["privileged"] != false {
		t.Fatal("privileged not remediated")
	}
}

func TestAllowPrivilegeEscalationDefaultsTrue(t *testing.T) {
	spec := map[string]any{"containers": []any{container("c", nil)}}
	res := run(t, policy.RulePrivilegeEscalation, spec, nil, false)
	if len(res.Findings) != 1 {
		t.Fatal("unset allowPrivilegeEscalation must be reported")
	}
}

func TestCapabilitiesDropAllException(t *testing.T) {
	// Dropping ALL then adding something is still a violation.
	spec := map[string]any{"containers": []any{container("c", map[string]any{
		"securityContext": map[string]any{"capabilities": map[string]any{
			"drop": []any{"ALL"},
			"add":  []any{"NET_ADMIN"},
		}},
	})}}
	res := run(t, policy.RuleCapabilities, spec, nil, false)
	if len(res.Findings) != 1 {
		t.Fatalf("capability added despite drop ALL must be reported: %+v", res.Findings)
	}
}

func TestCapabilitiesAllowList(t *testing.T) {
	spec := map[string]any{"containers": []any{container("c", map[string]any{
		"securityContext": map[string]any{"capabilities": map[string]any{
			"add": []any{"NET_BIND_SERVICE", "SYS_TIME"},
		}},
	})}}
	cfg := map[string]any{"allowed": []any{"NET_BIND_SERVICE"}}
	res := run(t, policy.RuleCapabilities, spec, cfg, false)
	if len(res.Findings) != 1 || !strings.Contains(res.Findings[0].Message, "SYS_TIME") {
		t.Fatalf("only SYS_TIME should be flagged: %+v", res.Findings)
	}
}

func TestSeccompPodLevelUnconfined(t *testing.T) {
	spec := map[string]any{
		"securityContext": map[string]any{"seccompProfile": map[string]any{"type": "Unconfined"}},
		"containers":      []any{container("c", nil)},
	}
	res := run(t, policy.RuleSeccompProfile, spec, nil, false)
	if len(res.Findings) != 1 {
		t.Fatal("pod-level Unconfined must be flagged")
	}
}

func TestHostPathAllowedPrefixAndTraversal(t *testing.T) {
	mk := func(p string) map[string]any {
		return map[string]any{
			"containers": []any{container("c", nil)},
			"volumes":    []any{map[string]any{"name": "v", "hostPath": map[string]any{"path": p}}},
		}
	}
	cfg := map[string]any{"allowedPaths": []any{"/var/log/pods"}}
	if res := run(t, policy.RuleHostPath, mk("/var/log/pods/app"), cfg, false); len(res.Findings) != 0 {
		t.Fatalf("allowedPrefix should allow subpath: %+v", res.Findings)
	}
	if res := run(t, policy.RuleHostPath, mk("/var/log/pods/../../etc"), cfg, false); len(res.Findings) != 1 {
		t.Fatal("path traversal must not slip past an allowed prefix")
	}
	if res := run(t, policy.RuleHostPath, mk("/"), cfg, false); len(res.Findings) != 1 {
		t.Fatal("root hostPath must be denied")
	}
}

func TestHostNamespaceRemediation(t *testing.T) {
	spec := map[string]any{
		"hostNetwork": true,
		"hostPID":     true,
		"containers":  []any{container("c", nil)},
	}
	res := run(t, policy.RuleHostNamespaces, spec, nil, true)
	if res.Remediated != 2 {
		t.Fatalf("remediated = %d", res.Remediated)
	}
}

func TestHostPorts(t *testing.T) {
	spec := map[string]any{"containers": []any{container("c", map[string]any{
		"ports": []any{map[string]any{"containerPort": 80, "hostPort": 8080}},
	})}}
	res := run(t, policy.RuleHostPorts, spec, nil, false)
	if len(res.Findings) != 1 {
		t.Fatalf("host port must be flagged: %+v", res.Findings)
	}
	cfg := map[string]any{"allowedPorts": []any{8080}}
	if res := run(t, policy.RuleHostPorts, spec, cfg, false); len(res.Findings) != 0 {
		t.Fatal("allowed host port should pass")
	}
}

func TestImageProvenanceRegistryPrefix(t *testing.T) {
	mk := func(image string) map[string]any {
		return map[string]any{"containers": []any{map[string]any{"name": "c", "image": image}}}
	}
	cfg := map[string]any{"allowedRegistries": []any{"registry.example.com/platform"}}
	if res := run(t, policy.RuleImageProvenance, mk("registry.example.com/platform/app:1"), cfg, false); len(res.Findings) != 0 {
		t.Fatalf("matching registry rejected: %+v", res.Findings)
	}
	if res := run(t, policy.RuleImageProvenance, mk("registry.example.com/other/app:1"), cfg, false); len(res.Findings) != 1 {
		t.Fatal("registry prefix must not match a sibling prefix")
	}
	if res := run(t, policy.RuleImageProvenance, mk("registry.example.com/platform-evil/app:1"), cfg, false); len(res.Findings) != 1 {
		t.Fatal("prefix match must be path-segment aware")
	}
}

func TestEphemeralContainers(t *testing.T) {
	spec := map[string]any{
		"containers":          []any{container("main", nil)},
		"ephemeralContainers": []any{container("debug", nil)},
	}
	res := run(t, policy.RuleEphemeralContainers, spec, nil, false)
	if len(res.Findings) != 1 || res.Findings[0].Container != "debug" {
		t.Fatalf("ephemeral container must be flagged: %+v", res.Findings)
	}
}

func TestRunAsNonRootSatisfiedByNonZeroUID(t *testing.T) {
	spec := map[string]any{"containers": []any{container("c", map[string]any{
		"securityContext": map[string]any{"runAsUser": int64(1000)},
	})}}
	res := run(t, policy.RuleRunAsNonRoot, spec, nil, false)
	// Non-zero UID alone is accepted but remediation adds the explicit guard.
	if len(res.Findings) != 0 {
		t.Fatalf("non-zero runAsUser should not be denied: %+v", res.Findings)
	}
}

func TestUnknownWorkloadObjectRule(t *testing.T) {
	obj := map[string]any{
		"apiVersion": "x/v1", "kind": "Doohickey",
		"spec": map[string]any{"nested": map[string]any{"spec": map[string]any{
			"containers": []any{container("c", nil)},
		}}},
	}
	w := workload.Extract(schema.GroupVersionKind{Group: "x", Version: "v1", Kind: "Doohickey"}, obj)
	findings := EvaluateObject(policy.RuleUnknownWorkload, w)
	if len(findings) != 1 {
		t.Fatalf("expected 1 advisory finding, got %+v", findings)
	}
	if !findings[0].Advisory {
		t.Fatal("structural-scan notice must be advisory (never denying)")
	}
}

func TestHostPathRelativePathDenied(t *testing.T) {
	spec := map[string]any{
		"containers": []any{container("c", nil)},
		"volumes":    []any{map[string]any{"name": "v", "hostPath": map[string]any{"path": "relative/path"}}},
	}
	cfg := map[string]any{"allowedPaths": []any{"/var/log/pods"}}
	if res := run(t, policy.RuleHostPath, mk(spec), cfg, false); len(res.Findings) != 1 {
		t.Fatalf("relative hostPath must be denied: %+v", res.Findings)
	}
}

// mk wraps a pod spec so tests can pass it to run without rebuilding the
// wrapper each time.
func mk(spec map[string]any) map[string]any { return spec }
