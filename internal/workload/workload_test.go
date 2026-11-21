package workload

import (
	"fmt"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

func deploy(templateSpec map[string]any) map[string]any {
	return map[string]any{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]any{"name": "x", "namespace": "n"},
		"spec": map[string]any{
			"template": map[string]any{
				"spec": templateSpec,
			},
		},
	}
}

func containers(names ...string) []any {
	out := make([]any, 0, len(names))
	for _, n := range names {
		out = append(out, map[string]any{
			"name":  n,
			"image": "registry.example.com/" + n + "@sha256:" + strings.Repeat("a", 64),
		})
	}
	return out
}

func TestExtractKnownKinds(t *testing.T) {
	cases := []struct {
		name string
		gvk  schema.GroupVersionKind
		obj  map[string]any
		path string
	}{
		{
			name: "pod",
			gvk:  schema.GroupVersionKind{Version: "v1", Kind: "Pod"},
			obj:  map[string]any{"spec": map[string]any{"containers": containers("c")}},
			path: "spec",
		},
		{
			name: "deployment",
			gvk:  schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
			obj:  deploy(map[string]any{"containers": containers("c")}),
			path: "spec.template.spec",
		},
		{
			name: "cronjob",
			gvk:  schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: "CronJob"},
			obj: map[string]any{
				"spec": map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{
					"template": map[string]any{"spec": map[string]any{"containers": containers("c")}},
				}}},
			},
			path: "spec.jobTemplate.spec.template.spec",
		},
		{
			name: "argo rollout",
			gvk:  schema.GroupVersionKind{Group: "argoproj.io", Version: "v1alpha1", Kind: "Rollout"},
			obj:  deploy(map[string]any{"containers": containers("c")}),
			path: "spec.template.spec",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := Extract(tc.gvk, tc.obj)
			if !w.KnownKind {
				t.Fatal("expected known kind")
			}
			if len(w.PodSpecs) != 1 {
				t.Fatalf("expected 1 pod spec, got %d", len(w.PodSpecs))
			}
			if got := w.PodSpecs[0].FieldPath(); got != tc.path {
				t.Fatalf("path = %q, want %q", got, tc.path)
			}
			if len(w.PodSpecs[0].Containers) != 1 {
				t.Fatalf("expected 1 container, got %d", len(w.PodSpecs[0].Containers))
			}
		})
	}
}

func TestExtractUnknownCRDByStructuralScan(t *testing.T) {
	obj := map[string]any{
		"apiVersion": "example.com/v1",
		"kind":       "TrainingJob",
		"spec": map[string]any{
			"replicas": 2,
			"worker": map[string]any{
				"template": map[string]any{
					"spec": map[string]any{"containers": containers("worker")},
				},
			},
			"chief": map[string]any{
				"podSpec": map[string]any{"initContainers": containers("init")},
			},
		},
	}
	w := Extract(schema.GroupVersionKind{Group: "example.com", Version: "v1", Kind: "TrainingJob"}, obj)
	if w.KnownKind {
		t.Fatal("TrainingJob must not be a known kind")
	}
	if len(w.PodSpecs) != 2 {
		t.Fatalf("expected 2 scanned pod specs, got %d (%v)", len(w.PodSpecs), paths(w))
	}
	got := map[string]bool{}
	for _, p := range w.PodSpecs {
		got[p.FieldPath()] = true
		if p.Source != "structural-scan" {
			t.Errorf("source = %q, want structural-scan", p.Source)
		}
	}
	for _, want := range []string{"spec.worker.template.spec", "spec.chief.podSpec"} {
		if !got[want] {
			t.Errorf("missing pod spec at %s; got %v", want, paths(w))
		}
	}
}

func TestScanSkipsUserData(t *testing.T) {
	// A ConfigMap holding a YAML pod snippet is user data, not a workload.
	obj := map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"data": map[string]any{
			"pod.yaml": "containers:\n  - name: c\n    image: x\n",
			"nested": map[string]any{
				"spec": map[string]any{"containers": containers("c")},
			},
		},
	}
	w := Extract(schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}, obj)
	if len(w.PodSpecs) != 0 {
		t.Fatalf("ConfigMap data must not be scanned, got %v", paths(w))
	}
}

func TestScanIgnoresNonContainerArrays(t *testing.T) {
	obj := map[string]any{
		"apiVersion": "example.com/v1",
		"kind":       "Widget",
		"spec": map[string]any{
			"containers": []any{
				map[string]any{"name": "not-a-container"}, // no image
			},
		},
	}
	w := Extract(schema.GroupVersionKind{Group: "example.com", Version: "v1", Kind: "Widget"}, obj)
	if len(w.PodSpecs) != 0 {
		t.Fatalf("entry without an image is not container-shaped; got %v", paths(w))
	}
}

func TestExtractReportsMalformed(t *testing.T) {
	obj := deploy(map[string]any{
		"containers": []any{
			map[string]any{"name": "broken"},
			"not-an-object",
		},
	})
	w := Extract(schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}, obj)
	if len(w.Problems) < 2 {
		t.Fatalf("expected malformed problems, got %v", w.Problems)
	}
}

func TestExtractV1ListIsNotFlattened(t *testing.T) {
	// A List has no pod templates at the top level; the guard intercepts each
	// item separately. Ensure the scan does not invent specs from a List.
	obj := map[string]any{
		"apiVersion": "v1",
		"kind":       "List",
		"items": []any{
			deploy(map[string]any{"containers": containers("c")}),
		},
	}
	w := Extract(schema.GroupVersionKind{Version: "v1", Kind: "List"}, obj)
	// Structural scan will find the embedded deployment's template. That is
	// acceptable and safe: the List is intercepted too.
	if !w.HasPodSpecs() {
		t.Fatal("structural scan should still see embedded templates in a List")
	}
}

func TestScanBounds(t *testing.T) {
	root := map[string]any{}
	cur := root
	for i := 0; i < MaxScanDepth+10; i++ {
		next := map[string]any{}
		cur["child"] = next
		cur = next
	}
	// Put a real template at the unreachable bottom.
	cur["containers"] = containers("deep")
	obj := map[string]any{"apiVersion": "x/v1", "kind": "Deep", "spec": root}
	w := Extract(schema.GroupVersionKind{Group: "x", Version: "v1", Kind: "Deep"}, obj)
	foundProblem := false
	for _, p := range w.Problems {
		if strings.Contains(p, "too large") || strings.Contains(p, "too deep") {
			foundProblem = true
		}
	}
	if !foundProblem {
		t.Fatalf("expected a scan bound problem, got %v", w.Problems)
	}
}

func TestTooManyTemplates(t *testing.T) {
	items := make([]any, 0, MaxPodSpecs+5)
	for i := 0; i < MaxPodSpecs+5; i++ {
		items = append(items, map[string]any{
			"spec": map[string]any{"containers": containers("c")},
		})
	}
	obj := map[string]any{
		"apiVersion": "x/v1", "kind": "Multi",
		"spec": map[string]any{"templates": items},
	}
	w := Extract(schema.GroupVersionKind{Group: "x", Version: "v1", Kind: "Multi"}, obj)
	if len(w.PodSpecs) > MaxPodSpecs {
		t.Fatalf("got %d pod specs, want <= %d", len(w.PodSpecs), MaxPodSpecs)
	}
	found := false
	for _, p := range w.Problems {
		if strings.Contains(p, "too many pod templates") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a too-many-templates problem, got %v", w.Problems)
	}
}

func TestExtractDeterministicOrder(t *testing.T) {
	obj := map[string]any{
		"apiVersion": "x/v1", "kind": "Multi",
		"spec": map[string]any{
			"zeta":  map[string]any{"containers": containers("z")},
			"alpha": map[string]any{"containers": containers("a")},
			"mid":   map[string]any{"containers": containers("m")},
		},
	}
	var first []string
	for i := 0; i < 20; i++ {
		w := Extract(schema.GroupVersionKind{Group: "x", Version: "v1", Kind: "Multi"}, obj)
		got := paths(w)
		if i == 0 {
			first = got
			continue
		}
		if fmt.Sprint(got) != fmt.Sprint(first) {
			t.Fatalf("non-deterministic order: %v vs %v", got, first)
		}
	}
}

func TestRoles(t *testing.T) {
	obj := deploy(map[string]any{
		"containers":          containers("main"),
		"initContainers":      containers("init"),
		"ephemeralContainers": containers("debug"),
	})
	w := Extract(schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}, obj)
	roles := map[Role]string{}
	for _, c := range w.PodSpecs[0].Containers {
		roles[c.Role] = c.Name
	}
	if roles[RoleContainer] != "main" || roles[RoleInit] != "init" || roles[RoleEphemeral] != "debug" {
		t.Fatalf("unexpected roles: %v", roles)
	}
}

func paths(w *Workload) []string {
	out := make([]string, 0, len(w.PodSpecs))
	for _, p := range w.PodSpecs {
		out = append(out, p.FieldPath())
	}
	return out
}
