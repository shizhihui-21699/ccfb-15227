package admission_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/cluster-admission-guard/internal/admission"
	"github.com/example/cluster-admission-guard/internal/audit"
	"github.com/example/cluster-admission-guard/internal/simulator"
	"github.com/example/cluster-admission-guard/internal/store"
	"github.com/example/cluster-admission-guard/internal/testcluster"
	"github.com/example/cluster-admission-guard/internal/webhook"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// TestClusterBackedEndToEnd drives the whole stack: fake API server informers
// feed the real ClusterStore, SecurityPolicy objects define policy, the real
// webhook serves AdmissionReview over HTTP, and the simulator applies patches
// and failure policies.
func TestClusterBackedEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	policyObj := policyDocument()
	cluster, err := testcluster.New(ctx, map[string]map[string]string{
		"payments": {"guard.example.com/team": "payments"},
		"strict":   {"guard.example.com/team": "payments", "guard.example.com/enforcement": "strict"},
		"other":    {"guard.example.com/team": "other"},
	}, policyObj)
	if err != nil {
		t.Fatal(err)
	}
	if err := cluster.WaitForPolicy(1, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	validate := admission.NewEngine(cluster.Store)
	validate.AllowMutation = false
	mutate := admission.NewEngine(cluster.Store)
	mutate.AllowMutation = true
	sink := &memSink{}
	srv := webhook.NewServer(validate, &audit.Logger{Sinks: []audit.Sink{sink}}, nil)
	srv.MutateEngine = mutate
	httpSrv := httptest.NewServer(srv.Routes())
	defer httpSrv.Close()

	sim := simulator.New(&simulator.WebhookRef{
		URL:           httpSrv.URL + "/validate",
		MutateURL:     httpSrv.URL + "/mutate",
		FailurePolicy: simulator.Ignore,
		NamespaceFailurePolicy: map[string]simulator.Policy{
			"strict": simulator.Fail,
		},
		Timeout: 5 * time.Second,
	})

	deployGVK := schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}
	cronGVK := schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: "CronJob"}
	jobGVK := schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: "Job"}
	crdGVK := schema.GroupVersionKind{Group: "example.com", Version: "v1", Kind: "TrainingJob"}

	t.Run("deployment privileged denied", func(t *testing.T) {
		_, err := sim.Create(deployGVK, privilegedDeploy("payments", "bad"))
		if err == nil {
			t.Fatal("expected denial")
		}
	})

	t.Run("cronjob nested template denied", func(t *testing.T) {
		obj := map[string]any{
			"apiVersion": "batch/v1", "kind": "CronJob",
			"metadata": map[string]any{"name": "nightly", "namespace": "payments"},
			"spec": map[string]any{"schedule": "0 0 * * *", "jobTemplate": map[string]any{
				"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
					"containers": []any{map[string]any{
						"name": "j", "image": "registry.example.com/app@sha256:" + strings.Repeat("a", 64),
						"securityContext": map[string]any{"privileged": true},
					}},
				}}},
			}},
		}
		if _, err := sim.Create(cronGVK, obj); err == nil {
			t.Fatal("privileged container nested in a CronJob must be denied")
		}
	})

	t.Run("unknown CRD template denied", func(t *testing.T) {
		obj := map[string]any{
			"apiVersion": "example.com/v1", "kind": "TrainingJob",
			"metadata": map[string]any{"name": "sneaky", "namespace": "payments"},
			"spec": map[string]any{"worker": map[string]any{"template": map[string]any{"spec": map[string]any{
				"hostPID": true,
				"containers": []any{map[string]any{
					"name": "w", "image": "registry.example.com/app@sha256:" + strings.Repeat("a", 64),
				}},
			}}}},
		}
		if _, err := sim.Create(crdGVK, obj); err == nil {
			t.Fatal("hostPID inside an unknown CRD must be denied")
		}
	})

	t.Run("remediable job patched and stored", func(t *testing.T) {
		obj := map[string]any{
			"apiVersion": "batch/v1", "kind": "Job",
			"metadata": map[string]any{"name": "worker", "namespace": "payments"},
			"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
				"containers": []any{map[string]any{
					"name": "w", "image": "registry.example.com/app@sha256:" + strings.Repeat("a", 64),
				}},
			}}},
		}
		res, err := sim.Create(jobGVK, obj)
		if err != nil {
			t.Fatalf("remediable job denied: %v", err)
		}
		if !res.Patched {
			t.Fatal("expected a patch")
		}
		stored, ok := sim.Get(jobGVK, "payments", "worker")
		if !ok {
			t.Fatal("job not stored")
		}
		spec := stored.Object["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
		sc := spec["containers"].([]any)[0].(map[string]any)["securityContext"].(map[string]any)
		if sc["runAsNonRoot"] != true || sc["allowPrivilegeEscalation"] != false {
			t.Fatalf("patch not reflected in stored object: %v", sc)
		}
	})

	t.Run("exemption applies then unrelated violation still denied", func(t *testing.T) {
		// In "strict", privileged is exempted but hostNetwork is not.
		obj := privilegedDeploy("strict", "exempted")
		if _, err := sim.Create(deployGVK, obj); err != nil {
			t.Fatalf("exempted privileged must be allowed: %v", err)
		}
		obj2 := privilegedDeploy("strict", "exempted2")
		obj2["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["hostNetwork"] = true
		if _, err := sim.Create(deployGVK, obj2); err == nil {
			t.Fatal("non-exempted violation must still be denied")
		}
	})

	t.Run("classic update of legacy object is not blocked", func(t *testing.T) {
		// Store a legacy privileged deployment with admission bypassed (as if it
		// predates the guard): create it in an excluded namespace, then move it.
		// Instead, simulate by writing directly through the simulator with a
		// permissive policy: simplest is to create it while the webhook is down
		// with Ignore.
		legacy := privilegedDeploy("payments", "legacy")
		before := sim.FailNextWebhook
		sim.FailNextWebhook = 1 << 20
		if _, err := sim.Create(deployGVK, legacy); err != nil {
			t.Fatalf("legacy create during outage should be admitted in a standard namespace: %v", err)
		}
		sim.FailNextWebhook = before

		// Unrelated update must succeed, with a pre-existing warning.
		updated := privilegedDeploy("payments", "legacy")
		updated["metadata"].(map[string]any)["labels"] = map[string]any{"team": "payments"}
		res, err := sim.Update(deployGVK, updated)
		if err != nil {
			t.Fatalf("unrelated update blocked by pre-existing violation: %v", err)
		}
		found := false
		for _, w := range res.Warnings {
			if strings.Contains(w, "pre-existing") {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected a pre-existing warning, got %v", res.Warnings)
		}

		// Introducing a *new* violation in the same update is denied.
		worse := privilegedDeploy("payments", "legacy")
		worse["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["hostNetwork"] = true
		if _, err := sim.Update(deployGVK, worse); err == nil {
			t.Fatal("a newly introduced violation must be denied even on a legacy object")
		}
	})

	t.Run("webhook outage strict vs standard", func(t *testing.T) {
		sim.FailNextWebhook = 1 << 20
		defer func() { sim.FailNextWebhook = 0 }()
		if _, err := sim.Create(deployGVK, safeDeploy("payments", "during-outage")); err != nil {
			t.Fatalf("standard namespace must keep deploying during an outage: %v", err)
		}
		if _, err := sim.Create(deployGVK, safeDeploy("strict", "during-outage")); err == nil {
			t.Fatal("strict namespace must fail closed during an outage")
		}
	})

	if len(sink.events) == 0 {
		t.Fatal("expected audit events")
	}
}

func privilegedDeploy(ns, name string) map[string]any {
	obj := safeDeploy(ns, name)
	obj["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["securityContext"].(map[string]any)["privileged"] = true
	return obj
}

func safeDeploy(ns, name string) map[string]any {
	return map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"automountServiceAccountToken": false,
			"containers": []any{map[string]any{
				"name": "c", "image": "registry.example.com/app@sha256:" + strings.Repeat("a", 64),
				"securityContext": map[string]any{
					"allowPrivilegeEscalation": false,
					"runAsNonRoot":             true,
					"readOnlyRootFilesystem":   true,
					"seccompProfile":           map[string]any{"type": "RuntimeDefault"},
				},
			}},
		}}},
	}
}

type memSink struct{ events []audit.Event }

func (m *memSink) Write(e audit.Event) error { m.events = append(m.events, e); return nil }
func (m *memSink) Close() error              { return nil }

var _ = fmt.Sprintf
var _ = json.Marshal
var _ = http.StatusOK

// policyDocument is a cluster-sourced policy with a namespace-scoped expiring
// exemption for privileged workloads.
func policyDocument() map[string]any {
	return map[string]any{
		"apiVersion": "guard.example.com/v1alpha1",
		"kind":       "SecurityPolicy",
		"metadata":   map[string]any{"name": "baseline", "namespace": "platform"},
		"spec": map[string]any{
			"failureMode": "closed",
			"rules": []any{
				map[string]any{"id": "pod.privileged", "severity": "critical"},
				map[string]any{"id": "pod.hostNamespaces", "severity": "critical"},
				map[string]any{"id": "pod.allowPrivilegeEscalation", "action": "remediate"},
				map[string]any{"id": "pod.runAsNonRoot", "action": "remediate"},
				map[string]any{"id": "object.malformedWorkload", "severity": "high"},
			},
			"exemptions": []any{
				map[string]any{
					"id":          "payments-break-glass",
					"reason":      "migration window",
					"requestedBy": "payments",
					"expiresAt":   time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
					"scope": map[string]any{
						"namespaces": []any{"strict"},
						"rules":      []any{"pod.privileged"},
					},
				},
			},
		},
	}
}

// TestClusterPolicyReloadKeepsLastGood covers the operator workflow: a bad edit
// to a cluster policy must not replace working policy, and the store must report
// unhealthy so strict namespaces fail closed.
func TestClusterPolicyReloadKeepsLastGood(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cluster, err := testcluster.New(ctx, map[string]map[string]string{
		"strict": {"guard.example.com/enforcement": "strict"},
	}, policyDocument())
	if err != nil {
		t.Fatal(err)
	}
	if err := cluster.WaitForPolicy(1, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	good := len(cluster.Store.Policies())

	// Apply a syntactically valid but semantically broken policy.
	bad := map[string]any{
		"apiVersion": "guard.example.com/v1alpha1",
		"kind":       "SecurityPolicy",
		"metadata":   map[string]any{"name": "broken", "namespace": "platform"},
		"spec":       map[string]any{"rules": []any{map[string]any{"id": "pod.not.a.rule"}}},
	}
	if err := cluster.ApplyPolicy(ctx, bad); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && cluster.Store.Health() == nil {
		time.Sleep(20 * time.Millisecond)
	}
	if cluster.Store.Health() == nil {
		t.Fatal("a broken policy must make the store report unhealthy")
	}
	if len(cluster.Store.Policies()) != good {
		t.Fatalf("last good policy was replaced: have %d, want %d", len(cluster.Store.Policies()), good)
	}

	// Removing it restores health.
	if err := cluster.Dyn.Resource(storePolicyGVR()).Namespace("platform").Delete(ctx, "broken", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && cluster.Store.Health() != nil {
		time.Sleep(20 * time.Millisecond)
	}
	if err := cluster.Store.Health(); err != nil {
		t.Fatalf("health should recover: %v", err)
	}
}

func storePolicyGVR() schema.GroupVersionResource { return store.PolicyGVR }
