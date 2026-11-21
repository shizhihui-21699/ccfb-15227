package simulator_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/cluster-admission-guard/internal/simulator"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var gvk = schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}

func obj(ns, name string) map[string]any {
	return map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "c", "image": "x"}},
		}}},
	}
}

// allowServer answers every review with allowed=true and echoes the UID.
func allowServer(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var review admissionv1.AdmissionReview
		if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		out := admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
			Response: &admissionv1.AdmissionResponse{UID: review.Request.UID, Allowed: true},
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func denyServer(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var review admissionv1.AdmissionReview
		_ = json.NewDecoder(r.Body).Decode(&review)
		out := admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
			Response: &admissionv1.AdmissionResponse{
				UID:     review.Request.UID,
				Allowed: false,
				Result:  &metav1.Status{Message: "denied: privileged"},
			},
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func patchServer(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var review admissionv1.AdmissionReview
		_ = json.NewDecoder(r.Body).Decode(&review)
		var o map[string]any
		_ = json.Unmarshal(review.Request.Object.Raw, &o)
		meta := o["metadata"].(map[string]any)
		meta["labels"] = map[string]any{"patched": "true"}
		patch := []byte(`[{"op":"add","path":"/metadata/labels","value":{"patched":"true"}}]`)
		pt := admissionv1.PatchTypeJSONPatch
		out := admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
			Response: &admissionv1.AdmissionResponse{
				UID:       review.Request.UID,
				Allowed:   true,
				Patch:     patch,
				PatchType: &pt,
				Warnings:  []string{"auto-remediated"},
			},
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestCreateAllowed(t *testing.T) {
	ts := allowServer(t)
	c := simulator.New(&simulator.WebhookRef{URL: ts.URL, FailurePolicy: simulator.Fail, Timeout: 5 * time.Second})
	res, err := c.Create(gvk, obj("ns", "a"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Allowed {
		t.Fatal("expected allowed")
	}
	if got, ok := c.Get(gvk, "ns", "a"); !ok || got.Name != "a" {
		t.Fatal("object not stored")
	}
	if len(c.Recorded()) != 1 {
		t.Fatalf("expected a recorded review, got %d", len(c.Recorded()))
	}
}

func TestCreateDenied(t *testing.T) {
	ts := denyServer(t)
	c := simulator.New(&simulator.WebhookRef{URL: ts.URL, FailurePolicy: simulator.Fail})
	res, err := c.Create(gvk, obj("ns", "a"))
	if err == nil {
		t.Fatal("expected denial error")
	}
	if res == nil || res.Allowed {
		t.Fatal("result should be not-allowed")
	}
	if !strings.Contains(err.Error(), "denied: privileged") {
		t.Fatalf("error should carry the webhook message: %v", err)
	}
	if _, ok := c.Get(gvk, "ns", "a"); ok {
		t.Fatal("denied object must not be stored")
	}
}

func TestPatchAppliedAndReported(t *testing.T) {
	mut := patchServer(t)
	val := allowServer(t)
	// A mutating webhook is where patches belong.
	c := simulator.New(&simulator.WebhookRef{URL: val.URL, MutateURL: mut.URL, FailurePolicy: simulator.Fail})
	res, err := c.Create(gvk, obj("ns", "a"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Patched {
		t.Fatal("expected a patched result")
	}
	stored, _ := c.Get(gvk, "ns", "a")
	labels := stored.Object["metadata"].(map[string]any)["labels"].(map[string]any)
	if labels["patched"] != "true" {
		t.Fatalf("patch not applied to stored object: %v", stored.Object)
	}
}

func TestValidatingPatchIsRejected(t *testing.T) {
	// A validating webhook (no mutate URL) must not be able to mutate.
	ts := patchServer(t)
	c := simulator.New(&simulator.WebhookRef{URL: ts.URL, FailurePolicy: simulator.Fail})
	_, err := c.Create(gvk, obj("ns", "a"))
	if err == nil || !strings.Contains(err.Error(), "validating webhook returned a patch") {
		t.Fatalf("expected validating patch rejection, got %v", err)
	}
}

func TestMutateThenValidate(t *testing.T) {
	var order []string
	mut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "mutate")
		var review admissionv1.AdmissionReview
		_ = json.NewDecoder(r.Body).Decode(&review)
		pt := admissionv1.PatchTypeJSONPatch
		out := admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
			Response: &admissionv1.AdmissionResponse{
				UID:       review.Request.UID,
				Allowed:   true,
				Patch:     []byte(`[{"op":"add","path":"/spec/patched","value":true}]`),
				PatchType: &pt,
			},
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer mut.Close()
	var sawPatched atomic.Bool
	val := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "validate")
		var review admissionv1.AdmissionReview
		_ = json.NewDecoder(r.Body).Decode(&review)
		var o map[string]any
		_ = json.Unmarshal(review.Request.Object.Raw, &o)
		if spec, ok := o["spec"].(map[string]any); ok && spec["patched"] == true {
			sawPatched.Store(true)
		}
		out := admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
			Response: &admissionv1.AdmissionResponse{UID: review.Request.UID, Allowed: true},
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer val.Close()

	c := simulator.New(&simulator.WebhookRef{URL: val.URL, MutateURL: mut.URL, FailurePolicy: simulator.Fail})
	if _, err := c.Create(gvk, obj("ns", "a")); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "mutate" || order[1] != "validate" {
		t.Fatalf("order = %v, want [mutate validate]", order)
	}
	if !sawPatched.Load() {
		t.Fatal("validation must see the mutated object")
	}
}

func TestOutageFailurePolicy(t *testing.T) {
	// Point at a closed port to force a transport error.
	c := simulator.New(&simulator.WebhookRef{URL: "http://127.0.0.1:1", FailurePolicy: simulator.Ignore, Timeout: 500 * time.Millisecond})
	res, err := c.Create(gvk, obj("ns", "a"))
	if err != nil {
		t.Fatalf("Ignore must admit during an outage: %v", err)
	}
	if !res.FailurePolicyApplied {
		t.Fatal("result should record that the failure policy decided")
	}

	c2 := simulator.New(&simulator.WebhookRef{URL: "http://127.0.0.1:1", FailurePolicy: simulator.Fail, Timeout: 500 * time.Millisecond})
	if _, err := c2.Create(gvk, obj("ns", "a")); err == nil || !strings.Contains(err.Error(), "failurePolicy=Fail") {
		t.Fatalf("Fail must deny during an outage, got %v", err)
	}
}

func TestPerNamespaceFailurePolicy(t *testing.T) {
	c := simulator.New(&simulator.WebhookRef{
		URL:                    "http://127.0.0.1:1",
		FailurePolicy:          simulator.Ignore,
		NamespaceFailurePolicy: map[string]simulator.Policy{"strict": simulator.Fail},
		Timeout:                300 * time.Millisecond,
	})
	if _, err := c.Create(gvk, obj("normal", "a")); err != nil {
		t.Fatalf("standard namespace must fail open: %v", err)
	}
	if _, err := c.Create(gvk, obj("strict", "a")); err == nil {
		t.Fatal("strict namespace must fail closed")
	}
}

func TestUIDMismatchIsProtocolFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var review admissionv1.AdmissionReview
		_ = json.NewDecoder(r.Body).Decode(&review)
		out := admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
			Response: &admissionv1.AdmissionResponse{UID: "wrong", Allowed: true},
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer ts.Close()
	c := simulator.New(&simulator.WebhookRef{URL: ts.URL, FailurePolicy: simulator.Fail})
	if _, err := c.Create(gvk, obj("ns", "a")); err == nil || !strings.Contains(err.Error(), "UID") {
		t.Fatalf("UID mismatch must be fatal, got %v", err)
	}
}

func TestServerErrorHonoursFailurePolicy(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer ts.Close()
	c := simulator.New(&simulator.WebhookRef{URL: ts.URL, FailurePolicy: simulator.Fail})
	if _, err := c.Create(gvk, obj("ns", "a")); err == nil {
		t.Fatal("500 must fail closed")
	}
	c2 := simulator.New(&simulator.WebhookRef{URL: ts.URL, FailurePolicy: simulator.Ignore})
	if _, err := c2.Create(gvk, obj("ns", "a")); err != nil {
		t.Fatalf("500 with Ignore must admit: %v", err)
	}
}

func TestDeleteIsNotIntercepted(t *testing.T) {
	ts := allowServer(t)
	c := simulator.New(&simulator.WebhookRef{URL: ts.URL, FailurePolicy: simulator.Fail})
	if _, err := c.Create(gvk, obj("ns", "a")); err != nil {
		t.Fatal(err)
	}
	before := c.WebhookCalls
	c.Delete(gvk, "ns", "a")
	if c.WebhookCalls != before {
		t.Fatal("delete must not call the webhook")
	}
	if _, ok := c.Get(gvk, "ns", "a"); ok {
		t.Fatal("delete did not remove the object")
	}
}
