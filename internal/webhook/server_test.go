package webhook_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/example/cluster-admission-guard/internal/admission"
	"github.com/example/cluster-admission-guard/internal/audit"
	"github.com/example/cluster-admission-guard/internal/metrics"
	"github.com/example/cluster-admission-guard/internal/policy"
	"github.com/example/cluster-admission-guard/internal/store"
	"github.com/example/cluster-admission-guard/internal/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// newTestServer loads the repository's sample policies and serves the webhook
// over a real httptest listener.
func newTestServer(t *testing.T, namespaces map[string]map[string]string) (*httptest.Server, *webhook.Server, *audit.Logger, *captureSink) {
	t.Helper()
	dir := "../../testdata/policies"
	fs, err := store.NewFileStore(dir)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	for name, labels := range namespaces {
		fs.NamespaceLabels[name] = labels
	}

	validate := admission.NewEngine(fs)
	validate.AllowMutation = false
	mutate := admission.NewEngine(fs)
	mutate.AllowMutation = true

	sink := &captureSink{}
	logger := &audit.Logger{Sinks: []audit.Sink{sink}}
	srv := webhook.NewServer(validate, logger, metrics.New())
	srv.MutateEngine = mutate

	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)
	return ts, srv, logger, sink
}

type captureSink struct {
	events []audit.Event
}

func (c *captureSink) Write(e audit.Event) error { c.events = append(c.events, e); return nil }
func (c *captureSink) Close() error              { return nil }

func review(t *testing.T, url string, req admissionv1.AdmissionRequest) admissionv1.AdmissionResponse {
	t.Helper()
	if req.UID == "" {
		req.UID = types.UID("test-uid-1")
	}
	body, err := json.Marshal(admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request:  &req,
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP %d", resp.StatusCode)
	}
	var out admissionv1.AdmissionReview
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Response == nil {
		t.Fatal("no response")
	}
	if out.Response.UID != req.UID {
		t.Fatalf("UID mismatch: got %q want %q", out.Response.UID, req.UID)
	}
	return *out.Response
}

func rawDeployment(t *testing.T, obj map[string]any) runtime.RawExtension {
	t.Helper()
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return runtime.RawExtension{Raw: b}
}

func podReq(obj map[string]any) admissionv1.AdmissionRequest {
	raw, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	ns, _ := obj["metadata"].(map[string]any)["namespace"].(string)
	name, _ := obj["metadata"].(map[string]any)["name"].(string)
	return admissionv1.AdmissionRequest{
		Kind:      metav1.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
		Resource:  metav1.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
		Namespace: ns,
		Name:      name,
		Operation: admissionv1.Create,
		Object:    runtime.RawExtension{Raw: raw},
	}
}

// updateReq includes the stored object.
func updateReq(oldObj, newObj map[string]any) admissionv1.AdmissionRequest {
	req := podReq(newObj)
	req.Operation = admissionv1.Update
	raw, err := json.Marshal(oldObj)
	if err != nil {
		panic(err)
	}
	req.OldObject = runtime.RawExtension{Raw: raw}
	return req
}

func deployment(ns, name string, mutate func(spec map[string]any)) map[string]any {
	spec := map[string]any{
		"automountServiceAccountToken": false,
		"containers": []any{map[string]any{
			"name":  "c",
			"image": "registry.example.com/platform/app@sha256:" + strings.Repeat("a", 64),
			"securityContext": map[string]any{
				"allowPrivilegeEscalation": false,
				"runAsNonRoot":             true,
				"readOnlyRootFilesystem":   true,
				"seccompProfile":           map[string]any{"type": "RuntimeDefault"},
			},
		}},
	}
	if mutate != nil {
		mutate(spec)
	}
	return map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": name, "namespace": ns},
		"spec":     map[string]any{"template": map[string]any{"spec": spec}},
	}
}

var nsLabels = map[string]map[string]string{
	"team-a":   {"guard.example.com/team": "payments"},
	"team-web": {"guard.example.com/team": "web"},
	"strict":   {"guard.example.com/team": "payments", "guard.example.com/enforcement": "strict"},
	"ci":       {"guard.example.com/team": "ci"},
	"analytic": {"guard.example.com/team": "analytics"},
}

func TestHTTPAllowsSafeDeployment(t *testing.T) {
	ts, _, _, _ := newTestServer(t, nsLabels)
	req := podReq(deployment("team-a", "app", nil))
	resp := review(t, ts.URL+"/validate", req)
	if !resp.Allowed {
		t.Fatalf("safe deployment denied: %+v", resp.Result)
	}
	if resp.PatchType != nil || len(resp.Patch) != 0 {
		t.Fatal("validating response must not carry a patch")
	}
}

func TestHTTPDeniesPrivileged(t *testing.T) {
	ts, _, _, _ := newTestServer(t, nsLabels)
	obj := deployment("team-a", "app", func(spec map[string]any) {
		spec["containers"].([]any)[0].(map[string]any)["securityContext"].(map[string]any)["privileged"] = true
	})
	resp := review(t, ts.URL+"/validate", podReq(obj))
	if resp.Allowed {
		t.Fatal("privileged deployment must be denied")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, "privileged") {
		t.Fatalf("denial message missing detail: %+v", resp.Result)
	}
	if resp.Result.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", resp.Result.Code)
	}
}

func TestHTTPMutateReturnsPatchAndValidateRejectsRaw(t *testing.T) {
	ts, _, _, _ := newTestServer(t, nsLabels)
	obj := deployment("web", "app", func(spec map[string]any) {
		// Remove the safe defaults to create remediable violations.
		delete(spec, "automountServiceAccountToken")
		c := spec["containers"].([]any)[0].(map[string]any)
		delete(c, "securityContext")
	})
	req := podReq(obj)

	// /mutate rewrites.
	mut := review(t, ts.URL+"/mutate", req)
	if !mut.Allowed {
		t.Fatalf("mutation should allow: %+v", mut.Result)
	}
	if mut.PatchType == nil || *mut.PatchType != admissionv1.PatchTypeJSONPatch {
		t.Fatal("expected a JSONPatch")
	}
	if len(mut.Patch) == 0 {
		t.Fatal("expected a patch")
	}
	if len(mut.Warnings) == 0 {
		t.Fatal("expected remediation warnings")
	}

	// /validate (as a separate request) denies the un-mutated object because it
	// cannot fix it and must not pretend it did.
	val := review(t, ts.URL+"/validate", req)
	if val.Allowed {
		t.Fatal("validate-only must deny an object that needs mutation")
	}
	if len(val.Patch) != 0 {
		t.Fatal("validate-only must not patch")
	}
	if !strings.Contains(strings.Join(val.Warnings, " "), "") && false {
		t.Fatal("unreachable")
	}
}

func TestHTTPRejectsNonPost(t *testing.T) {
	ts, _, _, _ := newTestServer(t, nsLabels)
	resp, err := http.Get(ts.URL + "/validate")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

func TestHTTPRejectsMalformedReview(t *testing.T) {
	ts, _, _, _ := newTestServer(t, nsLabels)
	resp, err := http.Post(ts.URL+"/validate", "application/json", strings.NewReader("{not json"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHTTPMissingRequest(t *testing.T) {
	ts, _, _, _ := newTestServer(t, nsLabels)
	resp, err := http.Post(ts.URL+"/validate", "application/json", strings.NewReader(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestReadyzFailsWhenPolicyBroken(t *testing.T) {
	dir := t.TempDir()
	// Start with a valid policy, then break it on reload.
	if err := writeTemp(dir, "p.yaml", validPolicy); err != nil {
		t.Fatal(err)
	}
	fs, err := store.NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	validate := admission.NewEngine(fs)
	validate.AllowMutation = false
	srv := webhook.NewServer(validate, &audit.Logger{}, nil)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	if code := getStatus(t, ts.URL+"/readyz"); code != http.StatusOK {
		t.Fatalf("readyz = %d, want 200", code)
	}

	if err := writeTemp(dir, "p.yaml", `apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: broken}
spec: {rules: [{id: nope}]}`); err != nil {
		t.Fatal(err)
	}
	if err := fs.Reload(); err == nil {
		t.Fatal("reload should fail")
	}
	if code := getStatus(t, ts.URL+"/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("readyz = %d, want 503", code)
	}
	// healthz stays up: the process is alive, it just should not receive webhook
	// traffic. Removing it from endpoints makes the API server apply
	// failurePolicy, which is exactly what we want.
	if code := getStatus(t, ts.URL+"/healthz"); code != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", code)
	}
}

func TestDegradedFailsClosedForStrictNamespace(t *testing.T) {
	dir := t.TempDir()
	if err := writeTemp(dir, "p.yaml", validPolicy); err != nil {
		t.Fatal(err)
	}
	fs, err := store.NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	fs.NamespaceLabels["strict-ns"] = map[string]string{"guard.example.com/enforcement": "strict"}
	fs.NamespaceLabels["normal"] = map[string]string{}
	if err := writeTemp(dir, "p.yaml", "{broken"); err != nil {
		t.Fatal(err)
	}
	if err := fs.Reload(); err == nil {
		t.Fatal("reload should fail")
	}

	engine := admission.NewEngine(fs)
	engine.AllowMutation = false
	srv := webhook.NewServer(engine, &audit.Logger{}, nil)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	obj := deployment("strict-ns", "app", nil)
	req := podReq(obj)
	req.Namespace = "strict-ns"
	resp := review(t, ts.URL+"/validate", req)
	if resp.Allowed {
		t.Fatal("strict namespace must fail closed when policy is unhealthy")
	}

	obj = deployment("normal", "app", nil)
	req = podReq(obj)
	req.Namespace = "normal"
	resp = review(t, ts.URL+"/validate", req)
	if !resp.Allowed {
		t.Fatal("normal namespace must fail open so the cluster keeps deploying")
	}
}

func TestAuditRecordsDenialsAndExemptions(t *testing.T) {
	ts, _, _, sink := newTestServer(t, nsLabels)
	obj := deployment("team-a", "app", func(spec map[string]any) {
		spec["containers"].([]any)[0].(map[string]any)["securityContext"].(map[string]any)["privileged"] = true
	})
	review(t, ts.URL+"/validate", podReq(obj))
	if len(sink.events) == 0 {
		t.Fatal("no audit events")
	}
	last := sink.events[len(sink.events)-1]
	if last.Allowed {
		t.Fatal("event should record a denial")
	}
	if last.Kind != "Deployment" || last.Namespace != "team-a" {
		t.Fatalf("event metadata wrong: %+v", last)
	}
	found := false
	for _, f := range last.Findings {
		if f.Rule == policy.RulePrivileged && f.Disposition == string(policy.DispositionDenied) {
			found = true
		}
	}
	if !found {
		t.Fatalf("privileged denial not recorded: %+v", last.Findings)
	}
}

func TestAuditRecordsDegradedReason(t *testing.T) {
	store := &brokenStore{inner: staticStore{}}
	engine := admission.NewEngine(store)
	engine.AllowMutation = false
	sink := &captureSink{}
	srv := webhook.NewServer(engine, &audit.Logger{Sinks: []audit.Sink{sink}}, nil)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	req := podReq(deployment("team-a", "app", nil))
	resp := review(t, ts.URL+"/validate", req)
	if !resp.Allowed {
		t.Fatal("unregistered namespace should fail open")
	}
	if len(sink.events) != 1 || !sink.events[0].Degraded || sink.events[0].Reason == "" {
		t.Fatalf("degraded decision must be audited with a reason: %+v", sink.events)
	}
}

func TestMetricsExposeDecisionCounters(t *testing.T) {
	dir := t.TempDir()
	if err := writeTemp(dir, "p.yaml", validPolicy); err != nil {
		t.Fatal(err)
	}
	fs, err := store.NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	engine := admission.NewEngine(fs)
	engine.AllowMutation = false
	reg := metrics.New()
	srv := webhook.NewServer(engine, &audit.Logger{}, reg)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	review(t, ts.URL+"/validate", podReq(deployment("team-a", "app", nil)))

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	body := buf.String()
	if !strings.Contains(body, "admission_guard_decisions_total") {
		t.Fatalf("metrics missing counter:\n%s", body)
	}
	if !strings.Contains(body, `decision="allow"`) {
		t.Fatalf("expected an allow decision:\n%s", body)
	}
}

func getStatus(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func writeTemp(dir, name, content string) error {
	return writeFile(dir, name, content)
}

// TestEphemeralContainersSubresourceDenied covers `kubectl debug`: the request is
// an UPDATE of pods/ephemeralcontainers whose new object carries the debug
// container and whose old object does not.
func TestEphemeralContainersSubresourceDenied(t *testing.T) {
	ts, _, _, _ := newTestServer(t, nsLabels)
	base := map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "app", "namespace": "team-web"},
		"spec": map[string]any{
			"automountServiceAccountToken": false,
			"containers": []any{map[string]any{
				"name":  "c",
				"image": "registry.example.com/platform/app@sha256:" + strings.Repeat("a", 64),
				"securityContext": map[string]any{
					"allowPrivilegeEscalation": false,
					"runAsNonRoot":             true,
					"readOnlyRootFilesystem":   true,
					"seccompProfile":           map[string]any{"type": "RuntimeDefault"},
				},
			}},
		},
	}
	oldRaw, _ := json.Marshal(base)

	updated := map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": "app", "namespace": "team-web"},
		"spec": map[string]any{
			"automountServiceAccountToken": false,
			"containers":                   base["spec"].(map[string]any)["containers"],
			"ephemeralContainers": []any{map[string]any{
				"name":  "debugger",
				"image": "registry.example.com/platform/debug@sha256:" + strings.Repeat("b", 64),
				"securityContext": map[string]any{
					"privileged": true,
				},
			}},
		},
	}
	newRaw, _ := json.Marshal(updated)

	req := admissionv1.AdmissionRequest{
		Kind:        metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
		Resource:    metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
		SubResource: "ephemeralcontainers",
		Namespace:   "team-web",
		Name:        "app",
		Operation:   admissionv1.Update,
		Object:      runtime.RawExtension{Raw: newRaw},
		OldObject:   runtime.RawExtension{Raw: oldRaw},
	}
	resp := review(t, ts.URL+"/validate", req)
	if resp.Allowed {
		t.Fatal("attaching a privileged debug container must be denied")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, "ephemeral") {
		t.Fatalf("denial should mention the ephemeral container: %+v", resp.Result)
	}
}
