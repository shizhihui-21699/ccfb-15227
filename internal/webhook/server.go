// Package webhook implements the Kubernetes admission webhook HTTP protocol.
//
// Kubernetes sends an AdmissionReview to /validate and expects an
// AdmissionReview back. Failure handling has two layers:
//
//   - failurePolicy on the webhook configuration. A single webhook cannot fail
//     open for some namespaces and closed for others, so the deployment ships
//     two configurations: one matching namespaces labelled
//     guard.example.com/enforcement=strict with failurePolicy=Fail, and one
//     matching everything else with failurePolicy=Ignore. Both point at this
//     server. "Ignore" means a webhook outage never blocks deployments in
//     ordinary namespaces; strict namespaces keep the guarantee.
//
//   - In-process degradation. If policy files fail to parse or informers have
//     not synced, the engine itself fails closed for strict namespaces and open
//     elsewhere, records a loud audit entry, and exposes a metric. That way a
//     misconfigured policy cannot silently disable protection in strict
//     namespaces while the process is healthy.
package webhook

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/example/cluster-admission-guard/internal/admission"
	"github.com/example/cluster-admission-guard/internal/audit"
	"github.com/example/cluster-admission-guard/internal/metrics"
	"github.com/example/cluster-admission-guard/internal/policy"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// MaxBodyBytes caps the request body. The API server limits objects to ~1.5MiB;
// 8MiB leaves headroom without allowing unbounded memory use.
const MaxBodyBytes = 8 << 20

// Server is the HTTP handler.
type Server struct {
	// Engine evaluates /validate (mutating webhook runs a second engine with
	// mutation enabled).
	Engine *admission.Engine
	// MutateEngine handles /mutate. When nil, /mutate uses Engine.
	MutateEngine *admission.Engine
	Audit        *audit.Logger
	// Registry is optional; when set the server publishes metrics.
	Registry *metrics.Registry
	// Clock allows tests to control timestamps; defaults to time.Now.
	Clock func() time.Time
	// MaxAuditFindings caps findings recorded per event.
	MaxAuditFindings int

	mu       sync.Mutex
	inflight atomic.Int64

	// counters resolve lazily.
	allowCtr, degradedCtr, auditErrCtr *int64Counter
	inflightGauge                      *int64Gauge
}

// int64Counter adapts a metrics.Counter to Inc.
type int64Counter struct{ c interface{ Inc(...string) } }

func (c *int64Counter) Inc(values ...string) {
	if c != nil && c.c != nil {
		c.c.Inc(values...)
	}
}

type int64Gauge struct {
	g interface{ Set(int64, ...string) }
}

func (g *int64Gauge) Set(v int64, values ...string) {
	if g != nil && g.g != nil {
		g.g.Set(v, values...)
	}
}

// NewServer wires metrics from a registry.
func NewServer(engine *admission.Engine, logger *audit.Logger, reg *metrics.Registry) *Server {
	s := &Server{Engine: engine, Audit: logger, Registry: reg, Clock: time.Now, MaxAuditFindings: 64}
	if reg != nil {
		s.allowCtr = &int64Counter{c: reg.Counter("admission_guard_decisions_total", "Admission decisions by outcome.", "decision")}
		s.degradedCtr = &int64Counter{c: reg.Counter("admission_guard_degraded_total", "Requests served while the policy store was unhealthy.", "enforcement")}
		s.auditErrCtr = &int64Counter{c: reg.Counter("admission_guard_audit_write_errors_total", "Audit sink write failures.")}
		s.inflightGauge = &int64Gauge{g: reg.Gauge("admission_guard_inflight_requests", "Admission requests currently being evaluated.")}
		if logger != nil && logger.OnError == nil {
			logger.OnError = func(error) { s.auditErrCtr.Inc() }
		}
	}
	return s
}

// Routes returns the HTTP mux.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		s.handleAdmission(w, r, s.validateEngine())
	})
	mux.HandleFunc("/mutate", func(w http.ResponseWriter, r *http.Request) {
		s.handleAdmission(w, r, s.mutateEngine())
	})
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReady)
	if s.Registry != nil {
		mux.Handle("/metrics", s.Registry.Handler())
	}
	return mux
}

// validateEngine returns an engine that never rewrites objects.
func (s *Server) validateEngine() *admission.Engine {
	return s.Engine.WithoutMutation()
}

func (s *Server) mutateEngine() *admission.Engine {
	if s.MutateEngine != nil {
		return s.MutateEngine
	}
	return s.Engine
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// handleReady reports readiness. It is intentionally "not ready" when the
// policy store is unhealthy: removing the pod from the Service endpoints means
// the API server falls back to the webhook's failurePolicy instead of receiving
// evaluate-with-stale-policy answers.
func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	if err := s.Engine.Store.Health(); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "policy store unhealthy: %v\n", err)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready\n"))
}

func (s *Server) handleAdmission(w http.ResponseWriter, r *http.Request, engine *admission.Engine) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	start := s.Clock()

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		http.Error(w, "cannot read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		// Malformed review: the API server never sends this, so answer with a
		// plain 400. A misbehaving intermediary must not be able to make us
		// emit an allow response.
		http.Error(w, "invalid AdmissionReview: "+err.Error(), http.StatusBadRequest)
		return
	}
	if review.Request == nil {
		http.Error(w, "AdmissionReview has no request", http.StatusBadRequest)
		return
	}

	resp := s.evaluate(review.Request, start, engine)

	out := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: admissionv1.SchemeGroupVersion.String(),
			Kind:       "AdmissionReview",
		},
		Response: resp,
	}
	// The response must echo the request UID; clients (and some versions of the
	// API server) treat a mismatch as a protocol error.
	if review.Request.UID != "" {
		out.Response.UID = review.Request.UID
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	if err := enc.Encode(out); err != nil {
		// Response already partially written; nothing left to do but log.
		_ = err
	}
}

// Evaluate converts an AdmissionReview request into a response using the
// validating engine. Exported so the CLI and tests can exercise the exact HTTP
// path.
func (s *Server) Evaluate(req *admissionv1.AdmissionRequest, start time.Time) *admissionv1.AdmissionResponse {
	return s.evaluate(req, start, s.validateEngine())
}

func (s *Server) evaluate(req *admissionv1.AdmissionRequest, start time.Time, engine *admission.Engine) *admissionv1.AdmissionResponse {
	s.inflight.Add(1)
	defer s.inflight.Add(-1)
	s.inflightGauge.Set(s.inflight.Load())

	resp := &admissionv1.AdmissionResponse{}
	resp.UID = req.UID

	gvk := schema.GroupVersionKind{
		Group:   req.Kind.Group,
		Version: req.Kind.Version,
		Kind:    req.Kind.Kind,
	}
	ns := req.Namespace
	if ns == "" && req.Kind.Kind == "Namespace" && req.Kind.Group == "" {
		ns = ""
	}
	name := req.Name
	if name == "" && len(req.Object.Raw) > 0 {
		// CREATE requests may carry only generateName.
		var probe struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(req.Object.Raw, &probe); err == nil {
			name = probe.Metadata.Name
		}
	}

	admissionReq := admission.Request{
		Operation: admission.Operation(req.Operation),
		GVK:       gvk,
		Namespace: ns,
		Name:      name,
		User:      req.UserInfo.Username,
		Groups:    append([]string{}, req.UserInfo.Groups...),
	}
	var err error
	if len(req.Object.Raw) > 0 {
		admissionReq.Object, err = decodeObject(req.Object.Raw)
		if err != nil {
			return s.protocolError(err, req, start)
		}
	}
	if len(req.OldObject.Raw) > 0 {
		admissionReq.OldObject, err = decodeObject(req.OldObject.Raw)
		if err != nil {
			return s.protocolError(err, req, start)
		}
	}

	result := engine.Evaluate(admissionReq)

	resp.Allowed = result.Allowed
	resp.Warnings = result.Warnings
	if len(result.Patch) > 0 {
		resp.Patch = result.Patch
		pt := admissionv1.PatchTypeJSONPatch
		resp.PatchType = &pt
	}
	if !result.Allowed {
		resp.Result = &metav1.Status{
			Status:  metav1.StatusFailure,
			Message: strings.Join(result.Reasons, "\n"),
			Reason:  metav1.StatusReasonForbidden,
			Code:    http.StatusForbidden,
		}
	}

	if s.Registry != nil {
		decision := "allow"
		if !result.Allowed {
			decision = "deny"
		}
		s.allowCtr.Inc(decision)
		if result.Degraded {
			s.degradedCtr.Inc(enforcementFor(req.Namespace, engine.Store))
		}
	}
	if s.Audit != nil {
		s.Audit.Record(buildAuditEvent(admissionReq, result, req, start, s.Clock(), s.MaxAuditFindings))
	}
	return resp
}

func enforcementFor(namespace string, store admission.Store) string {
	if namespace == "" {
		return "unknown"
	}
	if info, ok := store.Namespace(namespace); ok {
		if info.Enforcement == "" {
			return policy.EnforcementStandard
		}
		return info.Enforcement
	}
	return "unregistered"
}

func (s *Server) protocolError(err error, req *admissionv1.AdmissionRequest, start time.Time) *admissionv1.AdmissionResponse {
	resp := &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: false,
		Result: &metav1.Status{
			Status:  metav1.StatusFailure,
			Message: "admission guard could not decode the request: " + err.Error(),
			Code:    http.StatusBadRequest,
		},
	}
	if s.Audit != nil {
		s.Audit.Record(audit.Event{
			Time:       s.Clock(),
			UID:        string(req.UID),
			Operation:  string(req.Operation),
			Kind:       req.Kind.Kind,
			Namespace:  req.Namespace,
			Name:       req.Name,
			Allowed:    false,
			Degraded:   true,
			Reason:     "request decode failure: " + err.Error(),
			DurationMs: s.Clock().Sub(start).Milliseconds(),
		})
	}
	return resp
}

func decodeObject(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var obj map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, err
	}
	return obj, nil
}

func buildAuditEvent(req admission.Request, result admission.Response, raw *admissionv1.AdmissionRequest, start, now time.Time, maxFindings int) audit.Event {
	ev := audit.Event{
		Time:       now,
		UID:        string(raw.UID),
		Operation:  string(req.Operation),
		Kind:       req.GVK.Kind,
		Group:      req.GVK.Group,
		Version:    req.GVK.Version,
		Namespace:  req.Namespace,
		Name:       req.Name,
		Allowed:    result.Allowed,
		Degraded:   result.Degraded,
		Reason:     result.DegradedReason,
		Policies:   result.Policies,
		Reasons:    result.Reasons,
		Warnings:   result.Warnings,
		DurationMs: now.Sub(start).Milliseconds(),
	}
	if raw.UserInfo.Username != "" {
		ev.User = raw.UserInfo.Username
		ev.UserGroups = raw.UserInfo.Groups
	}
	if len(result.Patch) > 0 {
		ev.Patch = json.RawMessage(result.Patch)
	}
	seenExemption := map[string]bool{}
	for i, f := range result.Findings {
		if i < maxFindings {
			ev.Findings = append(ev.Findings, audit.FindingRecord{
				Policy:      f.Policy,
				Rule:        f.Rule,
				Severity:    string(f.Severity),
				Action:      string(f.Action),
				Disposition: string(f.Disposition),
				Path:        f.Path,
				Container:   f.Container,
				Message:     f.Message,
				Exemption:   f.Exemption,
			})
		}
		if f.Disposition == policy.DispositionExempted && f.Exemption != "" && f.ExemptionExpiresAt != nil && !seenExemption[f.Exemption] {
			seenExemption[f.Exemption] = true
			ev.Exemptions = append(ev.Exemptions, audit.ExemptionRecord{
				ID:        f.Exemption,
				Policy:    f.Policy,
				Rule:      f.Rule,
				ExpiresAt: *f.ExemptionExpiresAt,
			})
		}
	}
	return ev
}

// ObjectMetaFromRaw extracts metadata from a raw object.
func ObjectMetaFromRaw(raw []byte) (name, namespace string, labels map[string]string) {
	var probe struct {
		Metadata struct {
			Name      string            `json:"name"`
			Namespace string            `json:"namespace"`
			Labels    map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", "", nil
	}
	return probe.Metadata.Name, probe.Metadata.Namespace, probe.Metadata.Labels
}

// Ensure imports used only for docs stay honest.
var (
	_ = runtime.Object(nil)
	_ = types.UID("")
	_ = strconv.Itoa
)
