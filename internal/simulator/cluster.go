// Package simulator is an in-memory Kubernetes API server for testing the
// admission webhook without a cluster.
//
// It implements the parts of the API server that matter for admission:
// create/update of arbitrary resources (including CRDs), namespaced storage,
// and — crucially — sending a real AdmissionReview v1 request to the webhook
// over HTTP, applying returned JSON patches, honouring the response UID, and
// surfacing denial messages the way the real API server does.
//
// Two failure modes are modelled explicitly because they are what the
// availability requirement is about:
//
//   - the webhook is unreachable (connection refused, timeout), and
//   - the webhook answers 5xx / malformed JSON.
//
// The cluster applies the webhook configuration's failurePolicy (Fail or
// Ignore) to decide what happens, exactly like the API server would.
package simulator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// Policy is the failure policy the simulated API server applies when the
// webhook cannot be reached or returns an error.
type Policy string

const (
	Fail   Policy = "Fail"
	Ignore Policy = "Ignore"
)

// WebhookRef points the simulator at the webhook endpoints. Kubernetes runs the
// mutating webhooks first, applies their patches, and then runs the validating
// webhooks against the mutated object; the simulator reproduces that order.
type WebhookRef struct {
	URL string
	// MutateURL, when set, is called before URL for CREATE/UPDATE and its patch
	// is applied to the object before validation.
	MutateURL string
	// FailurePolicy applies when no namespace-specific policy is configured.
	FailurePolicy Policy
	// NamespaceFailurePolicy overrides FailurePolicy per namespace. This is how
	// the simulator models the two-webhook split (strict namespaces Fail,
	// everyone else Ignore).
	NamespaceFailurePolicy map[string]Policy
	// Timeout for each admission call.
	Timeout time.Duration
}

// Object is one stored resource.
type Object struct {
	GVK       schema.GroupVersionKind `json:"gvk"`
	Namespace string                  `json:"namespace,omitempty"`
	Name      string                  `json:"name"`
	Object    map[string]any          `json:"object"`
	// CreatedAt/UpdatedAt make list output deterministic enough for tests.
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Cluster is the simulated API server.
type Cluster struct {
	mu      sync.RWMutex
	store   map[string]*Object
	webhook *WebhookRef
	client  *http.Client
	now     func() time.Time

	// RecordedRequests is every AdmissionReview sent (for assertions).
	RecordedRequests []admissionv1.AdmissionRequest
	// WebhookCalls counts calls, and Failures counts transport/protocol errors.
	WebhookCalls    int
	WebhookFailures int
	// FailNextWebhook makes the next N calls fail at the transport layer,
	// simulating an outage.
	FailNextWebhook int
}

// New builds an empty cluster. webhook may be nil (admission disabled).
func New(webhook *WebhookRef) *Cluster {
	if webhook != nil && webhook.Timeout == 0 {
		// Match the API server's default admission timeout.
		webhook = &WebhookRef{
			URL:                    webhook.URL,
			MutateURL:              webhook.MutateURL,
			FailurePolicy:          webhook.FailurePolicy,
			NamespaceFailurePolicy: webhook.NamespaceFailurePolicy,
			Timeout:                10 * time.Second,
		}
	}
	return &Cluster{
		store:   map[string]*Object{},
		webhook: webhook,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		now: time.Now,
	}
}

// SetClock controls timestamps in tests.
func (c *Cluster) SetClock(fn func() time.Time) { c.now = fn }

// CreateResult is the outcome of a create/update.
type CreateResult struct {
	Object   *Object
	Allowed  bool
	Patched  bool
	Warnings []string
	Message  string
	// FailurePolicyApplied is set when the webhook was unavailable and the
	// configured failure policy decided the outcome.
	FailurePolicyApplied bool
}

// APIError mirrors a Kubernetes Status error.
type APIError struct {
	Code    int
	Message string
}

func (e *APIError) Error() string { return e.Message }

func key(gvk schema.GroupVersionKind, ns, name string) string {
	return gvk.Group + "/" + gvk.Version + "/" + gvk.Kind + "/" + ns + "/" + name
}

func canonicalKind(gvk schema.GroupVersionKind) string { return gvk.Kind }

// Create applies admission then stores the object. It returns an *APIError when
// the request is denied.
func (c *Cluster) Create(gvk schema.GroupVersionKind, obj map[string]any) (*CreateResult, error) {
	return c.apply(admissionv1.Create, gvk, obj)
}

// Update applies admission then replaces the stored object.
func (c *Cluster) Update(gvk schema.GroupVersionKind, obj map[string]any) (*CreateResult, error) {
	return c.apply(admissionv1.Update, gvk, obj)
}

func (c *Cluster) apply(op admissionv1.Operation, gvk schema.GroupVersionKind, obj map[string]any) (*CreateResult, error) {
	meta, err := metaOf(obj)
	if err != nil {
		return nil, &APIError{Code: 400, Message: err.Error()}
	}
	res := &CreateResult{}
	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, &APIError{Code: 400, Message: err.Error()}
	}

	c.mu.Lock()
	prev := c.store[key(gvk, meta.Namespace, meta.Name)]
	var oldObj map[string]any
	if prev != nil {
		oldObj = prev.Object
	}
	if op == admissionv1.Create && prev != nil {
		c.mu.Unlock()
		return nil, &APIError{Code: 409, Message: fmt.Sprintf("%s %q already exists", canonicalKind(gvk), meta.Name)}
	}
	if op == admissionv1.Update && prev == nil {
		c.mu.Unlock()
		return nil, &APIError{Code: 404, Message: fmt.Sprintf("%s %q not found", canonicalKind(gvk), meta.Name)}
	}
	c.mu.Unlock()

	if c.webhook != nil {
		outcome := c.admit(op, gvk, meta.Namespace, meta.Name, raw, oldObj)
		res.Warnings = outcome.warnings
		res.FailurePolicyApplied = outcome.failurePolicyApplied
		if !outcome.allowed {
			return res, &APIError{Code: 403, Message: outcome.message}
		}
		if len(outcome.patch) > 0 {
			decoded, err := jsonpatch.DecodePatch(outcome.patch)
			if err != nil {
				return res, &APIError{Code: 500, Message: "webhook returned an unparsable patch: " + err.Error()}
			}
			patched, err := decoded.Apply(raw)
			if err != nil {
				return res, &APIError{Code: 500, Message: "webhook patch does not apply: " + err.Error()}
			}
			var newObj map[string]any
			if err := json.Unmarshal(patched, &newObj); err != nil {
				return res, &APIError{Code: 500, Message: "patched object is not valid JSON: " + err.Error()}
			}
			obj = newObj
			res.Patched = true
			// A mutating webhook must not change identity.
			newMeta, err := metaOf(obj)
			if err != nil || newMeta.Name != meta.Name || newMeta.Namespace != meta.Namespace {
				return res, &APIError{Code: 500, Message: "webhook patch changed object identity"}
			}
			raw, _ = json.Marshal(obj)
		}
	}

	now := c.now()
	o := &Object{GVK: gvk, Namespace: meta.Namespace, Name: meta.Name, Object: obj, CreatedAt: now, UpdatedAt: now}
	if prev != nil {
		o.CreatedAt = prev.CreatedAt
	}
	c.mu.Lock()
	c.store[key(gvk, meta.Namespace, meta.Name)] = o
	c.mu.Unlock()
	res.Allowed = true
	res.Object = o
	return res, nil
}

// Delete removes an object without admission (DELETE is not intercepted).
func (c *Cluster) Delete(gvk schema.GroupVersionKind, ns, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.store, key(gvk, ns, name))
}

type admitOutcome struct {
	allowed              bool
	message              string
	warnings             []string
	patch                []byte
	failurePolicyApplied bool
}

func (c *Cluster) failurePolicyFor(ns string) Policy {
	if c.webhook.NamespaceFailurePolicy != nil {
		if p, ok := c.webhook.NamespaceFailurePolicy[ns]; ok {
			return p
		}
	}
	if c.webhook.FailurePolicy == "" {
		return Ignore
	}
	return c.webhook.FailurePolicy
}

func (c *Cluster) admit(op admissionv1.Operation, gvk schema.GroupVersionKind, ns, name string, raw []byte, old map[string]any) admitOutcome {
	policy := c.failurePolicyFor(ns)

	var patch []byte
	if c.webhook.MutateURL != "" {
		mout := c.callWebhook(c.webhook.MutateURL, op, gvk, ns, name, raw, old, policy)
		if !mout.allowed {
			return mout
		}
		if len(mout.patch) > 0 {
			decoded, err := jsonpatch.DecodePatch(mout.patch)
			if err != nil {
				return failOutcome(policy, "mutating webhook returned an unparsable patch: "+err.Error())
			}
			applied, err := decoded.Apply(raw)
			if err != nil {
				return failOutcome(policy, "mutating webhook patch does not apply: "+err.Error())
			}
			var obj map[string]any
			if err := json.Unmarshal(applied, &obj); err != nil {
				return failOutcome(policy, "mutating webhook produced invalid JSON: "+err.Error())
			}
			// Identity must survive mutation.
			m1, err1 := metaOf(obj)
			m2, _ := metaOf(mustDecode(raw))
			if err1 != nil || m1.Name != m2.Name || m1.Namespace != m2.Namespace {
				return failOutcome(policy, "mutating webhook changed object identity")
			}
			raw = applied
			patch = mout.patch
		}
	}
	out := c.callWebhook(c.webhook.URL, op, gvk, ns, name, raw, old, policy)
	if out.allowed && len(out.patch) > 0 {
		// A validating webhook must not mutate.
		return failOutcome(policy, "validating webhook returned a patch; only the mutating webhook may modify objects")
	}
	if len(patch) > 0 {
		out.patch = patch
	}
	if len(out.warnings) == 0 {
		out.warnings = nil
	}
	return out
}

func mustDecode(raw []byte) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

func (c *Cluster) callWebhook(url string, op admissionv1.Operation, gvk schema.GroupVersionKind, ns, name string, raw []byte, old map[string]any, policy Policy) admitOutcome {

	c.mu.Lock()
	c.WebhookCalls++
	failNow := c.FailNextWebhook > 0
	if failNow {
		c.FailNextWebhook--
	}
	c.mu.Unlock()

	if failNow {
		c.mu.Lock()
		c.WebhookFailures++
		c.mu.Unlock()
		return failOutcome(policy, "simulated webhook outage")
	}

	req := c.buildReview(op, gvk, ns, name, raw, old)
	c.mu.Lock()
	c.RecordedRequests = append(c.RecordedRequests, req)
	c.mu.Unlock()

	body, err := json.Marshal(admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request:  &req,
	})
	if err != nil {
		return failOutcome(policy, "marshal review: "+err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.webhook.Timeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return failOutcome(policy, err.Error())
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(httpReq)
	if err != nil {
		c.mu.Lock()
		c.WebhookFailures++
		c.mu.Unlock()
		return failOutcome(policy, "webhook unreachable: "+err.Error())
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		c.mu.Lock()
		c.WebhookFailures++
		c.mu.Unlock()
		return failOutcome(policy, "read webhook response: "+err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		c.mu.Lock()
		c.WebhookFailures++
		c.mu.Unlock()
		return failOutcome(policy, fmt.Sprintf("webhook returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody))))
	}
	var review admissionv1.AdmissionReview
	if err := json.Unmarshal(respBody, &review); err != nil {
		c.mu.Lock()
		c.WebhookFailures++
		c.mu.Unlock()
		return failOutcome(policy, "webhook returned invalid JSON: "+err.Error())
	}
	if review.Response == nil {
		c.mu.Lock()
		c.WebhookFailures++
		c.mu.Unlock()
		return failOutcome(policy, "webhook returned an empty response")
	}
	// The API server rejects mismatched UIDs. Enforcing it here catches a
	// daemon that accidentally drops or rewrites the UID.
	if review.Response.UID != req.UID {
		c.mu.Lock()
		c.WebhookFailures++
		c.mu.Unlock()
		return failOutcome(policy, fmt.Sprintf("webhook response UID %q does not match request UID %q", review.Response.UID, req.UID))
	}
	out := admitOutcome{
		allowed:  review.Response.Allowed,
		warnings: review.Response.Warnings,
		patch:    review.Response.Patch,
	}
	if !out.allowed {
		out.message = "admission webhook \"guard.example.com\" denied the request: "
		if review.Response.Result != nil && review.Response.Result.Message != "" {
			out.message += review.Response.Result.Message
		} else {
			out.message += "request rejected by admission guard"
		}
	}
	return out
}

func failOutcome(policy Policy, reason string) admitOutcome {
	if policy == Fail {
		return admitOutcome{
			allowed:              false,
			failurePolicyApplied: true,
			message:              "admission webhook unavailable and failurePolicy=Fail: " + reason,
		}
	}
	return admitOutcome{allowed: true, failurePolicyApplied: true}
}

func (c *Cluster) buildReview(op admissionv1.Operation, gvk schema.GroupVersionKind, ns, name string, raw []byte, old map[string]any) admissionv1.AdmissionRequest {
	uid := types.UID(fmt.Sprintf("req-%d", time.Now().UnixNano()))
	req := admissionv1.AdmissionRequest{
		UID:       uid,
		Kind:      metav1.GroupVersionKind{Group: gvk.Group, Version: gvk.Version, Kind: gvk.Kind},
		Resource:  metav1.GroupVersionResource{Group: gvk.Group, Version: gvk.Version, Resource: strings.ToLower(gvk.Kind) + "s"},
		Namespace: ns,
		Name:      name,
		Operation: op,
		UserInfo:  authUserOf(gvk, ns),
		Object:    runtime.RawExtension{Raw: raw},
	}
	if old != nil {
		oldRaw, _ := json.Marshal(old)
		req.OldObject = runtime.RawExtension{Raw: oldRaw}
	}
	return req
}

// Get returns a stored object.
func (c *Cluster) Get(gvk schema.GroupVersionKind, ns, name string) (*Object, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	o, ok := c.store[key(gvk, ns, name)]
	if !ok {
		return nil, false
	}
	return o, true
}

// List returns objects of a kind, sorted by namespace/name.
func (c *Cluster) List(gvk schema.GroupVersionKind, ns string) []*Object {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []*Object
	for _, o := range c.store {
		if o.GVK.Kind != gvk.Kind || o.GVK.Group != gvk.Group || o.GVK.Version != gvk.Version {
			continue
		}
		if ns != "" && o.Namespace != ns {
			continue
		}
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Namespaces returns namespace names and their labels, sorted.
func (c *Cluster) Namespaces() map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, o := range c.List(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"}, "") {
		labels := map[string]string{}
		if l, ok := o.Object["metadata"].(map[string]any)["labels"].(map[string]any); ok {
			for k, v := range l {
				if s, ok := v.(string); ok {
					labels[k] = s
				}
			}
		}
		out[o.Name] = labels
	}
	return out
}

// Recorded returns a copy of admission requests seen so far.
func (c *Cluster) Recorded() []admissionv1.AdmissionRequest {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]admissionv1.AdmissionRequest{}, c.RecordedRequests...)
}

// --- helpers ---------------------------------------------------------------------

type objectMeta struct {
	Name      string
	Namespace string
	Labels    map[string]string
}

func metaOf(obj map[string]any) (objectMeta, error) {
	m, ok := obj["metadata"].(map[string]any)
	if !ok {
		return objectMeta{}, fmt.Errorf("object has no metadata")
	}
	name, _ := m["name"].(string)
	if name == "" {
		gen, _ := m["generateName"].(string)
		if gen == "" {
			return objectMeta{}, fmt.Errorf("object has no metadata.name or metadata.generateName")
		}
		// The API server generates a unique name; a deterministic suffix keeps
		// tests reproducible.
		name = gen + "sim"
		m["name"] = name
	}
	ns, _ := m["namespace"].(string)
	labels := map[string]string{}
	if lm, ok := m["labels"].(map[string]any); ok {
		for k, v := range lm {
			if s, ok := v.(string); ok {
				labels[k] = s
			}
		}
	}
	return objectMeta{Name: name, Namespace: ns, Labels: labels}, nil
}

// Unstructured is a convenience for building objects.
func Unstructured(obj map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: obj}
}

// authUserOf returns a deterministic requester identity for review requests.
// The simulator does not model RBAC; the UserInfo exists so audit records and
// tests have a realistic identity.
func authUserOf(gvk schema.GroupVersionKind, ns string) authenticationv1.UserInfo {
	if ns == "" {
		ns = "cluster"
	}
	return authenticationv1.UserInfo{
		Username: "simulator-user",
		UID:      "simulator-uid",
		Groups:   []string{"system:authenticated", "simulator/" + ns},
	}
}
