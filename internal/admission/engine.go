// Package admission turns a submitted object into an admission decision.
//
// The engine is deliberately independent of HTTP and of client-go: the webhook
// handler, the CLI and the tests all call Evaluate. This keeps the security
// logic testable without a cluster.
package admission

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	jsonpatchlib "gomodules.xyz/jsonpatch/v2"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/example/cluster-admission-guard/internal/policy"
	"github.com/example/cluster-admission-guard/internal/rules"
	"github.com/example/cluster-admission-guard/internal/workload"
)

// Operation is the admission operation as sent by the API server.
type Operation string

const (
	Create  Operation = "CREATE"
	Update  Operation = "UPDATE"
	Delete  Operation = "DELETE"
	Connect Operation = "CONNECT"
)

// Request is a normalized admission request.
type Request struct {
	Operation Operation
	GVK       schema.GroupVersionKind
	Namespace string
	Name      string
	// Object is the new object (nil for DELETE).
	Object map[string]any
	// OldObject is the previously stored object (UPDATE only).
	OldObject map[string]any
	// User is the authenticated username of the requester.
	User string
	// Groups are the requester's group memberships.
	Groups []string
}

// Response is the decision.
type Response struct {
	Allowed bool
	// Patch is an RFC 6902 patch relative to the submitted object.
	Patch []byte
	// Warnings are surfaced by kubectl/api clients.
	Warnings []string
	// Findings is every finding, for audit logging.
	Findings []policy.Finding
	// Reasons is the denial message shown to the user.
	Reasons []string
	// Policies lists the names of policies that applied.
	Policies []string
	// Evaluated reports how many pod specs were checked.
	Evaluated int
	// Degraded is set when an internal error or a stale policy store forced a
	// fail-open/fail-closed decision. It is always audited.
	Degraded bool
	// DegradedReason explains a Degraded response.
	DegradedReason string
}

// Store supplies policy documents and namespace metadata. Implementations may
// read from files, ConfigMaps or an informer cache.
type Store interface {
	// Policies returns the compiled policies that currently apply.
	Policies() []*policy.CompiledPolicy
	// TrustStore returns the platform image trust store, or nil.
	TrustStore() *policy.TrustStore
	// Namespace returns metadata for a namespace. The second return value is
	// false when the namespace is not known.
	Namespace(name string) (policy.NamespaceInfo, bool)
	// Health reports whether the store is synchronized. A non-nil error makes
	// the engine treat policy as unavailable.
	Health() error
}

// Engine evaluates requests against a Store.
type Engine struct {
	Store Store
	// Now allows tests to control exemption clocks.
	Now func() time.Time
	// MaxWarnings caps the warnings returned to clients; all findings are still
	// audited.
	MaxWarnings int
	// AllowMutation enables remediation. The mutating webhook runs with it on;
	// the validating webhook runs with it off, so a violation that should have
	// been fixed is denied rather than reported as fixed.
	AllowMutation bool
	// AdminGroups may grant a namespace the "disabled" enforcement label.
	// Without this, anyone able to update a Namespace could opt out of
	// admission review for everything inside it.
	AdminGroups []string
	// StrictWhenUnlabelled treats a namespace with no enforcement label as
	// strict when the policy store is unhealthy. It is a stricter posture for
	// clusters that want "unknown namespace" to never mean "fail open".
	StrictWhenUnlabelled bool
}

// NewEngine builds an engine.
func NewEngine(store Store) *Engine {
	return &Engine{Store: store, Now: time.Now, MaxWarnings: 12, AllowMutation: true}
}

// WithoutMutation returns a shallow copy that never rewrites objects. It is used
// by the validating endpoint so a remediation request cannot masquerade as an
// already-safe object.
func (e *Engine) WithoutMutation() *Engine {
	cp := *e
	cp.AllowMutation = false
	return &cp
}

// Evaluate decides an admission request.
func (e *Engine) Evaluate(req Request) Response {
	now := e.Now()

	if req.Operation == Delete || req.Operation == Connect {
		return Response{Allowed: true}
	}
	if req.Object == nil {
		return Response{
			Allowed:        false,
			Degraded:       true,
			DegradedReason: "admission request carried no object",
			Reasons:        []string{"admission request carried no object; refusing to admit an object that could not be inspected"},
		}
	}

	ns, nsKnown := e.namespaceFor(req)

	// If the policy store is not usable (files failed to parse, sync failed),
	// we cannot claim the object is safe. Fail closed for namespaces that
	// opted into strict enforcement and fail open (with a loud audit entry) for
	// everyone else, so one broken policy file cannot freeze the whole cluster.
	if err := e.Store.Health(); err != nil {
		closed := ns.Enforcement == policy.EnforcementStrict
		if e.StrictWhenUnlabelled && !nsKnown {
			closed = true
		}
		resp := e.degraded(closed, fmt.Sprintf("policy store unavailable: %v", err))
		resp.DegradedReason = fmt.Sprintf("policy store unavailable: %v (enforcement=%s)", err, enforcementOrDefault(ns))
		return resp
	}

	isNamespaceObject := req.GVK.Kind == "Namespace" && req.GVK.Group == ""

	// Namespaces labelled disabled are excluded by the webhook configuration.
	// Honour the label here too, so the guarantee does not depend on the
	// configuration being rendered exactly right.
	if !isNamespaceObject && ns.Enforcement == policy.EnforcementDisabled {
		return Response{Allowed: true, Warnings: []string{"namespace " + ns.Name + " is exempt from admission review (enforcement=disabled)"}}
	}

	applied := e.applicablePolicies(ns)
	if len(applied) == 0 {
		return Response{Allowed: true}
	}

	// A Namespace object changes enforcement for everything inside it; there is
	// no pod template to validate, but the change must be authorized.
	if isNamespaceObject {
		return e.evaluateNamespaceObject(ns, applied, req)
	}

	original, err := json.Marshal(req.Object)
	if err != nil {
		return e.degraded(true, fmt.Sprintf("cannot serialize object: %v", err))
	}

	w := workload.Extract(req.GVK, req.Object)
	ctx := &rules.Context{
		Namespace:  ns.Name,
		Teams:      ns.Teams(teamLabelFor(applied)),
		Kind:       req.GVK.Kind,
		Workload:   workloadName(req.Object),
		Operation:  string(req.Operation),
		TrustStore: e.Store.TrustStore(),
	}

	accepted := e.acceptedExemptions(applied, ns, ctx, now)
	findings := e.evaluateObjectRules(w, applied, ns, ctx, now, accepted)
	findings = append(findings, e.evaluatePodSpecs(w, applied, ns, ctx, now, true, accepted)...)

	// Pre-existing violations: the same violation already exists on the stored
	// object. Blocking an unrelated edit of a fleet-wide Deployment because of
	// one legacy privileged container would freeze operations, so pre-existing
	// violations are reported but do not deny the request. Any newly introduced
	// violation still does.
	preExisting := map[string]bool{}
	if req.Operation == Update && req.OldObject != nil {
		oldW := workload.Extract(req.GVK, req.OldObject)
		oldCtx := *ctx
		for _, f := range e.evaluatePodSpecs(oldW, applied, ns, &oldCtx, now, false, accepted) {
			if f.Disposition == policy.DispositionDenied || f.Disposition == policy.DispositionRemediated {
				preExisting[f.Key()] = true
			}
		}
	}

	resp := Response{Policies: policyNames(applied), Evaluated: len(w.PodSpecs)}
	var denyMsgs, warnings []string
	remediated := false

	for i := range findings {
		f := &findings[i]
		switch f.Disposition {
		case policy.DispositionExempted, policy.DispositionAudited:
			// Exemptions and audit-only findings never affect the outcome.
			continue
		case policy.DispositionDenied:
			if preExisting[f.Key()] {
				f.Disposition = policy.DispositionPreExisting
				if len(warnings) < e.MaxWarnings {
					warnings = append(warnings, "pre-existing violation, not blocking this update: "+f.Message)
				}
				continue
			}
			denyMsgs = append(denyMsgs, formatDenial(*f))
		case policy.DispositionRemediated:
			remediated = true
			if len(warnings) < e.MaxWarnings {
				warnings = append(warnings, fmt.Sprintf("auto-remediated %s at %s: %s", f.Rule, f.Path, f.Fix))
			}
		case policy.DispositionWarned:
			if len(warnings) < e.MaxWarnings && !f.Advisory {
				warnings = append(warnings, f.Message)
			}
		}
	}

	resp.Findings = findings
	resp.Warnings = warnings
	if len(denyMsgs) > 0 {
		sort.Strings(denyMsgs)
		resp.Allowed = false
		resp.Reasons = denyMsgs
		// The object was rejected; a "fixed X" warning would be false, because
		// no patch is applied to a denied request.
		resp.Warnings = nil
		return resp
	}
	resp.Allowed = true

	if remediated {
		patched, err := json.Marshal(req.Object)
		if err != nil {
			return e.degraded(true, fmt.Sprintf("cannot serialize remediated object: %v", err))
		}
		ops, err := jsonpatchlib.CreatePatch(original, patched)
		if err != nil {
			return e.degraded(true, fmt.Sprintf("cannot build remediation patch: %v", err))
		}
		if len(ops) == 0 {
			return resp
		}
		patch, err := json.Marshal(ops)
		if err != nil {
			return e.degraded(true, fmt.Sprintf("cannot serialize remediation patch: %v", err))
		}
		if bytes.Equal(patch, []byte("[]")) {
			return resp
		}
		// Apply the patch to the original object and re-evaluate. A patch that
		// fails to apply, or that leaves a deny-level violation behind, must
		// never be admitted: the user would be told the object was fixed when
		// it was not.
		verr := e.verifyPatch(original, patch, req, ns, ctx, now, preExistingKeys(findings))
		if verr != nil {
			resp.Allowed = false
			resp.Reasons = []string{verr.Error()}
			return resp
		}
		resp.Patch = patch
	}
	return resp
}

// preExistingKeys returns the keys of findings that are only reported because
// they already existed on the stored object.
func preExistingKeys(findings []policy.Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range findings {
		if f.Disposition == policy.DispositionPreExisting {
			out[f.Key()] = true
		}
	}
	return out
}

func (e *Engine) verifyPatch(original, patch []byte, req Request, ns policy.NamespaceInfo, ctx *rules.Context, now time.Time, tolerated map[string]bool) error {
	decoded, err := jsonpatch.DecodePatch(patch)
	if err != nil {
		return fmt.Errorf("remediation produced an invalid patch: %v", err)
	}
	appliedRaw, err := decoded.Apply(original)
	if err != nil {
		return fmt.Errorf("remediation patch does not apply: %v", err)
	}
	var applied map[string]any
	if err := json.Unmarshal(appliedRaw, &applied); err != nil {
		return fmt.Errorf("remediated object is not valid JSON: %v", err)
	}
	policies := e.applicablePolicies(ns)
	w := workload.Extract(req.GVK, applied)
	var remaining []string
	accepted := e.acceptedExemptions(policies, ns, ctx, now)
	for _, f := range e.evaluateObjectRules(w, policies, ns, ctx, now, accepted) {
		if f.Disposition == policy.DispositionDenied && !tolerated[f.Key()] {
			remaining = append(remaining, formatDenial(f))
		}
	}
	for _, f := range e.evaluatePodSpecs(w, policies, ns, ctx, now, false, accepted) {
		if f.Disposition == policy.DispositionDenied && !tolerated[f.Key()] {
			remaining = append(remaining, formatDenial(f))
		}
	}
	if len(remaining) > 0 {
		sort.Strings(remaining)
		return fmt.Errorf("automatic remediation could not produce a compliant object; the request is rejected instead. Remaining violations: %s", strings.Join(remaining, "; "))
	}
	return nil
}

// namespaceFor resolves namespace metadata and whether the namespace is known
// to the store. Kubernetes itself guarantees the namespace exists when a
// namespaced object is created, so an unknown namespace means the informer
// cache is behind (bootstrap) or the request targets a cluster-scoped resource.
func (e *Engine) namespaceFor(req Request) (policy.NamespaceInfo, bool) {
	if req.GVK.Kind == "Namespace" && req.GVK.Group == "" && req.Namespace == "" {
		ns := policy.NamespaceInfo{}
		if meta, ok := req.Object["metadata"].(map[string]any); ok {
			ns.Name, _ = meta["name"].(string)
			ns.Labels = stringMap(meta["labels"])
		}
		ns.Enforcement = policy.EnforcementOf(ns.Labels)
		return ns, true
	}
	if req.Namespace != "" {
		if info, ok := e.Store.Namespace(req.Namespace); ok {
			return info, true
		}
		// Use the name with no labels rather than failing the request;
		// enforcement defaults to standard (fail open on outage), which is the
		// availability-preserving choice.
		return policy.NamespaceInfo{Name: req.Namespace, Enforcement: policy.EnforcementStandard}, false
	}
	// Cluster-scoped object: no namespace means no admission failure class.
	return policy.NamespaceInfo{Enforcement: policy.EnforcementStandard}, true
}

// acceptedExemption is an exemption from one policy that another policy has
// opted into via spec.acceptExemptions.
type acceptedExemption struct {
	policy    string
	exemption *policy.Exemption
}

// acceptedExemptions collects every active exemption that at least one
// applicable policy accepts (declares itself or names in acceptExemptions) and
// that matches this request. Rules are matched per finding in finalize so the
// exemption's rule selector is honoured against the finding's own rule.
func (e *Engine) acceptedExemptions(policies []*policy.CompiledPolicy, ns policy.NamespaceInfo, ctx *rules.Context, now time.Time) []acceptedExemption {
	var out []acceptedExemption
	seen := map[string]bool{}
	for _, owner := range policies {
		for i := range owner.Spec.Exemptions {
			ex := &owner.Spec.Exemptions[i]
			if !exemptionActive(ex, now) {
				continue
			}
			// At least one applicable policy must accept this exemption id.
			var acceptedBy *policy.CompiledPolicy
			for _, consumer := range policies {
				if consumer.AcceptsExemption(ex.ID) {
					acceptedBy = consumer
					break
				}
			}
			if acceptedBy == nil {
				continue
			}
			// Scope matching uses the declaring policy's team label so mixed
			// label conventions do not silently disable an exemption.
			if !owner.ScopeMatches(ex, ns, ctx.Kind, ctx.Workload) {
				continue
			}
			key := owner.Metadata.Name + "/" + ex.ID
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, acceptedExemption{policy: owner.Metadata.Name, exemption: ex})
		}
	}
	return out
}

func exemptionActive(ex *policy.Exemption, now time.Time) bool {
	end, err := time.Parse(time.RFC3339, ex.ExpiresAt)
	if err != nil || !now.Before(end) {
		return false
	}
	if ex.NotBefore != "" {
		start, err := time.Parse(time.RFC3339, ex.NotBefore)
		if err != nil || now.Before(start) {
			return false
		}
	}
	return true
}

func (e *Engine) applicablePolicies(ns policy.NamespaceInfo) []*policy.CompiledPolicy {
	all := e.Store.Policies()
	out := make([]*policy.CompiledPolicy, 0, len(all))
	for _, p := range all {
		if p.AppliesTo(ns) {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Metadata.Name < out[j].Metadata.Name })
	return out
}

func (e *Engine) evaluateObjectRules(w *workload.Workload, policies []*policy.CompiledPolicy, ns policy.NamespaceInfo, ctx *rules.Context, now time.Time, accepted []acceptedExemption) []policy.Finding {
	var out []policy.Finding
	for _, p := range policies {
		for _, ruleID := range rules.ObjectRuleIDs {
			spec, ok := p.RuleConfig(ruleID)
			if !ok || (spec.Enabled != nil && !*spec.Enabled) {
				continue
			}
			action, severity := effectiveAction(p, spec)
			for _, raw := range rules.EvaluateObject(ruleID, w) {
				f := e.finalize(p, ns, ruleID, action, severity, raw, ctx, now, accepted)
				if f != nil {
					out = append(out, *f)
				}
			}
		}
	}
	return out
}

func (e *Engine) evaluatePodSpecs(w *workload.Workload, policies []*policy.CompiledPolicy, ns policy.NamespaceInfo, ctx *rules.Context, now time.Time, allowMutate bool, accepted []acceptedExemption) []policy.Finding {
	var out []policy.Finding
	for _, p := range policies {
		for _, ruleID := range ruleIDsOf(p) {
			spec, ok := p.RuleConfig(ruleID)
			if !ok || (spec.Enabled != nil && !*spec.Enabled) {
				continue
			}
			impl := rules.Get(ruleID)
			if impl == nil {
				continue
			}
			action, severity := effectiveAction(p, spec)
			canMutate := allowMutate && e.AllowMutation && action == policy.ActionRemediate && p.Mode == policy.ModeEnforce
			for _, ps := range w.PodSpecs {
				res := impl.Evaluate(ctx, ps, spec.Config, canMutate)
				for _, raw := range res.Findings {
					f := e.finalize(p, ns, ruleID, action, severity, raw, ctx, now, accepted)
					if f != nil {
						out = append(out, *f)
					}
				}
			}
		}
	}
	return out
}

// finalize applies mode, exemption and disposition rules to a raw finding. It
// returns nil when the finding is fully exempted and should not even be
// reported as an informational record.
func (e *Engine) finalize(p *policy.CompiledPolicy, ns policy.NamespaceInfo, ruleID string, action policy.Action, severity policy.Severity, raw policy.Finding, ctx *rules.Context, now time.Time, accepted []acceptedExemption) *policy.Finding {
	raw.Policy = p.Metadata.Name
	raw.Rule = ruleID
	raw.Severity = severity
	raw.Action = action
	raw.Disposition = dispositionFor(p.Mode, action)

	if action == policy.ActionRemediate && raw.Disposition == policy.DispositionRemediated {
		switch {
		case !e.AllowMutation:
			// Validating only: the object is still dangerous because no patch
			// can be applied here. Deny so the caller resubmits through the
			// mutating webhook, which runs first in a real cluster.
			raw.Disposition = policy.DispositionDenied
			raw.Message = raw.Message + " (this rule is configured to auto-remediate; submit through the mutating webhook, which the webhook configuration runs before validation)"
		case raw.Fix == "":
			// The rule reported a violation it could not fix. Admitting it
			// would be a silent security hole.
			raw.Disposition = policy.DispositionDenied
		}
	}

	for _, ae := range accepted {
		if !policy.RuleMatches(ae.exemption, ruleID) {
			continue
		}
		raw.Disposition = policy.DispositionExempted
		raw.Exemption = ae.exemption.ID
		raw.ExemptionPolicy = ae.policy
		if exp, err := time.Parse(time.RFC3339, ae.exemption.ExpiresAt); err == nil {
			raw.ExemptionExpiresAt = &exp
		}
		break
	}
	// An advisory finding is informational only: it must never deny, remediate
	// or warn, regardless of the configured action.
	if raw.Advisory {
		raw.Action = policy.ActionAudit
		raw.Disposition = policy.DispositionAudited
		raw.Severity = policy.SeverityInfo
	}
	return &raw
}

func dispositionFor(mode policy.Mode, action policy.Action) policy.Disposition {
	if mode == policy.ModeAudit {
		return policy.DispositionAudited
	}
	switch action {
	case policy.ActionAudit:
		return policy.DispositionAudited
	case policy.ActionWarn:
		return policy.DispositionWarned
	case policy.ActionRemediate:
		return policy.DispositionRemediated
	default:
		return policy.DispositionDenied
	}
}

func effectiveAction(p *policy.CompiledPolicy, spec policy.RuleSpec) (policy.Action, policy.Severity) {
	action := spec.Action
	if action == "" {
		action = policy.ActionDeny
	}
	severity := spec.Severity
	if severity == "" {
		severity = policy.SeverityHigh
	}
	return action, severity
}

func ruleIDsOf(p *policy.CompiledPolicy) []string {
	out := make([]string, 0, len(p.Spec.Rules))
	for _, r := range p.Spec.Rules {
		if rules.IsObjectRule(r.ID) {
			continue
		}
		out = append(out, r.ID)
	}
	return out
}

func teamLabelFor(policies []*policy.CompiledPolicy) string {
	for _, p := range policies {
		if p.TeamLabel != "" {
			return p.TeamLabel
		}
	}
	return policy.DefaultTeamLabel
}

func (e *Engine) evaluateNamespaceObject(ns policy.NamespaceInfo, policies []*policy.CompiledPolicy, req Request) Response {
	// Downgrading a strict namespace back to standard removes its guarantee
	// that admission never fails open. That is as powerful as disabling review.
	if req.Operation == Update && req.OldObject != nil {
		oldLabels := stringMap(req.OldObject["metadata"].(map[string]any)["labels"])
		if policy.EnforcementOf(oldLabels) == policy.EnforcementStrict && ns.Enforcement != policy.EnforcementStrict && !e.isAdmin(req) {
			return Response{
				Allowed:  false,
				Reasons:  []string{"removing guard.example.com/enforcement=strict downgrades this namespace to fail-open on webhook outages; only members of the cluster-admin group may do that"},
				Policies: policyNames(policies),
			}
		}
	}

	if ns.Enforcement != policy.EnforcementDisabled || !hasEnforcePolicy(policies) {
		return Response{Allowed: true, Policies: policyNames(policies)}
	}
	// Opting an entire namespace out of admission review is a cluster-level
	// decision. A workload author with Namespace write access must not be able
	// to make privileged pods admissible simply by labelling the namespace.
	if e.isAdmin(req) {
		return Response{
			Allowed:  true,
			Policies: policyNames(policies),
			Warnings: []string{"enforcement=disabled accepted: requester is in an admin group and everything in this namespace will bypass admission review"},
		}
	}
	return Response{
		Allowed:  false,
		Reasons:  []string{"setting guard.example.com/enforcement=disabled would exclude this namespace from admission review; only members of the cluster-admin group may do that"},
		Policies: policyNames(policies),
	}
}

func (e *Engine) isAdmin(req Request) bool {
	if len(e.AdminGroups) == 0 {
		return false
	}
	for _, g := range req.Groups {
		for _, admin := range e.AdminGroups {
			if g == admin {
				return true
			}
		}
	}
	return false
}

func hasEnforcePolicy(policies []*policy.CompiledPolicy) bool {
	for _, p := range policies {
		if p.Mode == policy.ModeEnforce {
			return true
		}
	}
	return false
}

func (e *Engine) degraded(failClosed bool, reason string) Response {
	return Response{
		Allowed:        !failClosed,
		Degraded:       true,
		DegradedReason: reason,
		Reasons:        []string{reason},
	}
}

func enforcementOrDefault(ns policy.NamespaceInfo) string {
	if ns.Enforcement == "" {
		return policy.EnforcementStandard
	}
	return ns.Enforcement
}

func formatDenial(f policy.Finding) string {
	var b strings.Builder
	b.WriteString("[")
	b.WriteString(string(f.Severity))
	b.WriteString("] ")
	b.WriteString(f.Message)
	if f.Policy != "" {
		b.WriteString(" (policy ")
		b.WriteString(f.Policy)
		b.WriteString(", rule ")
		b.WriteString(f.Rule)
		b.WriteString(")")
	}
	if f.Path != "" {
		b.WriteString(" at ")
		b.WriteString(f.Path)
	}
	return b.String()
}

func policyNames(policies []*policy.CompiledPolicy) []string {
	out := make([]string, 0, len(policies))
	for _, p := range policies {
		out = append(out, p.Metadata.Name)
	}
	return out
}

func stringMap(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	return out
}

func workloadName(obj map[string]any) string {
	if meta, ok := obj["metadata"].(map[string]any); ok {
		if name, ok := meta["name"].(string); ok {
			return name
		}
		if gen, ok := meta["generateName"].(string); ok {
			return gen + "*"
		}
	}
	return ""
}
