package policy

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/yaml"
)

// Rule IDs understood by the engine. Keeping them in one place lets policy
// validation reject typos instead of silently disabling protection.
const (
	RulePrivileged              = "pod.privileged"
	RulePrivilegeEscalation     = "pod.allowPrivilegeEscalation"
	RuleCapabilities            = "pod.capabilities"
	RuleSeccompProfile          = "pod.seccompProfile"
	RuleRunAsNonRoot            = "pod.runAsNonRoot"
	RuleReadOnlyRootFilesystem  = "pod.readOnlyRootFilesystem"
	RuleHostPath                = "pod.hostPathVolumes"
	RuleHostNamespaces          = "pod.hostNamespaces"
	RuleHostPorts               = "pod.hostPorts"
	RuleHostUsers               = "pod.hostUsers"
	RuleVolumeTypes             = "pod.volumeTypes"
	RuleImageProvenance         = "image.provenance"
	RuleImageDigestOrPullAlways = "image.digestOrPullAlways"
	RuleServiceAccountToken     = "pod.serviceAccountToken"
	RuleUnsafeSysctls           = "pod.unsafeSysctls"
	RuleEphemeralContainers     = "pod.ephemeralContainers"
	RuleUnknownWorkload         = "object.unknownWorkload"
	RuleMalformedWorkload       = "object.malformedWorkload"
	RuleProcMount               = "pod.procMount"
	RuleHostProcess             = "pod.hostProcess"
	RuleShareProcessNamespace   = "pod.shareProcessNamespace"
)

var knownRules = map[string]bool{
	RulePrivileged:              true,
	RulePrivilegeEscalation:     true,
	RuleCapabilities:            true,
	RuleSeccompProfile:          true,
	RuleRunAsNonRoot:            true,
	RuleReadOnlyRootFilesystem:  true,
	RuleHostPath:                true,
	RuleHostNamespaces:          true,
	RuleHostPorts:               true,
	RuleHostUsers:               true,
	RuleVolumeTypes:             true,
	RuleImageProvenance:         true,
	RuleImageDigestOrPullAlways: true,
	RuleServiceAccountToken:     true,
	RuleUnsafeSysctls:           true,
	RuleEphemeralContainers:     true,
	RuleUnknownWorkload:         true,
	RuleMalformedWorkload:       true,
	RuleProcMount:               true,
	RuleHostProcess:             true,
	RuleShareProcessNamespace:   true,
}

// KnownRule reports whether id is a built-in rule.
func KnownRule(id string) bool { return knownRules[id] }

// DefaultMaxExemptionDuration is the cap applied when a policy does not set one.
const DefaultMaxExemptionDuration = 30 * 24 * time.Hour

// CompiledPolicy is a validated policy with pre-computed selectors.
type CompiledPolicy struct {
	Policy
	Mode         Mode
	FailureMode  FailureMode
	TeamLabel    string
	MaxExemption time.Duration
	selector     *metav1.LabelSelector
	ruleSpecs    map[string]RuleSpec
	ruleOrder    []string
	accepted     map[string]bool
}

// Compile validates a policy document and returns the compiled form.
// Policies are rejected whole: a partially valid policy must never be applied.
func Compile(p Policy) (*CompiledPolicy, error) {
	errs := &CompileError{}
	if p.APIVersion != APIVersion {
		errs.Add("apiVersion must be %q, got %q", APIVersion, p.APIVersion)
	}
	if p.Kind != KindPolicy {
		errs.Add("kind must be %q, got %q", KindPolicy, p.Kind)
	}
	if p.Metadata.Name == "" {
		errs.Add("metadata.name is required")
	}
	if p.Spec.FailureMode != "" && p.Spec.FailureMode != FailureClosed && p.Spec.FailureMode != FailureOpen {
		errs.Add("spec.failureMode must be %q or %q", FailureClosed, FailureOpen)
	}
	if p.Spec.Mode != "" && p.Spec.Mode != ModeEnforce && p.Spec.Mode != ModeAudit {
		errs.Add("spec.mode must be %q or %q", ModeEnforce, ModeAudit)
	}
	if len(p.Spec.Rules) == 0 {
		errs.Add("spec.rules must contain at least one rule")
	}
	maxEx := DefaultMaxExemptionDuration
	if p.Spec.MaxExemptionDuration != "" {
		d, err := time.ParseDuration(p.Spec.MaxExemptionDuration)
		if err != nil || d <= 0 {
			errs.Add("spec.maxExemptionDuration must be a positive duration, got %q", p.Spec.MaxExemptionDuration)
		} else {
			maxEx = d
		}
	}

	seenRules := map[string]bool{}
	order := make([]string, 0, len(p.Spec.Rules))
	specs := make(map[string]RuleSpec, len(p.Spec.Rules))
	for i, r := range p.Spec.Rules {
		prefix := fmt.Sprintf("spec.rules[%d]", i)
		if !KnownRule(r.ID) {
			errs.Add("%s: unknown rule %q", prefix, r.ID)
			continue
		}
		if seenRules[r.ID] {
			errs.Add("%s: rule %q listed more than once", prefix, r.ID)
			continue
		}
		seenRules[r.ID] = true
		if r.Action != "" && !r.Action.Valid() {
			errs.Add("%s: invalid action %q", prefix, r.Action)
		}
		if r.Severity != "" && !r.Severity.Valid() {
			errs.Add("%s: invalid severity %q", prefix, r.Severity)
		}
		if r.Action == ActionRemediate && !Remediable(r.ID) {
			errs.Add("%s: rule %q does not support action %q", prefix, r.ID, ActionRemediate)
		}
		if cfgErr := validateRuleConfig(r); cfgErr != nil {
			errs.Add("%s: %v", prefix, cfgErr)
		}
		specs[r.ID] = r
		order = append(order, r.ID)
	}

	seenEx := map[string]bool{}
	for i, ex := range p.Spec.Exemptions {
		prefix := fmt.Sprintf("spec.exemptions[%d]", i)
		if ex.ID == "" {
			errs.Add("%s: id is required", prefix)
		} else if seenEx[ex.ID] {
			errs.Add("%s: duplicate exemption id %q", prefix, ex.ID)
		}
		seenEx[ex.ID] = true
		if strings.TrimSpace(ex.Reason) == "" {
			errs.Add("%s: reason is required (this is the audit trail)", prefix)
		}
		if strings.TrimSpace(ex.RequestedBy) == "" {
			errs.Add("%s: requestedBy is required", prefix)
		}
		if ex.ExpiresAt == "" {
			errs.Add("%s: expiresAt is required (exemptions are always time-limited)", prefix)
		} else if t, err := time.Parse(time.RFC3339, ex.ExpiresAt); err != nil {
			errs.Add("%s: expiresAt must be RFC3339, got %q", prefix, ex.ExpiresAt)
		} else if time.Since(t) > 0 {
			// Expired exemptions are allowed to remain in the file (they are
			// simply ignored) but are reported so the file stays tidy.
			errs.Add("%s: exemption %q already expired at %s; remove it", prefix, ex.ID, ex.ExpiresAt)
		}
		if ex.NotBefore != "" {
			t, err := time.Parse(time.RFC3339, ex.NotBefore)
			if err != nil {
				errs.Add("%s: notBefore must be RFC3339", prefix)
			} else if ex.ExpiresAt != "" {
				if end, err := time.Parse(time.RFC3339, ex.ExpiresAt); err == nil && !end.After(t) {
					errs.Add("%s: expiresAt must be after notBefore", prefix)
				}
			}
		}
		if len(ex.Scope.Rules) == 0 {
			errs.Add("%s: scope.rules must name the exempted rules (use \"*\" to exempt all)", prefix)
		}
		for _, ruleID := range ex.Scope.Rules {
			if ruleID != "*" && !KnownRule(ruleID) {
				errs.Add("%s: unknown rule %q in scope.rules", prefix, ruleID)
			}
		}
		if ex.ExpiresAt != "" {
			if end, err := time.Parse(time.RFC3339, ex.ExpiresAt); err == nil {
				if end.Sub(time.Now()) > maxEx {
					errs.Add("%s: exemption %q exceeds maxExemptionDuration %s", prefix, ex.ID, maxEx)
				}
			}
		}
		if ex.Scope.Teams == nil && ex.Scope.Namespaces == nil && ex.Scope.Workloads == nil && ex.Scope.Kinds == nil {
			errs.Add("%s: exemption must be scoped by at least one of namespaces, teams, workloads or kinds", prefix)
		}
	}

	if len(errs.Problems) > 0 {
		sort.Strings(errs.Problems)
		return nil, errs
	}

	accepted := make(map[string]bool, len(p.Spec.AcceptExemptions))
	for _, id := range p.Spec.AcceptExemptions {
		if strings.TrimSpace(id) == "" {
			errs.Add("spec.acceptExemptions contains an empty id")
			continue
		}
		accepted[id] = true
	}
	if len(errs.Problems) > 0 {
		sort.Strings(errs.Problems)
		return nil, errs
	}

	cp := &CompiledPolicy{
		Policy:       p,
		Mode:         p.Spec.Mode,
		FailureMode:  p.Spec.FailureMode,
		TeamLabel:    p.Spec.TeamLabel,
		MaxExemption: maxEx,
		selector:     p.Spec.Scope.NamespaceSelector,
		ruleSpecs:    specs,
		ruleOrder:    order,
		accepted:     accepted,
	}
	if cp.Mode == "" {
		cp.Mode = ModeEnforce
	}
	if cp.FailureMode == "" {
		cp.FailureMode = FailureClosed
	}
	if cp.TeamLabel == "" {
		cp.TeamLabel = DefaultTeamLabel
	}
	return cp, nil
}

// Remediable reports whether a rule can safely rewrite an object.
func Remediable(rule string) bool {
	switch rule {
	case RulePrivileged, RulePrivilegeEscalation, RuleCapabilities,
		RuleSeccompProfile, RuleRunAsNonRoot, RuleReadOnlyRootFilesystem,
		RuleHostNamespaces, RuleHostPorts, RuleHostUsers,
		RuleImageDigestOrPullAlways, RuleServiceAccountToken,
		RuleProcMount, RuleHostProcess, RuleShareProcessNamespace:
		return true
	}
	return false
}

func validateRuleConfig(r RuleSpec) error {
	switch r.ID {
	case RuleCapabilities:
		if raw, ok := r.Config["allowed"]; ok {
			if _, ok := toStringSlice(raw); !ok {
				return fmt.Errorf("config.allowed must be a list of capability names")
			}
		}
	case RuleHostPath:
		if raw, ok := r.Config["allowedPaths"]; ok {
			if _, ok := toStringSlice(raw); !ok {
				return fmt.Errorf("config.allowedPaths must be a list of path prefixes")
			}
		}
	case RuleHostPorts:
		if raw, ok := r.Config["allowedPorts"]; ok {
			if _, ok := toIntSlice(raw); !ok {
				return fmt.Errorf("config.allowedPorts must be a list of integers")
			}
		}
	case RuleVolumeTypes:
		if raw, ok := r.Config["allowed"]; ok {
			if _, ok := toStringSlice(raw); !ok {
				return fmt.Errorf("config.allowed must be a list of volume types")
			}
		}
	case RuleImageProvenance:
		if raw, ok := r.Config["allowedRegistries"]; ok {
			if _, ok := toStringSlice(raw); !ok {
				return fmt.Errorf("config.allowedRegistries must be a list of registry prefixes")
			}
		}
	}
	return nil
}

func toStringSlice(v any) ([]string, bool) {
	switch t := v.(type) {
	case []string:
		return t, true
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

func toIntSlice(v any) ([]int64, bool) {
	switch t := v.(type) {
	case []any:
		out := make([]int64, 0, len(t))
		for _, item := range t {
			switch n := item.(type) {
			case int64:
				out = append(out, n)
			case int:
				out = append(out, int64(n))
			case float64:
				out = append(out, int64(n))
			default:
				return nil, false
			}
		}
		return out, true
	case []int:
		out := make([]int64, 0, len(t))
		for _, n := range t {
			out = append(out, int64(n))
		}
		return out, true
	}
	return nil, false
}

// RuleConfig resolves the effective action/severity for a rule.
func (cp *CompiledPolicy) RuleConfig(id string) (RuleSpec, bool) {
	r, ok := cp.ruleSpecs[id]
	return r, ok
}

// AppliesTo reports whether the policy covers a namespace/team combination.
// Teams are read from the policy's own teamLabel, so different policy bundles
// can use different label conventions.
func (cp *CompiledPolicy) AppliesTo(ns NamespaceInfo) bool {
	scope := cp.Spec.Scope
	teams := ns.Teams(cp.TeamLabel)
	if matchesAny(scope.ExcludeNamespaces, ns.Name) || anyTeamMatches(scope.ExcludeTeams, teams) {
		return false
	}
	if len(scope.Namespaces) > 0 && !matchesAny(scope.Namespaces, ns.Name) {
		return false
	}
	if len(scope.Teams) > 0 && !anyTeamMatches(scope.Teams, teams) {
		return false
	}
	if cp.selector != nil {
		sel, err := metav1.LabelSelectorAsSelector(cp.selector)
		if err != nil || !sel.Matches(labels.Set(ns.Labels)) {
			return false
		}
	}
	return true
}

// EffectiveExemption returns the first active exemption matching the request.
// Expired and not-yet-active exemptions are ignored; wildcards are supported in
// namespaces, workloads and rules, and "*" as a rule selector.
func (cp *CompiledPolicy) EffectiveExemption(ns NamespaceInfo, kind, workload string, ruleID string, now time.Time) (*Exemption, bool) {
	for i := range cp.Spec.Exemptions {
		ex := &cp.Spec.Exemptions[i]
		if !exemptionWindowActive(ex, now) {
			continue
		}
		if !exemptionMatches(*ex, ns, cp.TeamLabel, kind, workload, ruleID) {
			continue
		}
		return ex, true
	}
	return nil, false
}

// AcceptsExemption reports whether this policy honours the given exemption ID
// either because it declares it or because spec.acceptExemptions names it.
func (cp *CompiledPolicy) AcceptsExemption(id string) bool {
	if cp.accepted[id] {
		return true
	}
	for i := range cp.Spec.Exemptions {
		if cp.Spec.Exemptions[i].ID == id {
			return true
		}
	}
	return false
}

// ExemptionByID returns the policy's own exemption with the given id.
func (cp *CompiledPolicy) ExemptionByID(id string) (*Exemption, bool) {
	for i := range cp.Spec.Exemptions {
		if cp.Spec.Exemptions[i].ID == id {
			return &cp.Spec.Exemptions[i], true
		}
	}
	return nil, false
}

func exemptionWindowActive(ex *Exemption, now time.Time) bool {
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

// ScopeMatches reports whether an exemption's non-rule selectors (namespace,
// team, workload, kind) match the request. Rule selectors are matched per
// finding by RuleMatches.
func (cp *CompiledPolicy) ScopeMatches(ex *Exemption, ns NamespaceInfo, kind, workload string) bool {
	if len(ex.Scope.Namespaces) > 0 && !matchesAny(ex.Scope.Namespaces, ns.Name) {
		return false
	}
	if len(ex.Scope.Teams) > 0 && !anyTeamMatches(ex.Scope.Teams, ns.Teams(cp.TeamLabel)) {
		return false
	}
	if len(ex.Scope.Workloads) > 0 && !matchesAny(ex.Scope.Workloads, workload) {
		return false
	}
	if len(ex.Scope.Kinds) > 0 && !matchesAny(ex.Scope.Kinds, kind) {
		return false
	}
	return true
}

// RuleMatches reports whether the exemption covers the given rule ID.
func RuleMatches(ex *Exemption, ruleID string) bool {
	return scopeListMatches(ex.Scope.Rules, ruleID)
}

func exemptionMatches(ex Exemption, ns NamespaceInfo, teamLabel, kind, workload, ruleID string) bool {
	if !scopeListMatches(ex.Scope.Rules, ruleID) {
		return false
	}
	// At least one selector dimension must be explicit; any explicit dimension
	// that does not match makes the exemption inapplicable.
	if len(ex.Scope.Namespaces) > 0 && !matchesAny(ex.Scope.Namespaces, ns.Name) {
		return false
	}
	if len(ex.Scope.Teams) > 0 && !anyTeamMatches(ex.Scope.Teams, ns.Teams(teamLabel)) {
		return false
	}
	if len(ex.Scope.Workloads) > 0 && !matchesAny(ex.Scope.Workloads, workload) {
		return false
	}
	if len(ex.Scope.Kinds) > 0 && !matchesAny(ex.Scope.Kinds, kind) {
		return false
	}
	return true
}

func scopeListMatches(patterns []string, value string) bool {
	for _, p := range patterns {
		if p == "*" || p == value {
			return true
		}
		if strings.Contains(p, "*") {
			if ok, err := path.Match(p, value); err == nil && ok {
				return true
			}
		}
	}
	return false
}

func matchesAny(patterns []string, value string) bool {
	return scopeListMatches(patterns, value)
}

func anyTeamMatches(patterns, teams []string) bool {
	for _, team := range teams {
		if matchesAny(patterns, team) {
			return true
		}
	}
	return false
}

// NamespaceInfo is the policy-relevant view of a namespace.
type NamespaceInfo struct {
	Name        string
	Labels      map[string]string
	Enforcement string
}

// Teams returns the teams that own the namespace under the given label key.
func (n NamespaceInfo) Teams(labelKey string) []string {
	return TeamLabelValue(n.Labels, labelKey)
}

// TeamLabelValue splits a comma-separated team label.
func TeamLabelValue(labels map[string]string, key string) []string {
	raw := strings.TrimSpace(labels[key])
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// EnforcementOf reads the enforcement label, defaulting to standard.
func EnforcementOf(labels map[string]string) string {
	switch strings.ToLower(strings.TrimSpace(labels[EnforcementLabel])) {
	case EnforcementStrict:
		return EnforcementStrict
	case EnforcementDisabled:
		return EnforcementDisabled
	default:
		return EnforcementStandard
	}
}

// ParsePolicy decodes and compiles one YAML document.
func ParsePolicy(data []byte) (*CompiledPolicy, error) {
	var p Policy
	if err := yaml.UnmarshalStrict(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	return Compile(p)
}

// ParseTrustStore decodes a TrustStore document.
func ParseTrustStore(data []byte) (*TrustStore, error) {
	var ts TrustStore
	if err := yaml.UnmarshalStrict(data, &ts); err != nil {
		return nil, fmt.Errorf("parse trust store: %w", err)
	}
	if ts.APIVersion != APIVersion || ts.Kind != KindTrustStore {
		return nil, fmt.Errorf("trust store must be %s/%s", APIVersion, KindTrustStore)
	}
	seen := map[string]bool{}
	for i, sig := range ts.Spec.Signatures {
		if strings.TrimSpace(sig.Image) == "" {
			return nil, fmt.Errorf("trust store signatures[%d].image is required", i)
		}
		if strings.TrimSpace(sig.Signer) == "" {
			return nil, fmt.Errorf("trust store signatures[%d].signer is required", i)
		}
		if sig.ExpiresAt != "" {
			if _, err := time.Parse(time.RFC3339, sig.ExpiresAt); err != nil {
				return nil, fmt.Errorf("trust store signatures[%d].expiresAt must be RFC3339", i)
			}
		}
		if seen[sig.Image] {
			return nil, fmt.Errorf("trust store lists image %q more than once", sig.Image)
		}
		seen[sig.Image] = true
	}
	return &ts, nil
}
