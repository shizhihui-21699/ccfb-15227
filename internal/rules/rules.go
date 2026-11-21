// Package rules implements the individual security checks. Each rule inspects
// one pod spec and returns findings; rules that support remediation mutate the
// JSON object in place and return a JSON Patch describing the change.
package rules

import (
	"strings"

	"github.com/example/cluster-admission-guard/internal/policy"
	"github.com/example/cluster-admission-guard/internal/workload"
)

// Result is what one rule produced for one pod spec.
//
// Remediation rules mutate the submitted JSON in place. The engine snapshots
// the original object and derives the RFC 6902 patch by diffing before/after,
// which keeps patches exact (including array indices and nested creations)
// without hand-built JSON pointers.
type Result struct {
	Findings []policy.Finding
	// Remediated counts successful rewrites for operator-facing messages.
	Remediated int
}

// Context carries request-level information rules may need.
type Context struct {
	Namespace  string
	Teams      []string
	Kind       string
	Workload   string
	Operation  string // CREATE or UPDATE
	TrustStore *policy.TrustStore
}

// Rule is one security check.
type Rule interface {
	ID() string
	// Evaluate checks one pod spec. mutate controls whether a remediation rule
	// is allowed to rewrite the object.
	Evaluate(ctx *Context, spec *workload.PodSpec, cfg map[string]any, mutate bool) Result
}

// Merge combines results.
func Merge(dst *Result, src Result) {
	dst.Findings = append(dst.Findings, src.Findings...)
	dst.Remediated += src.Remediated
}

// Registry maps rule IDs to implementations.
var Registry = map[string]Rule{
	policy.RulePrivileged:              privilegedRule{},
	policy.RulePrivilegeEscalation:     allowPrivilegeEscalationRule{},
	policy.RuleCapabilities:            capabilitiesRule{},
	policy.RuleSeccompProfile:          seccompRule{},
	policy.RuleRunAsNonRoot:            runAsNonRootRule{},
	policy.RuleReadOnlyRootFilesystem:  readOnlyRootFSRule{},
	policy.RuleHostPath:                hostPathRule{},
	policy.RuleHostNamespaces:          hostNamespaceRule{},
	policy.RuleHostUsers:               hostUsersRule{},
	policy.RuleHostPorts:               hostPortRule{},
	policy.RuleVolumeTypes:             volumeTypesRule{},
	policy.RuleImageProvenance:         imageProvenanceRule{},
	policy.RuleImageDigestOrPullAlways: imagePinRule{},
	policy.RuleServiceAccountToken:     saTokenRule{},
	policy.RuleUnsafeSysctls:           unsafeSysctlsRule{},
	policy.RuleEphemeralContainers:     ephemeralContainersRule{},
	policy.RuleProcMount:               procMountRule{},
	policy.RuleHostProcess:             hostProcessRule{},
	policy.RuleShareProcessNamespace:   shareProcessNamespaceRule{},
}

// Get returns a rule implementation, or nil.
func Get(id string) Rule { return Registry[id] }

// --- helpers ---------------------------------------------------------------------

// containerContext returns the container's securityContext map and the pod
// spec's securityContext map for fallback lookups.
func containerContext(c *workload.Container) map[string]any {
	return workload.GetMap(c.Obj, "securityContext")
}

func podContext(spec *workload.PodSpec) map[string]any {
	return workload.GetMap(spec.Obj, "securityContext")
}

// lookupBool resolves a securityContext boolean, falling back to the pod-level
// securityContext when the container does not set it (mirrors kubelet
// semantics for allowPrivilegeEscalation, runAsNonRoot and seccompProfile).
func lookupBool(c *workload.Container, spec *workload.PodSpec, key string) (value bool, set bool) {
	if v, ok := workload.GetBool(containerContext(c), key); ok {
		return v, true
	}
	if v, ok := workload.GetBool(podContext(spec), key); ok {
		return v, true
	}
	return false, false
}

func finding(rule, severity string, action policy.Action, path, container, msg string) policy.Finding {
	return policy.Finding{
		Rule:      rule,
		Severity:  policy.Severity(severity),
		Action:    action,
		Path:      path,
		Container: container,
		Message:   msg,
	}
}

func deny(rule, sev string, path, container, msg string) policy.Finding {
	return finding(rule, sev, policy.ActionDeny, path, container, msg)
}

func remediated(rule, sev string, path, container, msg, fix string) policy.Finding {
	f := finding(rule, sev, policy.ActionRemediate, path, container, msg)
	f.Fix = fix
	return f
}

func cfgStrings(cfg map[string]any, key string) []string {
	raw, ok := cfg[key]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func cfgInts(cfg map[string]any, key string) []int64 {
	raw, ok := cfg[key]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []int:
		out := make([]int64, 0, len(v))
		for _, n := range v {
			out = append(out, int64(n))
		}
		return out
	case []any:
		out := make([]int64, 0, len(v))
		for _, item := range v {
			switch n := item.(type) {
			case int:
				out = append(out, int64(n))
			case int64:
				out = append(out, n)
			case float64:
				out = append(out, int64(n))
			}
		}
		return out
	}
	return nil
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func fmtList(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ", ")
}
