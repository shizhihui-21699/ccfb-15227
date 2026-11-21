package policy

import (
	"strings"
	"testing"
	"time"
)

// at returns an RFC3339 timestamp offset from now, so exemption tests do not
// break as wall-clock time advances.
func at(d time.Duration) string { return time.Now().Add(d).UTC().Format(time.RFC3339) }

func basePolicy(yamlText string) *CompiledPolicy {
	p, err := ParsePolicy([]byte(yamlText))
	if err != nil {
		panic(err)
	}
	return p
}

const minimal = `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec:
  rules:
    - id: pod.privileged
`

func TestCompileDefaults(t *testing.T) {
	p := basePolicy(minimal)
	if p.Mode != ModeEnforce {
		t.Errorf("mode = %q, want enforce", p.Mode)
	}
	if p.FailureMode != FailureClosed {
		t.Errorf("failureMode = %q, want closed", p.FailureMode)
	}
	if p.TeamLabel != DefaultTeamLabel {
		t.Errorf("teamLabel = %q", p.TeamLabel)
	}
	if p.MaxExemption != DefaultMaxExemptionDuration {
		t.Errorf("maxExemption = %v", p.MaxExemption)
	}
}

func TestCompileRejectsBadPolicies(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"wrong apiVersion", strings.Replace(minimal, APIJSONVersion(), "v1", 1), "apiVersion"},
		{"unknown rule", strings.Replace(minimal, "pod.privileged", "pod.magic", 1), "unknown rule"},
		{"empty rules", `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec: {rules: []}`, "at least one rule"},
		{"duplicate rule", `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec:
  rules:
    - id: pod.privileged
    - id: pod.privileged`, "more than once"},
		{"remediate unsupported", `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec:
  rules:
    - id: pod.ephemeralContainers
      action: remediate`, "does not support"},
		{"invalid action", `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec:
  rules:
    - id: pod.privileged
      action: ignore`, "invalid action"},
		{"exemption without expiry", `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec:
  rules: [{id: pod.privileged}]
  exemptions:
    - id: e1
      reason: r
      requestedBy: u
      scope: {namespaces: [a], rules: ["*"]}`, "expiresAt is required"},
		{"exemption without reason", `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec:
  rules: [{id: pod.privileged}]
  exemptions:
    - id: e1
      requestedBy: u
      expiresAt: "2099-01-01T00:00:00Z"
      scope: {namespaces: [a], rules: ["*"]}`, "reason is required"},
		{"exemption without rules", `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec:
  rules: [{id: pod.privileged}]
  exemptions:
    - id: e1
      reason: r
      requestedBy: u
      expiresAt: "2099-01-01T00:00:00Z"
      scope: {namespaces: [a]}`, "scope.rules"},
		{"exemption too long", `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec:
  maxExemptionDuration: 24h
  rules: [{id: pod.privileged}]
  exemptions:
    - id: e1
      reason: r
      requestedBy: u
      expiresAt: "2099-01-01T00:00:00Z"
      scope: {namespaces: [a], rules: ["*"]}`, "exceeds maxExemptionDuration"},
		{"expired exemption", `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec:
  rules: [{id: pod.privileged}]
  exemptions:
    - id: e1
      reason: r
      requestedBy: u
      expiresAt: "2020-01-01T00:00:00Z"
      scope: {namespaces: [a], rules: ["*"]}`, "already expired"},
		{"unknown accepted exemption rule", `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec:
  rules: [{id: pod.privileged}]
  exemptions:
    - id: e1
      reason: r
      requestedBy: u
      expiresAt: "2099-01-01T00:00:00Z"
      scope: {namespaces: [a], rules: [pod.nope]}`, "unknown rule"},
		{"bad config type", `
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec:
  rules:
    - id: pod.privileged
    - id: pod.hostPorts
      config: {allowedPorts: "8080"}`, "allowedPorts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePolicy([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// APIJSONVersion lets tests construct the apiVersion string without duplicating
// the literal.
func APIJSONVersion() string { return APIVersion }

func TestCompileStrictYAML(t *testing.T) {
	// Unknown fields are rejected so a typo like "exemptionss" cannot silently
	// disable an exemption or a rule option.
	bad := strings.Replace(minimal, "rules:", "ruls:", 1)
	if _, err := ParsePolicy([]byte(bad)); err == nil {
		t.Fatal("unknown field must be rejected")
	}
}

func ns(name string, labels map[string]string) NamespaceInfo {
	return NamespaceInfo{Name: name, Labels: labels, Enforcement: EnforcementOf(labels)}
}

func TestScopeMatching(t *testing.T) {
	p := basePolicy(`
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec:
  scope:
    teams: [payments, "web-*"]
    excludeNamespaces: [payments-sandbox]
  rules: [{id: pod.privileged}]
`)
	cases := []struct {
		ns   NamespaceInfo
		want bool
	}{
		{ns("a", map[string]string{DefaultTeamLabel: "payments"}), true},
		{ns("a", map[string]string{DefaultTeamLabel: "web-frontend"}), true},
		{ns("payments-sandbox", map[string]string{DefaultTeamLabel: "payments"}), false},
		{ns("a", map[string]string{DefaultTeamLabel: "analytics"}), false},
		{ns("a", nil), false},
	}
	for _, tc := range cases {
		if got := p.AppliesTo(tc.ns); got != tc.want {
			t.Errorf("AppliesTo(%s %v) = %v, want %v", tc.ns.Name, tc.ns.Labels, got, tc.want)
		}
	}
}

func TestScopeNamespaceSelector(t *testing.T) {
	p := basePolicy(`
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec:
  scope:
    namespaceSelector:
      matchLabels: {tier: prod}
  rules: [{id: pod.privileged}]
`)
	if !p.AppliesTo(ns("a", map[string]string{"tier": "prod"})) {
		t.Error("prod namespace should match")
	}
	if p.AppliesTo(ns("a", map[string]string{"tier": "dev"})) {
		t.Error("dev namespace should not match")
	}
}

func TestExemptionExpiry(t *testing.T) {
	p := basePolicy(`
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec:
  maxExemptionDuration: 2400h
  rules: [{id: pod.privileged}, {id: pod.hostNamespaces}]
  exemptions:
    - id: e1
      reason: r
      requestedBy: u
      expiresAt: "` + at(30*24*time.Hour) + `"
      scope: {namespaces: [ci], rules: [pod.privileged]}
`)
	ci := ns("ci", nil)
	before := time.Now().Add(24 * time.Hour)
	after := time.Now().Add(31 * 24 * time.Hour)

	if ex, ok := p.EffectiveExemption(ci, "Pod", "job", RulePrivileged, before); !ok || ex.ID != "e1" {
		t.Fatalf("expected exemption before expiry, got %v %v", ex, ok)
	}
	if _, ok := p.EffectiveExemption(ci, "Pod", "job", RulePrivileged, after); ok {
		t.Fatal("exemption must not apply at/after expiry")
	}
	// Rule selector must be respected.
	if _, ok := p.EffectiveExemption(ci, "Pod", "job", RuleHostNamespaces, before); ok {
		t.Fatal("exemption must not cover an unlisted rule")
	}
	// Namespace selector must be respected.
	if _, ok := p.EffectiveExemption(ns("other", nil), "Pod", "job", RulePrivileged, before); ok {
		t.Fatal("exemption must not apply to another namespace")
	}
}

func TestExemptionNotBefore(t *testing.T) {
	p := basePolicy(`
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec:
  maxExemptionDuration: 2400h
  rules: [{id: pod.privileged}]
  exemptions:
    - id: e1
      reason: r
      requestedBy: u
      notBefore: "` + at(20*24*time.Hour) + `"
      expiresAt: "` + at(40*24*time.Hour) + `"
      scope: {namespaces: [ci], rules: ["*"]}
`)
	ci := ns("ci", nil)
	feb := time.Now().Add(10 * 24 * time.Hour)
	mar := time.Now().Add(30 * 24 * time.Hour)
	if _, ok := p.EffectiveExemption(ci, "Pod", "job", RulePrivileged, feb); ok {
		t.Fatal("exemption must not apply before notBefore")
	}
	if _, ok := p.EffectiveExemption(ci, "Pod", "job", RulePrivileged, mar); !ok {
		t.Fatal("exemption should apply inside the window")
	}
}

func TestAcceptExemptionsOptIn(t *testing.T) {
	owner := basePolicy(`
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: owner}
spec:
  rules: [{id: pod.privileged}]
  exemptions:
    - id: team-ex
      reason: r
      requestedBy: u
      expiresAt: "` + at(24*time.Hour) + `"
      scope: {namespaces: [a], rules: ["*"]}
`)
	if !owner.AcceptsExemption("team-ex") {
		t.Fatal("a policy must accept its own exemptions")
	}
	consumer := basePolicy(`
apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: consumer}
spec:
  acceptExemptions: [team-ex]
  rules: [{id: pod.hostNamespaces}]
`)
	if !consumer.AcceptsExemption("team-ex") {
		t.Fatal("acceptExemptions must be honoured")
	}
	unrelated := basePolicy(minimal)
	if unrelated.AcceptsExemption("team-ex") {
		t.Fatal("policies must not accept unlisted exemptions")
	}
}

func TestTrustStoreValidation(t *testing.T) {
	good := `
apiVersion: guard.example.com/v1alpha1
kind: TrustStore
metadata: {name: t}
spec:
  signatures:
    - image: registry.example.com/a@sha256:1111111111111111111111111111111111111111111111111111111111111111
      signer: release
`
	if _, err := ParseTrustStore([]byte(good)); err != nil {
		t.Fatalf("valid trust store rejected: %v", err)
	}
	dup := strings.Replace(good, "      signer: release", "      signer: release\n    - image: registry.example.com/a@sha256:1111111111111111111111111111111111111111111111111111111111111111\n      signer: other", 1)
	if _, err := ParseTrustStore([]byte(dup)); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("duplicate image should be rejected, got %v", err)
	}
}
