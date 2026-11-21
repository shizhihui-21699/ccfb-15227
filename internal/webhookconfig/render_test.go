package webhookconfig_test

import (
	"strings"
	"testing"

	"github.com/example/cluster-admission-guard/internal/policy"
	"github.com/example/cluster-admission-guard/internal/webhookconfig"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

func render(t *testing.T, mode string) *admissionregistrationv1.ValidatingWebhookConfiguration {
	t.Helper()
	cfg, err := webhookconfig.Render(webhookconfig.Options{
		Service:           &webhookconfig.ServiceRef{Namespace: "guard", Name: "admission-guard"},
		FailurePolicyMode: mode,
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return cfg
}

func TestSplitModeIsTheDefaultAndSplitsByEnforcement(t *testing.T) {
	cfg := render(t, "")
	if len(cfg.Webhooks) != 2 {
		t.Fatalf("expected 2 webhooks, got %d", len(cfg.Webhooks))
	}
	var strict, def *admissionregistrationv1.ValidatingWebhook
	for i := range cfg.Webhooks {
		switch cfg.Webhooks[i].Name {
		case "guard.example.com.strict":
			strict = &cfg.Webhooks[i]
		case "guard.example.com.default":
			def = &cfg.Webhooks[i]
		}
	}
	if strict == nil || def == nil {
		t.Fatalf("unexpected webhook names: %v", names(cfg))
	}
	if strict.FailurePolicy == nil || *strict.FailurePolicy != admissionregistrationv1.Fail {
		t.Fatal("strict webhook must use failurePolicy=Fail (availability must not weaken safety)")
	}
	if def.FailurePolicy == nil || *def.FailurePolicy != admissionregistrationv1.Ignore {
		t.Fatal("default webhook must use failurePolicy=Ignore (webhook outage must not block deployments)")
	}
	// The strict selector targets exactly the strict label.
	if !selectorContains(strict.NamespaceSelector, policy.EnforcementLabel, policy.EnforcementStrict) {
		t.Fatalf("strict selector wrong: %+v", strict.NamespaceSelector)
	}
	// The default selector excludes strict and disabled namespaces.
	if !selectorExcludes(defaultSelectorKeys(def), policy.EnforcementStrict) {
		t.Fatalf("default selector must exclude strict namespaces: %+v", def.NamespaceSelector)
	}
	if !selectorExcludes(defaultSelectorKeys(def), policy.EnforcementDisabled) {
		t.Fatalf("default selector must exclude disabled namespaces: %+v", def.NamespaceSelector)
	}
}

func TestFailClosedModeIsSingleWebhook(t *testing.T) {
	cfg := render(t, "fail-closed")
	if len(cfg.Webhooks) != 1 {
		t.Fatalf("expected 1 webhook, got %d", len(cfg.Webhooks))
	}
	wh := cfg.Webhooks[0]
	if *wh.FailurePolicy != admissionregistrationv1.Fail {
		t.Fatal("fail-closed must use Fail")
	}
	if !selectorExcludes(wh.NamespaceSelector, policy.EnforcementDisabled) {
		t.Fatal("disabled namespaces must stay excluded")
	}
}

func TestRulesCoverIndirectCreationPaths(t *testing.T) {
	cfg := render(t, "")
	resources := map[string]bool{}
	for _, wh := range cfg.Webhooks {
		for _, r := range wh.Rules {
			for _, res := range r.Resources {
				resources[res] = true
			}
			for _, op := range r.Operations {
				if op != admissionregistrationv1.Create && op != admissionregistrationv1.Update {
					t.Fatalf("unexpected operation %s", op)
				}
			}
			if len(r.APIVersions) != 1 || r.APIVersions[0] != "*" {
				t.Fatalf("should watch all versions, got %v", r.APIVersions)
			}
		}
	}
	for _, need := range []string{"pods", "podtemplates", "deployments", "statefulsets", "daemonsets", "replicasets", "replicationcontrollers", "jobs", "cronjobs", "rollouts"} {
		if !resources[need] {
			t.Errorf("resource %q not intercepted; workloads could be created around the guard", need)
		}
	}
}

func TestNamespacesAreInterceptedForOptOut(t *testing.T) {
	cfg := render(t, "")
	found := false
	for _, wh := range cfg.Webhooks {
		for _, r := range wh.Rules {
			for _, res := range r.Resources {
				if res == "namespaces" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("namespaces must be intercepted so enforcement cannot be disabled by relabelling")
	}
}

func TestRenderYAMLWarnsAboutTheSplit(t *testing.T) {
	data, err := webhookconfig.RenderYAML(webhookconfig.Options{
		Service: &webhookconfig.ServiceRef{Namespace: "guard", Name: "admission-guard"},
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "failurePolicy=Fail") || !strings.Contains(text, "failurePolicy=Ignore") {
		t.Fatalf("rendered YAML should document the split:\n%s", text)
	}
	var cfg admissionregistrationv1.ValidatingWebhookConfiguration
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("rendered YAML is invalid: %v", err)
	}
	if len(cfg.Webhooks) != 2 {
		t.Fatalf("expected 2 webhooks, got %d", len(cfg.Webhooks))
	}
}

func TestRequiresServiceOrURL(t *testing.T) {
	if _, err := webhookconfig.Render(webhookconfig.Options{}); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := webhookconfig.Render(webhookconfig.Options{
		Service: &webhookconfig.ServiceRef{Name: "a", Namespace: "b"},
		URL:     "https://x",
	}); err == nil {
		t.Fatal("Service and URL are mutually exclusive")
	}
}

func TestUnknownModeRejected(t *testing.T) {
	if _, err := webhookconfig.Render(webhookconfig.Options{
		Service:           &webhookconfig.ServiceRef{Name: "a", Namespace: "b"},
		FailurePolicyMode: "sideways",
	}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestMutationConfigUsesMutatePath(t *testing.T) {
	mc, err := webhookconfig.MutationConfig(webhookconfig.Options{
		Service: &webhookconfig.ServiceRef{Namespace: "guard", Name: "admission-guard"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(mc.Webhooks) != 2 {
		t.Fatalf("expected 2 mutating webhooks, got %d", len(mc.Webhooks))
	}
	for _, wh := range mc.Webhooks {
		if wh.ClientConfig.Service == nil || wh.ClientConfig.Service.Path == nil || *wh.ClientConfig.Service.Path != "/mutate" {
			t.Fatalf("mutating webhook must target /mutate: %+v", wh.ClientConfig)
		}
		if wh.ReinvocationPolicy == nil || *wh.ReinvocationPolicy != admissionregistrationv1.NeverReinvocationPolicy {
			t.Fatal("remediation is idempotent; reinvocation is unnecessary")
		}
	}
}

func names(cfg *admissionregistrationv1.ValidatingWebhookConfiguration) []string {
	out := make([]string, 0, len(cfg.Webhooks))
	for _, wh := range cfg.Webhooks {
		out = append(out, wh.Name)
	}
	return out
}

func selectorContains(sel *metav1.LabelSelector, key, value string) bool {
	for _, expr := range sel.MatchExpressions {
		if expr.Key != key {
			continue
		}
		if expr.Operator != metav1.LabelSelectorOpIn {
			return false
		}
		for _, v := range expr.Values {
			if v == value {
				return true
			}
		}
	}
	return false
}

func defaultSelectorKeys(wh *admissionregistrationv1.ValidatingWebhook) *metav1.LabelSelector {
	return wh.NamespaceSelector
}

func selectorExcludes(sel *metav1.LabelSelector, value string) bool {
	for _, expr := range sel.MatchExpressions {
		if expr.Key != policy.EnforcementLabel || expr.Operator != metav1.LabelSelectorOpNotIn {
			continue
		}
		for _, v := range expr.Values {
			if v == value {
				return true
			}
		}
	}
	return false
}
