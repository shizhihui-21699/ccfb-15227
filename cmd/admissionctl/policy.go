package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/example/cluster-admission-guard/internal/policy"
	"github.com/example/cluster-admission-guard/internal/store"
	"github.com/example/cluster-admission-guard/internal/webhookconfig"
)

type policyReport struct {
	OK         bool            `json:"ok"`
	Policies   []policySummary `json:"policies,omitempty"`
	TrustStore *trustSummary   `json:"trustStore,omitempty"`
	Errors     []string        `json:"errors,omitempty"`
}

type policySummary struct {
	Name        string   `json:"name"`
	Mode        string   `json:"mode"`
	FailureMode string   `json:"failureMode"`
	Rules       []string `json:"rules"`
	Exemptions  int      `json:"exemptions"`
	// ExpiringExemptions are exemptions expiring within 14 days; surfacing them
	// in CI makes sure "temporary" exceptions actually get reviewed.
	ExpiringExemptions []exemptionSummary `json:"expiringExemptions,omitempty"`
}

type exemptionSummary struct {
	ID        string `json:"id"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expiresAt"`
	In        string `json:"expiresIn"`
}

type trustSummary struct {
	Signatures int `json:"signatures"`
}

func cmdValidatePolicies(args []string) error {
	fs := flag.NewFlagSet("validate-policies", flag.ContinueOnError)
	dir := fs.String("policy-dir", "", "directory containing policy YAML")
	asJSON := fs.Bool("json", false, "emit JSON")
	warnWindow := fs.Duration("expiry-warning-window", 14*24*time.Hour, "warn when exemptions expire within this window")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("--policy-dir is required")
	}
	loaded, err := store.LoadDir(*dir)
	rep := policyReport{OK: err == nil}
	for _, e := range loaded.Errors {
		rep.Errors = append(rep.Errors, e.Error())
	}
	now := time.Now()
	for _, p := range loaded.Policies {
		sum := policySummary{
			Name:        p.Metadata.Name,
			Mode:        string(p.Mode),
			FailureMode: string(p.FailureMode),
			Exemptions:  len(p.Spec.Exemptions),
		}
		for _, r := range p.Spec.Rules {
			sum.Rules = append(sum.Rules, r.ID)
		}
		sort.Strings(sum.Rules)
		for _, ex := range p.Spec.Exemptions {
			end, err := time.Parse(time.RFC3339, ex.ExpiresAt)
			if err != nil {
				continue
			}
			if end.Sub(now) <= *warnWindow {
				sum.ExpiringExemptions = append(sum.ExpiringExemptions, exemptionSummary{
					ID:        ex.ID,
					Reason:    ex.Reason,
					ExpiresAt: ex.ExpiresAt,
					In:        end.Sub(now).Round(time.Hour).String(),
				})
			}
		}
		rep.Policies = append(rep.Policies, sum)
	}
	if loaded.TrustStore != nil {
		rep.TrustStore = &trustSummary{Signatures: len(loaded.TrustStore.Spec.Signatures)}
	}

	if *asJSON {
		if err := printJSON(rep); err != nil {
			return err
		}
	} else {
		if rep.OK {
			fmt.Printf("OK: %d policies loaded\n", len(rep.Policies))
		} else {
			fmt.Printf("INVALID: %d problems\n", len(rep.Errors))
		}
		for _, e := range rep.Errors {
			fmt.Printf("  - %s\n", e)
		}
		for _, p := range rep.Policies {
			fmt.Printf("  policy %s (mode=%s failure=%s rules=%d exemptions=%d)\n", p.Name, p.Mode, p.FailureMode, len(p.Rules), p.Exemptions)
			for _, ex := range p.ExpiringExemptions {
				fmt.Printf("    ! exemption %s expires in %s (%s): %s\n", ex.ID, ex.In, ex.ExpiresAt, ex.Reason)
			}
		}
	}
	if !rep.OK {
		return &exitError{code: 1, msg: "policy validation failed"}
	}
	return nil
}

func cmdExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	dir := fs.String("policy-dir", "", "directory containing policy YAML")
	namespace := fs.String("namespace", "", "namespace to explain")
	labels := fs.String("labels", "", "comma separated k=v namespace labels")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *namespace == "" {
		return fmt.Errorf("--policy-dir and --namespace are required")
	}
	loaded, err := store.LoadDir(*dir)
	if err != nil {
		return err
	}
	labelMap := map[string]string{}
	for _, pair := range strings.Split(*labels, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return fmt.Errorf("invalid label %q", pair)
		}
		labelMap[kv[0]] = kv[1]
	}
	info := policy.NamespaceInfo{Name: *namespace, Labels: labelMap, Enforcement: policy.EnforcementOf(labelMap)}

	type explained struct {
		Namespace   string            `json:"namespace"`
		Enforcement string            `json:"enforcement"`
		Teams       []string          `json:"teams"`
		Policies    []policySummary   `json:"policies"`
		Exemptions  []exemptionDetail `json:"activeExemptions"`
	}
	out := explained{Namespace: *namespace, Enforcement: info.Enforcement, Teams: info.Teams(policy.DefaultTeamLabel)}
	now := time.Now()
	for _, p := range loaded.Policies {
		if !p.AppliesTo(info) {
			continue
		}
		sum := policySummary{Name: p.Metadata.Name, Mode: string(p.Mode), FailureMode: string(p.FailureMode), Exemptions: len(p.Spec.Exemptions)}
		for _, r := range p.Spec.Rules {
			sum.Rules = append(sum.Rules, r.ID)
		}
		sort.Strings(sum.Rules)
		out.Policies = append(out.Policies, sum)
		for _, ex := range p.Spec.Exemptions {
			end, err := time.Parse(time.RFC3339, ex.ExpiresAt)
			if err != nil || !now.Before(end) {
				continue
			}
			if ex.NotBefore != "" {
				start, err := time.Parse(time.RFC3339, ex.NotBefore)
				if err != nil || now.Before(start) {
					continue
				}
			}
			// Only list exemptions that could apply to this namespace.
			if len(ex.Scope.Namespaces) > 0 && !scopeHas(ex.Scope.Namespaces, *namespace) {
				continue
			}
			if len(ex.Scope.Teams) > 0 && !teamIntersects(ex.Scope.Teams, info.Teams(p.TeamLabel)) {
				continue
			}
			out.Exemptions = append(out.Exemptions, exemptionDetail{
				Policy:    p.Metadata.Name,
				ID:        ex.ID,
				Rules:     ex.Scope.Rules,
				Reason:    ex.Reason,
				ExpiresAt: ex.ExpiresAt,
				ExpiresIn: end.Sub(now).Round(time.Hour).String(),
			})
		}
	}
	if *asJSON {
		return printJSON(out)
	}
	fmt.Printf("namespace %s: enforcement=%s teams=%v\n", out.Namespace, out.Enforcement, out.Teams)
	for _, p := range out.Policies {
		fmt.Printf("  policy %s mode=%s failure=%s rules=%v\n", p.Name, p.Mode, p.FailureMode, p.Rules)
	}
	if len(out.Exemptions) == 0 {
		fmt.Println("  no active exemptions")
	}
	for _, ex := range out.Exemptions {
		fmt.Printf("  exemption %s (policy %s) rules=%v expires in %s: %s\n", ex.ID, ex.Policy, ex.Rules, ex.ExpiresIn, ex.Reason)
	}
	return nil
}

type exemptionDetail struct {
	Policy    string   `json:"policy"`
	ID        string   `json:"id"`
	Rules     []string `json:"rules"`
	Reason    string   `json:"reason"`
	ExpiresAt string   `json:"expiresAt"`
	ExpiresIn string   `json:"expiresIn"`
}

func scopeHas(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func teamIntersects(patterns, teams []string) bool {
	for _, t := range teams {
		if scopeHas(patterns, t) {
			return true
		}
	}
	return false
}

func cmdRenderWebhookConfig(args []string) error {
	fs := flag.NewFlagSet("render-webhook-config", flag.ContinueOnError)
	service := fs.String("service", "admission-guard", "webhook service name")
	namespace := fs.String("namespace", "admission-guard", "webhook service namespace")
	caBundle := fs.String("ca-bundle", "", "file containing the PEM CA bundle")
	mode := fs.String("mode", "split", "split|fail-closed|fail-open")
	out := fs.String("out", "", "write to this file instead of stdout")
	wildcard := fs.Bool("wildcard-resources", false, "intercept every API resource, not just the curated workload kinds (evaluates policy on all objects)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var ca []byte
	if *caBundle != "" {
		data, err := os.ReadFile(*caBundle)
		if err != nil {
			return fmt.Errorf("read CA bundle: %w", err)
		}
		ca = data
	}
	data, err := webhookconfig.RenderYAML(webhookconfig.Options{
		Service:           &webhookconfig.ServiceRef{Name: *service, Namespace: *namespace},
		CABundle:          ca,
		FailurePolicyMode: *mode,
		WildcardResources: *wildcard,
	})
	if err != nil {
		return err
	}
	if *out != "" {
		return os.WriteFile(*out, data, 0o644)
	}
	_, err = os.Stdout.Write(data)
	return err
}
