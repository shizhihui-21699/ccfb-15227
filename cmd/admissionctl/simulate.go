package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/example/cluster-admission-guard/internal/admission"
	"github.com/example/cluster-admission-guard/internal/policy"
	"github.com/example/cluster-admission-guard/internal/store"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// simulateResult is one object's outcome.
type simulateResult struct {
	Source     string   `json:"source"`
	Document   int      `json:"document"`
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Namespace  string   `json:"namespace,omitempty"`
	Name       string   `json:"name"`
	Allowed    bool     `json:"allowed"`
	Remediated bool     `json:"remediated"`
	Warnings   []string `json:"warnings,omitempty"`
	Denials    []string `json:"denials,omitempty"`
	Policy     []string `json:"policies,omitempty"`
	// Deny is set when the object would be rejected.
	Deny bool `json:"denied"`
}

type simulateReport struct {
	Total    int              `json:"total"`
	Denied   int              `json:"denied"`
	Modified int              `json:"remediated"`
	Results  []simulateResult `json:"results"`
}

func cmdSimulate(args []string) error {
	fs := flag.NewFlagSet("simulate", flag.ContinueOnError)
	dir := fs.String("policy-dir", "", "directory containing policy YAML")
	manifest := fs.String("manifest", "", "file or directory of manifests to replay")
	nsLabels := fs.String("namespace-labels", "", "comma separated namespace=team1,+enforcement=strict pairs, e.g. team-a=payments,strict")
	asJSON := fs.Bool("json", false, "emit JSON")
	failOn := fs.Bool("fail-on-deny", false, "exit non-zero if any object is denied")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *manifest == "" {
		return fmt.Errorf("--policy-dir and --manifest are required")
	}
	loaded, err := store.LoadDir(*dir)
	if err != nil {
		return fmt.Errorf("policy load failed: %w", err)
	}
	nsMap := parseNamespaceLabels(*nsLabels)
	engine := admission.NewEngine(staticStore{loaded: loaded, namespaces: nsMap})

	objs, err := loadManifests(*manifest)
	if err != nil {
		return err
	}
	rep := simulateReport{}
	for _, o := range objs {
		gvk, err := parseGVK(o.APIVersion, o.Kind)
		if err != nil {
			return fmt.Errorf("%s document %d: %w", o.Source, o.Doc, err)
		}
		meta := metaFromObject(o.Object)
		resp := engine.Evaluate(admission.Request{
			Operation: admission.Create,
			GVK:       gvk,
			Namespace: meta.namespace,
			Name:      meta.name,
			Object:    cloneMap(o.Object),
		})
		rep.Total++
		r := simulateResult{
			Source:     o.Source,
			Document:   o.Doc,
			APIVersion: o.APIVersion,
			Kind:       o.Kind,
			Namespace:  meta.namespace,
			Name:       meta.name,
			Allowed:    resp.Allowed,
			Policy:     resp.Policies,
			Warnings:   resp.Warnings,
			Denials:    resp.Reasons,
			Deny:       !resp.Allowed,
		}
		if len(resp.Patch) > 0 {
			r.Remediated = true
			rep.Modified++
		}
		if !resp.Allowed {
			rep.Denied++
		}
		rep.Results = append(rep.Results, r)
	}

	if *asJSON {
		if err := printJSON(rep); err != nil {
			return err
		}
	} else {
		for _, r := range rep.Results {
			status := "ALLOW"
			switch {
			case r.Deny:
				status = "DENY "
			case r.Remediated:
				status = "FIX  "
			}
			fmt.Printf("%s %s/%s %s/%s\n", status, r.Kind, r.Name, r.Namespace, joinOr(r.Policy, "-"))
			for _, d := range r.Denials {
				fmt.Printf("      %s\n", d)
			}
			for _, w := range r.Warnings {
				fmt.Printf("      ~ %s\n", w)
			}
		}
		fmt.Printf("\n%d objects: %d denied, %d remediated\n", rep.Total, rep.Denied, rep.Modified)
	}
	if *failOn && rep.Denied > 0 {
		return &exitError{code: 3, msg: fmt.Sprintf("%d objects would be denied", rep.Denied)}
	}
	return nil
}

// staticStore is an admission.Store over a fixed policy snapshot and a
// namespace->labels map, used by offline commands.
type staticStore struct {
	loaded     *store.Loaded
	namespaces map[string]map[string]string
}

func (s staticStore) Policies() []*policy.CompiledPolicy { return s.loaded.Policies }
func (s staticStore) TrustStore() *policy.TrustStore     { return s.loaded.TrustStore }
func (s staticStore) Health() error {
	if len(s.loaded.Errors) > 0 {
		var msgs []string
		for _, e := range s.loaded.Errors {
			msgs = append(msgs, e.Error())
		}
		return fmt.Errorf("%s", strings.Join(msgs, "; "))
	}
	return nil
}
func (s staticStore) Namespace(name string) (policy.NamespaceInfo, bool) {
	labels, ok := s.namespaces[name]
	if !ok {
		return policy.NamespaceInfo{}, false
	}
	return policy.NamespaceInfo{Name: name, Labels: labels, Enforcement: policy.EnforcementOf(labels)}, true
}

type objectMeta struct {
	name      string
	namespace string
}

func metaFromObject(obj map[string]any) objectMeta {
	m, _ := obj["metadata"].(map[string]any)
	name, _ := m["name"].(string)
	ns, _ := m["namespace"].(string)
	return objectMeta{name: name, namespace: ns}
}

func parseGVK(apiVersion, kind string) (schema.GroupVersionKind, error) {
	group, version := "", apiVersion
	if i := strings.Index(apiVersion, "/"); i >= 0 {
		group, version = apiVersion[:i], apiVersion[i+1:]
	}
	if kind == "" || version == "" {
		return schema.GroupVersionKind{}, fmt.Errorf("object has no kind or apiVersion")
	}
	return schema.GroupVersionKind{Group: group, Version: version, Kind: kind}, nil
}

// parseNamespaceLabels understands:
//
//	"team-a=payments,team-b=platform"            -> namespace=team label
//	"team-a=payments:strict,team-b=platform"     -> enforcement override after ':'
//	"team-a=payments,guard.example.com/team=x"   -> arbitrary kv
//
// Teams are stored under the default team label; a ":strict" or ":standard"
// suffix sets the enforcement label.
func parseNamespaceLabels(s string) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		enforcement := ""
		if i := strings.LastIndex(entry, ":"); i > 0 && i > strings.LastIndex(entry, "=") {
			enforcement = strings.TrimSpace(entry[i+1:])
			entry = entry[:i]
		}
		kv := strings.SplitN(entry, "=", 2)
		if len(kv) != 2 {
			continue
		}
		ns := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		if out[ns] == nil {
			out[ns] = map[string]string{}
		}
		if strings.Contains(val, "=") {
			// "ns=k=v" form: arbitrary label assignment.
			parts := strings.SplitN(val, "=", 2)
			out[ns][parts[0]] = parts[1]
		} else {
			out[ns][policy.DefaultTeamLabel] = val
		}
		if enforcement != "" {
			out[ns][policy.EnforcementLabel] = enforcement
		}
	}
	return out
}

func joinOr(list []string, fallback string) string {
	if len(list) == 0 {
		return fallback
	}
	return strings.Join(list, ",")
}

func cloneMap(m map[string]any) map[string]any {
	data, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return out
}
