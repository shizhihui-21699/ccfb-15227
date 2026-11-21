package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"time"

	"github.com/example/cluster-admission-guard/internal/admission"
	"github.com/example/cluster-admission-guard/internal/audit"
	"github.com/example/cluster-admission-guard/internal/policy"
	"github.com/example/cluster-admission-guard/internal/simulator"
	"github.com/example/cluster-admission-guard/internal/store"
	"github.com/example/cluster-admission-guard/internal/webhook"
)

// e2eReport is the result of replaying manifests through the real HTTP path.
type e2eReport struct {
	Total        int              `json:"total"`
	Created      int              `json:"created"`
	Denied       int              `json:"denied"`
	Remediated   int              `json:"remediated"`
	WebhookCalls int              `json:"webhookCalls"`
	Results      []simulateResult `json:"results"`
	// Outage demonstrates fail-open/fail-closed behaviour by taking the webhook
	// down and retrying one dangerous object per namespace class.
	Outage *outageReport `json:"outage,omitempty"`
	Audit  []audit.Event `json:"audit,omitempty"`
}

type outageReport struct {
	WebhookCallsBefore int           `json:"webhookCallsBefore"`
	StandardNamespace  outageOutcome `json:"standardNamespace"`
	StrictNamespace    outageOutcome `json:"strictNamespace"`
}

type outageOutcome struct {
	Namespace string `json:"namespace"`
	Allowed   bool   `json:"allowed"`
	Reason    string `json:"reason"`
}

// cmdE2E starts the real webhook server (plain HTTP on a loopback listener for
// the test) plus the simulated API server, and replays a manifest file through
// genuine AdmissionReview round trips.
//
// This exercises exactly what a cluster does: object -> AdmissionReview HTTP
// POST -> allowed/denied/patch -> stored object.
func cmdE2E(args []string) error {
	fs := flag.NewFlagSet("e2e", flag.ContinueOnError)
	dir := fs.String("policy-dir", "", "directory containing policy YAML")
	manifest := fs.String("manifest", "", "file or directory of manifests")
	nsLabels := fs.String("namespace-labels", "", "namespace label map, see simulate")
	asJSON := fs.Bool("json", false, "emit JSON")
	failOn := fs.Bool("fail-on-deny", false, "exit non-zero if any object is denied")
	withOutage := fs.Bool("outage", true, "also demonstrate fail-open/fail-closed during a webhook outage")
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

	// Audit goes to an in-memory sink so the report can include it.
	sink := &memorySink{}
	logger := &audit.Logger{Sinks: []audit.Sink{sink}}
	fakeStore := &e2eStore{loaded: loaded, namespaces: nsMap}
	engine := admission.NewEngine(fakeStore)
	srv := webhook.NewServer(engine, logger, nil)
	// The mutating endpoint is a separate engine with remediation enabled; the
	// validating endpoint never rewrites.
	mutEngine := admission.NewEngine(fakeStore)
	srv.MutateEngine = mutEngine
	engine.AllowMutation = false

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	httpSrv := &httptest.Server{
		Listener: ln,
		Config:   &http.Server{Handler: srv.Routes(), ReadHeaderTimeout: 5 * time.Second},
	}
	httpSrv.Start()
	defer httpSrv.Close()

	// The webhook URL policy mirrors the split configuration: strict namespaces
	// use Fail, everyone else Ignore.
	nsFailure := map[string]simulator.Policy{}
	for name, labels := range nsMap {
		if policy.EnforcementOf(labels) == "strict" {
			nsFailure[name] = simulator.Fail
		} else {
			nsFailure[name] = simulator.Ignore
		}
	}
	cluster := simulator.New(&simulator.WebhookRef{
		URL:                    httpSrv.URL + "/validate",
		MutateURL:              httpSrv.URL + "/mutate",
		FailurePolicy:          simulator.Ignore,
		NamespaceFailurePolicy: nsFailure,
		Timeout:                5 * time.Second,
	})

	objs, err := loadManifests(*manifest)
	if err != nil {
		return err
	}
	rep := e2eReport{}
	ctx := context.Background()
	for _, o := range objs {
		gvk, err := parseGVK(o.APIVersion, o.Kind)
		if err != nil {
			return fmt.Errorf("%s document %d: %w", o.Source, o.Doc, err)
		}
		meta := metaFromObject(o.Object)
		obj := cloneMap(o.Object)
		res, err := cluster.Create(gvk, obj)
		r := simulateResult{
			Source:     o.Source,
			Document:   o.Doc,
			APIVersion: o.APIVersion,
			Kind:       o.Kind,
			Namespace:  meta.namespace,
			Name:       meta.name,
		}
		rep.Total++
		if err != nil {
			r.Deny = true
			r.Allowed = false
			r.Denials = []string{err.Error()}
			rep.Denied++
		} else {
			r.Allowed = true
			r.Warnings = res.Warnings
			r.Remediated = res.Patched
			if res.Patched {
				rep.Remediated++
			}
			rep.Created++
			// If remediation happened, also report what it changed.
			if res.Object != nil {
				r.Policy = []string{"stored"}
			}
		}
		rep.Results = append(rep.Results, r)
		_ = ctx
	}
	rep.WebhookCalls = cluster.WebhookCalls

	if *withOutage {
		outage, err := runOutageDemo(cluster, nsMap)
		if err != nil {
			return err
		}
		rep.Outage = outage
	}
	rep.Audit = sink.events

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
			fmt.Printf("%s %s/%s %s/%s\n", status, r.Kind, r.Name, r.Namespace, strings.Join(r.Policy, ","))
			for _, d := range r.Denials {
				fmt.Printf("      %s\n", d)
			}
			for _, w := range r.Warnings {
				fmt.Printf("      ~ %s\n", w)
			}
		}
		fmt.Printf("\n%d objects: %d created, %d denied, %d remediated, %d webhook calls\n",
			rep.Total, rep.Created, rep.Denied, rep.Remediated, rep.WebhookCalls)
		if rep.Outage != nil {
			fmt.Println("\nwebhook outage behaviour:")
			fmt.Printf("  standard namespace %s: allowed=%v (%s)\n", rep.Outage.StandardNamespace.Namespace, rep.Outage.StandardNamespace.Allowed, rep.Outage.StandardNamespace.Reason)
			fmt.Printf("  strict   namespace %s: allowed=%v (%s)\n", rep.Outage.StrictNamespace.Namespace, rep.Outage.StrictNamespace.Allowed, rep.Outage.StrictNamespace.Reason)
		}
		fmt.Printf("\naudit events recorded: %d\n", len(rep.Audit))
	}
	if *failOn && rep.Denied > 0 {
		return &exitError{code: 3, msg: fmt.Sprintf("%d objects were denied", rep.Denied)}
	}
	return nil
}

// runOutageDemo takes the webhook down and retries a dangerous object in one
// standard and one strict namespace.
func runOutageDemo(cluster *simulator.Cluster, nsMap map[string]map[string]string) (*outageReport, error) {
	var standard, strict string
	names := make([]string, 0, len(nsMap))
	for name := range nsMap {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		enf := policy.EnforcementOf(nsMap[name])
		if standard == "" && enf != "strict" {
			standard = name
		}
		if strict == "" && enf == "strict" {
			strict = name
		}
	}
	rep := &outageReport{WebhookCallsBefore: cluster.WebhookCalls}
	mk := func(ns string) map[string]any {
		return map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata":   map[string]any{"name": "outage-probe", "namespace": ns},
			"spec": map[string]any{
				"selector": map[string]any{"matchLabels": map[string]any{"app": "outage-probe"}},
				"template": map[string]any{
					"metadata": map[string]any{"labels": map[string]any{"app": "outage-probe"}},
					"spec": map[string]any{
						"hostNetwork": true,
						"containers": []any{map[string]any{
							"name":  "c",
							"image": "registry.example.com/app@sha256:" + strings.Repeat("a", 64),
							"securityContext": map[string]any{
								"privileged": true,
							},
						}},
					},
				},
			},
		}
	}
	gvk, _ := parseGVK("apps/v1", "Deployment")
	cluster.FailNextWebhook = 1 << 20 // webhook down until cleared
	try := func(ns string) outageOutcome {
		if ns == "" {
			return outageOutcome{Namespace: "(none)", Allowed: true, Reason: "no namespace of this class in --namespace-labels"}
		}
		_, err := cluster.Create(gvk, mk(ns))
		out := outageOutcome{Namespace: ns}
		if err != nil {
			out.Allowed = false
			out.Reason = err.Error()
		} else {
			out.Allowed = true
			out.Reason = "failurePolicy=Ignore: admitted during outage"
		}
		// Leave the simulated cluster clean for repeat runs.
		cluster.Delete(gvk, ns, "outage-probe")
		return out
	}
	rep.StandardNamespace = try(standard)
	rep.StrictNamespace = try(strict)
	cluster.FailNextWebhook = 0
	return rep, nil
}

// e2eStore is the admission.Store used by the e2e command.
type e2eStore struct {
	loaded     *store.Loaded
	namespaces map[string]map[string]string
}

func (s *e2eStore) Policies() []*policy.CompiledPolicy { return s.loaded.Policies }
func (s *e2eStore) TrustStore() *policy.TrustStore     { return s.loaded.TrustStore }
func (s *e2eStore) Health() error {
	if len(s.loaded.Errors) > 0 {
		msgs := make([]string, 0, len(s.loaded.Errors))
		for _, e := range s.loaded.Errors {
			msgs = append(msgs, e.Error())
		}
		return fmt.Errorf("%s", strings.Join(msgs, "; "))
	}
	return nil
}
func (s *e2eStore) Namespace(name string) (policy.NamespaceInfo, bool) {
	labels, ok := s.namespaces[name]
	if !ok {
		return policy.NamespaceInfo{}, false
	}
	return policy.NamespaceInfo{Name: name, Labels: labels, Enforcement: policy.EnforcementOf(labels)}, true
}

// memorySink keeps audit events for the report.
type memorySink struct {
	events []audit.Event
}

func (m *memorySink) Write(e audit.Event) error {
	m.events = append(m.events, e)
	return nil
}
func (m *memorySink) Close() error { return nil }
