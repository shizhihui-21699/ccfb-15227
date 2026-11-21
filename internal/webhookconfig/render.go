// Package webhookconfig renders the ValidatingWebhookConfiguration.
//
// The availability requirement ("a webhook outage must not block the whole
// cluster") and the safety requirement ("a dangerous object must never slip
// through") are in direct tension, and Kubernetes' failurePolicy is per-webhook,
// not per-namespace. This package resolves it by emitting two webhooks that
// share one server:
//
//   - strict: namespaceSelector matches the strict enforcement label,
//     failurePolicy=Fail. Namespaces that must never admit an unreviewed
//     workload keep their guarantee even if the service is down.
//   - default: matches everything except strict and disabled namespaces,
//     failurePolicy=Ignore. Everywhere else a webhook outage means deployments
//     proceed (and the outage is counted/alerted) instead of freezing.
//
// Namespaces labelled enforcement=disabled are excluded from both. They exist
// for cluster bootstrap (kube-system, the guard's own namespace) and for
// break-glass; the guard's Namespace admission check prevents ordinary users
// from creating or relabelling a namespace into that state.
package webhookconfig

import (
	"fmt"
	"sort"
	"strings"

	"github.com/example/cluster-admission-guard/internal/policy"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// Options configure the rendered configuration.
type Options struct {
	// Service is the webhook service. Exactly one of Service or URL must be set.
	Service *ServiceRef
	// URL is used when the webhook is served outside the cluster (tests, local
	// http endpoints). It must be https in production.
	URL string
	// CABundle is the PEM CA that signs the webhook serving certificate.
	CABundle []byte
	// Port is the service port.
	Port int32
	// Path is the HTTP path.
	Path string
	// TimeoutSeconds defaults to 10.
	TimeoutSeconds int32
	// FailurePolicyMode selects how the split is generated.
	// "split" (default) -> two webhooks with Fail/Ignore.
	// "fail-closed" -> one webhook, Fail everywhere except disabled.
	// "fail-open" -> one webhook, Ignore everywhere. Only for break-glass.
	FailurePolicyMode string
	// Timeout for the strict webhook can be shorter than the default one.
	StrictTimeoutSeconds int32
	// WildcardResources intercepts every API resource instead of the curated
	// workload list. Operators that create pods through custom controllers need
	// this; it evaluates policy on every object in the cluster.
	WildcardResources bool
}

// ServiceRef names the webhook Service.
type ServiceRef struct {
	Namespace string
	Name      string
}

// Resources are the API resources the webhook intercepts.
//
// The list is broad on purpose: the same container settings can be created
// through many resource types (Deployment, StatefulSet, DaemonSet, Job,
// CronJob, ReplicaSet, ReplicationController, Pod, and any CRD embedding a pod
// template). Intercepting only Deployments would leave an obvious bypass.
func Resources() []admissionregistrationv1.RuleWithOperations {
	groups := []string{
		"", "apps", "batch", "extensions",
		"argoproj.io", "serving.knative.dev", "ray.io", "kubeflow.org",
		"tekton.dev", "apps.openshift.io", "kubevirt.io",
	}
	var rules []admissionregistrationv1.RuleWithOperations
	for _, group := range groups {
		rules = append(rules, admissionregistrationv1.RuleWithOperations{
			Operations: []admissionregistrationv1.OperationType{
				admissionregistrationv1.Create,
				admissionregistrationv1.Update,
			},
			Rule: admissionregistrationv1.Rule{
				APIGroups:   []string{group},
				APIVersions: []string{"*"},
				Resources: []string{
					"pods", "podtemplates", "deployments", "statefulsets", "daemonsets",
					"replicasets", "replicationcontrollers", "jobs", "cronjobs",
					"rollouts", "cronworkflows", "services", "revisions", "rayclusters",
					"pytorchjobs", "tfjobs", "taskruns", "pipelineruns",
					"deploymentconfigs", "virtualmachineinstances", "virtualmachines",
					"namespaces",
					// Ephemeral debug containers are attached via a subresource
					// UPDATE; without it kubectl debug bypasses the guard.
					"pods/ephemeralcontainers",
				},
			},
		})
	}
	// Custom resources cannot be enumerated ahead of time. Intercepting
	// "*/*" for CREATE/UPDATE would include every CRD, but it would also bypass
	// the namespaceSelector optimisation and slow every write cluster-wide.
	// The daemon therefore supports an optional wildcard rule in addition to
	// the curated list (see WildcardResources).
	return rules
}

// WildcardResources intercepts every namespaced and cluster-scoped resource.
// It is opt-in because it evaluates policy on every object in the cluster.
func WildcardResources() []admissionregistrationv1.RuleWithOperations {
	return []admissionregistrationv1.RuleWithOperations{{
		Operations: []admissionregistrationv1.OperationType{
			admissionregistrationv1.Create,
			admissionregistrationv1.Update,
		},
		Rule: admissionregistrationv1.Rule{
			APIGroups:   []string{"*"},
			APIVersions: []string{"*"},
			Resources:   []string{"*"},
		},
	}}
}

// Render produces the ValidatingWebhookConfiguration.
func Render(opts Options) (*admissionregistrationv1.ValidatingWebhookConfiguration, error) {
	if opts.Service == nil && opts.URL == "" {
		return nil, fmt.Errorf("one of Service or URL is required")
	}
	if opts.Service != nil && opts.URL != "" {
		return nil, fmt.Errorf("Service and URL are mutually exclusive")
	}
	port := opts.Port
	if port == 0 {
		port = 443
	}
	webhookPath := opts.Path
	if webhookPath == "" {
		webhookPath = "/validate"
	}
	timeout := opts.TimeoutSeconds
	if timeout == 0 {
		timeout = 10
	}

	clientConfig := admissionregistrationv1.WebhookClientConfig{CABundle: opts.CABundle}
	if opts.Service != nil {
		clientConfig.Service = &admissionregistrationv1.ServiceReference{
			Namespace: opts.Service.Namespace,
			Name:      opts.Service.Name,
			Path:      &webhookPath,
			Port:      &port,
		}
	} else {
		clientConfig.URL = &opts.URL
	}

	sideEffects := admissionregistrationv1.SideEffectClassNone
	matchPolicy := admissionregistrationv1.Equivalent
	failureFail := admissionregistrationv1.Fail
	failureIgnore := admissionregistrationv1.Ignore

	strictSelector := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      policy.EnforcementLabel,
			Operator: metav1.LabelSelectorOpIn,
			Values:   []string{policy.EnforcementStrict},
		}},
	}
	// Everything except strict and disabled.
	defaultSelector := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      policy.EnforcementLabel,
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   []string{policy.EnforcementStrict, policy.EnforcementDisabled},
		}},
	}

	rules := Resources()
	if opts.WildcardResources {
		rules = WildcardResources()
	}
	base := admissionregistrationv1.ValidatingWebhook{
		ClientConfig:            clientConfig,
		Rules:                   rules,
		AdmissionReviewVersions: []string{"v1"},
		SideEffects:             &sideEffects,
		MatchPolicy:             &matchPolicy,
		NamespaceSelector:       defaultSelector,
		FailurePolicy:           &failureIgnore,
		TimeoutSeconds:          &timeout,
	}

	var webhooks []admissionregistrationv1.ValidatingWebhook
	switch opts.FailurePolicyMode {
	case "", "split":
		strict := base.DeepCopy()
		strict.Name = "guard.example.com.strict"
		strict.NamespaceSelector = strictSelector
		strict.FailurePolicy = &failureFail
		if opts.StrictTimeoutSeconds > 0 {
			strict.TimeoutSeconds = &opts.StrictTimeoutSeconds
		}
		def := base.DeepCopy()
		def.Name = "guard.example.com.default"
		def.NamespaceSelector = defaultSelector
		def.FailurePolicy = &failureIgnore
		webhooks = []admissionregistrationv1.ValidatingWebhook{*strict, *def}
	case "fail-closed":
		failClosedSelector := &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      policy.EnforcementLabel,
				Operator: metav1.LabelSelectorOpNotIn,
				Values:   []string{policy.EnforcementDisabled},
			}},
		}
		wh := base.DeepCopy()
		wh.Name = "guard.example.com.fail-closed"
		wh.FailurePolicy = &failureFail
		wh.NamespaceSelector = failClosedSelector
		webhooks = []admissionregistrationv1.ValidatingWebhook{*wh}
	case "fail-open":
		wh := base.DeepCopy()
		wh.Name = "guard.example.com.fail-open"
		webhooks = []admissionregistrationv1.ValidatingWebhook{*wh}
	default:
		return nil, fmt.Errorf("unknown failure policy mode %q (want split, fail-closed or fail-open)", opts.FailurePolicyMode)
	}
	sort.Slice(webhooks, func(i, j int) bool { return webhooks[i].Name < webhooks[j].Name })

	return &admissionregistrationv1.ValidatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind:       "ValidatingWebhookConfiguration",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "admission-guard",
			Labels: map[string]string{
				"app.kubernetes.io/name":    "admission-guard",
				"app.kubernetes.io/part-of": "admission-guard",
			},
		},
		Webhooks: webhooks,
	}, nil
}

// RenderYAML renders the configuration as YAML.
func RenderYAML(opts Options) ([]byte, error) {
	cfg, err := Render(opts)
	if err != nil {
		return nil, err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("# Generated by admissionctl render-webhook-config. Do not edit by hand.\n")
	b.WriteString("#\n")
	b.WriteString("# strict webhook: failurePolicy=Fail, namespaces labelled\n")
	b.WriteString("#   guard.example.com/enforcement=strict\n")
	b.WriteString("# default webhook: failurePolicy=Ignore, all other namespaces\n")
	b.WriteString("# Namespaces labelled enforcement=disabled are excluded from both.\n")
	b.Write(data)
	return []byte(b.String()), nil
}

// MutationConfig renders the MutatingWebhookConfiguration used for remediation.
// Mutating webhooks cannot use failurePolicy=Fail per-namespace either, so the
// split mirrors the validating one. Remediation is idempotent, so a duplicate
// invocation from both configurations is safe.
func MutationConfig(opts Options) (*admissionregistrationv1.MutatingWebhookConfiguration, error) {
	cfg, err := Render(opts)
	if err != nil {
		return nil, err
	}
	out := &admissionregistrationv1.MutatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind:       "MutatingWebhookConfiguration",
		},
		ObjectMeta: cfg.ObjectMeta,
	}
	sideEffects := admissionregistrationv1.SideEffectClassNone
	timeout := opts.TimeoutSeconds
	if timeout == 0 {
		timeout = 10
	}
	rein := admissionregistrationv1.NeverReinvocationPolicy
	for _, wh := range cfg.Webhooks {
		mw := admissionregistrationv1.MutatingWebhook{
			Name:                    wh.Name,
			ClientConfig:            wh.ClientConfig,
			Rules:                   wh.Rules,
			AdmissionReviewVersions: wh.AdmissionReviewVersions,
			SideEffects:             &sideEffects,
			NamespaceSelector:       wh.NamespaceSelector,
			FailurePolicy:           wh.FailurePolicy,
			TimeoutSeconds:          &timeout,
			ReinvocationPolicy:      &rein,
		}
		if mw.ClientConfig.URL != nil {
			path := "/mutate"
			mw.ClientConfig.URL = &path
		}
		if mw.ClientConfig.Service != nil {
			path := "/mutate"
			mw.ClientConfig.Service.Path = &path
			port := mw.ClientConfig.Service.Port
			if port == nil {
				p := int32(443)
				port = &p
			}
			mw.ClientConfig.Service.Port = port
		}
		out.Webhooks = append(out.Webhooks, mw)
	}
	return out, nil
}
