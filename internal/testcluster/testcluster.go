// Package testcluster wires the real policy store and informers against
// client-go's fake clients, giving tests a cluster-backed admission.Store
// without a real API server.
package testcluster

import (
	"context"
	"fmt"
	"time"

	"github.com/example/cluster-admission-guard/internal/policy"
	"github.com/example/cluster-admission-guard/internal/store"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
)

// GVKs of policy objects.
var (
	SecurityPolicyGVK = schema.GroupVersionKind{Group: "guard.example.com", Version: "v1alpha1", Kind: "SecurityPolicy"}
	TrustStoreGVK     = schema.GroupVersionKind{Group: "guard.example.com", Version: "v1alpha1", Kind: "TrustStore"}
)

// Cluster is a fake API server with the guard's informers started.
type Cluster struct {
	Store *store.ClusterStore
	Kube  *fake.Clientset
	Dyn   *dynamicfake.FakeDynamicClient
}

// New creates the fake clients, seeds namespaces and policy objects and starts
// the store's informers. Policies seeded here are present before the informers
// start, which exercises the initial list path (the realistic startup case).
func New(ctx context.Context, namespaces map[string]map[string]string, policies ...map[string]any) (*Cluster, error) {
	kube := fake.NewSimpleClientset()
	// Seed namespaces through the typed client.
	for name, labels := range namespaces {
		_, err := kube.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		}, metav1.CreateOptions{})
		if err != nil {
			return nil, fmt.Errorf("seed namespace %s: %w", name, err)
		}
	}

	scheme := runtime.NewScheme()
	listKinds := map[schema.GroupVersionResource]string{
		store.PolicyGVR:     "SecurityPolicyList",
		store.TrustStoreGVR: "TrustStoreList",
	}
	seed := make([]runtime.Object, 0, len(policies))
	for _, p := range policies {
		seed = append(seed, wrapPolicy(p))
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds, seed...)
	cs := store.NewClusterStore(kube, dyn)
	// The fake clientset's discovery does not know about CRDs; the policy
	// objects are seeded above, so tell the store the API exists.
	cs.CRDInstalled = func() bool { return true }
	// Informers must outlive this call so later object creation is observed;
	// they stop when the caller's context is cancelled.
	if err := cs.Run(ctx); err != nil {
		return nil, err
	}
	return &Cluster{Store: cs, Kube: kube, Dyn: dyn}, nil
}

// ApplyPolicy creates or replaces a SecurityPolicy object.
func (c *Cluster) ApplyPolicy(ctx context.Context, policyObj map[string]any) error {
	u := &unstructured.Unstructured{Object: policyObj}
	u.SetGroupVersionKind(SecurityPolicyGVK)
	if u.GetNamespace() == "" {
		u.SetNamespace("platform")
	}
	_, err := c.Dyn.Resource(store.PolicyGVR).Namespace(u.GetNamespace()).Create(ctx, u, metav1.CreateOptions{})
	return err
}

// ApplyTrustStore creates or replaces a TrustStore object.
func (c *Cluster) ApplyTrustStore(ctx context.Context, obj map[string]any) error {
	u := &unstructured.Unstructured{Object: obj}
	u.SetGroupVersionKind(TrustStoreGVK)
	if u.GetNamespace() == "" {
		u.SetNamespace("platform")
	}
	_, err := c.Dyn.Resource(store.TrustStoreGVR).Namespace(u.GetNamespace()).Create(ctx, u, metav1.CreateOptions{})
	return err
}

// UpdatePolicyLabels patches a namespace's labels.
func (c *Cluster) UpdateNamespaceLabels(ctx context.Context, name string, labels map[string]string) error {
	ns, err := c.Kube.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	ns.Labels = labels
	_, err = c.Kube.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{})
	return err
}

// WaitForPolicy waits until the store has compiled at least n policies.
func (c *Cluster) WaitForPolicy(n int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(c.Store.Policies()) >= n && c.Store.Health() == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %d policies (have %d, health: %v)", n, len(c.Store.Policies()), c.Store.Health())
}

// NamespaceInfo builds policy.NamespaceInfo for a namespace known to the store.
func (c *Cluster) NamespaceInfo(name string) policy.NamespaceInfo {
	info, _ := c.Store.Namespace(name)
	return info
}

func wrapPolicy(obj map[string]any) runtime.Object {
	u := &unstructured.Unstructured{Object: obj}
	if u.GetNamespace() == "" {
		u.SetNamespace("platform")
	}
	return u
}
