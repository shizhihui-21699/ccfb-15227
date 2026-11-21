package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/example/cluster-admission-guard/internal/policy"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/yaml"
)

// PolicyGVR is where SecurityPolicy documents live in the cluster.
var PolicyGVR = schema.GroupVersionResource{
	Group:    "guard.example.com",
	Version:  "v1alpha1",
	Resource: "securitypolicies",
}

// TrustStoreGVR is where the TrustStore document lives.
var TrustStoreGVR = schema.GroupVersionResource{
	Group:    "guard.example.com",
	Version:  "v1alpha1",
	Resource: "truststores",
}

// ClusterStore watches SecurityPolicy/TrustStore custom resources and core
// Namespaces through informers.
//
// SecurityPolicy CRDs are optional: when the dynamic client is nil or the CRDs
// are absent the store reports no cluster policies, and the daemon composes it
// with a FileStore. Namespaces are required because they decide strict versus
// standard enforcement.
type ClusterStore struct {
	*SnapshotStore

	dyn  dynamic.Interface
	kube kubernetes.Interface

	mu         sync.Mutex
	policyObjs map[string]*unstructured.Unstructured
	trustObjs  map[string]*unstructured.Unstructured
	nsCache    sync.Map // name -> policy.NamespaceInfo
	// PoliciesWatched is true once the policy informers synced.
	PoliciesWatched bool

	// CRDInstalled overrides the discovery probe. Tests and clusters where
	// discovery is restricted (aggregated API servers behind RBAC) use it.
	CRDInstalled func() bool
}

// NewClusterStore builds the store. dyn may be nil.
func NewClusterStore(kube kubernetes.Interface, dyn dynamic.Interface) *ClusterStore {
	cs := &ClusterStore{
		SnapshotStore: NewSnapshotStore(nil),
		dyn:           dyn,
		kube:          kube,
		policyObjs:    map[string]*unstructured.Unstructured{},
		trustObjs:     map[string]*unstructured.Unstructured{},
	}
	// Read namespaces from the live cache so label changes are visible at once.
	cs.SnapshotStore.SetNamespaceResolver(func(name string) (policy.NamespaceInfo, bool) {
		if v, ok := cs.nsCache.Load(name); ok {
			return v.(policy.NamespaceInfo), true
		}
		return policy.NamespaceInfo{}, false
	})
	return cs
}

// Run starts informers and returns once initial sync completed. Informers keep
// running in the background until ctx is done. Any error here means the webhook
// should not report ready.
func (cs *ClusterStore) Run(ctx context.Context) error {
	nsInf := informers.NewSharedInformerFactory(cs.kube, 10*time.Minute).Core().V1().Namespaces().Informer()
	if _, err := nsInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    cs.onNamespace,
		UpdateFunc: func(_, obj any) { cs.onNamespace(obj) },
		DeleteFunc: cs.onNamespaceDelete,
	}); err != nil {
		return fmt.Errorf("subscribe to namespaces: %w", err)
	}
	go nsInf.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), nsInf.HasSynced) {
		return fmt.Errorf("namespace informer did not sync")
	}

	if cs.dyn != nil && cs.crdInstalled() {
		factory := dynamicinformer.NewDynamicSharedInformerFactory(cs.dyn, 10*time.Minute)
		pInf := factory.ForResource(PolicyGVR).Informer()
		tInf := factory.ForResource(TrustStoreGVR).Informer()
		if _, err := pInf.AddEventHandler(handlerFor(cs, false)); err != nil {
			return err
		}
		if _, err := tInf.AddEventHandler(handlerFor(cs, true)); err != nil {
			return err
		}
		go factory.Start(ctx.Done())
		// Bound the initial sync. An informer for a CRD that was installed but
		// whose API is unreachable would otherwise block the webhook from ever
		// starting. A timeout is reported as a store error, which makes strict
		// namespaces fail closed instead of silently running with no policy.
		syncCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		synced := cache.WaitForCacheSync(syncCtx.Done(), pInf.HasSynced, tInf.HasSynced)
		cancel()
		if !synced {
			// Keep informers running: they recover on their own, and a later
			// event calls reloadPolicies. Until then Health() reports the gap.
			cs.setSyncError(fmt.Errorf("policy informers did not sync within 30s; cluster policies are unavailable"))
			return nil
		}
		cs.PoliciesWatched = true
		cs.reloadPolicies()
	}
	return nil
}

// crdInstalled reports whether the policy API exists. If the CRD is absent the
// daemon simply runs on file policy; that must not block startup.
func (cs *ClusterStore) crdInstalled() bool {
	if cs.CRDInstalled != nil {
		return cs.CRDInstalled()
	}
	disc := cs.kube.Discovery()
	if disc == nil {
		return true
	}
	resources, err := disc.ServerResourcesForGroupVersion(PolicyGVR.GroupVersion().String())
	if err != nil {
		return false
	}
	for _, r := range resources.APIResources {
		if r.Name == PolicyGVR.Resource {
			return true
		}
	}
	return false
}

// setSyncError records a store-level failure while keeping any policies that
// were already loaded.
func (cs *ClusterStore) setSyncError(err error) {
	cs.mu.Lock()
	objs := make([]unstructured.Unstructured, 0, len(cs.policyObjs)+len(cs.trustObjs))
	for _, o := range cs.policyObjs {
		objs = append(objs, *o.DeepCopy())
	}
	for _, o := range cs.trustObjs {
		objs = append(objs, *o.DeepCopy())
	}
	cs.mu.Unlock()
	loaded := LoadedFromObjects(objs)
	loaded.Source = "cluster"
	loaded.Errors = append(loaded.Errors, err)
	cs.Swap(loaded)
}

func handlerFor(cs *ClusterStore, trust bool) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { cs.upsert(obj, trust) },
		UpdateFunc: func(_, obj any) { cs.upsert(obj, trust) },
		DeleteFunc: func(obj any) { cs.remove(obj, trust) },
	}
}

func (cs *ClusterStore) onNamespace(obj any) {
	if ns, ok := obj.(*corev1.Namespace); ok {
		cs.nsCache.Store(ns.Name, namespaceInfo(ns.Name, ns.Labels))
	}
}

func (cs *ClusterStore) onNamespaceDelete(obj any) {
	switch ns := obj.(type) {
	case *corev1.Namespace:
		cs.nsCache.Delete(ns.Name)
	case cache.DeletedFinalStateUnknown:
		if n, ok := ns.Obj.(*corev1.Namespace); ok {
			cs.nsCache.Delete(n.Name)
		}
	}
}

func (cs *ClusterStore) upsert(obj any, trust bool) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return
	}
	key := u.GetNamespace() + "/" + u.GetName()
	cs.mu.Lock()
	if trust {
		cs.trustObjs[key] = u.DeepCopy()
	} else {
		cs.policyObjs[key] = u.DeepCopy()
	}
	cs.mu.Unlock()
	cs.reloadPolicies()
}

func (cs *ClusterStore) remove(obj any, trust bool) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		if tomb, ok := obj.(cache.DeletedFinalStateUnknown); ok {
			if uu, ok := tomb.Obj.(*unstructured.Unstructured); ok {
				u = uu
			} else {
				return
			}
		} else {
			return
		}
	}
	key := u.GetNamespace() + "/" + u.GetName()
	cs.mu.Lock()
	if trust {
		delete(cs.trustObjs, key)
	} else {
		delete(cs.policyObjs, key)
	}
	cs.mu.Unlock()
	cs.reloadPolicies()
}

func (cs *ClusterStore) reloadPolicies() {
	cs.mu.Lock()
	objs := make([]unstructured.Unstructured, 0, len(cs.policyObjs)+len(cs.trustObjs))
	for _, o := range cs.policyObjs {
		objs = append(objs, *o.DeepCopy())
	}
	for _, o := range cs.trustObjs {
		objs = append(objs, *o.DeepCopy())
	}
	cs.mu.Unlock()
	loaded := LoadedFromObjects(objs)
	loaded.Source = "cluster"
	cs.Swap(loaded)
}

func namespaceInfo(name string, labels map[string]string) policy.NamespaceInfo {
	return policy.NamespaceInfo{
		Name:        name,
		Labels:      labels,
		Enforcement: policy.EnforcementOf(labels),
	}
}

// LoadedFromObjects compiles raw SecurityPolicy/TrustStore objects.
func LoadedFromObjects(objs []unstructured.Unstructured) *Loaded {
	loaded := &Loaded{LoadedAt: time.Now()}
	sortObjs(objs)
	seen := map[string]string{}
	for _, o := range objs {
		key := o.GetNamespace() + "/" + o.GetName()
		switch o.GetKind() {
		case policy.KindPolicy:
			cp, err := syncCompilePolicy(o)
			if err != nil {
				loaded.Errors = append(loaded.Errors, fmt.Errorf("%s: %w", key, err))
				continue
			}
			if prev, dup := seen[cp.Metadata.Name]; dup {
				loaded.Errors = append(loaded.Errors, fmt.Errorf("%s: policy %q already defined in %s", key, cp.Metadata.Name, prev))
				continue
			}
			seen[cp.Metadata.Name] = key
			loaded.Policies = append(loaded.Policies, cp)
		case policy.KindTrustStore:
			ts, err := syncParseTrustStore(o)
			if err != nil {
				loaded.Errors = append(loaded.Errors, fmt.Errorf("%s: %w", key, err))
				continue
			}
			if loaded.TrustStore != nil {
				loaded.Errors = append(loaded.Errors, fmt.Errorf("%s: multiple TrustStore objects are not allowed", key))
				continue
			}
			loaded.TrustStore = ts
		default:
			loaded.Errors = append(loaded.Errors, fmt.Errorf("%s: unsupported kind %s", key, o.GetKind()))
		}
	}
	return loaded
}

func sortObjs(objs []unstructured.Unstructured) {
	byKey := func(i int) string { return objs[i].GetNamespace() + "/" + objs[i].GetName() }
	for i := 1; i < len(objs); i++ {
		for j := i; j > 0 && byKey(j) < byKey(j-1); j-- {
			objs[j], objs[j-1] = objs[j-1], objs[j]
		}
	}
}

// Compose merges policy snapshots: files first, then cluster objects. Both must
// be healthy for the composed store to be healthy.
type Composed struct {
	Sources []*SnapshotStore
}

// Policies implements admission.Store by concatenating sources.
func (c *Composed) Policies() []*policy.CompiledPolicy {
	var out []*policy.CompiledPolicy
	for _, s := range c.Sources {
		out = append(out, s.Policies()...)
	}
	return out
}

// TrustStore implements admission.Store. The first non-nil store wins.
func (c *Composed) TrustStore() *policy.TrustStore {
	for _, s := range c.Sources {
		if ts := s.TrustStore(); ts != nil {
			return ts
		}
	}
	return nil
}

// Namespace implements admission.Store.
func (c *Composed) Namespace(name string) (policy.NamespaceInfo, bool) {
	for _, s := range c.Sources {
		if info, ok := s.Namespace(name); ok {
			return info, true
		}
	}
	return policy.NamespaceInfo{}, false
}

// Health implements admission.Store.
func (c *Composed) Health() error {
	for _, s := range c.Sources {
		if err := s.Health(); err != nil {
			return err
		}
	}
	return nil
}

func syncCompilePolicy(o unstructured.Unstructured) (*policy.CompiledPolicy, error) {
	data, err := yaml.Marshal(o.Object)
	if err != nil {
		return nil, err
	}
	return policy.ParsePolicy(data)
}

func syncParseTrustStore(o unstructured.Unstructured) (*policy.TrustStore, error) {
	data, err := yaml.Marshal(o.Object)
	if err != nil {
		return nil, err
	}
	return policy.ParseTrustStore(data)
}
