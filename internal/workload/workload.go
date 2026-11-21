// Package workload extracts Kubernetes PodSpec-shaped sections from arbitrary
// submitted objects.
//
// Admission webhooks see an untyped JSON object. Security-relevant settings
// (containers, securityContext, volumes, hostNetwork, ...) may live in a Pod
// itself, in a controller template (Deployment, StatefulSet, CronJob, ...) or
// in a third-party custom resource that embeds a pod template (Argo Rollout,
// RayCluster, Knative Service, ...). Evaluating only a fixed list of built-in
// kinds is therefore easy to bypass: create the same dangerous settings through
// a CRD that the policy does not know about.
//
// To close that gap this package combines:
//
//   - a registry of known workload kinds and their exact pod-spec paths, and
//   - a structural scan that finds pod-spec-shaped maps anywhere under "spec"
//     of an unknown object. A map is considered pod-spec-shaped when it has a
//     non-empty containers/initContainers/ephemeralContainers array whose
//     entries look like containers (image and/or name).
//
// ConfigMap/Secret payloads are never scanned (their keys are user data, not
// schemas), and pathological objects are bounded so a hostile request cannot
// exhaust the admission controller.
package workload

import (
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// MaxPodSpecs bounds how many embedded templates one object may contain.
	MaxPodSpecs = 32
	// MaxScanDepth bounds recursive traversal of unknown objects.
	MaxScanDepth = 24
	// MaxScanNodes bounds the total number of maps/slices visited.
	MaxScanNodes = 20000
)

// Role identifies where a container came from inside a pod spec.
type Role string

const (
	RoleContainer Role = "container"
	RoleInit      Role = "initContainer"
	RoleEphemeral Role = "ephemeralContainer"
)

// Container is a single container (regular, init or ephemeral) with its
// mutable JSON object retained so rules can inspect and fix it in place.
type Container struct {
	Obj   map[string]any
	Name  string
	Image string
	Role  Role
	// Path is the JSON field path of the container, used in human messages.
	Path string
}

// PodSpec is one pod template found in the submitted object.
type PodSpec struct {
	Obj        map[string]any
	Path       []string
	Containers []*Container
	// Source explains how the spec was found ("pod", "template", "scan", ...).
	Source string
}

// FieldPath returns a readable path such as spec.template.spec.containers[0].
func (p *PodSpec) FieldPath(extra ...string) string {
	parts := append([]string{}, p.Path...)
	parts = append(parts, extra...)
	var b strings.Builder
	for i, part := range parts {
		if isIndex(part) {
			b.WriteString("[")
			b.WriteString(part)
			b.WriteString("]")
			continue
		}
		if i > 0 {
			b.WriteString(".")
		}
		b.WriteString(part)
	}
	return b.String()
}

// Workload is the normalized view of the submitted object.
type Workload struct {
	Object   map[string]any
	GVK      schema.GroupVersionKind
	PodSpecs []*PodSpec

	// KnownKind reports whether the kind is in the built-in workload registry.
	KnownKind bool
	// SuspiciousPaths records container-shaped data that could not be parsed
	// into a pod spec. In strict mode this is rejected (fail closed).
	SuspiciousPaths []string
	// Problems records structural issues such as missing images or a truncated
	// scan.
	Problems []string
}

// HasPodSpecs reports whether any pod template was found.
func (w *Workload) HasPodSpecs() bool { return len(w.PodSpecs) > 0 }

// Extract parses an object submitted through admission.
func Extract(gvk schema.GroupVersionKind, obj map[string]any) *Workload {
	w := &Workload{Object: obj, GVK: gvk}
	if obj == nil {
		return w
	}
	exact, byKind := registryLookup(gvk)
	w.KnownKind = exact || byKind

	seen := map[string]bool{}
	add := func(spec map[string]any, path []string, source string) {
		key := strings.Join(path, "/")
		if seen[key] || len(w.PodSpecs) >= MaxPodSpecs {
			if len(w.PodSpecs) >= MaxPodSpecs && !containsString(w.Problems, "too many pod templates") {
				w.Problems = append(w.Problems, "too many pod templates; only the first templates were evaluated")
			}
			return
		}
		seen[key] = true
		w.PodSpecs = append(w.PodSpecs, buildPodSpec(spec, path, source, w))
	}

	paths := knownPodSpecPaths(gvk)
	for _, path := range paths {
		if spec, ok := mapAtPath(obj, path); ok {
			add(spec, path, "known-template")
		}
	}

	// Always scan: CRDs and even built-in objects can carry additional embedded
	// templates (for example a custom resource's worker templates).
	// Depth is measured from spec, because that is where workload definitions
	// begin; metadata and apiVersion add fixed depth and must not eat the
	// budget (and the top-level object itself must not be considered a spec).
	root := obj
	if spec, ok := obj["spec"].(map[string]any); ok {
		root = spec
	}
	scanner := &scanState{maxDepth: MaxScanDepth, maxNodes: MaxScanNodes}
	scanner.walk(root, []string{"spec"}, w, func(spec map[string]any, path []string) {
		add(spec, path, "structural-scan")
	})

	// Deterministic ordering is important: error messages, audit records and
	// patch order must not depend on Go map iteration.
	sort.SliceStable(w.PodSpecs, func(i, j int) bool {
		return strings.Join(w.PodSpecs[i].Path, "/") < strings.Join(w.PodSpecs[j].Path, "/")
	})
	sort.Strings(w.SuspiciousPaths)
	sort.Strings(w.Problems)
	return w
}

// ExtractUnstructured is a convenience wrapper.
func ExtractUnstructured(gvk schema.GroupVersionKind, u *unstructured.Unstructured) *Workload {
	if u == nil {
		return Extract(gvk, nil)
	}
	return Extract(gvk, u.Object)
}

func buildPodSpec(obj map[string]any, path []string, source string, w *Workload) *PodSpec {
	ps := &PodSpec{Obj: obj, Path: append([]string{}, path...), Source: source}
	for _, role := range []struct {
		key  string
		role Role
	}{
		{"containers", RoleContainer},
		{"initContainers", RoleInit},
		{"ephemeralContainers", RoleEphemeral},
	} {
		list, ok := obj[role.key].([]any)
		if !ok {
			if _, present := obj[role.key]; present {
				w.Problems = append(w.Problems, fmt.Sprintf("%s.%s is not a list", ps.FieldPath(), role.key))
			}
			continue
		}
		for i, item := range list {
			cm, ok := item.(map[string]any)
			if !ok {
				w.Problems = append(w.Problems, fmt.Sprintf("%s.%s[%d] is not an object", ps.FieldPath(), role.key, i))
				continue
			}
			name, _ := cm["name"].(string)
			image, _ := cm["image"].(string)
			if image == "" {
				w.Problems = append(w.Problems, fmt.Sprintf("%s.%s[%d] has no image", ps.FieldPath(), role.key, i))
			}
			ps.Containers = append(ps.Containers, &Container{
				Obj:   cm,
				Name:  name,
				Image: image,
				Role:  role.role,
				Path:  ps.FieldPath(role.key, fmt.Sprintf("%d", i)),
			})
		}
	}
	return ps
}

type scanState struct {
	nodes    int
	maxNodes int
	maxDepth int
}

// walk traverses obj looking for pod-spec-shaped maps. It deliberately skips
// opaque user-data fields and metadata.
func (s *scanState) walk(m map[string]any, path []string, w *Workload, found func(map[string]any, []string)) {
	if s.nodes >= s.maxNodes || len(path) > s.maxDepth {
		if !containsString(w.Problems, "object too large to scan completely") {
			w.Problems = append(w.Problems, "object too large to scan completely")
		}
		return
	}
	s.nodes++
	if looksLikePodSpec(m) {
		found(m, append([]string{}, path...))
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if skipScanKey(k) {
			continue
		}
		switch v := m[k].(type) {
		case map[string]any:
			s.walk(v, append(path, k), w, found)
		case []any:
			s.walkSlice(v, append(path, k), w, found)
		}
	}
}

func (s *scanState) walkSlice(list []any, path []string, w *Workload, found func(map[string]any, []string)) {
	for i, item := range list {
		if s.nodes >= s.maxNodes {
			if !containsString(w.Problems, "object too large to scan completely") {
				w.Problems = append(w.Problems, "object too large to scan completely")
			}
			return
		}
		switch v := item.(type) {
		case map[string]any:
			s.walk(v, append(path, fmt.Sprintf("%d", i)), w, found)
		case []any:
			s.walkSlice(v, append(path, fmt.Sprintf("%d", i)), w, found)
		}
	}
}

// looksLikePodSpec requires a container array with plausible entries. Requiring
// an image/name makes false positives on arbitrary CRD fields unlikely while
// still catching unrecognized gusted templates.
func looksLikePodSpec(m map[string]any) bool {
	for _, key := range []string{"containers", "initContainers", "ephemeralContainers"} {
		raw, ok := m[key]
		if !ok {
			continue
		}
		list, ok := raw.([]any)
		if !ok {
			continue
		}
		for _, item := range list {
			cm, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if _, hasImage := cm["image"].(string); hasImage {
				if _, hasName := cm["name"].(string); hasName {
					return true
				}
			}
		}
	}
	return false
}

func skipScanKey(k string) bool {
	switch k {
	case "metadata", "managedFields", "data", "stringData", "binaryData", "status":
		return true
	}
	return false
}

func registryLookup(gvk schema.GroupVersionKind) (exact, byKind bool) {
	if _, ok := podSpecPathTable[schema.GroupVersionKind{Group: gvk.Group, Kind: gvk.Kind}]; ok {
		return true, true
	}
	_, ok := podSpecPathTable[schema.GroupVersionKind{Kind: gvk.Kind}]
	return false, ok
}

func knownPodSpecPaths(gvk schema.GroupVersionKind) [][]string {
	if p, ok := podSpecPathTable[schema.GroupVersionKind{Group: gvk.Group, Kind: gvk.Kind}]; ok {
		return p
	}
	if p, ok := podSpecPathTable[schema.GroupVersionKind{Kind: gvk.Kind}]; ok {
		return p
	}
	return nil
}

// podSpecPathTable maps workload kinds to the paths that contain their pod
// template. Group-qualified entries take precedence; unqualified entries cover
// any group (some operators mirror core kinds).
var podSpecPathTable = map[schema.GroupVersionKind][][]string{
	{Group: "", Kind: "Pod"}:                               {{"spec"}},
	{Group: "", Kind: "PodTemplate"}:                       {{"template", "spec"}},
	{Group: "apps", Kind: "Deployment"}:                    {{"spec", "template", "spec"}},
	{Group: "apps", Kind: "StatefulSet"}:                   {{"spec", "template", "spec"}},
	{Group: "apps", Kind: "DaemonSet"}:                     {{"spec", "template", "spec"}},
	{Group: "apps", Kind: "ReplicaSet"}:                    {{"spec", "template", "spec"}},
	{Group: "", Kind: "ReplicationController"}:             {{"spec", "template", "spec"}},
	{Group: "batch", Kind: "Job"}:                          {{"spec", "template", "spec"}},
	{Group: "batch", Kind: "CronJob"}:                      {{"spec", "jobTemplate", "spec", "template", "spec"}},
	{Group: "argoproj.io", Kind: "Rollout"}:                {{"spec", "template", "spec"}},
	{Group: "argoproj.io", Kind: "CronWorkflow"}:           {{"spec", "workflowSpec", "templates"}},
	{Group: "serving.knative.dev", Kind: "Service"}:        {{"spec", "template", "spec"}},
	{Group: "serving.knative.dev", Kind: "Revision"}:       {{"spec"}},
	{Group: "ray.io", Kind: "RayCluster"}:                  {{"spec", "headGroupSpec", "template", "spec"}, {"spec", "workerGroupSpecs"}},
	{Group: "kubeflow.org", Kind: "PyTorchJob"}:            {{"spec", "pytorchReplicaSpecs"}},
	{Group: "kubeflow.org", Kind: "TFJob"}:                 {{"spec", "tfReplicaSpecs"}},
	{Group: "tekton.dev", Kind: "TaskRun"}:                 {{"spec", "podTemplate"}},
	{Group: "tekton.dev", Kind: "PipelineRun"}:             {{"spec", "podTemplate"}},
	{Group: "apps.openshift.io", Kind: "DeploymentConfig"}: {{"spec", "template", "spec"}},
	{Group: "kubevirt.io", Kind: "VirtualMachineInstance"}: {{"spec", "template", "spec"}},
	{Group: "kubevirt.io", Kind: "VirtualMachine"}:         {{"spec", "template", "spec", "template", "spec"}},
}

// mapAtPath resolves a JSON path. Numeric segments index arrays.
func mapAtPath(obj map[string]any, path []string) (map[string]any, bool) {
	var cur any = obj
	for _, seg := range path {
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[seg]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			idx := -1
			fmt.Sscanf(seg, "%d", &idx)
			if idx < 0 || idx >= len(node) {
				return nil, false
			}
			cur = node[idx]
		default:
			return nil, false
		}
	}
	m, ok := cur.(map[string]any)
	return m, ok
}

func isIndex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// --- small helpers shared by rules -------------------------------------------------

// GetMap returns a nested map value or nil.
func GetMap(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	v, _ := m[key].(map[string]any)
	return v
}

// EnsureMap returns the nested map, creating it when absent.
func EnsureMap(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	v := map[string]any{}
	m[key] = v
	return v
}

// GetBool reads a bool; ok is false when absent or of another type.
func GetBool(m map[string]any, key string) (value, ok bool) {
	if m == nil {
		return false, false
	}
	v, ok := m[key].(bool)
	return v, ok
}

// SetBool writes a bool.
func SetBool(m map[string]any, key string, v bool) {
	if m != nil {
		m[key] = v
	}
}

// GetString reads a string.
func GetString(m map[string]any, key string) (string, bool) {
	if m == nil {
		return "", false
	}
	v, ok := m[key].(string)
	return v, ok
}

// GetInt64 reads an integer from any JSON number encoding.
func GetInt64(m map[string]any, key string) (int64, bool) {
	if m == nil {
		return 0, false
	}
	switch v := m[key].(type) {
	case int64:
		return v, true
	case int32:
		return int64(v), true
	case int:
		return int64(v), true
	case float64:
		return int64(v), true
	case jsonNumber:
		n, err := v.Int64()
		return n, err == nil
	}
	return 0, false
}

type jsonNumber interface{ Int64() (int64, error) }

// GetStringSlice reads a []any of strings.
func GetStringSlice(m map[string]any, key string) ([]string, bool) {
	if m == nil {
		return nil, false
	}
	list, ok := m[key].([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out, true
}

// SetStringSlice writes a []any of strings.
func SetStringSlice(m map[string]any, key string, vals []string) {
	if m == nil {
		return
	}
	out := make([]any, 0, len(vals))
	for _, v := range vals {
		out = append(out, v)
	}
	m[key] = out
}

// RemoveKey deletes a key.
func RemoveKey(m map[string]any, key string) {
	delete(m, key)
}

// Volumes returns the volumes array of the pod spec.
func (p *PodSpec) Volumes() []map[string]any {
	return listOfMaps(p.Obj, "volumes")
}

// SetVolumes writes the volumes array back.
func (p *PodSpec) SetVolumes(vols []map[string]any) {
	out := make([]any, 0, len(vols))
	for _, v := range vols {
		out = append(out, v)
	}
	p.Obj["volumes"] = out
}

func listOfMaps(m map[string]any, key string) []map[string]any {
	raw, ok := m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if mm, ok := item.(map[string]any); ok {
			out = append(out, mm)
		}
	}
	return out
}

// ContainerRoleName is a human label for a role.
func ContainerRoleName(r Role) string { return string(r) }
