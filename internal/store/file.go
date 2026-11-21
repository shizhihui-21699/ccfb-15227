package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/example/cluster-admission-guard/internal/policy"
	"sigs.k8s.io/yaml"
)

// FileStore loads policy YAML from a directory (the layout produced by mounting
// a ConfigMap). Each *.yaml/*.yml file may hold one document or a multi-document
// stream.
//
// The directory is the unit of atomicity: a single bad document makes the whole
// load fail and the previous snapshot is kept, because silently applying only
// the policies that happened to parse would drop protection without anyone
// noticing.
type FileStore struct {
	*SnapshotStore
	Dir string
	// NamespaceLabels optionally supplies namespace metadata when running
	// without a cluster (see cmd/admissiond --offline and the simulator).
	NamespaceLabels map[string]map[string]string
}

// NewFileStore loads dir.
func NewFileStore(dir string) (*FileStore, error) {
	fs := &FileStore{
		SnapshotStore:   NewSnapshotStore(nil),
		Dir:             dir,
		NamespaceLabels: map[string]map[string]string{},
	}
	fs.SnapshotStore.SetNamespaceResolver(func(name string) (policy.NamespaceInfo, bool) {
		labels, ok := fs.NamespaceLabels[name]
		if !ok {
			return policy.NamespaceInfo{}, false
		}
		return namespaceInfo(name, labels), true
	})
	if err := fs.Reload(); err != nil {
		return fs, err
	}
	return fs, nil
}

// Reload re-reads the directory. On any error the last good snapshot is kept
// with its policies but Health() starts reporting the failure, so the webhook
// can fail closed for strict namespaces and fail open elsewhere.
func (f *FileStore) Reload() error {
	loaded, err := LoadDir(f.Dir)
	if err != nil {
		prev := f.Current()
		f.Swap(&Loaded{
			Policies:   prev.Policies,
			TrustStore: prev.TrustStore,
			Errors:     loaded.Errors,
			LoadedAt:   prev.LoadedAt,
			Source:     prev.Source,
		})
		return err
	}
	loaded.Source = f.Dir
	f.Swap(loaded)
	return nil
}

// LoadDir parses every YAML document in dir.
func LoadDir(dir string) (*Loaded, error) {
	loaded := &Loaded{LoadedAt: time.Now()}
	entries, err := os.ReadDir(dir)
	if err != nil {
		loaded.Errors = append(loaded.Errors, fmt.Errorf("read policy directory %s: %w", dir, err))
		return loaded, loaded.Errors[0]
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	var problems []error
	seen := map[string]string{}
	for _, name := range names {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", name, err))
			continue
		}
		docs, err := splitDocuments(data)
		if err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", name, err))
			continue
		}
		for i, doc := range docs {
			if len(strings.TrimSpace(string(doc))) == 0 {
				continue
			}
			kind, apiVersion := peekKind(doc)
			where := fmt.Sprintf("%s document %d", name, i+1)
			switch {
			case kind == policy.KindPolicy:
				cp, err := policy.ParsePolicy(doc)
				if err != nil {
					problems = append(problems, fmt.Errorf("%s: %w", where, err))
					continue
				}
				if prev, dup := seen[cp.Metadata.Name]; dup {
					problems = append(problems, fmt.Errorf("%s: policy %q already defined in %s", where, cp.Metadata.Name, prev))
					continue
				}
				seen[cp.Metadata.Name] = where
				loaded.Policies = append(loaded.Policies, cp)
			case kind == policy.KindTrustStore:
				ts, err := policy.ParseTrustStore(doc)
				if err != nil {
					problems = append(problems, fmt.Errorf("%s: %w", where, err))
					continue
				}
				if loaded.TrustStore != nil {
					problems = append(problems, fmt.Errorf("%s: multiple TrustStore documents are not allowed", where))
					continue
				}
				loaded.TrustStore = ts
			default:
				problems = append(problems, fmt.Errorf("%s: unsupported document %s/%s (expected %s or %s)", where, apiVersion, kind, policy.KindPolicy, policy.KindTrustStore))
			}
		}
	}
	sort.Slice(loaded.Policies, func(i, j int) bool {
		return loaded.Policies[i].Metadata.Name < loaded.Policies[j].Metadata.Name
	})
	loaded.Errors = problems
	if len(problems) > 0 {
		return loaded, problems[0]
	}
	return loaded, nil
}

func peekKind(doc []byte) (kind, apiVersion string) {
	var header struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
	}
	if err := yaml.Unmarshal(doc, &header); err != nil {
		return "", ""
	}
	return header.Kind, header.APIVersion
}

// splitDocuments splits a YAML stream on "---" separator lines. Using the raw
// separators instead of a streaming decoder means one malformed document does
// not hide the document boundaries needed for precise error messages.
func splitDocuments(data []byte) ([][]byte, error) {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	var docs [][]byte
	var cur []string
	flush := func() {
		if len(cur) > 0 {
			docs = append(docs, []byte(strings.Join(cur, "\n")))
			cur = nil
		}
	}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "---" || strings.HasPrefix(trimmed, "--- #") {
			flush()
			continue
		}
		cur = append(cur, line)
	}
	flush()
	return docs, nil
}
