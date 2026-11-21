package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// manifestObject is one resource from a manifest file.
type manifestObject struct {
	Source string
	Doc    int
	// Kind, APIVersion as written.
	Kind       string
	APIVersion string
	Object     map[string]any
}

// loadManifests reads a file or every *.yaml/*.yml under a directory. It
// supports multi-document streams and v1 List objects (flattened), which is how
// `kubectl get -o yaml` output and Helm manifests are usually laid out.
func loadManifests(path string) ([]manifestObject, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	var files []string
	if info.IsDir() {
		err := filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if ext == ".yaml" || ext == ".yml" || ext == ".json" {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		sort.Strings(files)
	} else {
		files = []string{path}
	}

	var out []manifestObject
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		docs, err := splitYAML(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		for i, doc := range docs {
			if len(strings.TrimSpace(string(doc))) == 0 {
				continue
			}
			var obj map[string]any
			if err := yaml.Unmarshal(doc, &obj); err != nil {
				return nil, fmt.Errorf("%s document %d: %w", f, i+1, err)
			}
			if obj == nil {
				continue
			}
			kind, _ := obj["kind"].(string)
			apiVersion, _ := obj["apiVersion"].(string)
			if kind == "List" || strings.HasSuffix(kind, "List") {
				if items, ok := obj["items"].([]any); ok {
					for j, item := range items {
						im, ok := item.(map[string]any)
						if !ok {
							continue
						}
						k, _ := im["kind"].(string)
						av, _ := im["apiVersion"].(string)
						out = append(out, manifestObject{Source: f, Doc: i + 1, Kind: k, APIVersion: av, Object: im})
						_ = j
					}
					continue
				}
			}
			out = append(out, manifestObject{Source: f, Doc: i + 1, Kind: kind, APIVersion: apiVersion, Object: obj})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no objects found in %s", path)
	}
	return out, nil
}

func splitYAML(data []byte) ([][]byte, error) {
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
