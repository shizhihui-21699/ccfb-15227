package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadManifestsMultiDocAndList(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "m.yaml")
	content := `apiVersion: v1
kind: Deployment
metadata: {name: a}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: b}
---
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Pod
    metadata: {name: c}
  - apiVersion: v1
    kind: Pod
    metadata: {name: d}
`
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	objs, err := loadManifests(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 4 {
		t.Fatalf("expected 4 objects (List flattened), got %d", len(objs))
	}
	names := []string{}
	for _, o := range objs {
		names = append(names, metaFromObject(o.Object).name)
	}
	if strings.Join(names, ",") != "a,b,c,d" {
		t.Fatalf("names = %v", names)
	}
}

func TestParseNamespaceLabels(t *testing.T) {
	got := parseNamespaceLabels("team-a=payments:strict,team-b=web,team-c=guard.example.com/enforcement=disabled")
	if got["team-a"]["guard.example.com/team"] != "payments" {
		t.Fatalf("team label missing: %v", got)
	}
	if got["team-a"]["guard.example.com/enforcement"] != "strict" {
		t.Fatalf("enforcement override missing: %v", got)
	}
	if got["team-b"]["guard.example.com/team"] != "web" {
		t.Fatalf("team-b wrong: %v", got)
	}
	if got["team-c"]["guard.example.com/enforcement"] != "disabled" {
		t.Fatalf("arbitrary label form wrong: %v", got)
	}
}

func TestParseGVK(t *testing.T) {
	g, err := parseGVK("apps/v1", "Deployment")
	if err != nil || g.Group != "apps" || g.Version != "v1" || g.Kind != "Deployment" {
		t.Fatalf("got %+v err=%v", g, err)
	}
	g, err = parseGVK("v1", "Pod")
	if err != nil || g.Group != "" || g.Kind != "Pod" {
		t.Fatalf("core group: got %+v err=%v", g, err)
	}
	if _, err := parseGVK("", ""); err == nil {
		t.Fatal("empty kind/apiVersion must be rejected")
	}
}

func TestValidatePoliciesCommand(t *testing.T) {
	dir := t.TempDir()
	// A policy whose exemption expires within the warning window.
	soon := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	policy := `apiVersion: guard.example.com/v1alpha1
kind: SecurityPolicy
metadata: {name: p}
spec:
  rules: [{id: pod.privileged}]
  exemptions:
    - id: e
      reason: r
      requestedBy: u
      expiresAt: "` + soon + `"
      scope: {namespaces: [a], rules: ["*"]}
`
	if err := os.WriteFile(filepath.Join(dir, "p.yaml"), []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdValidatePolicies([]string{"--policy-dir", dir, "--json"}); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	// A broken policy exits with an error.
	bad := strings.Replace(policy, "pod.privileged", "pod.nope", 1)
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	err := cmdValidatePolicies([]string{"--policy-dir", dir})
	if err == nil {
		t.Fatal("invalid policy must fail the command")
	}
	if ee, ok := err.(*exitError); !ok || ee.code == 0 {
		t.Fatalf("expected an exit error, got %#v", err)
	}
}
