// Command admissionctl is the operator CLI.
//
// Subcommands:
//
//	validate-policies   parse and validate policy files (CI gate)
//	render-webhook-config  emit the split-failurePolicy webhook configuration
//	simulate            evaluate manifests against a policy directory offline
//	e2e                 start the real webhook + simulated API server and
//	                    replay manifests through a real AdmissionReview round trip
//	explain             print the effective policies and exemptions for a namespace
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "validate-policies":
		err = cmdValidatePolicies(args)
	case "render-webhook-config":
		err = cmdRenderWebhookConfig(args)
	case "simulate":
		err = cmdSimulate(args)
	case "e2e":
		err = cmdE2E(args)
	case "explain":
		err = cmdExplain(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `admissionctl - manage cluster admission guard policies

Usage:
  admissionctl validate-policies --policy-dir DIR [--json]
  admissionctl render-webhook-config --service NAME --namespace NS [--ca-bundle FILE] [--mode split|fail-closed|fail-open]
  admissionctl simulate --policy-dir DIR --manifest FILE|DIR [--namespace LABELS-FILE] [--json]
  admissionctl e2e --policy-dir DIR --manifest FILE|DIR [--json]
  admissionctl explain --policy-dir DIR --namespace NS [--labels k=v,...]
`)
}

// stringListFlag collects repeated flags.
type stringListFlag []string

func (s *stringListFlag) String() string { return strings.Join(*s, ",") }
func (s *stringListFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// exitError lets a command return a non-zero exit code with a message.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
