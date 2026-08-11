package main

import (
	"flag"
	"fmt"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/policy"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/rulestore"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/schemacheck"
)

// runValidate is the `mcp-policy-proxy validate` subcommand: the "compiler"
// a rule author (human or agent) runs before committing a rule. It checks
// every rule in rules-dir for CEL compile errors and for params fields that
// don't exist on any tool in scope, using the schema dump on disk — no live
// MCP connections required.
//
// Usage: mcp-policy-proxy validate [--schemas-dir dir] [rules-dir]
// Flags must precede the positional rules-dir argument — Go's flag package
// stops parsing flags at the first non-flag argument.
func runValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	schemasDir := fs.String("schemas-dir", "schemas", "directory schema dumps are read from")
	if err := fs.Parse(args); err != nil {
		return err
	}

	rulesDir := "rules"
	if fs.NArg() > 0 {
		rulesDir = fs.Arg(0)
	}

	store, loadErrors, err := rulestore.Load(rulesDir)
	if err != nil {
		return fmt.Errorf("loading rules from %q: %w", rulesDir, err)
	}

	ok := true
	for server, err := range loadErrors {
		ok = false
		fmt.Printf("FAIL  %s: failed to load: %v\n", server, err)
	}

	_, compileErrors, err := policy.NewEngine(store.All())
	if err != nil {
		return fmt.Errorf("building policy engine: %w", err)
	}
	for server, err := range compileErrors {
		ok = false
		fmt.Printf("FAIL  %s: failed to compile: %v\n", server, err)
	}

	env, err := policy.NewEnv()
	if err != nil {
		return err
	}
	src, err := schemacheck.FromDump(*schemasDir)
	if err != nil {
		return fmt.Errorf("loading schema dumps from %q: %w", *schemasDir, err)
	}

	checked := 0
	for _, r := range store.All() {
		if _, compileFailed := compileErrors[r.ServerScope]; compileFailed {
			// Already reported above; compile errors are tracked per-server,
			// not per-rule, so this server's other rules aren't individually
			// re-checked until the compile error is fixed.
			continue
		}
		checked++
		if err := schemacheck.Check(r, env, src); err != nil {
			ok = false
			fmt.Printf("FAIL  %s\n", err)
			continue
		}
		fmt.Printf("PASS  %s\n", r.ID)
	}

	fmt.Printf("\n%d rule(s) loaded from %q, %d checked against schema data in %q\n",
		len(store.All()), rulesDir, checked, *schemasDir)

	if !ok {
		return fmt.Errorf("validation failed")
	}
	fmt.Println("all rules valid")
	return nil
}
