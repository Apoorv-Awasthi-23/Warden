package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/audit"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/backtest"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/rulestore"
)

// runBacktest is the `mcp-policy-proxy backtest` subcommand: the "test
// suite" a rule author runs before committing a rule (architecture.md
// section 5.6). It replays every rule in the given file against the audit
// log and reports what each would have matched.
func runBacktest(args []string) error {
	fs := flag.NewFlagSet("backtest", flag.ContinueOnError)
	since := fs.String("since", "168h", "how far back to replay, as a Go duration (default 168h = 7 days)")
	auditLogPath := fs.String("audit-log", "audit.log", "path to the audit log to replay")
	server := fs.String("server", "", "override the server scope derived from the rule file's name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		// Flags must precede the positional rule-file argument — that's a
		// property of Go's flag package (it stops parsing flags at the
		// first non-flag argument), not a proxy-specific convention.
		return fmt.Errorf("usage: mcp-policy-proxy backtest [--since 168h] [--audit-log audit.log] <rule-file>")
	}
	ruleFile := fs.Arg(0)

	window, err := time.ParseDuration(*since)
	if err != nil {
		return fmt.Errorf("invalid --since duration %q: %w", *since, err)
	}

	rules, err := rulestore.LoadFile(ruleFile, *server)
	if err != nil {
		return fmt.Errorf("loading rule file %q: %w", ruleFile, err)
	}
	if len(rules) == 0 {
		return fmt.Errorf("%q: no rules found", ruleFile)
	}

	entries, err := audit.ReadAll(*auditLogPath)
	if err != nil {
		return fmt.Errorf("reading audit log %q: %w", *auditLogPath, err)
	}

	sinceTime := time.Now().Add(-window)

	for _, r := range rules {
		result, err := backtest.Run(r, entries, sinceTime)
		if err != nil {
			fmt.Printf("%s: ERROR %v\n", r.ID, err)
			continue
		}

		fmt.Printf("%s: would have matched %d/%d call(s) since %s\n",
			result.RuleID, result.Matched, result.TotalEntries, result.Since.Format(time.RFC3339))
		for _, e := range result.Examples {
			fmt.Printf("    %s  %s/%s\n", e.Timestamp.Format(time.RFC3339), e.Server, e.ToolName)
		}
	}

	return nil
}
