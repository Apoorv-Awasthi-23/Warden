// Package backtest is the "test suite" a rule author (human or agent) runs
// before committing a rule: it replays a single candidate rule against real
// historical traffic recorded in the Audit Log and reports what it would
// have matched, without touching live enforcement or the Rule Store.
package backtest

import (
	"fmt"
	"time"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/audit"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/policy"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/rule"
)

// maxExamples caps how many matched entries Result.Examples keeps, so a rule
// that matches thousands of historical calls doesn't blow up the report.
const maxExamples = 20

// Result summarizes how often r would have matched, and against what.
type Result struct {
	RuleID       string
	Since        time.Time
	TotalEntries int
	Matched      int
	Examples     []audit.Entry
}

// Run evaluates r against every entry in entries whose Timestamp is at or
// after since, reconstructing each entry's original call and checking it
// against r in isolation (no other rules involved). A per-entry evaluation
// error (e.g. the candidate rule references a field this particular
// historical call didn't have) is skipped rather than aborting the whole
// backtest — the same call would have fail-closed in live enforcement, but a
// backtest's job is to report what the rule *would* have matched, not to
// simulate the full enforcement pipeline.
func Run(r rule.Rule, entries []audit.Entry, since time.Time) (Result, error) {
	engine, failures, err := policy.NewEngine([]rule.Rule{r})
	if err != nil {
		return Result{}, fmt.Errorf("building policy engine: %w", err)
	}
	if err, broken := failures[r.ServerScope]; broken {
		return Result{}, fmt.Errorf("rule %q does not compile: %w", r.ID, err)
	}

	result := Result{RuleID: r.ID, Since: since}

	for _, e := range entries {
		if e.Timestamp.Before(since) {
			continue
		}
		if r.ServerScope != "*" && e.Server != r.ServerScope {
			continue
		}

		params, _ := e.Params.(map[string]any)
		cc := policy.CallContext{Server: e.Server, Tool: e.ToolName, Params: params}

		result.TotalEntries++

		verdict, err := engine.Evaluate(cc)
		if err != nil {
			continue
		}
		if !verdict.Allowed {
			result.Matched++
			if len(result.Examples) < maxExamples {
				result.Examples = append(result.Examples, e)
			}
		}
	}

	return result, nil
}
