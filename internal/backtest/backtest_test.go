package backtest

import (
	"testing"
	"time"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/audit"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/rule"
)

func TestRun_CountsMatchesWithinWindow(t *testing.T) {
	now := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	entries := []audit.Entry{
		{Timestamp: now.Add(-10 * 24 * time.Hour), Server: "github", ToolName: "delete_file"}, // outside 7d window
		{Timestamp: now.Add(-1 * time.Hour), Server: "github", ToolName: "delete_file"},       // in window, matches
		{Timestamp: now.Add(-2 * time.Hour), Server: "github", ToolName: "read_file"},         // in window, no match
		{Timestamp: now.Add(-3 * time.Hour), Server: "aws", ToolName: "delete_file"},          // in window, different server
	}
	r := rule.Rule{ID: "r1", ServerScope: "github", CELExpression: `tool == "delete_file"`, Action: rule.ActionHardStop}

	result, err := Run(r, entries, now.Add(-7*24*time.Hour))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.TotalEntries != 2 {
		t.Fatalf("expected 2 in-scope entries within the window, got %d (%+v)", result.TotalEntries, result)
	}
	if result.Matched != 1 {
		t.Fatalf("expected exactly 1 match, got %d (%+v)", result.Matched, result)
	}
	if len(result.Examples) != 1 || result.Examples[0].ToolName != "delete_file" {
		t.Fatalf("expected the matched example to be delete_file, got %+v", result.Examples)
	}
}

func TestRun_WildcardScopeCoversEveryServer(t *testing.T) {
	now := time.Now()
	entries := []audit.Entry{
		{Timestamp: now, Server: "github", ToolName: "delete_file"},
		{Timestamp: now, Server: "aws", ToolName: "delete_file"},
	}
	r := rule.Rule{ID: "global", ServerScope: "*", CELExpression: `tool == "delete_file"`, Action: rule.ActionHardStop}

	result, err := Run(r, entries, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Matched != 2 {
		t.Fatalf("expected the wildcard rule to match both servers, got %d (%+v)", result.Matched, result)
	}
}

func TestRun_InvalidRuleReturnsError(t *testing.T) {
	r := rule.Rule{ID: "bad", ServerScope: "github", CELExpression: `tool ===`, Action: rule.ActionHardStop}

	_, err := Run(r, nil, time.Now())
	if err == nil {
		t.Fatalf("expected an error for a rule that fails to compile")
	}
}

func TestRun_EvaluationErrorsAreSkippedNotFatal(t *testing.T) {
	now := time.Now()
	entries := []audit.Entry{
		// params.force is absent on this historical call, which would fail
		// closed in live enforcement — Run should skip it, not error out.
		{Timestamp: now, Server: "github", ToolName: "push", Params: map[string]any{}},
	}
	r := rule.Rule{ID: "r1", ServerScope: "github", CELExpression: `params.force == true`, Action: rule.ActionHardStop}

	result, err := Run(r, entries, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Matched != 0 {
		t.Fatalf("expected the evaluation-error entry not to count as a match, got %+v", result)
	}
}
