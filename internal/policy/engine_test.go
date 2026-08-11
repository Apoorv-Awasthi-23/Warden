package policy

import (
	"strings"
	"testing"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/rule"
)

func mustEngine(t *testing.T, rules []rule.Rule) *Engine {
	t.Helper()
	engine, failures, err := NewEngine(rules)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if len(failures) != 0 {
		t.Fatalf("unexpected compile failures: %v", failures)
	}
	return engine
}

func TestEvaluate_NoMatchAllows(t *testing.T) {
	engine := mustEngine(t, []rule.Rule{
		{ID: "r1", ServerScope: "github", CELExpression: `tool == "delete_file"`, Action: rule.ActionHardStop},
	})

	v, err := engine.Evaluate(CallContext{Server: "github", Tool: "read_file"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !v.Allowed {
		t.Fatalf("expected Allowed=true, got %+v", v)
	}
	if len(v.MatchedRules) != 0 {
		t.Fatalf("expected no matched rules, got %v", v.MatchedRules)
	}
}

func TestEvaluate_HardStopMatch(t *testing.T) {
	engine := mustEngine(t, []rule.Rule{
		{ID: "r1", ServerScope: "github", CELExpression: `tool == "delete_file"`, Action: rule.ActionHardStop},
	})

	v, err := engine.Evaluate(CallContext{Server: "github", Tool: "delete_file"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Allowed || v.Action != rule.ActionHardStop {
		t.Fatalf("expected hard_stop, got %+v", v)
	}
	if len(v.MatchedRules) != 1 || v.MatchedRules[0] != "r1" {
		t.Fatalf("expected matched rule r1, got %v", v.MatchedRules)
	}
}

func TestEvaluate_RequireApprovalMatch(t *testing.T) {
	engine := mustEngine(t, []rule.Rule{
		{ID: "r1", ServerScope: "github", CELExpression: `tool == "push"`, Action: rule.ActionRequireApproval},
	})

	v, err := engine.Evaluate(CallContext{Server: "github", Tool: "push"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Allowed || v.Action != rule.ActionRequireApproval {
		t.Fatalf("expected require_approval, got %+v", v)
	}
}

func TestEvaluate_ConflictHardStopWins(t *testing.T) {
	engine := mustEngine(t, []rule.Rule{
		{ID: "hard", ServerScope: "github", CELExpression: `tool == "push"`, Action: rule.ActionHardStop},
		{ID: "approval", ServerScope: "github", CELExpression: `tool == "push"`, Action: rule.ActionRequireApproval},
	})

	v, err := engine.Evaluate(CallContext{Server: "github", Tool: "push"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Allowed || v.Action != rule.ActionHardStop {
		t.Fatalf("expected hard_stop to win, got %+v", v)
	}
	if !v.Conflict {
		t.Fatalf("expected Conflict=true when both actions match, got %+v", v)
	}
	if len(v.MatchedRules) != 2 {
		t.Fatalf("expected both rules recorded as matched, got %v", v.MatchedRules)
	}
}

func TestEvaluate_ServerScopeFiltering(t *testing.T) {
	engine := mustEngine(t, []rule.Rule{
		{ID: "github-only", ServerScope: "github", CELExpression: `tool == "delete_file"`, Action: rule.ActionHardStop},
		{ID: "everywhere", ServerScope: "*", CELExpression: `tool == "delete_file"`, Action: rule.ActionHardStop},
	})

	v, err := engine.Evaluate(CallContext{Server: "aws", Tool: "delete_file"})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Allowed {
		t.Fatalf("expected wildcard rule to still block aws, got %+v", v)
	}
	if len(v.MatchedRules) != 1 || v.MatchedRules[0] != "everywhere" {
		t.Fatalf("expected only the wildcard rule to match, got %v", v.MatchedRules)
	}
}

func TestEvaluate_UnrelatedServerRuleNeverEvaluated(t *testing.T) {
	// github's rule references params.force without a has() guard, which
	// errors at eval time if the field is missing (see
	// TestEvaluate_MissingFieldWithoutGuardFailsClosedWithExplicitError
	// below). A call to aws carries no such param. If Evaluate merely
	// skipped this rule on a scope mismatch after evaluating it, or scanned
	// it at all, this would surface that CEL runtime error; scoping it out
	// up front means it's never evaluated for an aws call.
	engine := mustEngine(t, []rule.Rule{
		{ID: "github-only", ServerScope: "github", CELExpression: `params.force == true`, Action: rule.ActionHardStop},
	})

	v, err := engine.Evaluate(CallContext{Server: "aws", Tool: "delete_file", Params: map[string]any{}})
	if err != nil {
		t.Fatalf("Evaluate: unexpected error, github's rule should never have been evaluated for aws: %v", err)
	}
	if !v.Allowed {
		t.Fatalf("expected Allowed=true, got %+v", v)
	}
}

func TestNewEngine_CompileErrorsAttributedPerServer(t *testing.T) {
	_, failures, err := NewEngine([]rule.Rule{
		{ID: "good", ServerScope: "github", CELExpression: `tool == "delete_file"`, Action: rule.ActionHardStop},
		{ID: "bad", ServerScope: "aws", CELExpression: `tool ===`, Action: rule.ActionHardStop},
	})
	if err != nil {
		t.Fatalf("NewEngine returned a fatal error for a per-rule problem: %v", err)
	}
	if _, ok := failures["aws"]; !ok {
		t.Fatalf("expected a compile failure attributed to 'aws', got %v", failures)
	}
	if _, ok := failures["github"]; ok {
		t.Fatalf("github's valid rule should not be affected by aws's broken rule, failures=%v", failures)
	}
}

func TestNewEngine_NonBoolOutputRejected(t *testing.T) {
	_, failures, err := NewEngine([]rule.Rule{
		{ID: "bad", ServerScope: "github", CELExpression: `"not a bool"`, Action: rule.ActionHardStop},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if _, ok := failures["github"]; !ok {
		t.Fatalf("expected a failure for non-bool cel_expression, got %v", failures)
	}
}

func TestEvaluate_MissingFieldWithoutGuardFailsClosedWithExplicitError(t *testing.T) {
	engine := mustEngine(t, []rule.Rule{
		{ID: "r1", ServerScope: "github", CELExpression: `params.force == true`, Action: rule.ActionHardStop},
	})

	_, err := engine.Evaluate(CallContext{Server: "github", Tool: "push", Params: map[string]any{}})
	if err == nil {
		t.Fatalf("expected an error for a missing params field, got nil")
	}
	if !strings.Contains(err.Error(), "r1") {
		t.Fatalf("expected error to name the offending rule, got: %v", err)
	}
}

func TestEvaluate_HasGuardAvoidsMissingFieldError(t *testing.T) {
	engine := mustEngine(t, []rule.Rule{
		{ID: "r1", ServerScope: "github", CELExpression: `has(params.force) && params.force == true`, Action: rule.ActionHardStop},
	})

	v, err := engine.Evaluate(CallContext{Server: "github", Tool: "push", Params: map[string]any{}})
	if err != nil {
		t.Fatalf("Evaluate with has() guard should not error: %v", err)
	}
	if !v.Allowed {
		t.Fatalf("expected allowed when guarded field is absent, got %+v", v)
	}
}

func TestEvaluate_NestedAndArrayFieldAccess(t *testing.T) {
	engine := mustEngine(t, []rule.Rule{
		{ID: "nested", ServerScope: "aws", CELExpression: `has(params.tags) && params.tags.environment == "production"`, Action: rule.ActionHardStop},
		{ID: "array", ServerScope: "github", CELExpression: `"main" in params.branches`, Action: rule.ActionHardStop},
	})

	v, err := engine.Evaluate(CallContext{
		Server: "aws",
		Tool:   "terminate_instance",
		Params: map[string]any{"tags": map[string]any{"environment": "production"}},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Allowed {
		t.Fatalf("expected nested field match to block the call, got %+v", v)
	}

	v2, err := engine.Evaluate(CallContext{
		Server: "github",
		Tool:   "push",
		Params: map[string]any{"branches": []any{"main", "dev"}},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v2.Allowed {
		t.Fatalf("expected array membership match to block the call, got %+v", v2)
	}
}
