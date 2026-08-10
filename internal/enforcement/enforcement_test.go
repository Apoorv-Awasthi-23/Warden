package enforcement

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/approval"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/audit"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/policy"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/rule"
)

type mockApprover struct {
	decision approval.Decision
	detail   string
	err      error
	called   bool
}

func (m *mockApprover) Request(ctx context.Context, timeout time.Duration, cc policy.CallContext, matchedRules []string) (approval.Decision, string, error) {
	m.called = true
	return m.decision, m.detail, m.err
}

func newTestAuditor(t *testing.T) (*audit.Writer, func() []audit.Entry) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	w, err := audit.Open(path)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { w.Close() })

	return w, func() []audit.Entry {
		w.Close() // flush by closing; test only reads after done writing
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("reopening audit log: %v", err)
		}
		defer f.Close()

		var entries []audit.Entry
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var e audit.Entry
			if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
				t.Fatalf("decoding audit entry: %v", err)
			}
			entries = append(entries, e)
		}
		return entries
	}
}

func mustEngine(t *testing.T, rules []rule.Rule) *policy.Engine {
	t.Helper()
	engine, failures, err := policy.NewEngine(rules)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if len(failures) != 0 {
		t.Fatalf("unexpected compile failures: %v", failures)
	}
	return engine
}

func TestEnforce_Allow(t *testing.T) {
	engine := mustEngine(t, nil)
	auditor, readEntries := newTestAuditor(t)
	e := New(engine, &mockApprover{}, auditor, time.Second, nil)

	result, err := e.Enforce(context.Background(), "agent-1", policy.CallContext{Server: "github", Tool: "read_file"})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed, got %+v", result)
	}

	entries := readEntries()
	if len(entries) != 1 || entries[0].Outcome != audit.OutcomeAllowed {
		t.Fatalf("expected exactly one allowed audit entry, got %+v", entries)
	}
}

func TestEnforce_HardStop(t *testing.T) {
	engine := mustEngine(t, []rule.Rule{
		{ID: "block", ServerScope: "github", CELExpression: `tool == "delete_file"`, Action: rule.ActionHardStop},
	})
	auditor, readEntries := newTestAuditor(t)
	e := New(engine, &mockApprover{}, auditor, time.Second, nil)

	result, err := e.Enforce(context.Background(), "agent-1", policy.CallContext{Server: "github", Tool: "delete_file"})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if result.Allowed || result.RejectReason == "" {
		t.Fatalf("expected a rejected call with a reason, got %+v", result)
	}

	entries := readEntries()
	if len(entries) != 1 || entries[0].Outcome != audit.OutcomeHardStopped {
		t.Fatalf("expected exactly one hard_stopped audit entry, got %+v", entries)
	}
	if len(entries[0].RulesEvaluated) != 1 || entries[0].RulesEvaluated[0] != "block" {
		t.Fatalf("expected rules_evaluated to include the matched rule, got %+v", entries[0].RulesEvaluated)
	}
}

func TestEnforce_EvaluationErrorBlocksWithExplicitReason(t *testing.T) {
	engine := mustEngine(t, []rule.Rule{
		{ID: "bad", ServerScope: "github", CELExpression: `params.force == true`, Action: rule.ActionHardStop},
	})
	auditor, readEntries := newTestAuditor(t)
	e := New(engine, &mockApprover{}, auditor, time.Second, nil)

	result, err := e.Enforce(context.Background(), "agent-1", policy.CallContext{Server: "github", Tool: "push", Params: map[string]any{}})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if result.Allowed {
		t.Fatalf("expected the call to be blocked on evaluation error")
	}
	if result.RejectReason == "" {
		t.Fatalf("expected a non-empty explicit reject reason")
	}

	entries := readEntries()
	if len(entries) != 1 || entries[0].Outcome != audit.OutcomeHardStopped {
		t.Fatalf("expected one hard_stopped audit entry for the evaluation error, got %+v", entries)
	}
}

func TestEnforce_RequireApproval_Approved(t *testing.T) {
	engine := mustEngine(t, []rule.Rule{
		{ID: "approve-me", ServerScope: "github", CELExpression: `tool == "push"`, Action: rule.ActionRequireApproval},
	})
	auditor, readEntries := newTestAuditor(t)
	approver := &mockApprover{decision: approval.DecisionApproved, detail: "alice"}
	e := New(engine, approver, auditor, time.Second, nil)

	result, err := e.Enforce(context.Background(), "agent-1", policy.CallContext{Server: "github", Tool: "push"})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed after approval, got %+v", result)
	}
	if !approver.called {
		t.Fatalf("expected the approver to be invoked")
	}

	entries := readEntries()
	if len(entries) != 1 || entries[0].Outcome != audit.OutcomeApproved || entries[0].Approver != "alice" {
		t.Fatalf("expected exactly one approved audit entry with approver, got %+v", entries)
	}
}

func TestEnforce_RequireApproval_Denied(t *testing.T) {
	engine := mustEngine(t, []rule.Rule{
		{ID: "approve-me", ServerScope: "github", CELExpression: `tool == "push"`, Action: rule.ActionRequireApproval},
	})
	auditor, readEntries := newTestAuditor(t)
	approver := &mockApprover{decision: approval.DecisionDenied, detail: "denied by approver"}
	e := New(engine, approver, auditor, time.Second, nil)

	result, err := e.Enforce(context.Background(), "agent-1", policy.CallContext{Server: "github", Tool: "push"})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if result.Allowed {
		t.Fatalf("expected denied, got %+v", result)
	}

	entries := readEntries()
	if len(entries) != 1 || entries[0].Outcome != audit.OutcomeDenied {
		t.Fatalf("expected exactly one denied audit entry, got %+v", entries)
	}
}

func TestEnforce_RequireApproval_TimedOut(t *testing.T) {
	engine := mustEngine(t, []rule.Rule{
		{ID: "approve-me", ServerScope: "github", CELExpression: `tool == "push"`, Action: rule.ActionRequireApproval},
	})
	auditor, readEntries := newTestAuditor(t)
	const wantReason = "blocked — no approval received within the time limit"
	approver := &mockApprover{decision: approval.DecisionTimedOut, detail: wantReason}
	e := New(engine, approver, auditor, time.Second, nil)

	result, err := e.Enforce(context.Background(), "agent-1", policy.CallContext{Server: "github", Tool: "push"})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if result.Allowed || result.RejectReason != wantReason {
		t.Fatalf("expected timed-out rejection with exact wording, got %+v", result)
	}

	entries := readEntries()
	if len(entries) != 1 || entries[0].Outcome != audit.OutcomeTimedOut {
		t.Fatalf("expected exactly one timed_out audit entry, got %+v", entries)
	}
}

func TestEnforce_BlockedServerSkipsEngineEntirely(t *testing.T) {
	engine := mustEngine(t, nil) // zero rules — would allow everything if reached
	auditor, readEntries := newTestAuditor(t)
	approver := &mockApprover{}
	blocked := map[string]string{"aws": "blocked — policy rules for server \"aws\" failed to load"}
	e := New(engine, approver, auditor, time.Second, blocked)

	result, err := e.Enforce(context.Background(), "agent-1", policy.CallContext{Server: "aws", Tool: "anything"})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if result.Allowed {
		t.Fatalf("expected the blocked server's call to be rejected, got %+v", result)
	}
	if approver.called {
		t.Fatalf("did not expect the approver to be consulted for a blocked server")
	}

	entries := readEntries()
	if len(entries) != 1 || entries[0].Outcome != audit.OutcomeHardStopped {
		t.Fatalf("expected exactly one hard_stopped audit entry, got %+v", entries)
	}
}
