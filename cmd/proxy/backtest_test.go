package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/audit"
)

func seedAuditLogFile(t *testing.T, entries ...audit.Entry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	w, err := audit.Open(path)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	for _, e := range entries {
		if err := w.Log(e); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

func TestRunBacktest_WrongArgCount(t *testing.T) {
	for _, args := range [][]string{{}, {"a", "b"}} {
		_, err := captureStdout(t, func() error { return runBacktest(args) })
		if err == nil || !strings.Contains(err.Error(), "usage: mcp-policy-proxy backtest") {
			t.Fatalf("args=%v: expected a usage error, got %v", args, err)
		}
	}
}

func TestRunBacktest_InvalidSinceDuration(t *testing.T) {
	ruleFile := filepath.Join(writeRulesDir(t, `tool == "push"`), "github.yaml")

	_, err := captureStdout(t, func() error {
		return runBacktest([]string{"--since", "not-a-duration", ruleFile})
	})
	if err == nil || !strings.Contains(err.Error(), "invalid --since duration") {
		t.Fatalf("expected an invalid --since duration error, got %v", err)
	}
}

func TestRunBacktest_NonexistentRuleFile(t *testing.T) {
	_, err := captureStdout(t, func() error {
		return runBacktest([]string{filepath.Join(t.TempDir(), "does-not-exist.yaml")})
	})
	if err == nil || !strings.Contains(err.Error(), "loading rule file") {
		t.Fatalf("expected a 'loading rule file' error, got %v", err)
	}
}

func TestRunBacktest_EmptyRuleFile(t *testing.T) {
	dir := t.TempDir()
	ruleFile := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(ruleFile, []byte("rules: []\n"), 0o644); err != nil {
		t.Fatalf("writing empty rules file: %v", err)
	}

	_, err := captureStdout(t, func() error { return runBacktest([]string{ruleFile}) })
	if err == nil || !strings.Contains(err.Error(), "no rules found") {
		t.Fatalf("expected a 'no rules found' error, got %v", err)
	}
}

func TestRunBacktest_MissingAuditLogIsNotAnError(t *testing.T) {
	ruleFile := filepath.Join(writeRulesDir(t, `tool == "push"`), "github.yaml")

	out, err := captureStdout(t, func() error {
		return runBacktest([]string{"--audit-log", filepath.Join(t.TempDir(), "no-such-log.jsonl"), ruleFile})
	})
	if err != nil {
		t.Fatalf("runBacktest: %v", err)
	}
	if !strings.Contains(out, "would have matched 0/0") {
		t.Fatalf("expected a zero-entry backtest report, got %q", out)
	}
}

func TestRunBacktest_HappyPath(t *testing.T) {
	ruleFile := filepath.Join(writeRulesDir(t, `tool == "push"`), "github.yaml")
	auditLog := seedAuditLogFile(t,
		audit.Entry{Server: "github", ToolName: "push", Params: map[string]any{}, Outcome: audit.OutcomeAllowed},
		audit.Entry{Server: "github", ToolName: "read_file", Params: map[string]any{}, Outcome: audit.OutcomeAllowed},
	)

	out, err := captureStdout(t, func() error {
		return runBacktest([]string{"--audit-log", auditLog, "--since", "24h", ruleFile})
	})
	if err != nil {
		t.Fatalf("runBacktest: %v", err)
	}
	if !strings.Contains(out, "would have matched 1/2") {
		t.Fatalf("expected the push call to match 1/2, got %q", out)
	}
}
