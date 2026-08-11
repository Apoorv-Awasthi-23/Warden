package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/audit"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/catalog"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/config"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/policy"
)

func mustAuditWriter(t *testing.T) *audit.Writer {
	t.Helper()
	w, err := audit.Open(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { w.Close() })
	return w
}

func catalogWithField(t *testing.T, field string) *catalog.Catalog {
	t.Helper()
	cat := catalog.New()
	if err := cat.Update("github", []*mcp.Tool{
		{
			Name: "delete_file",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{field: map[string]any{"type": "string"}},
			},
		},
	}); err != nil {
		t.Fatalf("cat.Update: %v", err)
	}
	return cat
}

func writeRulesDir(t *testing.T, celExpr string) string {
	t.Helper()
	dir := t.TempDir()
	content := "rules:\n  - id: block\n    cel_expression: '" + celExpr + "'\n    action: hard_stop\n"
	if err := os.WriteFile(filepath.Join(dir, "github.yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing rules file: %v", err)
	}
	return dir
}

func testConfig(rulesDir string) *config.Config {
	return &config.Config{
		Servers:  []config.ServerConfig{{Name: "github", Transport: config.TransportStdio, Command: "true"}},
		RulesDir: rulesDir,
	}
}

// TestBuildEnforcer_SchemaDriftBlocksAffectedServer simulates Schema Drift
// Detection's actual safety mechanism: a rule that was valid against one
// schema snapshot fails schemacheck.Check once
// the field it references disappears from the live catalog on a later
// startup, and the affected server fails closed exactly as it would for a
// CEL compile error — with no special drift-specific code path.
func TestBuildEnforcer_SchemaDriftBlocksAffectedServer(t *testing.T) {
	// has() guards the field so a call that doesn't set it just evaluates to
	// false (allowed) rather than a runtime error — the test only cares
	// about the load-time schema check, not this particular call matching.
	rulesDir := writeRulesDir(t, `has(params.path) && params.path == "x"`)
	cfg := testConfig(rulesDir)
	cc := policy.CallContext{Server: "github", Tool: "delete_file"}

	// First "startup": the schema still has the field the rule references.
	enforcer, err := buildEnforcer(cfg, mustAuditWriter(t), catalogWithField(t, "path"))
	if err != nil {
		t.Fatalf("buildEnforcer: %v", err)
	}
	result, err := enforcer.Enforce(context.Background(), "agent-1", cc)
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("expected the call to be allowed before drift, got %+v", result)
	}

	// Second "startup": upstream renamed the field out from under the rule.
	drifted, err := buildEnforcer(cfg, mustAuditWriter(t), catalogWithField(t, "file_path"))
	if err != nil {
		t.Fatalf("buildEnforcer after drift: %v", err)
	}
	result, err = drifted.Enforce(context.Background(), "agent-1", cc)
	if err != nil {
		t.Fatalf("Enforce after drift: %v", err)
	}
	if result.Allowed {
		t.Fatalf("expected the server to fail closed after its rule's field disappeared, got %+v", result)
	}
	if result.RejectReason == "" {
		t.Fatalf("expected a non-empty reject reason explaining the block")
	}

	// Fixing the rule (or the schema) to match again should unblock it.
	fixed, err := buildEnforcer(cfg, mustAuditWriter(t), catalogWithField(t, "path"))
	if err != nil {
		t.Fatalf("buildEnforcer after fix: %v", err)
	}
	result, err = fixed.Enforce(context.Background(), "agent-1", cc)
	if err != nil {
		t.Fatalf("Enforce after fix: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("expected the server to recover once the field exists again, got %+v", result)
	}
}
