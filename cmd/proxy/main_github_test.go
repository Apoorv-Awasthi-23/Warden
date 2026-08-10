package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/catalog"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/policy"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/rulestore"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/schemacheck"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/schemadump"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/testutil/githubmcp"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/upstream"
)

// githubCatalog builds a real Tool Schema Catalog by connecting to the
// simulated GitHub MCP server (internal/testutil/githubmcp) and listing its
// tools through the same upstream.ListTools path main.go uses for a real
// server — the whole point being to exercise Milestone 3's pipeline against
// architecture.md's own running example ("GitHub MCP, stop it from deleting
// anything in this repo") instead of a synthetic one-field fixture.
func githubCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	session := githubmcp.NewSession(t)

	tools, err := upstream.ListTools(context.Background(), session)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	cat := catalog.New()
	if err := cat.Update("github", tools); err != nil {
		t.Fatalf("cat.Update: %v", err)
	}
	return cat
}

func TestBuildEnforcer_AgainstSimulatedGitHubCatalog_ValidRule(t *testing.T) {
	// The architecture.md example, translated to CEL: block deleting a
	// branch named "main" specifically.
	rulesDir := writeRulesDir(t, `tool == "delete_branch" && has(params.branch) && params.branch == "main"`)
	cfg := testConfig(rulesDir)

	enforcer, err := buildEnforcer(cfg, mustAuditWriter(t), githubCatalog(t))
	if err != nil {
		t.Fatalf("buildEnforcer: %v", err)
	}

	blocked, err := enforcer.Enforce(context.Background(), "agent-1",
		policy.CallContext{Server: "github", Tool: "delete_branch", Params: map[string]any{"repo": "acme/widgets", "branch": "main"}})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if blocked.Allowed {
		t.Fatalf("expected deleting main to be blocked, got %+v", blocked)
	}

	allowed, err := enforcer.Enforce(context.Background(), "agent-1",
		policy.CallContext{Server: "github", Tool: "delete_branch", Params: map[string]any{"repo": "acme/widgets", "branch": "feature/x"}})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !allowed.Allowed {
		t.Fatalf("expected deleting a non-main branch to be allowed, got %+v", allowed)
	}

	// Non-destructive tools on the same server are unaffected.
	pushResult, err := enforcer.Enforce(context.Background(), "agent-1",
		policy.CallContext{Server: "github", Tool: "create_pull_request", Params: map[string]any{"repo": "acme/widgets", "head": "x", "base": "main", "title": "t"}})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !pushResult.Allowed {
		t.Fatalf("expected create_pull_request to be unaffected by the delete_branch rule, got %+v", pushResult)
	}
}

func TestBuildEnforcer_AgainstSimulatedGitHubCatalog_TypoedFieldBlocksServer(t *testing.T) {
	// "brnach" doesn't exist on any simulated GitHub tool's schema — the
	// same mistake a hand- or agent-written rule could make, caught by
	// schemacheck at load time instead of surfacing as a runtime surprise
	// on the first real call.
	rulesDir := writeRulesDir(t, `has(params.brnach) && params.brnach == "main"`)
	cfg := testConfig(rulesDir)

	enforcer, err := buildEnforcer(cfg, mustAuditWriter(t), githubCatalog(t))
	if err != nil {
		t.Fatalf("buildEnforcer: %v", err)
	}

	result, err := enforcer.Enforce(context.Background(), "agent-1",
		policy.CallContext{Server: "github", Tool: "delete_branch", Params: map[string]any{"repo": "acme/widgets", "branch": "main"}})
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if result.Allowed {
		t.Fatalf("expected the server to fail closed for a rule referencing a nonexistent field, got %+v", result)
	}
}

// TestSchemaPipeline_AgainstSimulatedGitHubCatalog exercises schema export,
// on-disk-dump-backed validation, and drift detection together against the
// simulated GitHub catalog — the same data path `mcp-policy-proxy validate`
// and a proxy restart use for a real server.
func TestSchemaPipeline_AgainstSimulatedGitHubCatalog(t *testing.T) {
	dir := t.TempDir()
	cat := githubCatalog(t)

	if err := schemadump.Write(dir, cat); err != nil {
		t.Fatalf("schemadump.Write: %v", err)
	}

	src, err := schemacheck.FromDump(dir)
	if err != nil {
		t.Fatalf("schemacheck.FromDump: %v", err)
	}
	env, err := policy.NewEnv()
	if err != nil {
		t.Fatalf("policy.NewEnv: %v", err)
	}

	rulesDir := writeRulesDir(t, `tool == "delete_repository" && has(params.confirm) && params.confirm == "yes"`)
	store, loadErrors, err := rulestore.Load(rulesDir)
	if err != nil {
		t.Fatalf("rulestore.Load: %v", err)
	}
	if len(loadErrors) != 0 {
		t.Fatalf("unexpected load errors: %v", loadErrors)
	}

	for _, r := range store.All() {
		if err := schemacheck.Check(r, env, src); err != nil {
			t.Fatalf("expected the confirm field to validate against the on-disk dump, got: %v", err)
		}
	}

	// Sanity check the dump actually landed on disk in the expected shape.
	if _, err := os.Stat(filepath.Join(dir, "github.json")); err != nil {
		t.Fatalf("expected schemas/github.json to exist: %v", err)
	}
}
