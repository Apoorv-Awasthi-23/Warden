package schemacheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/catalog"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/policy"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/rule"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/schemadump"
)

type fakeSource struct {
	byServer map[string][]ToolInfo
}

func (f fakeSource) ToolsForServer(server string) []ToolInfo { return f.byServer[server] }
func (f fakeSource) Servers() []string {
	var out []string
	for s := range f.byServer {
		out = append(out, s)
	}
	return out
}

func TestCheck_KnownFieldPasses(t *testing.T) {
	env, err := policy.NewEnv()
	if err != nil {
		t.Fatalf("policy.NewEnv: %v", err)
	}
	src := fakeSource{byServer: map[string][]ToolInfo{
		"github": {{Name: "delete_file", Fields: map[string]bool{"path": true}}},
	}}
	r := rule.Rule{ID: "r1", ServerScope: "github", CELExpression: `params.path == "x"`, Action: rule.ActionHardStop}

	if err := Check(r, env, src); err != nil {
		t.Fatalf("expected no error for a known field, got: %v", err)
	}
}

func TestCheck_UnknownFieldFails(t *testing.T) {
	env, err := policy.NewEnv()
	if err != nil {
		t.Fatalf("policy.NewEnv: %v", err)
	}
	src := fakeSource{byServer: map[string][]ToolInfo{
		"github": {{Name: "delete_file", Fields: map[string]bool{"path": true}}},
	}}
	r := rule.Rule{ID: "r1", ServerScope: "github", CELExpression: `params.brnach == "main"`, Action: rule.ActionHardStop}

	err = Check(r, env, src)
	if err == nil {
		t.Fatalf("expected an error for an unknown field")
	}
	if !strings.Contains(err.Error(), "brnach") {
		t.Fatalf("expected error to name the offending field, got: %v", err)
	}
	if !strings.Contains(err.Error(), "r1") {
		t.Fatalf("expected error to name the rule, got: %v", err)
	}
}

func TestCheck_HasGuardStillChecksField(t *testing.T) {
	env, err := policy.NewEnv()
	if err != nil {
		t.Fatalf("policy.NewEnv: %v", err)
	}
	src := fakeSource{byServer: map[string][]ToolInfo{
		"github": {{Name: "delete_file", Fields: map[string]bool{"path": true}}},
	}}
	r := rule.Rule{ID: "r1", ServerScope: "github", CELExpression: `has(params.brnach)`, Action: rule.ActionHardStop}

	if err := Check(r, env, src); err == nil {
		t.Fatalf("expected has() to still surface an unknown field")
	}
}

func TestCheck_WildcardScopeChecksEveryServer(t *testing.T) {
	env, err := policy.NewEnv()
	if err != nil {
		t.Fatalf("policy.NewEnv: %v", err)
	}
	src := fakeSource{byServer: map[string][]ToolInfo{
		"github": {{Name: "delete_file", Fields: map[string]bool{"path": true}}},
		"aws":    {{Name: "terminate_instance", Fields: map[string]bool{"instance_id": true}}},
	}}
	r := rule.Rule{ID: "global-rule", ServerScope: "*", CELExpression: `params.instance_id == "x"`, Action: rule.ActionHardStop}

	if err := Check(r, env, src); err != nil {
		t.Fatalf("expected wildcard scope to find instance_id on aws, got: %v", err)
	}
}

func TestCheck_NoToolsKnownDoesNotFail(t *testing.T) {
	env, err := policy.NewEnv()
	if err != nil {
		t.Fatalf("policy.NewEnv: %v", err)
	}
	src := fakeSource{byServer: map[string][]ToolInfo{}}
	r := rule.Rule{ID: "r1", ServerScope: "unconnected-server", CELExpression: `params.anything == "x"`, Action: rule.ActionHardStop}

	if err := Check(r, env, src); err != nil {
		t.Fatalf("expected no error when no schema data is available for the scope, got: %v", err)
	}
}

func TestCheck_NoParamsReferenceIsFine(t *testing.T) {
	env, err := policy.NewEnv()
	if err != nil {
		t.Fatalf("policy.NewEnv: %v", err)
	}
	src := fakeSource{byServer: map[string][]ToolInfo{"github": {{Name: "delete_file", Fields: map[string]bool{"path": true}}}}}
	r := rule.Rule{ID: "r1", ServerScope: "github", CELExpression: `tool == "delete_file"`, Action: rule.ActionHardStop}

	if err := Check(r, env, src); err != nil {
		t.Fatalf("expected no error for a rule that never references params, got: %v", err)
	}
}

func TestFromCatalog_Integration(t *testing.T) {
	cat := catalog.New()
	if err := cat.Update("github", []*mcp.Tool{
		{
			Name: "delete_file",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"path": map[string]any{"type": "string"}},
			},
		},
	}); err != nil {
		t.Fatalf("cat.Update: %v", err)
	}

	env, err := policy.NewEnv()
	if err != nil {
		t.Fatalf("policy.NewEnv: %v", err)
	}
	src := FromCatalog(cat)

	good := rule.Rule{ID: "good", ServerScope: "github", CELExpression: `params.path == "x"`, Action: rule.ActionHardStop}
	if err := Check(good, env, src); err != nil {
		t.Fatalf("expected no error for a real catalog field, got: %v", err)
	}

	bad := rule.Rule{ID: "bad", ServerScope: "github", CELExpression: `params.nonexistent == "x"`, Action: rule.ActionHardStop}
	if err := Check(bad, env, src); err == nil {
		t.Fatalf("expected an error for a field not in the real catalog schema")
	}
}

func TestFromDump_Integration(t *testing.T) {
	cat := catalog.New()
	if err := cat.Update("github", []*mcp.Tool{
		{
			Name: "delete_file",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"path": map[string]any{"type": "string"}},
			},
		},
	}); err != nil {
		t.Fatalf("cat.Update: %v", err)
	}

	dir := t.TempDir()
	if err := schemadump.Write(dir, cat); err != nil {
		t.Fatalf("schemadump.Write: %v", err)
	}

	src, err := FromDump(dir)
	if err != nil {
		t.Fatalf("FromDump: %v", err)
	}

	env, err := policy.NewEnv()
	if err != nil {
		t.Fatalf("policy.NewEnv: %v", err)
	}

	good := rule.Rule{ID: "good", ServerScope: "github", CELExpression: `params.path == "x"`, Action: rule.ActionHardStop}
	if err := Check(good, env, src); err != nil {
		t.Fatalf("expected no error for a field present in the on-disk dump, got: %v", err)
	}

	bad := rule.Rule{ID: "bad", ServerScope: "github", CELExpression: `params.nonexistent == "x"`, Action: rule.ActionHardStop}
	if err := Check(bad, env, src); err == nil {
		t.Fatalf("expected an error for a field not in the on-disk dump")
	}
}

func TestFromDump_MissingDirectoryYieldsEmptySource(t *testing.T) {
	src, err := FromDump(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("expected a missing dump directory to be treated as empty, not an error, got: %v", err)
	}
	if servers := src.Servers(); len(servers) != 0 {
		t.Fatalf("expected zero servers, got %v", servers)
	}
}

func TestFromDump_CorruptedDumpFilePropagatesError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "github.json"), []byte("{not valid json"), 0o644); err != nil {
		t.Fatalf("writing corrupted dump fixture: %v", err)
	}

	_, err := FromDump(dir)
	if err == nil || !strings.Contains(err.Error(), "loading schema dump") {
		t.Fatalf("expected an error loading the corrupted dump, got: %v", err)
	}
}
