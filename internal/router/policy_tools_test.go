package router

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/audit"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/catalog"
)

func makeReq(t *testing.T, args any) *mcp.CallToolRequest {
	t.Helper()
	if args == nil {
		return &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{}}
	}
	data, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshaling request args: %v", err)
	}
	return &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Arguments: data}}
}

func resultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatalf("expected non-empty content, got %+v", res)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Content[0])
	}
	return tc.Text
}

func githubToolCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	cat := catalog.New()
	if err := cat.Update("github", []*mcp.Tool{
		{Name: "delete_branch", Description: "Delete a branch", InputSchema: objectSchema("repo", "branch")},
		{Name: "push", Description: "Push commits", InputSchema: objectSchema("repo", "branch", "force")},
	}); err != nil {
		t.Fatalf("cat.Update: %v", err)
	}
	return cat
}

// --- decodeArgs / textResult / errorResult ---

func TestDecodeArgs_MissingArguments(t *testing.T) {
	var out struct{}
	err := decodeArgs(makeReq(t, nil), &out)
	if err == nil || !strings.Contains(err.Error(), "missing arguments") {
		t.Fatalf("expected 'missing arguments' error, got %v", err)
	}
}

func TestDecodeArgs_MalformedJSON(t *testing.T) {
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(`{bad`)}}
	var out struct{}
	if err := decodeArgs(req, &out); err == nil {
		t.Fatalf("expected a JSON decode error")
	}
}

func TestDecodeArgs_Valid(t *testing.T) {
	var out struct {
		Server string `json:"server"`
	}
	if err := decodeArgs(makeReq(t, map[string]string{"server": "github"}), &out); err != nil {
		t.Fatalf("decodeArgs: %v", err)
	}
	if out.Server != "github" {
		t.Fatalf("expected server=github, got %q", out.Server)
	}
}

func TestTextResult_Success(t *testing.T) {
	res, err := textResult(map[string]string{"result": "valid"})
	if err != nil {
		t.Fatalf("textResult: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected IsError=false, got true")
	}
	if !strings.Contains(resultText(t, res), "valid") {
		t.Fatalf("expected content to contain the encoded value, got %q", resultText(t, res))
	}
}

func TestErrorResult(t *testing.T) {
	res, err := errorResult("bad %s", "input")
	if err != nil {
		t.Fatalf("errorResult: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError=true")
	}
	if resultText(t, res) != "bad input" {
		t.Fatalf("expected formatted text, got %q", resultText(t, res))
	}
}

// --- listToolSchemas ---

func TestListToolSchemas_FiltersByServer(t *testing.T) {
	pt := &policyTools{cat: githubToolCatalog(t)}

	res, err := pt.listToolSchemas(context.Background(), makeReq(t, map[string]string{"server": "aws"}))
	if err != nil {
		t.Fatalf("listToolSchemas: %v", err)
	}
	if resultText(t, res) != "null" {
		t.Fatalf("expected no tools for an unknown server, got %q", resultText(t, res))
	}

	res, err = pt.listToolSchemas(context.Background(), makeReq(t, map[string]string{"server": "github"}))
	if err != nil {
		t.Fatalf("listToolSchemas: %v", err)
	}
	if !strings.Contains(resultText(t, res), "delete_branch") || !strings.Contains(resultText(t, res), "push") {
		t.Fatalf("expected both github tools listed, got %q", resultText(t, res))
	}
}

func TestListToolSchemas_QueryFilter(t *testing.T) {
	pt := &policyTools{cat: githubToolCatalog(t)}

	res, err := pt.listToolSchemas(context.Background(), makeReq(t, map[string]string{"server": "github", "query": "DELETE"}))
	if err != nil {
		t.Fatalf("listToolSchemas: %v", err)
	}
	text := resultText(t, res)
	if !strings.Contains(text, "delete_branch") || strings.Contains(text, `"push"`) {
		t.Fatalf("expected only delete_branch to match case-insensitive query, got %q", text)
	}
}

// --- validateRule ---

func TestValidateRule_Valid(t *testing.T) {
	pt := &policyTools{cat: githubToolCatalog(t)}

	res, err := pt.validateRule(context.Background(), makeReq(t, map[string]string{
		"server":         "github",
		"cel_expression": `tool == "delete_branch" && has(params.branch) && params.branch == "main"`,
		"action":         "hard_stop",
	}))
	if err != nil {
		t.Fatalf("validateRule: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected a valid rule to pass, got error: %s", resultText(t, res))
	}
	if !strings.Contains(resultText(t, res), "valid") {
		t.Fatalf("expected result to report valid, got %q", resultText(t, res))
	}
}

func TestValidateRule_RuleValidationFailure(t *testing.T) {
	pt := &policyTools{cat: githubToolCatalog(t)}

	res, err := pt.validateRule(context.Background(), makeReq(t, map[string]string{
		"server":         "github",
		"cel_expression": "",
		"action":         "hard_stop",
	}))
	if err != nil {
		t.Fatalf("validateRule: %v", err)
	}
	if !res.IsError || !strings.Contains(resultText(t, res), "missing cel_expression") {
		t.Fatalf("expected a missing cel_expression error, got %+v", res)
	}
}

func TestValidateRule_CompileFailure(t *testing.T) {
	pt := &policyTools{cat: githubToolCatalog(t)}

	res, err := pt.validateRule(context.Background(), makeReq(t, map[string]string{
		"server":         "github",
		"cel_expression": `tool ===`,
		"action":         "hard_stop",
	}))
	if err != nil {
		t.Fatalf("validateRule: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected a CEL compile error result, got %+v", res)
	}
}

func TestValidateRule_SchemaCheckFailure(t *testing.T) {
	pt := &policyTools{cat: githubToolCatalog(t)}

	res, err := pt.validateRule(context.Background(), makeReq(t, map[string]string{
		"server":         "github",
		"cel_expression": `has(params.brnach) && params.brnach == "main"`, // typo, not on any tool
		"action":         "hard_stop",
	}))
	if err != nil {
		t.Fatalf("validateRule: %v", err)
	}
	if !res.IsError || !strings.Contains(resultText(t, res), "brnach") {
		t.Fatalf("expected a schemacheck error naming the unknown field, got %+v", res)
	}
}

// --- backtestRule ---

func seedAuditLog(t *testing.T, entries ...audit.Entry) string {
	t.Helper()
	path := t.TempDir() + "/audit.log"
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

func TestBacktestRule_InvalidSinceDuration(t *testing.T) {
	pt := &policyTools{cat: githubToolCatalog(t), auditLogPath: seedAuditLog(t)}

	res, err := pt.backtestRule(context.Background(), makeReq(t, map[string]string{
		"server":         "github",
		"cel_expression": `tool == "push"`,
		"action":         "hard_stop",
		"since":          "not-a-duration",
	}))
	if err != nil {
		t.Fatalf("backtestRule: %v", err)
	}
	if !res.IsError || !strings.Contains(resultText(t, res), "invalid since duration") {
		t.Fatalf("expected an invalid-since-duration error, got %+v", res)
	}
}

func TestBacktestRule_RuleValidationFailure(t *testing.T) {
	pt := &policyTools{cat: githubToolCatalog(t), auditLogPath: seedAuditLog(t)}

	res, err := pt.backtestRule(context.Background(), makeReq(t, map[string]string{
		"server":         "github",
		"cel_expression": `tool == "push"`,
		"action":         "not-a-real-action",
	}))
	if err != nil {
		t.Fatalf("backtestRule: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected a rule validation error, got %+v", res)
	}
}

func TestBacktestRule_HappyPath(t *testing.T) {
	auditPath := seedAuditLog(t,
		audit.Entry{Server: "github", ToolName: "push", Params: map[string]any{"branch": "main"}, Outcome: audit.OutcomeAllowed},
		audit.Entry{Server: "github", ToolName: "push", Params: map[string]any{"branch": "dev"}, Outcome: audit.OutcomeAllowed},
		audit.Entry{Server: "github", ToolName: "delete_branch", Params: map[string]any{"branch": "main"}, Outcome: audit.OutcomeAllowed},
	)
	pt := &policyTools{cat: githubToolCatalog(t), auditLogPath: auditPath}

	res, err := pt.backtestRule(context.Background(), makeReq(t, map[string]string{
		"server":         "github",
		"cel_expression": `tool == "push"`,
		"action":         "hard_stop",
		"since":          "1h",
	}))
	if err != nil {
		t.Fatalf("backtestRule: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected a successful backtest, got error: %s", resultText(t, res))
	}

	var decoded struct {
		Matched      int `json:"Matched"`
		TotalEntries int `json:"TotalEntries"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &decoded); err != nil {
		t.Fatalf("decoding backtest result: %v", err)
	}
	if decoded.TotalEntries != 3 {
		t.Fatalf("expected 3 total entries examined, got %d", decoded.TotalEntries)
	}
	if decoded.Matched != 2 {
		t.Fatalf("expected 2 matched push calls, got %d", decoded.Matched)
	}
}
