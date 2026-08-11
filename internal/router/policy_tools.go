package router

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/audit"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/backtest"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/catalog"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/policy"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/rule"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/schemacheck"
)

const draftRuleID = "draft"

// RegisterPolicyTools adds three read-only, MCP-native tools for a rule
// author's own agent to call directly:
// policy__list_tool_schemas, policy__validate_rule, and
// policy__backtest_rule. This is the "agent pings the proxy" path,
// alongside (not instead of) reading the schema dump files on disk. None of
// them write anything — an agent still has to save the resulting YAML into
// rules/<server>.yaml itself using its own file-editing capability, and that
// change still goes through git review like any other code change. Off by
// default (Config.ExposePolicyTools) so they don't clutter the tool list for
// agents just using the proxy for normal pass-through traffic.
func (rt *Router) RegisterPolicyTools(cat *catalog.Catalog, auditLogPath string) {
	pt := &policyTools{cat: cat, auditLogPath: auditLogPath}

	rt.server.AddTool(&mcp.Tool{
		Name: "policy__list_tool_schemas",
		Description: "List real tool names, descriptions, and input schemas for a connected MCP " +
			"server — reference material for writing a CEL rule grounded in real field names, " +
			"without needing to read the schema dump files on disk.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"server": map[string]any{"type": "string", "description": "Server name as configured in config.yaml"},
				"query":  map[string]any{"type": "string", "description": "Optional substring filter on tool name/description"},
			},
			"required": []string{"server"},
		},
	}, pt.listToolSchemas)

	rt.server.AddTool(&mcp.Tool{
		Name: "policy__validate_rule",
		Description: "Check a draft CEL rule for compile errors and for params fields that don't " +
			"exist on any tool in scope, against the live tool catalog. Does not write anything.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"server":         map[string]any{"type": "string", "description": "Server name, or \"*\" for a wildcard rule"},
				"cel_expression": map[string]any{"type": "string"},
				"action":         map[string]any{"type": "string", "enum": []string{"hard_stop", "require_approval"}},
			},
			"required": []string{"server", "cel_expression", "action"},
		},
	}, pt.validateRule)

	rt.server.AddTool(&mcp.Tool{
		Name: "policy__backtest_rule",
		Description: "Replay a draft CEL rule against the live audit log and report how many " +
			"recent calls it would have matched. Does not write anything.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"server":         map[string]any{"type": "string", "description": "Server name, or \"*\" for a wildcard rule"},
				"cel_expression": map[string]any{"type": "string"},
				"action":         map[string]any{"type": "string", "enum": []string{"hard_stop", "require_approval"}},
				"since":          map[string]any{"type": "string", "description": "Go duration string, e.g. \"168h\" for 7 days. Defaults to 168h."},
			},
			"required": []string{"server", "cel_expression", "action"},
		},
	}, pt.backtestRule)
}

type policyTools struct {
	cat          *catalog.Catalog
	auditLogPath string
}

func textResult(v any) (*mcp.CallToolResult, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding result: %w", err)
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(data)}}}, nil
}

func errorResult(format string, args ...any) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(format, args...)}},
	}, nil
}

func decodeArgs(req *mcp.CallToolRequest, v any) error {
	if len(req.Params.Arguments) == 0 {
		return fmt.Errorf("missing arguments")
	}
	return json.Unmarshal(req.Params.Arguments, v)
}

func (pt *policyTools) listToolSchemas(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		Server string `json:"server"`
		Query  string `json:"query"`
	}
	if err := decodeArgs(req, &args); err != nil {
		return errorResult("decoding arguments: %v", err)
	}

	type toolOut struct {
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
		InputSchema any    `json:"input_schema"`
	}
	var out []toolOut
	query := strings.ToLower(args.Query)

	for _, entry := range pt.cat.All() {
		if entry.Server != args.Server {
			continue
		}
		if query != "" &&
			!strings.Contains(strings.ToLower(entry.ToolName), query) &&
			!strings.Contains(strings.ToLower(entry.Tool.Description), query) {
			continue
		}
		out = append(out, toolOut{Name: entry.ToolName, Description: entry.Tool.Description, InputSchema: entry.Tool.InputSchema})
	}

	return textResult(out)
}

func draftRule(server, celExpr, action string) rule.Rule {
	return rule.Rule{
		ID:            draftRuleID,
		ServerScope:   server,
		CELExpression: celExpr,
		Action:        rule.Action(action),
	}
}

func (pt *policyTools) validateRule(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		Server        string `json:"server"`
		CELExpression string `json:"cel_expression"`
		Action        string `json:"action"`
	}
	if err := decodeArgs(req, &args); err != nil {
		return errorResult("decoding arguments: %v", err)
	}

	r := draftRule(args.Server, args.CELExpression, args.Action)
	if err := r.Validate(); err != nil {
		return errorResult("%v", err)
	}

	_, compileErrors, err := policy.NewEngine([]rule.Rule{r})
	if err != nil {
		return errorResult("building policy engine: %v", err)
	}
	if compileErr, broken := compileErrors[r.ServerScope]; broken {
		return errorResult("%v", compileErr)
	}

	env, err := policy.NewEnv()
	if err != nil {
		return errorResult("building CEL environment: %v", err)
	}
	if err := schemacheck.Check(r, env, schemacheck.FromCatalog(pt.cat)); err != nil {
		return errorResult("%v", err)
	}

	return textResult(map[string]string{"result": "valid"})
}

func (pt *policyTools) backtestRule(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args struct {
		Server        string `json:"server"`
		CELExpression string `json:"cel_expression"`
		Action        string `json:"action"`
		Since         string `json:"since"`
	}
	if err := decodeArgs(req, &args); err != nil {
		return errorResult("decoding arguments: %v", err)
	}
	if args.Since == "" {
		args.Since = "168h"
	}
	window, err := time.ParseDuration(args.Since)
	if err != nil {
		return errorResult("invalid since duration %q: %v", args.Since, err)
	}

	r := draftRule(args.Server, args.CELExpression, args.Action)
	if err := r.Validate(); err != nil {
		return errorResult("%v", err)
	}

	entries, err := audit.ReadAll(pt.auditLogPath)
	if err != nil {
		return errorResult("reading audit log: %v", err)
	}

	result, err := backtest.Run(r, entries, time.Now().Add(-window))
	if err != nil {
		return errorResult("%v", err)
	}

	return textResult(result)
}
