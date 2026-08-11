// Package schemacheck is the deterministic "compiler" check for
// hand-or-agent-written rules: it verifies every params.<field> a rule's CEL
// expression references actually exists on at least one tool in that rule's
// scope. CEL syntax/type checking already
// happens in internal/policy; this package catches the mistake policy.Engine
// can't — a field name that will simply never match anything, whether from a
// typo or an upstream schema that changed out from under an existing rule
// (internal/drift feeds the same check).
//
// The check is intentionally shallow: it only validates the first path
// segment of a params reference (e.g. params.branch in
// params.branch.startsWith("x")), against each in-scope tool's top-level
// input_schema properties. Deeper nested field paths are not validated. This
// keeps the check simple and dependency-free while still catching the common
// mistake (a field that doesn't exist at all).
package schemacheck

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/catalog"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/rule"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/schemadump"
)

const globalScope = "*"

// ToolInfo is the minimal shape schemacheck needs from a tool schema: its
// name, and the set of top-level property names declared in its input
// schema.
type ToolInfo struct {
	Name   string
	Fields map[string]bool
}

// Source answers "what tools, with what fields, exist for server s" —
// implemented by both the live catalog (FromCatalog) and an on-disk schema
// dump (FromDump), so the same Check logic runs identically whether the
// proxy is live or a human/agent is just running the validate command
// against files on disk.
type Source interface {
	// ToolsForServer returns every known tool for one specific server name
	// (never "*" — callers resolve wildcard scope themselves via Servers).
	ToolsForServer(server string) []ToolInfo
	// Servers returns every known server name.
	Servers() []string
}

// FromCatalog builds a Source backed by the live Tool Schema Catalog.
func FromCatalog(cat *catalog.Catalog) Source {
	return catalogSource{cat: cat}
}

type catalogSource struct {
	cat *catalog.Catalog
}

func (s catalogSource) ToolsForServer(server string) []ToolInfo {
	var tools []ToolInfo
	for _, entry := range s.cat.All() {
		if entry.Server != server {
			continue
		}
		tools = append(tools, ToolInfo{Name: entry.ToolName, Fields: topLevelFields(entry.Tool.InputSchema)})
	}
	return tools
}

func (s catalogSource) Servers() []string {
	seen := make(map[string]bool)
	var servers []string
	for _, entry := range s.cat.All() {
		if !seen[entry.Server] {
			seen[entry.Server] = true
			servers = append(servers, entry.Server)
		}
	}
	return servers
}

// FromDump builds a Source by reading every schema dump file (written by
// internal/schemadump) in dir. Used by the standalone `validate` CLI command
// so rule validation needs no live MCP connections.
func FromDump(dir string) (Source, error) {
	servers, err := schemadump.ListServers(dir)
	if err != nil {
		return nil, err
	}

	toolsByServer := make(map[string][]ToolInfo, len(servers))
	for _, server := range servers {
		tools, _, err := schemadump.Load(dir, server)
		if err != nil {
			return nil, fmt.Errorf("loading schema dump for %q: %w", server, err)
		}
		infos := make([]ToolInfo, 0, len(tools))
		for _, t := range tools {
			infos = append(infos, ToolInfo{Name: t.Name, Fields: topLevelFieldsFromRaw(t.InputSchema)})
		}
		toolsByServer[server] = infos
	}

	return dumpSource{byServer: toolsByServer, servers: servers}, nil
}

type dumpSource struct {
	byServer map[string][]ToolInfo
	servers  []string
}

func (s dumpSource) ToolsForServer(server string) []ToolInfo { return s.byServer[server] }
func (s dumpSource) Servers() []string                       { return s.servers }

// Check walks r's compiled CEL expression, collects every top-level
// params.<field> reference, and verifies each exists on at least one tool's
// schema among the servers r.ServerScope resolves to ("*" means every known
// server). Returns a descriptive error naming every unknown field found.
func Check(r rule.Rule, env *cel.Env, src Source) error {
	ast, iss := env.Compile(r.CELExpression)
	if err := iss.Err(); err != nil {
		// Not schemacheck's job to report compile errors — policy.NewEngine
		// already does, with better context. Nothing to check without a
		// valid AST.
		return nil
	}

	referenced := referencedParamsFields(ast)
	if len(referenced) == 0 {
		return nil
	}

	var servers []string
	if r.ServerScope == globalScope {
		servers = src.Servers()
	} else {
		servers = []string{r.ServerScope}
	}

	known := make(map[string]bool)
	var matchedAnyTool bool
	for _, server := range servers {
		for _, tool := range src.ToolsForServer(server) {
			matchedAnyTool = true
			for field := range tool.Fields {
				known[field] = true
			}
		}
	}

	// No tools known at all for this scope yet (e.g. server hasn't connected
	// or has no dump on disk) — nothing to validate against, so don't fail a
	// rule just because schema data isn't available.
	if !matchedAnyTool {
		return nil
	}

	var unknown []string
	for field := range referenced {
		if !known[field] {
			unknown = append(unknown, field)
		}
	}
	if len(unknown) == 0 {
		return nil
	}

	sort.Strings(unknown)
	return fmt.Errorf("rule %q: references params field(s) %s not present on any tool in scope (server_scope %q)",
		r.ID, strings.Join(unknown, ", "), r.ServerScope)
}

// referencedParamsFields walks ast's expression tree and collects the field
// name of every top-level select off the "params" identifier — this covers
// both plain access (params.branch) and the has() macro (has(params.branch)),
// which compiles to a test-only select on the same shape. Index-style access
// (params["branch"]) is not covered; see the package doc comment.
func referencedParamsFields(ast *cel.Ast) map[string]bool {
	fields := make(map[string]bool)

	visitor := celast.NewExprVisitor(func(e celast.Expr) {
		if e.Kind() != celast.SelectKind {
			return
		}
		sel := e.AsSelect()
		operand := sel.Operand()
		if operand.Kind() == celast.IdentKind && operand.AsIdent() == "params" {
			fields[sel.FieldName()] = true
		}
	})
	celast.PostOrderVisit(ast.NativeRep().Expr(), visitor)

	return fields
}

type rawSchemaProperties struct {
	Properties map[string]json.RawMessage `json:"properties"`
}

// topLevelFields extracts the top-level property names from an mcp.Tool's
// InputSchema, whatever concrete type it happens to be (map[string]any,
// *jsonschema.Schema, json.RawMessage, ...) — it's re-marshaled to JSON and
// parsed generically rather than type-asserted.
func topLevelFields(inputSchema any) map[string]bool {
	data, err := json.Marshal(inputSchema)
	if err != nil {
		return nil
	}
	return topLevelFieldsFromRaw(data)
}

func topLevelFieldsFromRaw(data json.RawMessage) map[string]bool {
	var schema rawSchemaProperties
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil
	}
	fields := make(map[string]bool, len(schema.Properties))
	for name := range schema.Properties {
		fields[name] = true
	}
	return fields
}
