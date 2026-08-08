// Package router is the agent-facing half of the Router/Transport Layer
// (architecture.md section 5.1). It serves the aggregated tool catalog to a
// connecting agent and forwards every tools/call straight through to the
// owning upstream server, unmodified — no policy checks yet (Milestone 1).
package router

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/audit"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/catalog"
)

// separator namespaces each upstream tool by its server name (e.g.
// "github__delete_file"), since two different upstream servers are free to
// expose tools with the same name and the agent-facing catalog has to stay
// unambiguous about which server a call should be forwarded to.
const separator = "__"

type Router struct {
	server   *mcp.Server
	sessions map[string]*mcp.ClientSession
	audit    *audit.Writer
}

// New builds a Router exposing every tool currently in cat, forwarding calls
// to the matching session in sessions (keyed by server name, as configured).
// auditWriter may be nil, in which case calls are simply not logged.
func New(cat *catalog.Catalog, sessions map[string]*mcp.ClientSession, auditWriter *audit.Writer) *Router {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "mcp-policy-proxy",
		Version: "0.1.0",
	}, nil)

	rt := &Router{
		server:   server,
		sessions: sessions,
		audit:    auditWriter,
	}

	for _, entry := range cat.All() {
		rt.registerTool(entry)
	}

	return rt
}

func qualifiedName(server, toolName string) string {
	return server + separator + toolName
}

func splitQualifiedName(qualified string) (server, toolName string, ok bool) {
	parts := strings.SplitN(qualified, separator, 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func (rt *Router) registerTool(entry catalog.Entry) {
	exposed := &mcp.Tool{
		Name:        qualifiedName(entry.Server, entry.ToolName),
		Description: entry.Tool.Description,
		InputSchema: entry.Tool.InputSchema,
	}
	rt.server.AddTool(exposed, rt.callTool)
}

func (rt *Router) callTool(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	serverName, toolName, ok := splitQualifiedName(req.Params.Name)
	if !ok {
		return nil, fmt.Errorf("malformed tool name %q", req.Params.Name)
	}

	session, ok := rt.sessions[serverName]
	if !ok {
		return nil, fmt.Errorf("no connected server named %q", serverName)
	}

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      toolName,
		Arguments: req.Params.Arguments,
	})

	rt.logCall(req, serverName, toolName, err)

	if err != nil {
		return nil, fmt.Errorf("forwarding call to %s/%s: %w", serverName, toolName, err)
	}
	return result, nil
}

func (rt *Router) logCall(req *mcp.CallToolRequest, serverName, toolName string, callErr error) {
	if rt.audit == nil {
		return
	}

	outcome := audit.OutcomeAllowed
	if callErr != nil {
		outcome = audit.OutcomeHardStopped
	}

	entry := audit.Entry{
		AgentID:  req.Session.ID(),
		Server:   serverName,
		ToolName: toolName,
		Params:   json.RawMessage(req.Params.Arguments),
		Outcome:  outcome,
	}

	if err := rt.audit.Log(entry); err != nil {
		log.Printf("audit log write failed: %v", err)
	}
}

// Run starts serving the agent-facing MCP server over stdio. It blocks until
// the session ends or ctx is canceled.
func (rt *Router) Run(ctx context.Context) error {
	return rt.server.Run(ctx, &mcp.StdioTransport{})
}
