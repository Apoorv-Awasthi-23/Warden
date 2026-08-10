// Package githubmcp simulates a GitHub MCP server for tests. It's a
// realistic stand-in for architecture.md's own running example ("GitHub
// MCP, stop it from deleting anything in this repo") — a small set of
// tools shaped like the real GitHub MCP server's delete/push/PR surface,
// served over an in-process connection via [mcp.NewInMemoryTransports], so
// tests exercise a genuine MCP handshake and tool listing rather than
// hand-built catalog.Entry fixtures.
package githubmcp

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// objectSchema is a minimal JSON Schema object with the given top-level
// string properties, all required — enough shape for schemacheck's
// top-level property-name extraction without needing the full jsonschema-go
// types.
func objectSchema(properties ...string) map[string]any {
	props := make(map[string]any, len(properties))
	for _, p := range properties {
		props[p] = map[string]any{"type": "string"}
	}
	return map[string]any{
		"type":       "object",
		"properties": props,
		"required":   properties,
	}
}

// tools returns the simulated GitHub MCP server's tool set: the same
// delete-shaped tools architecture.md section 5.6 names as its running
// example, plus a couple of everyday tools so a rule scoped broadly still
// has non-destructive traffic to consider.
func tools() []struct {
	tool    *mcp.Tool
	handler mcp.ToolHandler
} {
	ok := func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
	}

	return []struct {
		tool    *mcp.Tool
		handler mcp.ToolHandler
	}{
		{
			tool: &mcp.Tool{
				Name:        "delete_file",
				Description: "Delete a file from a repository branch",
				InputSchema: objectSchema("repo", "branch", "path"),
			},
			handler: ok,
		},
		{
			tool: &mcp.Tool{
				Name:        "delete_branch",
				Description: "Delete a branch from a repository",
				InputSchema: objectSchema("repo", "branch"),
			},
			handler: ok,
		},
		{
			tool: &mcp.Tool{
				Name:        "delete_repository",
				Description: "Permanently delete a repository",
				InputSchema: objectSchema("repo", "confirm"),
			},
			handler: ok,
		},
		{
			tool: &mcp.Tool{
				Name:        "push",
				Description: "Push commits to a branch",
				InputSchema: objectSchema("repo", "branch", "force"),
			},
			handler: ok,
		},
		{
			tool: &mcp.Tool{
				Name:        "create_pull_request",
				Description: "Open a pull request",
				InputSchema: objectSchema("repo", "head", "base", "title"),
			},
			handler: ok,
		},
	}
}

// NewSession starts the simulated GitHub MCP server in-process and returns
// a *mcp.ClientSession already connected to it over an in-memory transport
// — a drop-in stand-in for what internal/upstream.Connect returns for a
// real server, usable directly with internal/upstream.ListTools. The
// server and both ends of the transport are closed automatically via
// t.Cleanup.
func NewSession(t *testing.T) *mcp.ClientSession {
	t.Helper()

	server := mcp.NewServer(&mcp.Implementation{Name: "simulated-github-mcp", Version: "0.0.0"}, nil)
	for _, entry := range tools() {
		server.AddTool(entry.tool, entry.handler)
	}

	serverTransport, clientTransport := mcp.NewInMemoryTransports()

	ctx := context.Background()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connecting simulated GitHub MCP server: %v", err)
	}
	t.Cleanup(func() { serverSession.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.0"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connecting to simulated GitHub MCP server: %v", err)
	}
	t.Cleanup(func() { clientSession.Close() })

	return clientSession
}
