package upstream

import (
	"context"
	"strings"
	"testing"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/config"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/testutil/githubmcp"
)

// TestConnect_UnsupportedTransport exercises the one branch of Connect that
// needs no real process or network I/O to reach: an unrecognized transport
// value hits the default case and returns immediately.
func TestConnect_UnsupportedTransport(t *testing.T) {
	_, err := Connect(context.Background(), config.ServerConfig{Name: "bogus", Transport: "carrier-pigeon"})
	if err == nil || !strings.Contains(err.Error(), "unsupported transport") {
		t.Fatalf("expected an unsupported transport error, got %v", err)
	}
}

// TestListTools_AgainstSimulatedGitHubServer exercises ListTools against a
// real MCP handshake and tool listing (in-process, via
// mcp.NewInMemoryTransports — see internal/testutil/githubmcp) rather than a
// hand-built fixture, closing what was previously zero test coverage for
// this package. upstream.Connect itself isn't exercised here since it's
// hardwired to real stdio/HTTP transports; ListTools is the part worth
// testing against something that behaves like a genuine server.
func TestListTools_AgainstSimulatedGitHubServer(t *testing.T) {
	session := githubmcp.NewSession(t)

	tools, err := ListTools(context.Background(), session)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	want := map[string]bool{
		"delete_file":         false,
		"delete_branch":       false,
		"delete_repository":   false,
		"push":                false,
		"create_pull_request": false,
	}
	for _, tool := range tools {
		if _, ok := want[tool.Name]; !ok {
			t.Fatalf("unexpected tool %q returned", tool.Name)
		}
		want[tool.Name] = true
		if tool.InputSchema == nil {
			t.Fatalf("tool %q: expected a non-nil input schema", tool.Name)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("expected tool %q to be listed, got %+v", name, tools)
		}
	}
}
