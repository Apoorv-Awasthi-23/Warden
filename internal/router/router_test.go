package router

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/approval"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/audit"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/catalog"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/enforcement"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/policy"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/rule"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/testutil/githubmcp"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/upstream"
)

// mockApprover is never expected to be consulted by any test in this file —
// none of the rules used here produce a require_approval verdict — but
// enforcement.New requires a non-nil Approver.
type mockApprover struct{ called bool }

func (m *mockApprover) Request(ctx context.Context, timeout time.Duration, cc policy.CallContext, matchedRules []string) (approval.Decision, string, error) {
	m.called = true
	return approval.DecisionDenied, "unexpected approval request", nil
}

func mustEngine(t *testing.T, rules []rule.Rule) *policy.Engine {
	t.Helper()
	engine, failures, err := policy.NewEngine(rules)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if len(failures) != 0 {
		t.Fatalf("unexpected compile failures: %v", failures)
	}
	return engine
}

func mustAuditor(t *testing.T) *audit.Writer {
	t.Helper()
	w, err := audit.Open(t.TempDir() + "/audit.log")
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { w.Close() })
	return w
}

// objectSchema mirrors githubmcp's helper of the same purpose: a minimal
// JSON Schema object with the given top-level string properties.
func objectSchema(properties ...string) map[string]any {
	props := make(map[string]any, len(properties))
	for _, p := range properties {
		props[p] = map[string]any{"type": "string"}
	}
	return map[string]any{"type": "object", "properties": props, "required": properties}
}

// newFakeUpstream starts an in-process MCP server exposing exactly the given
// tools/handlers and returns a connected client session — the same
// mcp.NewInMemoryTransports pattern internal/testutil/githubmcp uses, but
// with caller-supplied handlers so a test can simulate an upstream tool call
// failing.
func newFakeUpstream(t *testing.T, tools []*mcp.Tool, handler mcp.ToolHandler) *mcp.ClientSession {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "fake-upstream", Version: "0.0.0"}, nil)
	for _, tl := range tools {
		server.AddTool(tl, handler)
	}

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx := context.Background()

	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connecting fake upstream server: %v", err)
	}
	t.Cleanup(func() { serverSession.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.0"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connecting to fake upstream server: %v", err)
	}
	t.Cleanup(func() { clientSession.Close() })

	return clientSession
}

// connectAgent connects a client session to the Router's agent-facing MCP
// server, over another in-process transport pair — a real handshake, so
// req.Session is populated exactly as it would be for a genuine agent.
func connectAgent(t *testing.T, rt *Router) *mcp.ClientSession {
	t.Helper()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx := context.Background()

	serverSession, err := rt.server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connecting router's agent-facing server: %v", err)
	}
	t.Cleanup(func() { serverSession.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "0.0.0"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connecting agent client: %v", err)
	}
	t.Cleanup(func() { clientSession.Close() })

	return clientSession
}

func TestCallTool_AllowedForwardsToUpstream(t *testing.T) {
	upstreamSession := githubmcp.NewSession(t)
	cat := catalog.New()
	tools, err := upstream.ListTools(context.Background(), upstreamSession)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if err := cat.Update("github", tools); err != nil {
		t.Fatalf("cat.Update: %v", err)
	}

	engine := mustEngine(t, nil) // no rules — everything allowed
	enforcer := enforcement.New(engine, &mockApprover{}, mustAuditor(t), time.Second, nil)
	rt := New(cat, map[string]*mcp.ClientSession{"github": upstreamSession}, enforcer)

	agent := connectAgent(t, rt)
	result, err := agent.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "github__push",
		Arguments: map[string]any{"repo": "acme/widgets", "branch": "dev", "force": "false"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected a successful result, got error result: %+v", result)
	}
}

func TestCallTool_HardStopRejectsWithoutForwarding(t *testing.T) {
	upstreamSession := githubmcp.NewSession(t)
	cat := catalog.New()
	tools, err := upstream.ListTools(context.Background(), upstreamSession)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if err := cat.Update("github", tools); err != nil {
		t.Fatalf("cat.Update: %v", err)
	}

	engine := mustEngine(t, []rule.Rule{
		{ID: "block", ServerScope: "github", CELExpression: `tool == "delete_repository"`, Action: rule.ActionHardStop},
	})
	enforcer := enforcement.New(engine, &mockApprover{}, mustAuditor(t), time.Second, nil)
	rt := New(cat, map[string]*mcp.ClientSession{"github": upstreamSession}, enforcer)

	agent := connectAgent(t, rt)
	result, err := agent.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "github__delete_repository",
		Arguments: map[string]any{"repo": "acme/widgets", "confirm": "yes"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected an error result for a hard-stopped call, got %+v", result)
	}
	if len(result.Content) == 0 {
		t.Fatalf("expected reject reason content, got none")
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || !strings.Contains(text.Text, "block") {
		t.Fatalf("expected reject reason to mention the matched rule, got %+v", result.Content[0])
	}
}

func TestCallTool_UpstreamErrorIsWrapped(t *testing.T) {
	failingTool := &mcp.Tool{Name: "explode", Description: "always fails", InputSchema: objectSchema()}
	upstreamSession := newFakeUpstream(t, []*mcp.Tool{failingTool}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return nil, context.DeadlineExceeded
	})

	cat := catalog.New()
	if err := cat.Update("flaky", []*mcp.Tool{failingTool}); err != nil {
		t.Fatalf("cat.Update: %v", err)
	}

	engine := mustEngine(t, nil)
	enforcer := enforcement.New(engine, &mockApprover{}, mustAuditor(t), time.Second, nil)
	rt := New(cat, map[string]*mcp.ClientSession{"flaky": upstreamSession}, enforcer)

	agent := connectAgent(t, rt)
	_, err := agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "flaky__explode"})
	if err == nil {
		t.Fatalf("expected an error forwarding to a failing upstream tool")
	}
}

func TestCallTool_MalformedQualifiedName(t *testing.T) {
	rt := New(catalog.New(), nil, enforcement.New(mustEngine(t, nil), &mockApprover{}, mustAuditor(t), time.Second, nil))

	_, err := rt.callTool(context.Background(), &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Name: "no-separator-here"},
	})
	if err == nil || !strings.Contains(err.Error(), "malformed tool name") {
		t.Fatalf("expected a malformed tool name error, got %v", err)
	}
}

func TestCallTool_UnknownServerSession(t *testing.T) {
	rt := New(catalog.New(), map[string]*mcp.ClientSession{}, enforcement.New(mustEngine(t, nil), &mockApprover{}, mustAuditor(t), time.Second, nil))

	_, err := rt.callTool(context.Background(), &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Name: "unknown-server__push"},
	})
	if err == nil || !strings.Contains(err.Error(), `no connected server named`) {
		t.Fatalf("expected a no-connected-server error, got %v", err)
	}
}

func TestCallTool_MalformedArguments(t *testing.T) {
	upstreamSession := githubmcp.NewSession(t)
	rt := New(catalog.New(), map[string]*mcp.ClientSession{"github": upstreamSession},
		enforcement.New(mustEngine(t, nil), &mockApprover{}, mustAuditor(t), time.Second, nil))

	_, err := rt.callTool(context.Background(), &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Name: "github__push", Arguments: json.RawMessage(`{not valid json`)},
	})
	if err == nil || !strings.Contains(err.Error(), "decoding arguments") {
		t.Fatalf("expected a decoding-arguments error, got %v", err)
	}
}

func TestQualifiedName_RoundTrip(t *testing.T) {
	server, toolName, ok := splitQualifiedName(qualifiedName("github", "push"))
	if !ok || server != "github" || toolName != "push" {
		t.Fatalf("expected round-trip to recover (github, push, true), got (%q, %q, %v)", server, toolName, ok)
	}
}

func TestSplitQualifiedName_NoSeparator(t *testing.T) {
	if _, _, ok := splitQualifiedName("nosep"); ok {
		t.Fatalf("expected ok=false for a name without a separator")
	}
}

func TestSplitQualifiedName_ToolNameContainingSeparator(t *testing.T) {
	// SplitN(...,2) semantics: the server is the first segment, and the tool
	// name is everything after the first separator, even if it itself
	// contains "__" — a real edge case for a tool literally named "foo__bar".
	server, toolName, ok := splitQualifiedName("github__foo__bar")
	if !ok || server != "github" || toolName != "foo__bar" {
		t.Fatalf("expected (github, foo__bar, true), got (%q, %q, %v)", server, toolName, ok)
	}
}
