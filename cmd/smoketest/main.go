// Command smoketest is a throwaway verification client. It connects to the
// running proxy binary exactly as a real agent would, lists the aggregated
// tool catalog, and calls one tool through it, to prove Milestone 1's
// transparent pass-through actually works end to end.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("usage: smoketest <path-to-proxy-binary> <path-to-config.yaml>")
	}
	proxyPath, configPath := os.Args[1], os.Args[2]

	ctx := context.Background()

	client := mcp.NewClient(&mcp.Implementation{Name: "smoketest", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{
		Command: exec.Command(proxyPath, configPath),
	}

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		log.Fatalf("connect to proxy: %v", err)
	}
	defer session.Close()

	fmt.Println("=== tools/list (via proxy) ===")
	var echoTool string
	for tool, err := range session.Tools(ctx, nil) {
		if err != nil {
			log.Fatalf("list tools: %v", err)
		}
		fmt.Printf("- %s\n", tool.Name)
		if echoTool == "" && tool.Name == "everything__echo" {
			echoTool = tool.Name
		}
	}

	if echoTool == "" {
		log.Fatalf("expected tool %q not found in catalog", "everything__echo")
	}

	fmt.Printf("\n=== tools/call: %s ===\n", echoTool)
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      echoTool,
		Arguments: map[string]any{"message": "hello through the policy proxy"},
	})
	if err != nil {
		log.Fatalf("call tool: %v", err)
	}

	for _, c := range result.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			fmt.Println(tc.Text)
		}
	}
}
