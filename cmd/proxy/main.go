// Command proxy runs the MCP Policy Proxy: connects to every upstream MCP
// server listed in the config file, builds a live tool catalog, and serves
// an agent-facing MCP endpoint over stdio that transparently forwards calls
// and logs them. Milestone 1 — no enforcement yet.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/audit"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/catalog"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/config"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/router"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/upstream"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mcp-policy-proxy:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := "config.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	auditWriter, err := audit.Open("audit.log")
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}
	defer auditWriter.Close()

	ctx := context.Background()

	cat := catalog.New()
	sessions := make(map[string]*mcp.ClientSession)

	for _, sc := range cfg.Servers {
		session, err := upstream.Connect(ctx, sc)
		if err != nil {
			return fmt.Errorf("connecting to %q: %w", sc.Name, err)
		}
		defer session.Close()

		tools, err := upstream.ListTools(ctx, session)
		if err != nil {
			return fmt.Errorf("listing tools for %q: %w", sc.Name, err)
		}

		if err := cat.Update(sc.Name, tools); err != nil {
			return fmt.Errorf("updating catalog for %q: %w", sc.Name, err)
		}

		sessions[sc.Name] = session
		log.Printf("connected to %q: %d tools", sc.Name, len(tools))
	}

	rt := router.New(cat, sessions, auditWriter)

	log.Println("mcp-policy-proxy: serving on stdio")
	return rt.Run(ctx)
}
