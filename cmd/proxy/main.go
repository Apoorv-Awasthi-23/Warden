// Command proxy runs the MCP Policy Proxy: connects to every upstream MCP
// server listed in the config file, builds a live tool catalog, compiles the
// CEL policy rules in the Rule Store, and serves an agent-facing MCP
// endpoint over stdio that enforces those rules on every call before
// forwarding it and logging the outcome (architecture.md Milestone 2).
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/approval"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/audit"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/catalog"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/config"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/drift"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/enforcement"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/policy"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/router"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/rulestore"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/schemacheck"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/schemadump"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/upstream"
)

// main dispatches to the "validate" and "backtest" tooling subcommands
// (architecture.md section 5.6) or, for anything else, the normal proxy run
// mode — preserving the existing `mcp-policy-proxy [config-path]` usage,
// where a first argument that isn't one of the two reserved subcommand
// words is treated as a config path override by run() itself.
func main() {
	var err error
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "validate":
			err = runValidate(os.Args[2:])
		case "backtest":
			err = runBacktest(os.Args[2:])
		default:
			err = run()
		}
	} else {
		err = run()
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "mcp-policy-proxy:", err)
		os.Exit(1)
	}
}

// auditLogPath is the single audit log file, shared by the enforcement
// layer's writer and, when Config.ExposePolicyTools is enabled, the
// policy__backtest_rule tool's read path.
const auditLogPath = "audit.log"

func run() error {
	configPath := "config.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	auditWriter, err := audit.Open(auditLogPath)
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}
	defer auditWriter.Close()

	ctx := context.Background()

	cat := catalog.New()
	sessions := make(map[string]*mcp.ClientSession)
	priorSchemas := make(map[string][]schemadump.ToolSchema)

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

		// Load the prior schema dump before it gets overwritten below, so it
		// can be diffed against the freshly fetched schema (Schema Drift
		// Detection, architecture.md section 5.8). A server connected for
		// the first time simply has nothing to diff against yet.
		if old, existed, err := schemadump.Load(cfg.SchemasDir, sc.Name); err != nil {
			return fmt.Errorf("loading prior schema dump for %q: %w", sc.Name, err)
		} else if existed {
			priorSchemas[sc.Name] = old
		}

		if err := cat.Update(sc.Name, tools); err != nil {
			return fmt.Errorf("updating catalog for %q: %w", sc.Name, err)
		}

		sessions[sc.Name] = session
		log.Printf("connected to %q: %d tools", sc.Name, len(tools))
	}

	for _, sc := range cfg.Servers {
		old, existed := priorSchemas[sc.Name]
		if !existed {
			continue
		}
		for _, ev := range drift.Diff(sc.Name, old, cat.All()) {
			log.Printf("schema drift detected: server=%q tool=%q kind=%s — rules referencing a "+
				"now-missing field on this tool will fail closed below", ev.Server, ev.Tool, ev.Kind)
		}
	}

	if err := schemadump.Write(cfg.SchemasDir, cat); err != nil {
		return fmt.Errorf("writing schema dump to %q: %w", cfg.SchemasDir, err)
	}

	enforcer, err := buildEnforcer(cfg, auditWriter, cat)
	if err != nil {
		return fmt.Errorf("setting up policy enforcement: %w", err)
	}

	rt := router.New(cat, sessions, enforcer)
	if cfg.ExposePolicyTools {
		rt.RegisterPolicyTools(cat, auditLogPath)
		log.Println("policy__* rule-authoring tools exposed (expose_policy_tools: true)")
	}

	log.Println("mcp-policy-proxy: serving on stdio")
	return rt.Run(ctx)
}

// buildEnforcer loads the Rule Store, compiles it into a Policy Engine, and
// resolves what happens to each configured server whose rules failed to
// load, compile, or pass schema validation: by default every call to that
// server is blocked (fail-closed), unless its config explicitly opts into
// unenforced pass-through via UnsafeAllowPassThroughOnRuleError. A broken
// rules/_global.yaml (server_scope "*") is treated as affecting every
// server, since wildcard rules are cross-cutting — each server's own
// opt-out flag still applies individually.
//
// The schema-validation pass (internal/schemacheck, run against cat) is what
// catches both a hand-typo'd params field and a rule broken by an upstream
// schema change (internal/drift) — same fail-closed path as a CEL compile
// error, since both mean "this rule can never behave the way its author
// intended."
func buildEnforcer(cfg *config.Config, auditWriter *audit.Writer, cat *catalog.Catalog) (*enforcement.Enforcer, error) {
	store, loadErrors, err := rulestore.Load(cfg.RulesDir)
	if err != nil {
		return nil, fmt.Errorf("loading rules from %q: %w", cfg.RulesDir, err)
	}

	engine, compileErrors, err := policy.NewEngine(store.All())
	if err != nil {
		return nil, fmt.Errorf("building policy engine: %w", err)
	}
	log.Printf("loaded %d policy rules from %q", len(store.All()), cfg.RulesDir)

	brokenServers := make(map[string]error)
	for server, err := range loadErrors {
		brokenServers[server] = err
	}
	for server, err := range compileErrors {
		if existing, ok := brokenServers[server]; ok {
			brokenServers[server] = errors.Join(existing, err)
		} else {
			brokenServers[server] = err
		}
	}

	env, err := policy.NewEnv()
	if err != nil {
		return nil, fmt.Errorf("building CEL environment for schema checks: %w", err)
	}
	schemaSrc := schemacheck.FromCatalog(cat)
	for _, r := range store.All() {
		if _, compileFailed := compileErrors[r.ServerScope]; compileFailed {
			continue // already broken; schemacheck can't isolate which rule in that server is fine
		}
		if err := schemacheck.Check(r, env, schemaSrc); err != nil {
			if existing, ok := brokenServers[r.ServerScope]; ok {
				brokenServers[r.ServerScope] = errors.Join(existing, err)
			} else {
				brokenServers[r.ServerScope] = err
			}
		}
	}

	globalErr, globalBroken := brokenServers["*"]

	blockedServers := make(map[string]string)
	for _, sc := range cfg.Servers {
		serverErr, broken := brokenServers[sc.Name]
		if globalBroken {
			broken = true
			if serverErr != nil {
				serverErr = errors.Join(serverErr, globalErr)
			} else {
				serverErr = globalErr
			}
		}
		if !broken {
			continue
		}

		if sc.UnsafeAllowPassThroughOnRuleError {
			log.Printf("SECURITY WARNING: rules for server %q failed to load/compile (%v) and "+
				"unsafe_allow_pass_through_on_rule_error is enabled — calls to %q will NOT be "+
				"policy-checked until fixed", sc.Name, serverErr, sc.Name)
			continue
		}

		blockedServers[sc.Name] = fmt.Sprintf("blocked — policy rules for server %q failed to load: %v", sc.Name, serverErr)
		log.Printf("WARNING: %s", blockedServers[sc.Name])
	}

	prompter := approval.NewPrompter()
	return enforcement.New(engine, prompter, auditWriter, cfg.ApprovalTimeout, blockedServers), nil
}
