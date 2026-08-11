# MCP Policy Proxy — Build & Test Instructions

A transparent Go gateway that sits between an AI agent and one or more MCP
servers, enforcing team-authored CEL rules on every tool call. See
`architecture.md` for the full design; this doc is just "how do I run it on
my machine."

## 1. Prerequisites

- **Go** 1.25+ (`go version` — this machine has `go1.25.0`, matches `go.mod`)
- **Node.js / npx** — only needed because the default `config.yaml` points at
  the demo upstream server `@modelcontextprotocol/server-everything`, which
  npx fetches and runs on the fly. Not required if you point the proxy at a
  different MCP server.

No database, no Docker — everything is flat files (config, rules, audit log).

## 2. Build

From the repo root:

```bash
go build -o bin/proxy ./cmd/proxy
```

This produces the `mcp-policy-proxy` binary at `bin/proxy`. (A prebuilt copy
already exists there from a previous build — rerun the command above any
time you change code under `cmd/` or `internal/`.)

Optionally also build the smoketest client (used in step 4):

```bash
go build -o bin/smoketest ./cmd/smoketest
```

## 3. Run the proxy

`config.yaml` is gitignored (it's your personal server list, not a shared
default) — copy the template to get started:

```bash
cp config.example.yaml config.yaml
./bin/proxy config.yaml
```

(`config.yaml` is also the default if you omit the argument: `./bin/proxy`.)

On startup it will:
1. Connect to every server listed in `config.yaml` (by default just
   `everything`, launched via `npx -y @modelcontextprotocol/server-everything`
   — first run will download the package, so it needs network access once).
2. Fetch each server's tool schemas, write them to `schemas/<server>.json`,
   and log any schema drift vs. the previous dump.
3. Load and compile the CEL rules in `rules/` (see `rules/everything.yaml`
   for the two example rules: block `get-env` outright, require approval for
   `trigger-long-running-operation`).
4. Start serving the aggregated MCP endpoint **on stdio**.

Because it speaks stdio, it's meant to be spawned as a subprocess by an MCP
client (an agent, Claude Code, etc.) — running it directly in a terminal
will just sit there waiting on stdin, which is expected.

To point it at a real Claude Code / MCP client instead of the smoketest
below, add it as an MCP server whose command is the built binary, e.g. in
Claude Code:

```bash
claude mcp add policy-proxy -- /absolute/path/to/bin/proxy /absolute/path/to/config.yaml
```

## 4. Smoke-test it end to end

The included `smoketest` client connects to the proxy exactly like a real
agent would, lists the merged tool catalog, and calls one tool through it:

```bash
go build -o bin/smoketest ./cmd/smoketest
./bin/smoketest ./bin/proxy config.yaml
```

Expected output: a `tools/list` dump including `everything__echo`, followed
by a successful call to it and the echoed response text.

To see enforcement working, try calling `everything__get-env` instead (via
your own MCP client) — it should be hard-stopped per
`rules/everything.yaml`. Calling `everything__trigger-long-running-operation`
should block the call and prompt for approval in the terminal running the
proxy (fail-closed if you don't respond within `approval_timeout`, default
30s).

## 5. Run the automated test suite

```bash
go test ./...
```

This covers config loading, the CEL policy engine, rule store, schema
checking/drift, backtest, audit logging, and the `validate`/`backtest` CLI
subcommands.

## 6. Rule-authoring tooling (CLI)

These are the "compiler" and "test suite" for rules — run them before
committing a rule change.

**Validate** every rule file compiles and only references real schema fields:

```bash
./bin/proxy validate            # uses ./rules and ./schemas by default
./bin/proxy validate --schemas-dir schemas rules
```

**Backtest** a single rule file against the audit log to see what it would
have matched:

```bash
./bin/proxy backtest rules/everything.yaml
./bin/proxy backtest --since 24h --audit-log audit.log rules/everything.yaml
```

Note `backtest` needs audit log history to replay against — run the proxy
and make a few calls through it first (step 4) if `audit.log` is empty.

## 7. Config reference (`config.yaml`)

```yaml
servers:
  - name: everything            # required, becomes the tool-name prefix
    transport: stdio            # stdio | http
    command: npx                # stdio only
    args: ["-y", "@modelcontextprotocol/server-everything"]
    # url: https://...          # http only, instead of command/args
    # unsafe_allow_pass_through_on_rule_error: true   # opt out of fail-closed

rules_dir: rules                # default: "rules"
schemas_dir: schemas             # default: "schemas"
approval_timeout: 30s            # default: 30s; must stay under your MCP client's own timeout
expose_policy_tools: false       # default false; set true to expose policy__list_tool_schemas,
                                  # policy__validate_rule, policy__backtest_rule as MCP tools
```

To point the proxy at your own MCP server instead of the demo one, add
another entry under `servers:` and, if you want rules for it, create
`rules/<server-name>.yaml` (or `rules/_global.yaml` with `server_scope: "*"`
for rules that apply everywhere). If that server needs machine-specific setup
(a local browser path, credentials, etc.), keep that config under `local/`
(gitignored) and reference it from your own `config.yaml` — see
`TESTED_SERVERS.md` for servers already worked through this way.

## 8. Where things live

| Path | Purpose |
|---|---|
| `config.example.yaml` | committed onboarding template — copy to `config.yaml` |
| `config.yaml` | your personal server list (gitignored) |
| `local/` | gitignored machine-specific config for individual servers |
| `TESTED_SERVERS.md` | log of MCP servers tested through this proxy and any setup they needed |
| `rules/*.yaml` | CEL rules, one file per server (or `_global.yaml`) |
| `schemas/*.json` | live tool-schema dump, written on every startup |
| `audit.log` | append-only JSON Lines log of every call + outcome (gitignored) |
| `cmd/proxy` | main binary + `validate`/`backtest` subcommands |
| `cmd/smoketest` | throwaway client for exercising the proxy manually |
| `internal/*` | engine, router, enforcement, rulestore, etc. |
