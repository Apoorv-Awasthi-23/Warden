package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing config fixture: %v", err)
	}
	return path
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil || !strings.Contains(err.Error(), "reading config file") {
		t.Fatalf("expected a 'reading config file' error, got %v", err)
	}
}

func TestLoad_MalformedYAML(t *testing.T) {
	path := writeConfig(t, "servers: [this is not valid yaml")
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "parsing config file") {
		t.Fatalf("expected a 'parsing config file' error, got %v", err)
	}
}

func TestLoad_ValidationBranches(t *testing.T) {
	cases := []struct {
		name          string
		yaml          string
		wantErrSubstr string
	}{
		{
			name:          "missing server name",
			yaml:          "servers:\n  - transport: stdio\n    command: true\n",
			wantErrSubstr: "server missing name",
		},
		{
			name:          "stdio requires command",
			yaml:          "servers:\n  - name: github\n    transport: stdio\n",
			wantErrSubstr: `stdio transport requires command`,
		},
		{
			name:          "http requires url",
			yaml:          "servers:\n  - name: github\n    transport: http\n",
			wantErrSubstr: `http transport requires url`,
		},
		{
			name:          "unknown transport",
			yaml:          "servers:\n  - name: github\n    transport: carrier-pigeon\n",
			wantErrSubstr: `unknown transport method`,
		},
		{
			name:          "invalid approval_timeout duration",
			yaml:          "servers: []\napproval_timeout: not-a-duration\n",
			wantErrSubstr: "invalid approval_timeout",
		},
		{
			name:          "zero approval_timeout",
			yaml:          "servers: []\napproval_timeout: 0s\n",
			wantErrSubstr: "approval_timeout must be positive",
		},
		{
			name:          "negative approval_timeout",
			yaml:          "servers: []\napproval_timeout: -5s\n",
			wantErrSubstr: "approval_timeout must be positive",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErrSubstr, err)
			}
		})
	}
}

func TestLoad_DefaultsApplied(t *testing.T) {
	cfg, err := Load(writeConfig(t, "servers: []\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.RulesDir != "rules" {
		t.Fatalf("expected default RulesDir %q, got %q", "rules", cfg.RulesDir)
	}
	if cfg.SchemasDir != "schemas" {
		t.Fatalf("expected default SchemasDir %q, got %q", "schemas", cfg.SchemasDir)
	}
	if cfg.ApprovalTimeoutRaw != "30s" {
		t.Fatalf("expected default ApprovalTimeoutRaw %q, got %q", "30s", cfg.ApprovalTimeoutRaw)
	}
	if cfg.ApprovalTimeout != 30*time.Second {
		t.Fatalf("expected default ApprovalTimeout 30s, got %v", cfg.ApprovalTimeout)
	}
}

func TestLoad_FullValidConfig(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
servers:
  - name: github
    transport: stdio
    command: github-mcp-server
    args: ["--flag"]
  - name: internal-api
    transport: http
    url: https://example.com/mcp
rules_dir: my-rules
schemas_dir: my-schemas
expose_policy_tools: true
approval_timeout: 45s
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(cfg.Servers))
	}
	if cfg.Servers[0].Name != "github" || cfg.Servers[0].Transport != TransportStdio || cfg.Servers[0].Command != "github-mcp-server" {
		t.Fatalf("unexpected first server: %+v", cfg.Servers[0])
	}
	if cfg.Servers[1].Name != "internal-api" || cfg.Servers[1].Transport != TransportHTTP || cfg.Servers[1].URL != "https://example.com/mcp" {
		t.Fatalf("unexpected second server: %+v", cfg.Servers[1])
	}
	if cfg.RulesDir != "my-rules" || cfg.SchemasDir != "my-schemas" {
		t.Fatalf("expected custom dirs to be preserved, got RulesDir=%q SchemasDir=%q", cfg.RulesDir, cfg.SchemasDir)
	}
	if !cfg.ExposePolicyTools {
		t.Fatalf("expected ExposePolicyTools true")
	}
	if cfg.ApprovalTimeout != 45*time.Second {
		t.Fatalf("expected ApprovalTimeout 45s, got %v", cfg.ApprovalTimeout)
	}
}

func TestLoad_ServerEnv(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
servers:
  - name: calendar
    transport: stdio
    command: npx
    args: ["-y", "@cocal/google-calendar-mcp"]
    env:
      GOOGLE_OAUTH_CREDENTIALS: /home/user/.gmail-mcp/gcp-oauth.keys.json
  - name: gmail
    transport: stdio
    command: npx
    args: ["-y", "@gongrzhe/server-gmail-autoauth-mcp"]
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(cfg.Servers))
	}

	calendar := cfg.Servers[0]
	if got := calendar.Env["GOOGLE_OAUTH_CREDENTIALS"]; got != "/home/user/.gmail-mcp/gcp-oauth.keys.json" {
		t.Fatalf("expected GOOGLE_OAUTH_CREDENTIALS to be set, got %+v", calendar.Env)
	}

	gmail := cfg.Servers[1]
	if len(gmail.Env) != 0 {
		t.Fatalf("expected no env vars for gmail server, got %+v", gmail.Env)
	}
}
