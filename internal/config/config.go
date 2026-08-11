package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Transport string

const (
	TransportStdio Transport = "stdio"
	TransportHTTP  Transport = "http"
)

const (
	defaultRulesDir        = "rules"
	defaultSchemasDir      = "schemas"
	defaultApprovalTimeout = "30s"
)

type ServerConfig struct {
	Name      string    `yaml:"name"`
	Transport Transport `yaml:"transport"`
	Command   string    `yaml:"command,omitempty"`
	Args      []string  `yaml:"args,omitempty"`
	URL       string    `yaml:"url,omitempty"`

	// UnsafeAllowPassThroughOnRuleError lets an operator explicitly accept
	// running this one server unenforced if its rule file fails to load or
	// compile, instead of the default fail-closed behavior of blocking every
	// call to it. Named to be grep-able and to make the risk visible in the
	// config file itself.
	UnsafeAllowPassThroughOnRuleError bool `yaml:"unsafe_allow_pass_through_on_rule_error,omitempty"`
}

type Config struct {
	Servers []ServerConfig `yaml:"servers"`

	// RulesDir is the directory rulestore.Load reads rule files from.
	// Defaults to "rules" if empty. A directory that doesn't exist at all is
	// not an error — it means zero rules are configured yet, preserving
	// pass-through behavior.
	RulesDir string `yaml:"rules_dir"`

	// SchemasDir is the directory the Tool Schema Catalog is exported to on
	// every refresh (internal/schemadump): one JSON file per server, used as
	// reference material for hand- or agent-written rules and as the
	// baseline for schema drift detection. Defaults to "schemas" if empty.
	SchemasDir string `yaml:"schemas_dir"`

	// ExposePolicyTools enables three additional read-only MCP tools
	// (policy__list_tool_schemas, policy__validate_rule,
	// policy__backtest_rule) alongside the proxied ones, for an
	// MCP-connected agent authoring rules to query schema/validation/backtest
	// data live instead of reading the schema dump files. Off by default so
	// these don't clutter the tool list for agents just using the proxy for
	// normal pass-through traffic.
	ExposePolicyTools bool `yaml:"expose_policy_tools,omitempty"`

	// ApprovalTimeoutRaw is the configured approval hold duration (e.g.
	// "30s"), parsed into ApprovalTimeout during validate. Defaults to 30s.
	ApprovalTimeoutRaw string `yaml:"approval_timeout"`

	// ApprovalTimeout is the parsed form of ApprovalTimeoutRaw, populated by
	// validate. Not itself a YAML field.
	ApprovalTimeout time.Duration `yaml:"-"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	for _, s := range c.Servers {
		if s.Name == "" {
			return fmt.Errorf("server missing name")
		}

		switch s.Transport {
		case TransportStdio:
			if s.Command == "" {
				return fmt.Errorf("server %q: stdio transport requires command", s.Name)
			}
		case TransportHTTP:
			if s.URL == "" {
				return fmt.Errorf("server %q: http transport requires url", s.Name)
			}
		default:
			return fmt.Errorf("server %q: unknown transport method %q", s.Name, s.Transport)
		}
	}

	if c.RulesDir == "" {
		c.RulesDir = defaultRulesDir
	}

	if c.SchemasDir == "" {
		c.SchemasDir = defaultSchemasDir
	}

	if c.ApprovalTimeoutRaw == "" {
		c.ApprovalTimeoutRaw = defaultApprovalTimeout
	}
	timeout, err := time.ParseDuration(c.ApprovalTimeoutRaw)
	if err != nil {
		return fmt.Errorf("invalid approval_timeout %q: %w", c.ApprovalTimeoutRaw, err)
	}
	if timeout <= 0 {
		return fmt.Errorf("approval_timeout must be positive, got %q", c.ApprovalTimeoutRaw)
	}
	c.ApprovalTimeout = timeout

	return nil
}
