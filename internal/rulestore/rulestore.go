// Package rulestore implements the Rule Store described in architecture.md
// section 5.7: rules live as version-controlled YAML files, one per
// upstream server (rules/<server>.yaml), plus a reserved rules/_global.yaml
// for wildcard (server_scope "*") rules. This package owns storage only —
// CEL compilation is the policy package's job (section 5.3).
//
// A rule's "id" field in YAML is local to its file; Load qualifies it with
// the owning server's name (or "global" for _global.yaml) using the same
// "__" separator the router already uses for qualified tool names, so
// different servers can reuse the same short local rule names without
// colliding.
//
// Load failures are reported per server (architecture.md section 10 pairs
// with the product decision that one server's broken rule file must never
// stop the proxy or affect any other server's enforcement) rather than as a
// single fatal error. A missing rules directory is not an error at all — it
// means zero rules are configured, preserving Milestone 1's pass-through
// behavior.
package rulestore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/rule"
)

const (
	globalFileBase = "_global"
	globalScope    = "*"
	globalPrefix   = "global"
	separator      = "__"
)

// Store is an immutable, loaded snapshot of every valid rule found across
// the rule directory.
type Store struct {
	rules []rule.Rule
}

// All returns every successfully loaded rule, across every server.
func (s *Store) All() []rule.Rule {
	return s.rules
}

// ForServer returns every rule that applies to server: rules scoped
// specifically to it, plus every wildcard ("*") rule.
func (s *Store) ForServer(server string) []rule.Rule {
	var out []rule.Rule
	for _, r := range s.rules {
		if r.ServerScope == globalScope || r.ServerScope == server {
			out = append(out, r)
		}
	}
	return out
}

type fileSchema struct {
	Rules []rule.Rule `yaml:"rules"`
}

// Load reads every *.yaml/*.yml file in dir, one per server (plus the
// reserved _global.yaml for wildcard rules).
//
// The three return values are: the store of successfully loaded rules, a
// per-server map of load failures (keyed by server name, or "*" for a
// broken _global.yaml) for files that exist but are invalid, and a fatal
// error for problems with the directory itself (e.g. unreadable). A
// directory that simply doesn't exist is not an error — it yields an empty
// Store and a nil failure map.
func Load(dir string) (*Store, map[string]error, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return &Store{}, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("reading rules directory %q: %w", dir, err)
	}

	var loaded []rule.Rule
	failures := make(map[string]error)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		base := strings.TrimSuffix(entry.Name(), ext)
		scope, prefix := serverScopeAndPrefix(base)

		rules, err := loadFile(filepath.Join(dir, entry.Name()), scope, prefix)
		if err != nil {
			failures[scope] = err
			continue
		}
		loaded = append(loaded, rules...)
	}

	return &Store{rules: loaded}, failures, nil
}

// LoadFile reads a single rule file (the same "rules:" YAML shape a
// directory entry loaded by Load uses) without requiring the rest of the
// rules directory. Used by the standalone `backtest` command so a candidate
// rule can be backtested straight out of rules/<server>.yaml (or a scratch
// file) without loading every other server's rules too.
//
// serverOverride, if non-empty, is used as both the server scope and the
// qualified-id prefix instead of deriving them from the filename — for
// scratch files that aren't named like a real server. Pass "" to derive
// scope/prefix from the filename exactly as Load does (including the
// reserved "_global" -> "*" mapping).
func LoadFile(path, serverOverride string) ([]rule.Rule, error) {
	scope, prefix := serverOverride, serverOverride
	if serverOverride == "" {
		base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		scope, prefix = serverScopeAndPrefix(base)
	}
	return loadFile(path, scope, prefix)
}

func serverScopeAndPrefix(fileBase string) (scope, prefix string) {
	if fileBase == globalFileBase {
		return globalScope, globalPrefix
	}
	return fileBase, fileBase
}

func loadFile(path, scope, prefix string) ([]rule.Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}

	var schema fileSchema
	if err := yaml.Unmarshal(data, &schema); err != nil {
		return nil, fmt.Errorf("parsing %q: %w", path, err)
	}

	seen := make(map[string]bool, len(schema.Rules))
	rules := make([]rule.Rule, 0, len(schema.Rules))

	for _, r := range schema.Rules {
		localID := r.ID
		if localID == "" {
			return nil, fmt.Errorf("%q: rule missing id", path)
		}
		if seen[localID] {
			return nil, fmt.Errorf("%q: duplicate rule id %q", path, localID)
		}
		seen[localID] = true

		r.ID = prefix + separator + localID
		r.ServerScope = scope

		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("%q: %w", path, err)
		}

		rules = append(rules, r)
	}

	return rules, nil
}
