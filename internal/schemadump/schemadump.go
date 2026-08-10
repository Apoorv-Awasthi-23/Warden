// Package schemadump exports the live Tool Schema Catalog to disk as one
// human- and agent-readable JSON file per server (architecture.md section
// 5.2/5.6). This is the reference material a rule author — a person or any
// external MCP-capable coding agent — reads to know real tool and field
// names when hand-writing a rule, without needing a live connection to the
// proxy or the upstream server. The same file also serves as the baseline
// internal/drift diffs against on the next refresh.
package schemadump

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/catalog"
)

// ToolSchema is one tool's exported schema entry, matching the fields a rule
// author needs: real name, description, and full input schema.
type ToolSchema struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
	SchemaHash  string          `json:"schema_hash"`
}

type fileSchema struct {
	Server string       `json:"server"`
	Tools  []ToolSchema `json:"tools"`
}

// Write exports every server's tools from cat to dir, one JSON file per
// server (<server>.json), overwriting any prior dump. Tools are sorted by
// name for stable, diffable output.
func Write(dir string, cat *catalog.Catalog) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating schemas directory %q: %w", dir, err)
	}

	byServer := make(map[string][]ToolSchema)
	for _, entry := range cat.All() {
		schema, err := json.Marshal(entry.Tool.InputSchema)
		if err != nil {
			return fmt.Errorf("marshaling schema for %s/%s: %w", entry.Server, entry.ToolName, err)
		}
		byServer[entry.Server] = append(byServer[entry.Server], ToolSchema{
			Name:        entry.ToolName,
			Description: entry.Tool.Description,
			InputSchema: schema,
			SchemaHash:  entry.SchemaHash,
		})
	}

	for server, tools := range byServer {
		sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })

		data, err := json.MarshalIndent(fileSchema{Server: server, Tools: tools}, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling schema dump for %q: %w", server, err)
		}
		data = append(data, '\n')

		path := filepath.Join(dir, server+".json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return fmt.Errorf("writing schema dump %q: %w", path, err)
		}
	}

	return nil
}

// ListServers returns the server names that have a schema dump on disk in
// dir (derived from filenames), sorted. A missing directory yields an empty
// list rather than an error — nothing has been dumped there yet.
func ListServers(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading schemas directory %q: %w", dir, err)
	}

	var servers []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		servers = append(servers, strings.TrimSuffix(entry.Name(), ".json"))
	}
	sort.Strings(servers)
	return servers, nil
}

// Load reads the previously written dump for one server. The second return
// value is false (with a nil error) if no dump exists yet for that server —
// e.g. the very first time the proxy connects to it — which is not an error,
// just "nothing to diff against."
func Load(dir, server string) ([]ToolSchema, bool, error) {
	path := filepath.Join(dir, server+".json")

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("reading schema dump %q: %w", path, err)
	}

	var schema fileSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		return nil, false, fmt.Errorf("parsing schema dump %q: %w", path, err)
	}

	return schema.Tools, true, nil
}
