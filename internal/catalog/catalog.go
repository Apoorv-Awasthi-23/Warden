package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Entry is the Tool Schema Entry described in architecture.md section 8.
type Entry struct {
	Server     string
	ToolName   string
	Tool       *mcp.Tool
	LastSeen   time.Time
	SchemaHash string
}

// Catalog is the live, in-memory inventory of every tool on every connected
// upstream server. Safe for concurrent use.
type Catalog struct {
	mu      sync.RWMutex
	entries map[string]map[string]Entry // server -> tool name -> Entry
}

func New() *Catalog {
	return &Catalog{entries: make(map[string]map[string]Entry)}
}

// Update replaces the full set of tools known for one server, e.g. after a
// discovery refresh.
func (c *Catalog) Update(server string, tools []*mcp.Tool) error {
	now := time.Now()
	byName := make(map[string]Entry, len(tools))

	for _, t := range tools {
		hash, err := schemaHash(t.InputSchema)
		if err != nil {
			return fmt.Errorf("hashing schema for %s/%s: %w", server, t.Name, err)
		}
		byName[t.Name] = Entry{
			Server:     server,
			ToolName:   t.Name,
			Tool:       t,
			LastSeen:   now,
			SchemaHash: hash,
		}
	}

	c.mu.Lock()
	c.entries[server] = byName
	c.mu.Unlock()

	return nil
}

// Lookup returns the catalog entry for a specific server/tool pair.
func (c *Catalog) Lookup(server, toolName string) (Entry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	byName, ok := c.entries[server]
	if !ok {
		return Entry{}, false
	}
	entry, ok := byName[toolName]
	return entry, ok
}

// All returns every known entry across every server, in no particular order.
func (c *Catalog) All() []Entry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var all []Entry
	for _, byName := range c.entries {
		for _, entry := range byName {
			all = append(all, entry)
		}
	}
	return all
}

func schemaHash(schema any) (string, error) {
	data, err := json.Marshal(schema)
	if err != nil {
		return "", fmt.Errorf("marshaling schema: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
