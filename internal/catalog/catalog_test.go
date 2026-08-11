package catalog

import (
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func tool(name string, properties ...string) *mcp.Tool {
	props := make(map[string]any, len(properties))
	for _, p := range properties {
		props[p] = map[string]any{"type": "string"}
	}
	return &mcp.Tool{
		Name:        name,
		Description: "desc for " + name,
		InputSchema: map[string]any{"type": "object", "properties": props},
	}
}

func TestUpdate_LookupAndAll(t *testing.T) {
	cat := New()
	if err := cat.Update("github", []*mcp.Tool{tool("push", "branch"), tool("delete_file", "path")}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	entry, ok := cat.Lookup("github", "push")
	if !ok {
		t.Fatalf("expected to find github/push")
	}
	if entry.Server != "github" || entry.ToolName != "push" || entry.SchemaHash == "" {
		t.Fatalf("unexpected entry: %+v", entry)
	}

	if _, ok := cat.Lookup("github", "no-such-tool"); ok {
		t.Fatalf("expected Lookup to fail for an unknown tool")
	}
	if _, ok := cat.Lookup("no-such-server", "push"); ok {
		t.Fatalf("expected Lookup to fail for an unknown server")
	}

	all := cat.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 entries from All(), got %d: %+v", len(all), all)
	}
}

func TestUpdate_ReplacesPreviousToolSet(t *testing.T) {
	cat := New()
	if err := cat.Update("github", []*mcp.Tool{tool("push"), tool("delete_file")}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := cat.Update("github", []*mcp.Tool{tool("push")}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if _, ok := cat.Lookup("github", "delete_file"); ok {
		t.Fatalf("expected delete_file to be gone after the tool set was replaced")
	}
	if _, ok := cat.Lookup("github", "push"); !ok {
		t.Fatalf("expected push to still be present")
	}
	if all := cat.All(); len(all) != 1 {
		t.Fatalf("expected exactly 1 entry after replacement, got %d: %+v", len(all), all)
	}
}

func TestSchemaHash_DeterministicAndSensitiveToChange(t *testing.T) {
	cat := New()
	if err := cat.Update("github", []*mcp.Tool{tool("push", "branch")}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	first, _ := cat.Lookup("github", "push")

	// Re-running Update with an identical schema must produce the same hash.
	if err := cat.Update("github", []*mcp.Tool{tool("push", "branch")}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	second, _ := cat.Lookup("github", "push")
	if first.SchemaHash != second.SchemaHash {
		t.Fatalf("expected identical schema to hash identically, got %q vs %q", first.SchemaHash, second.SchemaHash)
	}

	// A changed schema must produce a different hash.
	if err := cat.Update("github", []*mcp.Tool{tool("push", "branch", "force")}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	third, _ := cat.Lookup("github", "push")
	if third.SchemaHash == second.SchemaHash {
		t.Fatalf("expected a changed schema to produce a different hash, both were %q", third.SchemaHash)
	}
}

func TestCatalog_ConcurrentAccess(t *testing.T) {
	cat := New()
	if err := cat.Update("github", []*mcp.Tool{tool("push")}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(3)
		go func(i int) {
			defer wg.Done()
			_ = cat.Update("github", []*mcp.Tool{tool("push"), tool("delete_file")})
		}(i)
		go func() {
			defer wg.Done()
			cat.Lookup("github", "push")
		}()
		go func() {
			defer wg.Done()
			cat.All()
		}()
	}
	wg.Wait()
}
