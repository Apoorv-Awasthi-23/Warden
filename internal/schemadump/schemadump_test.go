package schemadump

import (
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/catalog"
)

func mustCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	cat := catalog.New()
	if err := cat.Update("github", []*mcp.Tool{
		{
			Name:        "delete_file",
			Description: "Delete a file from the repo",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"path": map[string]any{"type": "string"}},
			},
		},
	}); err != nil {
		t.Fatalf("cat.Update: %v", err)
	}
	return cat
}

func TestWriteLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	cat := mustCatalog(t)

	if err := Write(dir, cat); err != nil {
		t.Fatalf("Write: %v", err)
	}

	tools, existed, err := Load(dir, "github")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !existed {
		t.Fatalf("expected a dump to exist after Write")
	}
	if len(tools) != 1 || tools[0].Name != "delete_file" {
		t.Fatalf("expected exactly one tool named delete_file, got %+v", tools)
	}
	if tools[0].SchemaHash == "" {
		t.Fatalf("expected a non-empty schema hash")
	}

	entry, ok := cat.Lookup("github", "delete_file")
	if !ok {
		t.Fatalf("lookup failed on fixture catalog")
	}
	if tools[0].SchemaHash != entry.SchemaHash {
		t.Fatalf("dumped hash %q does not match catalog hash %q", tools[0].SchemaHash, entry.SchemaHash)
	}
}

func TestLoad_MissingDumpIsNotAnError(t *testing.T) {
	dir := t.TempDir()

	tools, existed, err := Load(dir, "github")
	if err != nil {
		t.Fatalf("Load on a directory with no prior dump should not error: %v", err)
	}
	if existed {
		t.Fatalf("expected existed=false for a server with no prior dump")
	}
	if tools != nil {
		t.Fatalf("expected nil tools, got %+v", tools)
	}
}

func TestListServers(t *testing.T) {
	dir := t.TempDir()
	cat := mustCatalog(t)
	if err := Write(dir, cat); err != nil {
		t.Fatalf("Write: %v", err)
	}

	servers, err := ListServers(dir)
	if err != nil {
		t.Fatalf("ListServers: %v", err)
	}
	if len(servers) != 1 || servers[0] != "github" {
		t.Fatalf("expected [\"github\"], got %v", servers)
	}
}

func TestListServers_MissingDirIsNotAnError(t *testing.T) {
	servers, err := ListServers(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("ListServers on a missing directory should not error: %v", err)
	}
	if servers != nil {
		t.Fatalf("expected nil servers, got %v", servers)
	}
}
