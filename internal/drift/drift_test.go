package drift

import (
	"testing"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/catalog"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/schemadump"
)

func eventKind(t *testing.T, events []Event, tool string) Kind {
	t.Helper()
	for _, e := range events {
		if e.Tool == tool {
			return e.Kind
		}
	}
	t.Fatalf("no event found for tool %q in %+v", tool, events)
	return ""
}

func TestDiff_ToolAdded(t *testing.T) {
	old := []schemadump.ToolSchema{{Name: "delete_file", SchemaHash: "h1"}}
	current := []catalog.Entry{
		{Server: "github", ToolName: "delete_file", SchemaHash: "h1"},
		{Server: "github", ToolName: "create_file", SchemaHash: "h2"},
	}

	events := Diff("github", old, current)
	if len(events) != 1 {
		t.Fatalf("expected exactly one event, got %+v", events)
	}
	if eventKind(t, events, "create_file") != KindToolAdded {
		t.Fatalf("expected create_file to be tool_added, got %+v", events)
	}
}

func TestDiff_ToolRemoved(t *testing.T) {
	old := []schemadump.ToolSchema{
		{Name: "delete_file", SchemaHash: "h1"},
		{Name: "archive_file", SchemaHash: "h3"},
	}
	current := []catalog.Entry{
		{Server: "github", ToolName: "delete_file", SchemaHash: "h1"},
	}

	events := Diff("github", old, current)
	if len(events) != 1 {
		t.Fatalf("expected exactly one event, got %+v", events)
	}
	if eventKind(t, events, "archive_file") != KindToolRemoved {
		t.Fatalf("expected archive_file to be tool_removed, got %+v", events)
	}
}

func TestDiff_SchemaChanged(t *testing.T) {
	old := []schemadump.ToolSchema{{Name: "delete_file", SchemaHash: "h1"}}
	current := []catalog.Entry{
		{Server: "github", ToolName: "delete_file", SchemaHash: "h2-renamed-field"},
	}

	events := Diff("github", old, current)
	if len(events) != 1 {
		t.Fatalf("expected exactly one event, got %+v", events)
	}
	if eventKind(t, events, "delete_file") != KindSchemaChanged {
		t.Fatalf("expected delete_file to be schema_changed, got %+v", events)
	}
}

func TestDiff_NoChangeNoEvents(t *testing.T) {
	old := []schemadump.ToolSchema{{Name: "delete_file", SchemaHash: "h1"}}
	current := []catalog.Entry{
		{Server: "github", ToolName: "delete_file", SchemaHash: "h1"},
	}

	events := Diff("github", old, current)
	if len(events) != 0 {
		t.Fatalf("expected no events for an unchanged schema, got %+v", events)
	}
}

func TestDiff_IgnoresOtherServers(t *testing.T) {
	old := []schemadump.ToolSchema{{Name: "delete_file", SchemaHash: "h1"}}
	current := []catalog.Entry{
		{Server: "github", ToolName: "delete_file", SchemaHash: "h1"},
		{Server: "aws", ToolName: "terminate_instance", SchemaHash: "h9"},
	}

	events := Diff("github", old, current)
	if len(events) != 0 {
		t.Fatalf("expected aws entries to be ignored when diffing github, got %+v", events)
	}
}
