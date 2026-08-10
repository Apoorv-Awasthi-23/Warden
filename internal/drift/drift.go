// Package drift implements the startup-time half of Schema Drift Detection
// (architecture.md section 5.8): comparing the schema dump on disk from the
// last time the proxy started against what was just fetched live, so a
// changed upstream tool schema is visible instead of silent.
//
// This package is purely observability — it explains *why* a server's rules
// might have just broken. The actual safety enforcement (blocking a server
// whose rules now reference a field that no longer exists) falls out of
// internal/schemacheck running against the live, post-refresh catalog on
// every startup regardless of whether drift.Diff ran at all; drift just
// gives that failure a clear, logged cause.
package drift

import "github.com/awasthiapoorv23/mcp-policy-proxy/internal/catalog"
import "github.com/awasthiapoorv23/mcp-policy-proxy/internal/schemadump"

// Kind identifies what changed about one tool between two schema snapshots.
type Kind string

const (
	KindToolAdded     Kind = "tool_added"
	KindToolRemoved   Kind = "tool_removed"
	KindSchemaChanged Kind = "schema_changed"
)

// Event is one detected change for a single tool on a single server.
type Event struct {
	Server string
	Tool   string
	Kind   Kind
}

// Diff compares old (the last schema dump loaded from disk for server,
// server) against current (that server's freshly fetched catalog entries)
// and returns one Event per tool that was added, removed, or whose schema
// hash changed. Returns nil if nothing changed.
func Diff(server string, old []schemadump.ToolSchema, current []catalog.Entry) []Event {
	oldByName := make(map[string]schemadump.ToolSchema, len(old))
	for _, t := range old {
		oldByName[t.Name] = t
	}
	currentByName := make(map[string]catalog.Entry, len(current))
	for _, e := range current {
		if e.Server != server {
			continue
		}
		currentByName[e.ToolName] = e
	}

	var events []Event

	for name, entry := range currentByName {
		prev, existed := oldByName[name]
		switch {
		case !existed:
			events = append(events, Event{Server: server, Tool: name, Kind: KindToolAdded})
		case prev.SchemaHash != entry.SchemaHash:
			events = append(events, Event{Server: server, Tool: name, Kind: KindSchemaChanged})
		}
	}

	for name := range oldByName {
		if _, stillExists := currentByName[name]; !stillExists {
			events = append(events, Event{Server: server, Tool: name, Kind: KindToolRemoved})
		}
	}

	return events
}
