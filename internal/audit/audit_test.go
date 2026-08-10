package audit

import (
	"path/filepath"
	"testing"
	"time"
)

func TestReadAll_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	w, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	want := []Entry{
		{Server: "github", ToolName: "read_file", Outcome: OutcomeAllowed},
		{Server: "github", ToolName: "delete_file", Outcome: OutcomeHardStopped},
	}
	for _, e := range want {
		if err := w.Log(e); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, err := ReadAll(path)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d entries, got %d: %+v", len(want), len(got), got)
	}
	for i := range want {
		if got[i].Server != want[i].Server || got[i].ToolName != want[i].ToolName || got[i].Outcome != want[i].Outcome {
			t.Fatalf("entry %d mismatch: got %+v, want %+v", i, got[i], want[i])
		}
		if got[i].Timestamp.IsZero() {
			t.Fatalf("entry %d: expected an auto-populated timestamp", i)
		}
	}
}

func TestReadAll_MissingFileIsNotAnError(t *testing.T) {
	entries, err := ReadAll(filepath.Join(t.TempDir(), "does-not-exist.log"))
	if err != nil {
		t.Fatalf("ReadAll on a missing file should not error: %v", err)
	}
	if entries != nil {
		t.Fatalf("expected nil entries, got %+v", entries)
	}
}

func TestReadAll_EmptyFileIsNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	w, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := ReadAll(path)
	if err != nil {
		t.Fatalf("ReadAll on an empty file should not error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected zero entries, got %+v", entries)
	}
}

func TestReadAll_PreservesFileOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	w, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if err := w.Log(Entry{Timestamp: base.Add(time.Duration(i) * time.Hour), ToolName: string(rune('a' + i))}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := ReadAll(path)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	for i, want := range []string{"a", "b", "c"} {
		if entries[i].ToolName != want {
			t.Fatalf("entry %d: expected tool %q, got %q", i, want, entries[i].ToolName)
		}
	}
}
