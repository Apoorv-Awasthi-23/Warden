package audit

import (
	"os"
	"path/filepath"
	"sync"
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

func TestLog_ConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	w, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	const goroutines = 20
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := w.Log(Entry{Server: "github", ToolName: "push", Outcome: OutcomeAllowed}); err != nil {
				t.Errorf("Log: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := ReadAll(path)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != goroutines {
		t.Fatalf("expected %d entries from concurrent writers, got %d", goroutines, len(entries))
	}
}

func TestOpen_UnwritableDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root defeats permission checks")
	}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	_, err := Open(filepath.Join(dir, "audit.log"))
	if err == nil {
		t.Fatalf("expected an error opening an audit log in an unwritable directory")
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
