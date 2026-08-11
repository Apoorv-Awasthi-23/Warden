package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Outcome mirrors the enum in the Audit Log Entry data model.
type Outcome string

const (
	OutcomeAllowed         Outcome = "allowed"
	OutcomeHardStopped     Outcome = "hard_stopped"
	OutcomeHeldForApproval Outcome = "held_for_approval"
	OutcomeApproved        Outcome = "approved"
	OutcomeDenied          Outcome = "denied"
	OutcomeTimedOut        Outcome = "timed_out"
)

// Entry is one Audit Log Entry.
// RulesEvaluated, Approver, and PrevEntryHash stay empty until the
// enforcement layer and a hash-chaining upgrade exist to populate them.
type Entry struct {
	Timestamp      time.Time `json:"timestamp"`
	AgentID        string    `json:"agent_id"`
	Server         string    `json:"server"`
	ToolName       string    `json:"tool_name"`
	Params         any       `json:"params"`
	RulesEvaluated []string  `json:"rules_evaluated"`
	Outcome        Outcome   `json:"outcome"`
	Approver       string    `json:"approver,omitempty"`
	PrevEntryHash  string    `json:"prev_entry_hash,omitempty"`
}

// Writer appends Entries to a JSON Lines file. Safe for concurrent use.
type Writer struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
}

func Open(path string) (*Writer, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("opening audit log %q: %w", path, err)
	}
	return &Writer{file: f, enc: json.NewEncoder(f)}, nil
}

// Log appends one entry. Timestamp is set automatically if left zero.
func (w *Writer) Log(e Entry) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.enc.Encode(e); err != nil {
		return fmt.Errorf("writing audit entry: %w", err)
	}
	return nil
}

func (w *Writer) Close() error {
	return w.file.Close()
}

// ReadAll reads every entry from the JSON Lines audit log at path, in file
// order (oldest first). Used by internal/backtest to replay history against
// a candidate rule. A log that doesn't exist yet reads as zero entries
// rather than an error — nothing has been recorded.
func ReadAll(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening audit log %q: %w", path, err)
	}
	defer f.Close()

	var entries []Entry
	dec := json.NewDecoder(bufio.NewReader(f))
	for {
		var e Entry
		if err := dec.Decode(&e); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("parsing audit log %q: %w", path, err)
		}
		entries = append(entries, e)
	}

	return entries, nil
}
