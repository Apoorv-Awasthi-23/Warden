package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Outcome mirrors the enum in the Audit Log Entry data model, section 8.
type Outcome string

const (
	OutcomeAllowed         Outcome = "allowed"
	OutcomeHardStopped     Outcome = "hard_stopped"
	OutcomeHeldForApproval Outcome = "held_for_approval"
	OutcomeApproved        Outcome = "approved"
	OutcomeDenied          Outcome = "denied"
	OutcomeTimedOut        Outcome = "timed_out"
)

// Entry is one Audit Log Entry, matching architecture.md section 8.
// RulesEvaluated, Approver, and PrevEntryHash stay empty until Milestone 2's
// enforcement layer and the v2 hash-chaining upgrade exist to populate them.
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
