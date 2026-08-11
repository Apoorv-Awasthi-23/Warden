package approval

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestParseDecision(t *testing.T) {
	cases := []struct {
		input string
		want  Decision
	}{
		{"y", DecisionApproved},
		{"Y", DecisionApproved},
		{"yes", DecisionApproved},
		{"  yes  ", DecisionApproved},
		{"n", DecisionDenied},
		{"no", DecisionDenied},
		{"", DecisionDenied},
		{"garbage", DecisionDenied},
	}
	for _, c := range cases {
		got, _ := parseDecision(c.input)
		if got != c.want {
			t.Errorf("parseDecision(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestRunPrompt_Approve(t *testing.T) {
	r := strings.NewReader("y\n")
	var w strings.Builder
	decision, detail := runPrompt(context.Background(), r, &w, time.Second)
	if decision != DecisionApproved {
		t.Fatalf("decision = %q, want approved", decision)
	}
	if detail == "" {
		t.Fatalf("expected a non-empty approver identity")
	}
}

func TestRunPrompt_Deny(t *testing.T) {
	r := strings.NewReader("n\n")
	var w strings.Builder
	decision, detail := runPrompt(context.Background(), r, &w, time.Second)
	if decision != DecisionDenied {
		t.Fatalf("decision = %q, want denied", decision)
	}
	if detail != "denied by approver" {
		t.Fatalf("detail = %q", detail)
	}
}

func TestRunPrompt_UnrecognizedInputFailsClosedAsDeny(t *testing.T) {
	r := strings.NewReader("maybe??\n")
	var w strings.Builder
	decision, _ := runPrompt(context.Background(), r, &w, time.Second)
	if decision != DecisionDenied {
		t.Fatalf("decision = %q, want denied for unrecognized input", decision)
	}
}

func TestRunPrompt_TimesOutWithExactWording(t *testing.T) {
	r, cleanup := failingBlockingReader()
	defer cleanup()
	var w strings.Builder
	decision, detail := runPrompt(context.Background(), r, &w, 10*time.Millisecond)
	if decision != DecisionTimedOut {
		t.Fatalf("decision = %q, want timed_out", decision)
	}
	if detail != timedOutReason {
		t.Fatalf("detail = %q, want %q", detail, timedOutReason)
	}
}

func TestRunPrompt_ContextCancellation(t *testing.T) {
	r, cleanup := failingBlockingReader()
	defer cleanup()
	var w strings.Builder
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	decision, _ := runPrompt(ctx, r, &w, time.Second)
	if decision != DecisionDenied {
		t.Fatalf("decision = %q, want denied on context cancellation", decision)
	}
}

// failingBlockingReader returns a reader that never yields data, to
// exercise the timeout/cancellation paths without racing a real timer
// against real input.
func failingBlockingReader() (*blockingReader, func()) {
	br := &blockingReader{done: make(chan struct{})}
	return br, func() { close(br.done) }
}

type blockingReader struct {
	done chan struct{}
}

func (b *blockingReader) Read(p []byte) (int, error) {
	<-b.done
	return 0, nil
}
