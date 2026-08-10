// Package approval implements the v1 Approval Flow decision surface
// described in architecture.md section 5.4: a blocking CLI prompt, fail
// closed on timeout, with an explicit rejection message distinguishable
// from any other kind of failure.
//
// The proxy's own stdin/stdout are already claimed by the MCP stdio
// transport it uses to talk to the connecting agent (see router.Router.Run),
// so the prompt cannot read/write through them. Instead it opens the
// controlling terminal device directly, independent of the process's own
// stdio streams.
package approval

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"sync"
	"time"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/policy"
)

// timedOutReason is the exact wording architecture.md section 5.4
// prescribes, so a timeout is distinguishable from a crash or an unrelated
// failure when someone is debugging agent behavior later.
const timedOutReason = "blocked — no approval received within the time limit"

type Decision string

const (
	DecisionApproved Decision = "approved"
	DecisionDenied   Decision = "denied"
	DecisionTimedOut Decision = "timed_out"
)

// Prompter is the CLI approval decision surface. A sync.Mutex serializes
// concurrent prompts so two simultaneous require-approval calls can't
// interleave garbled output on the same terminal — the architecture doc's
// "CLI only" decision surface implicitly assumes one prompt at a time.
type Prompter struct {
	mu sync.Mutex
}

func NewPrompter() *Prompter {
	return &Prompter{}
}

// Request blocks until a human responds via the controlling terminal, the
// timeout elapses, or ctx is canceled. detail carries the approver identity
// on DecisionApproved, or a human-readable rejection reason otherwise.
func (p *Prompter) Request(ctx context.Context, timeout time.Duration, cc policy.CallContext, matchedRules []string) (decision Decision, detail string, err error) {
	tty, openErr := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if openErr != nil {
		return DecisionDenied, fmt.Sprintf("blocked — no controlling terminal available for approval prompt: %v", openErr), nil
	}
	defer tty.Close()

	p.mu.Lock()
	defer p.mu.Unlock()

	fmt.Fprint(tty, promptText(cc, matchedRules))
	decision, detail = runPrompt(ctx, tty, tty, timeout)
	return decision, detail, nil
}

func promptText(cc policy.CallContext, matchedRules []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n--- mcp-policy-proxy: approval required ---\n")
	fmt.Fprintf(&b, "server: %s\n", cc.Server)
	fmt.Fprintf(&b, "tool:   %s\n", cc.Tool)
	fmt.Fprintf(&b, "params: %v\n", cc.Params)
	fmt.Fprintf(&b, "matched rules: %s\n", strings.Join(matchedRules, ", "))
	fmt.Fprintf(&b, "approve? [y/n]: ")
	return b.String()
}

// runPrompt reads one line from r, racing it against ctx and timeout. It's
// factored out from Request so it's testable with an in-memory reader/writer
// instead of a real /dev/tty.
func runPrompt(ctx context.Context, r io.Reader, w io.Writer, timeout time.Duration) (Decision, string) {
	lines := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(r)
		if scanner.Scan() {
			lines <- scanner.Text()
			return
		}
		lines <- ""
	}()

	select {
	case line := <-lines:
		return parseDecision(line)
	case <-time.After(timeout):
		fmt.Fprintln(w, "\n(timed out)")
		return DecisionTimedOut, timedOutReason
	case <-ctx.Done():
		fmt.Fprintln(w, "\n(canceled)")
		return DecisionDenied, "blocked — request canceled"
	}
}

// parseDecision treats anything other than an explicit yes as a deny —
// fail-closed on garbage input rather than looping indefinitely, which
// would risk exceeding the timeout anyway.
func parseDecision(line string) (Decision, string) {
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return DecisionApproved, approverIdentity()
	default:
		return DecisionDenied, "denied by approver"
	}
}

// approverIdentity is necessarily just the local OS user, not a verified
// identity — architecture.md section 5.4 explicitly rules out building a
// separate auth system for v1, so the trust boundary is "whoever has access
// to the session the proxy is running in," not a per-decision credential.
func approverIdentity() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "unknown"
}
