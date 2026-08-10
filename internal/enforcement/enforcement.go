// Package enforcement implements the Enforcement Layer described in
// architecture.md section 5.4: it consumes the Policy Engine's verdict for
// each call and applies allow, hard-stop, or require-approval, handing
// every decision to the Audit Log Writer regardless of outcome.
package enforcement

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/approval"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/audit"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/policy"
	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/rule"
)

// Approver is the approval decision surface Enforcer depends on —
// satisfied by *approval.Prompter, and mockable in tests.
type Approver interface {
	Request(ctx context.Context, timeout time.Duration, cc policy.CallContext, matchedRules []string) (approval.Decision, string, error)
}

// Result is what the router needs back to decide whether to forward a call
// upstream or return a rejection to the agent.
type Result struct {
	Allowed      bool
	RejectReason string
}

// Enforcer holds everything needed to turn a call into an enforcement
// decision: the compiled Policy Engine, the approval decision surface, the
// Audit Log Writer, the configured approval timeout, and the set of servers
// whose rules failed to load or compile and are therefore blocked outright
// (architecture.md section 10's per-server isolation: one server's broken
// rules must never affect another server's enforcement, and must never
// silently fail open for the affected server either).
type Enforcer struct {
	engine          *policy.Engine
	approver        Approver
	auditor         *audit.Writer
	approvalTimeout time.Duration
	blockedServers  map[string]string
}

func New(engine *policy.Engine, approver Approver, auditor *audit.Writer, approvalTimeout time.Duration, blockedServers map[string]string) *Enforcer {
	return &Enforcer{
		engine:          engine,
		approver:        approver,
		auditor:         auditor,
		approvalTimeout: approvalTimeout,
		blockedServers:  blockedServers,
	}
}

// Enforce evaluates cc and returns whether the call may proceed. Every
// decision it reaches is logged to the audit writer before returning.
func (e *Enforcer) Enforce(ctx context.Context, agentID string, cc policy.CallContext) (Result, error) {
	if reason, blocked := e.blockedServers[cc.Server]; blocked {
		e.log(agentID, cc, nil, audit.OutcomeHardStopped, "")
		return Result{Allowed: false, RejectReason: reason}, nil
	}

	verdict, err := e.engine.Evaluate(cc)
	if err != nil {
		log.Printf("policy evaluation error on %s/%s: %v", cc.Server, cc.Tool, err)
		e.log(agentID, cc, nil, audit.OutcomeHardStopped, "")
		return Result{Allowed: false, RejectReason: err.Error()}, nil
	}

	if verdict.Allowed {
		e.log(agentID, cc, verdict.MatchedRules, audit.OutcomeAllowed, "")
		return Result{Allowed: true}, nil
	}

	if verdict.Action == rule.ActionHardStop {
		if verdict.Conflict {
			log.Printf("policy conflict on %s/%s: rules %s matched with both hard_stop and require_approval — hard_stop applied",
				cc.Server, cc.Tool, strings.Join(verdict.MatchedRules, ", "))
		}
		e.log(agentID, cc, verdict.MatchedRules, audit.OutcomeHardStopped, "")
		return Result{
			Allowed:      false,
			RejectReason: fmt.Sprintf("blocked by policy (rules: %s)", strings.Join(verdict.MatchedRules, ", ")),
		}, nil
	}

	return e.enforceApproval(ctx, agentID, cc, verdict)
}

func (e *Enforcer) enforceApproval(ctx context.Context, agentID string, cc policy.CallContext, verdict policy.Verdict) (Result, error) {
	decision, detail, err := e.approver.Request(ctx, e.approvalTimeout, cc, verdict.MatchedRules)
	if err != nil {
		log.Printf("approval prompt error on %s/%s: %v", cc.Server, cc.Tool, err)
		e.log(agentID, cc, verdict.MatchedRules, audit.OutcomeDenied, "")
		return Result{Allowed: false, RejectReason: fmt.Sprintf("blocked — approval prompt failed: %v", err)}, nil
	}

	switch decision {
	case approval.DecisionApproved:
		e.log(agentID, cc, verdict.MatchedRules, audit.OutcomeApproved, detail)
		return Result{Allowed: true}, nil
	case approval.DecisionTimedOut:
		e.log(agentID, cc, verdict.MatchedRules, audit.OutcomeTimedOut, "")
		return Result{Allowed: false, RejectReason: detail}, nil
	default: // approval.DecisionDenied
		e.log(agentID, cc, verdict.MatchedRules, audit.OutcomeDenied, "")
		return Result{Allowed: false, RejectReason: detail}, nil
	}
}

func (e *Enforcer) log(agentID string, cc policy.CallContext, rulesEvaluated []string, outcome audit.Outcome, approver string) {
	if e.auditor == nil {
		return
	}
	entry := audit.Entry{
		AgentID:        agentID,
		Server:         cc.Server,
		ToolName:       cc.Tool,
		Params:         cc.Params,
		RulesEvaluated: rulesEvaluated,
		Outcome:        outcome,
		Approver:       approver,
	}
	if err := e.auditor.Log(entry); err != nil {
		log.Printf("audit log write failed: %v", err)
	}
}
