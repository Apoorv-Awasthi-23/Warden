// Package policy implements the CEL Policy Engine: rules are CEL expressions
// evaluated against a structured representation of a single intercepted
// call (server, tool, params) with no history and no cross-call state. It is
// a pure evaluator — no I/O, no side effects.
package policy

import (
	"errors"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"

	"github.com/awasthiapoorv23/mcp-policy-proxy/internal/rule"
)

// CallContext is the structured representation of one intercepted call:
// server name, tool name, parameters.
type CallContext struct {
	Server string
	Tool   string
	Params map[string]any
}

// Verdict is the result of evaluating a CallContext against every rule that
// scopes to its server. MatchedRules lists every rule that matched,
// regardless of which one decided the outcome, so the audit log's
// rules_evaluated field always reflects everything that fired. Conflict is
// set when rules with both actions matched the same call — Action still
// resolves to hard_stop in that case (the safe outcome), but the caller is
// expected to surface the conflict distinctly, since silently picking one
// without flagging it would hide a rule-authoring problem.
type Verdict struct {
	Allowed      bool
	Action       rule.Action
	MatchedRules []string
	Conflict     bool
}

type compiledRule struct {
	rule    rule.Rule
	program cel.Program
}

// globalScope is the ServerScope value rulestore assigns to wildcard rules
// (those loaded from _global.yaml) — matches rulestore's own globalScope
// constant, which isn't exported since only the ServerScope string crosses
// the package boundary.
const globalScope = "*"

// Engine holds every rule that compiled successfully, ready to evaluate.
// Rules are partitioned by ServerScope so Evaluate only ever walks the
// rules that can apply to a given call (its own server's scope, plus the
// "*" wildcard/global bucket) instead of scanning every server's rules.
type Engine struct {
	env   *cel.Env
	rules map[string][]compiledRule
}

// NewEnv builds the fixed CEL evaluation environment every rule is compiled
// and checked against: server (string), tool (string), params (map of string
// to dyn). Exported so internal/schemacheck can compile the same expressions
// against an identical environment shape when validating rules against tool
// schemas, without duplicating these declarations.
func NewEnv() (*cel.Env, error) {
	env, err := cel.NewEnv(
		cel.Variable("server", cel.StringType),
		cel.Variable("tool", cel.StringType),
		cel.Variable("params", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("building CEL environment: %w", err)
	}
	return env, nil
}

// NewEngine compiles every rule's CEL expression against a fixed evaluation
// environment (server, tool, params) and checks it evaluates to a bool.
//
// Compile failures are attributed per rule.ServerScope in the returned
// failures map rather than aborting construction entirely, so one server's
// broken rule can never prevent another server's valid rules from loading —
// rule problems must isolate to the affected server. The returned error is
// reserved for a genuine construction failure unrelated to any specific rule
// (e.g. the fixed environment itself fails to build), which should not
// happen in practice since its declarations are static.
func NewEngine(rules []rule.Rule) (*Engine, map[string]error, error) {
	env, err := NewEnv()
	if err != nil {
		return nil, nil, err
	}

	failureLists := make(map[string][]error)
	compiled := make(map[string][]compiledRule)

	for _, r := range rules {
		ast, iss := env.Compile(r.CELExpression)
		if err := iss.Err(); err != nil {
			failureLists[r.ServerScope] = append(failureLists[r.ServerScope],
				fmt.Errorf("rule %q: compiling CEL expression: %w", r.ID, err))
			continue
		}
		if !ast.OutputType().IsExactType(cel.BoolType) {
			failureLists[r.ServerScope] = append(failureLists[r.ServerScope],
				fmt.Errorf("rule %q: cel_expression must evaluate to bool, got %s", r.ID, ast.OutputType()))
			continue
		}

		prg, err := env.Program(ast)
		if err != nil {
			failureLists[r.ServerScope] = append(failureLists[r.ServerScope],
				fmt.Errorf("rule %q: building CEL program: %w", r.ID, err))
			continue
		}

		compiled[r.ServerScope] = append(compiled[r.ServerScope], compiledRule{rule: r, program: prg})
	}

	var failures map[string]error
	if len(failureLists) > 0 {
		failures = make(map[string]error, len(failureLists))
		for scope, errs := range failureLists {
			failures[scope] = errors.Join(errs...)
		}
	}

	return &Engine{env: env, rules: compiled}, failures, nil
}

// Evaluate checks cc against every rule scoped to cc.Server (plus every
// wildcard rule) and returns the resulting Verdict.
//
// A CEL runtime error — most commonly a rule referencing a params field that
// doesn't exist in this particular call, e.g. `params.force` with no
// `has()` guard — aborts evaluation immediately and is returned as an error
// wrapping the offending rule's ID and the underlying CEL error text. This
// is a deliberate fail-closed choice: a broken rule blocks the call loudly
// and specifically, rather than silently degrading to "didn't match" (which
// could mask a rule that never fires) or blocking unrelated calls with a
// vague reason.
func (e *Engine) Evaluate(cc CallContext) (Verdict, error) {
	vars := map[string]any{
		"server": cc.Server,
		"tool":   cc.Tool,
		"params": cc.Params,
	}

	var matched []string
	var sawHardStop, sawRequireApproval bool

	evalRule := func(cr compiledRule) error {
		out, _, err := cr.program.Eval(vars)
		if err != nil {
			return fmt.Errorf("rule %q failed to evaluate: %w", cr.rule.ID, err)
		}

		b, ok := out.(types.Bool)
		if !ok {
			return fmt.Errorf("rule %q failed to evaluate: expected bool result, got %s", cr.rule.ID, out.Type())
		}
		if !bool(b) {
			return nil
		}

		matched = append(matched, cr.rule.ID)
		switch cr.rule.Action {
		case rule.ActionHardStop:
			sawHardStop = true
		case rule.ActionRequireApproval:
			sawRequireApproval = true
		}
		return nil
	}

	// Only the rules scoped to this call's server, plus the global/wildcard
	// bucket, can ever apply — walking anything else would be pure waste, so
	// this looks up exactly those two buckets instead of scanning every
	// server's rules. Two loops rather than one merged slice: appending
	// e.rules[globalScope] onto e.rules[cc.Server] would risk writing into
	// that bucket's shared backing array if it has spare capacity.
	for _, cr := range e.rules[cc.Server] {
		if err := evalRule(cr); err != nil {
			return Verdict{}, err
		}
	}
	if cc.Server != globalScope {
		for _, cr := range e.rules[globalScope] {
			if err := evalRule(cr); err != nil {
				return Verdict{}, err
			}
		}
	}

	switch {
	case sawHardStop:
		return Verdict{Allowed: false, Action: rule.ActionHardStop, MatchedRules: matched, Conflict: sawRequireApproval}, nil
	case sawRequireApproval:
		return Verdict{Allowed: false, Action: rule.ActionRequireApproval, MatchedRules: matched}, nil
	default:
		return Verdict{Allowed: true}, nil
	}
}
