// Package rule defines the Rule data model, and the shape a hand-written
// rule file's YAML unmarshals into.
package rule

import (
	"fmt"
	"time"
)

// Action mirrors the enforcement action enum in the Rule data model.
type Action string

const (
	ActionHardStop       Action = "hard_stop"
	ActionRequireApproval Action = "require_approval"
)

// Rule is one policy rule. ServerScope and ID are not written by hand in a
// rule file: rulestore.Load sets them after unmarshaling, based on which
// file the rule came from (the "id" a human writes in YAML is local to its
// file; ServerScope is derived from the filename). Author, IntentDescription,
// CreatedAt, and BacktestSummary are the fields an automated NL->CEL
// rule-authoring assistant would normally populate; for hand-written rules
// they're optional.
type Rule struct {
	ID                string         `yaml:"id"`
	ServerScope       string         `yaml:"-"`
	CELExpression     string         `yaml:"cel_expression"`
	Action            Action         `yaml:"action"`
	Author            string         `yaml:"author,omitempty"`
	IntentDescription string         `yaml:"intent_description,omitempty"`
	CreatedAt         time.Time      `yaml:"created_at,omitempty"`
	BacktestSummary   map[string]any `yaml:"backtest_summary,omitempty"`
}

// Validate checks that r has every field required to compile and enforce,
// independent of which file it was loaded from.
func (r Rule) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("rule missing id")
	}
	if r.CELExpression == "" {
		return fmt.Errorf("rule %q: missing cel_expression", r.ID)
	}
	switch r.Action {
	case ActionHardStop, ActionRequireApproval:
	default:
		return fmt.Errorf("rule %q: unknown action %q", r.ID, r.Action)
	}
	return nil
}
