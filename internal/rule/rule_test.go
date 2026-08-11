package rule

import "testing"

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		rule    Rule
		wantErr bool
	}{
		{
			name:    "missing id",
			rule:    Rule{CELExpression: "true", Action: ActionHardStop},
			wantErr: true,
		},
		{
			name:    "missing cel expression",
			rule:    Rule{ID: "x", Action: ActionHardStop},
			wantErr: true,
		},
		{
			name:    "unknown action",
			rule:    Rule{ID: "x", CELExpression: "true", Action: "delete_everything"},
			wantErr: true,
		},
		{
			name:    "valid hard_stop",
			rule:    Rule{ID: "x", CELExpression: "true", Action: ActionHardStop},
			wantErr: false,
		},
		{
			name:    "valid require_approval with optional metadata",
			rule:    Rule{ID: "x", CELExpression: "true", Action: ActionRequireApproval, Author: "a", IntentDescription: "d"},
			wantErr: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.rule.Validate()
			if (err != nil) != c.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}
