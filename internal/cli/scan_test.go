package cli

import (
	"context"
	"strings"
	"testing"
)

func TestScanRejectsBadFlags(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"scan", "--format", "yaml"}, `unknown --format "yaml"`},
		{[]string{"scan", "--fail-on", "critical"}, `unknown --fail-on "critical"`},
		{[]string{"scan", "--color", "sometimes"}, `unknown --color "sometimes"`},
		{[]string{"scan", "--label", "novalue"}, `want key=value`},
		{[]string{"scan", "extra"}, "unknown command"},
	}
	for _, tt := range tests {
		code, _, stderr := run(context.Background(), t, tt.args...)
		if code != ExitError || !strings.Contains(stderr, tt.want) {
			t.Errorf("%v: exit %d, stderr %q; want exit %d and %q", tt.args, code, stderr, ExitError, tt.want)
		}
	}
}
