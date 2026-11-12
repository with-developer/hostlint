package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/with-developer/vmsctl/internal/engine"
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

// A control that could not be checked counts as a failure to the exit code,
// at its severity: an unreadable file must not turn a CI gate green.
func TestFailedAtOrAboveCountsErrors(t *testing.T) {
	res := &engine.Result{Controls: []engine.ControlResult{
		{Status: engine.StatusFail, Severity: engine.SeverityLow},
		{Status: engine.StatusError, Severity: engine.SeverityHigh},
		{Status: engine.StatusManual, Severity: engine.SeverityHigh},
		{Status: engine.StatusPass, Severity: engine.SeverityHigh},
	}}
	for threshold, want := range map[string]int{"low": 2, "medium": 1, "high": 1, "none": 0} {
		if got := failedAtOrAbove(res, threshold); got != want {
			t.Errorf("--fail-on %s: %d, want %d", threshold, got, want)
		}
	}
}

func TestLanguageOfEnv(t *testing.T) {
	for in, want := range map[string]string{"ko": "ko", "KO": "ko", "ko_KR": "ko", "ko_KR.UTF-8": "ko", "ko-KR": "ko", "en": "en", "en_US.UTF-8": "en",
		"": "", "C": "", "POSIX": "", "fr_FR": "", "korean": "", "k": ""} {
		if got := languageOfEnv(in); got != want {
			t.Errorf("languageOfEnv(%q) = %q, want %q", in, got, want)
		}
	}
	if got := languageOfEnv("  ko\n"); got != "ko" { // surrounding white space is not part of the language
		t.Errorf("a value with white space: %q", got)
	}
}
