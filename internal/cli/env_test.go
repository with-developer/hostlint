package cli

import (
	"path/filepath"
	"testing"
)

// The old HOSTLINT_* variables still work; the new name wins, and an empty one counts as unset (ADR 0017).
func TestEnvFallsBackToTheOldName(t *testing.T) {
	t.Setenv("VMSCTL_TOKEN", "")
	t.Setenv("HOSTLINT_TOKEN", "")
	if got := env("TOKEN"); got != "" {
		t.Errorf("neither set: %q", got)
	}
	t.Setenv("HOSTLINT_TOKEN", "old")
	if got := env("TOKEN"); got != "old" {
		t.Errorf("only the old name: %q", got)
	}
	t.Setenv("VMSCTL_TOKEN", "new")
	if got := env("TOKEN"); got != "new" {
		t.Errorf("both set: %q", got)
	}
	t.Setenv("VMSCTL_TOKEN", "")
	if got := env("TOKEN"); got != "old" {
		t.Errorf("an empty new variable hides the old one: %q", got)
	}
}

// The pack lists of both variables are joined, each directory once, the new variable first.
func TestPackDirsFromBothVariables(t *testing.T) {
	a, b, c := t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("VMSCTL_PACK", a+string(filepath.ListSeparator)+b)
	t.Setenv("HOSTLINT_PACK", b+string(filepath.ListSeparator)+c)
	got := packDirsFrom(nil)
	if len(got) != 3 || got[0] != a || got[1] != b || got[2] != c {
		t.Errorf("pack dirs = %v", got)
	}
}
