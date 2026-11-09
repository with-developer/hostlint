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

// The pack list of VMSCTL_PACK wins over the old HOSTLINT_PACK: a stale old variable must not load a second pack.
func TestPackDirsNewVariableWins(t *testing.T) {
	a, b, c := t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("HOSTLINT_PACK", c)
	if got := packDirsFrom(nil); len(got) != 1 || got[0] != c {
		t.Errorf("only the old variable: %v", got)
	}
	t.Setenv("VMSCTL_PACK", a+string(filepath.ListSeparator)+b)
	if got := packDirsFrom(nil); len(got) != 2 || got[0] != a || got[1] != b {
		t.Errorf("both variables: %v", got)
	}
}
