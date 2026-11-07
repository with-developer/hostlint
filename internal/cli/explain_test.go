package cli

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestExplain(t *testing.T) {
	code, out, stderr := run(context.Background(), t, "explain", "U-02")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, want := range []string{"U-02  Password policy  [high]", "profile kisa-2026", "accounts.password-max-age", "How to fix it:", "Parameter max_days (default 90, stricter is lower)"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	// A check by its ID and a control by its, in one command; and a control ID in lower case.
	code, out, _ = run(context.Background(), t, "explain", "ssh.permit-root-login", "ES-01")
	if code != ExitOK || !strings.Contains(out, "ssh.permit-root-login  SSH does not allow direct root login  [high]") || !strings.Contains(out, "profile essentials") {
		t.Errorf("exit %d\n%s", code, out)
	}
	for _, line := range strings.Split(out, "\n") {
		if len(line) > 110 {
			t.Errorf("a line of %d characters: %q", len(line), line)
		}
	}
	if code, out, _ = run(context.Background(), t, "explain", "u-18"); code != ExitOK || !strings.Contains(out, "U-18  Ownership") {
		t.Errorf("a control ID in lower case: exit %d\n%s", code, out)
	}
	// One that is not there is said, and does not hide the others.
	code, out, stderr = run(context.Background(), t, "explain", "U-18", "U-999")
	if code != ExitError || !strings.Contains(out, "files.shadow-perms") || !strings.Contains(stderr, "nothing is called U-999") {
		t.Errorf("exit %d\n%s\n%s", code, out, stderr)
	}
	if code, _, _ = run(context.Background(), t, "explain"); code != ExitError {
		t.Errorf("no arguments: exit %d", code)
	}
}

// What a policy pack says reaches the terminal escaped.
func TestExplainOfAPackIsEscaped(t *testing.T) {
	pack := copyExamplePack(t)
	check := filepath.Join(pack, "rules", "x-acme", "motd-owned-by-root.yaml")
	data, _ := os.ReadFile(check)
	text := regexp.MustCompile(`(?m)^rationale: .*$`).ReplaceAllString(string(data), `rationale: "Run \e[2J and then chmod."`)
	if err := os.WriteFile(check, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := run(context.Background(), t, "explain", "x-acme.motd-owned-by-root", "--pack", pack)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if strings.ContainsAny(out+stderr, "\x1b") || !strings.Contains(out, "then chmod") {
		t.Errorf("out %q", out)
	}
}

// A pack: a control that has the ID of one of a built-in profile, parameters a control sets, prose over several
// lines, text with control characters and wide characters.
func TestExplainPackControlsAndText(t *testing.T) {
	pack := copyExamplePack(t)
	check := filepath.Join(pack, "rules", "x-acme", "motd-owned-by-root.yaml")
	data, _ := os.ReadFile(check)
	text := regexp.MustCompile(`(?m)^description: >-\n  .*$`).ReplaceAllString(string(data),
		"description: |\n  first line\n  second line\n  "+strings.Repeat("한국어 ", 60))
	if err := os.WriteFile(check, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	prof := filepath.Join(pack, "profiles", "x-acme-baseline.yaml")
	pdata, _ := os.ReadFile(prof)
	ptext := strings.Replace(string(pdata), "id: ACME-03", "id: ES-01", 1)
	if err := os.WriteFile(prof, []byte(ptext), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := run(context.Background(), t, "explain", "ES-01", "ACME-02", "--pack", pack)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	// ES-01 is in two profiles: both are shown.
	if !strings.Contains(out, "profile essentials") || !strings.Contains(out, "profile x-acme-baseline") {
		t.Errorf("the control of two profiles:\n%s", out)
	}
	// ACME-02 sets max_days 60 for a check whose default is 90.
	if !strings.Contains(out, "Parameter max_days (this control requires 60; the check's default is 90, stricter is lower)") {
		t.Errorf("the parameter of the control:\n%s", out)
	}
	if strings.Contains(out, "?") && strings.Contains(out, "second line?") {
		t.Errorf("line breaks became question marks:\n%s", out)
	}
	code, out, _ = run(context.Background(), t, "explain", "x-acme.motd-owned-by-root", "--pack", pack)
	if code != ExitOK || !strings.Contains(out, "first line second line") || strings.Contains(out, "?") {
		t.Errorf("a block scalar:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if utf8.RuneCountInString(line) > 105 {
			t.Errorf("a line of %d characters: %q", utf8.RuneCountInString(line), line)
		}
	}
	if !strings.Contains(out, "한국어 한국어") {
		t.Errorf("wide characters:\n%s", out)
	}
}

func TestExplainParameterDefaultsOfAPackAreEscaped(t *testing.T) {
	pack := copyExamplePack(t)
	check := filepath.Join(pack, "rules", "x-acme", "motd-owned-by-root.yaml")
	data, _ := os.ReadFile(check)
	text := strings.Replace(string(data), "file:\n", "params:\n  tag: {type: string, default: \"a\\e[2Jb\", description: \"Escape \\e]0;x\\a\"}\nfile:\n", 1)
	if err := os.WriteFile(check, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := run(context.Background(), t, "explain", "x-acme.motd-owned-by-root", "--pack", pack)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if strings.ContainsAny(out, "\x1b\x07") || !strings.Contains(out, "Parameter tag") {
		t.Errorf("a parameter default reached the terminal raw: %q", out)
	}
}
