package cli

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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
	// A check by its ID; a control that two profiles... (ES- IDs are unique) ; several at once.
	code, out, _ = run(context.Background(), t, "explain", "ssh.permit-root-login", "ES-01")
	if code != ExitOK || !strings.Contains(out, "ssh.permit-root-login  SSH does not allow direct root login  [high]") || !strings.Contains(out, "profile essentials") {
		t.Errorf("exit %d\n%s", code, out)
	}
	for _, line := range strings.Split(out, "\n") {
		if len(line) > 110 {
			t.Errorf("a line of %d characters: %q", len(line), line)
		}
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
	text := regexp.MustCompile(`(?m)^remediation: .*$`).ReplaceAllString(string(data), `remediation: "Run \e[2J and then chmod."`)
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
