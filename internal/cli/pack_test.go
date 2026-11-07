package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// copyExamplePack copies examples/policy-pack to a new directory with modes that do not depend on the
// umask of whoever ran the tests: a pack that others could write is not trusted.
func copyExamplePack(t *testing.T) string {
	t.Helper()
	src := filepath.Join("..", "..", "examples", "policy-pack")
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"", "rules", "rules/x-acme", "profiles"} {
		if err := os.Chmod(filepath.Join(dst, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func TestPackTestAndShow(t *testing.T) {
	dir := copyExamplePack(t)
	code, out, stderr := run(context.Background(), t, "pack", "test", dir)
	if code != ExitOK || !strings.Contains(out, "1 checks, 1 profiles, 4 tests") || !strings.HasSuffix(strings.TrimSpace(out), "ok") {
		t.Fatalf("pack test: exit %d\n%s\n%s", code, out, stderr)
	}
	code, out, stderr = run(context.Background(), t, "pack", "show", dir)
	if code != ExitOK {
		t.Fatalf("pack show: exit %d\n%s", code, stderr)
	}
	for _, want := range []string{"pack acme 1.0.0", "digest sha256:", "x-acme.motd-owned-by-root  low  file", "lists the files /etc/motd: owner one of [root]", "ACME-02  high", "parameters of accounts.password-max-age"} {
		if !strings.Contains(out, want) {
			t.Errorf("pack show lacks %q:\n%s", want, out)
		}
	}
}

func TestPackTestFindsProblems(t *testing.T) {
	// A test that does not hold: the check says PASS for a file the test expects to FAIL.
	dir := copyExamplePack(t)
	check := filepath.Join(dir, "rules", "x-acme", "motd-owned-by-root.yaml")
	data, _ := os.ReadFile(check)
	broken := strings.Replace(string(data), "/etc/motd: {mode: \"0666\"}\n    want: FAIL", "/etc/motd: {mode: \"0644\"}\n    want: FAIL", 1)
	if err := os.WriteFile(check, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(context.Background(), t, "pack", "test", dir)
	if code != ExitFail || !strings.Contains(out, "FAIL x-acme.motd-owned-by-root / writable by everyone") {
		t.Errorf("a failing test: exit %d\n%s", code, out)
	}

	// A pack whose checks no profile selects is of no use.
	dir = copyExamplePack(t)
	if err := os.Remove(filepath.Join(dir, "profiles", "x-acme-baseline.yaml")); err != nil {
		t.Fatal(err)
	}
	code, out, _ = run(context.Background(), t, "pack", "test", dir)
	if code != ExitFail || !strings.Contains(out, "the pack has no profile") || !strings.Contains(out, "is in no profile of the pack") {
		t.Errorf("no profile: exit %d\n%s", code, out)
	}
}

func TestPackRefusesWhatIsNotAPack(t *testing.T) {
	dir := copyExamplePack(t)
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"pack", "test", dir}, {"pack", "show", dir}, {"pack", "test", filepath.Join(t.TempDir(), "missing")}, {"pack", "test"}} {
		if code, _, _ := run(context.Background(), t, args...); code != ExitError {
			t.Errorf("%v: exit %d, want %d", args, code, ExitError)
		}
	}
}

func TestPackOutputDoesNotCarryControlCharacters(t *testing.T) {
	dir := copyExamplePack(t)
	// A name with an escape sequence in a place a reviewer's terminal would show it.
	if err := os.WriteFile(filepath.Join(dir, "x\x1b]0;pwned\x07"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, out, stderr := run(context.Background(), t, "pack", "show", dir)
	if strings.ContainsAny(out+stderr, "\x1b\x07") {
		t.Errorf("a stray file name reached the terminal: %q %q", out, stderr)
	}
	// Text inside the pack: the title of a profile, and a check's parameters.
	dir = copyExamplePack(t)
	prof := filepath.Join(dir, "profiles", "x-acme-baseline.yaml")
	data, _ := os.ReadFile(prof)
	evil := strings.Replace(string(data), "title: Acme baseline", "title: \"Acme \\e[2J baseline\"", 1)
	if err := os.WriteFile(prof, []byte(evil), 0o644); err != nil {
		t.Fatal(err)
	}
	_, out, _ = run(context.Background(), t, "pack", "show", dir)
	if strings.ContainsAny(out, "\x1b") || !strings.Contains(out, "Acme") {
		t.Errorf("a profile title: %q", out)
	}
}
