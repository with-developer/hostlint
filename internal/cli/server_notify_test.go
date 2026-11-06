package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadSecretFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if got, err := readSecretFile(write("ok", "  s3cret\n", 0o600)); err != nil || string(got) != "s3cret" {
		t.Errorf("%q %v", got, err)
	}
	if _, err := readSecretFile(write("open", "s3cret", 0o644)); err == nil {
		t.Error("a secret readable by others was accepted")
	}
	if _, err := readSecretFile(write("empty", " \n", 0o600)); err == nil {
		t.Error("an empty secret was accepted")
	}
	if _, err := readSecretFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing file was accepted")
	}
}

func TestServerRunRejectsABadWebhook(t *testing.T) {
	for _, args := range [][]string{
		{"server", "--db", filepath.Join(t.TempDir(), "s.db"), "run", "--plain-http", "--webhook-url", "http://hooks.example.com/x"},
		{"server", "--db", filepath.Join(t.TempDir(), "s.db"), "run", "--plain-http", "--webhook-secret-file", "x"},
	} {
		cmd := newRootCommand()
		cmd.SetArgs(args)
		cmd.SetOut(os.Stderr)
		cmd.SetErr(os.Stderr)
		if err := cmd.Execute(); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
}
