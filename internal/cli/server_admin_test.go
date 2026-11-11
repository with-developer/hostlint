package cli

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/with-developer/vmsctl/internal/server"
)

var publicKeyRe = regexp.MustCompile(`public key: (\S+)`)

// publicKeyOf reads the public key that `key generate` prints.
func publicKeyOf(output string) string {
	if m := publicKeyRe.FindStringSubmatch(output); m != nil {
		return m[1]
	}
	return ""
}

var tokenRe = regexp.MustCompile(`hlt_(ing|api|opr)_[A-Za-z0-9_-]{20,}`)

// runIn runs vmsctl with the VMSCTL_TOKEN given (and no HOSTLINT_TOKEN of the machine).
func runIn(t *testing.T, token string, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv("VMSCTL_TOKEN", token)
	t.Setenv("HOSTLINT_TOKEN", "")
	return run(context.Background(), t, args...)
}

// The administration of a server through its commands, with real files and a real result pushed through the CLI: tokens are shown
// once and kept only as hashes; a backup is private and does not overwrite; the audit chain verifies; a host is listed, its key
// reset and the host deleted; a revoked token stops working.
func TestServerAdministration(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "s.db")
	srv := func(args ...string) (int, string, string) {
		return runIn(t, "", append([]string{"server", "--db", db}, args...)...)
	}

	// Tokens: shown once, and the database never holds one in the clear.
	code, out, errOut := srv("token", "create", "--name", "web-01", "--host", "web-01")
	ingest := tokenRe.FindString(out)
	if code != ExitOK || !strings.HasPrefix(ingest, "hlt_ing_") || !strings.Contains(errOut, "only time it is shown") {
		t.Fatalf("create: %d %q %q", code, out, errOut)
	}
	code, out, _ = srv("token", "create", "--name", "dash", "--scope", "api")
	api := tokenRe.FindString(out)
	if code != ExitOK || !strings.HasPrefix(api, "hlt_api_") {
		t.Fatalf("create api: %d %q", code, out)
	}
	if code, _, errOut := srv("token", "create", "--name", "x", "--scope", "root"); code == ExitOK {
		t.Errorf("an unknown scope was accepted: %q", errOut)
	}
	if code, _, _ := srv("token", "create", "--host", "web-01"); code == ExitOK {
		t.Error("a token without a name was made")
	}
	_, list, _ := srv("token", "list")
	for _, tok := range []string{ingest, api} {
		if strings.Contains(list, tok) {
			t.Errorf("the list shows a whole token: %q", list)
		}
		if raw, err := os.ReadFile(db); err != nil || strings.Contains(string(raw), tok) {
			t.Errorf("the database holds a token in the clear (%v)", err)
		}
	}
	if !strings.Contains(list, "web-01") || !strings.Contains(list, "dash") || !strings.Contains(list, "active") {
		t.Errorf("list: %q", list)
	}

	// A result pushed through the CLI to a server on the same database.
	store, err := server.OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	web := httptest.NewServer(server.New(server.Config{Store: store, Rate: 100000}).Handler())
	t.Cleanup(func() { web.Close(); _ = store.Close() })
	result := filepath.Join("..", "output", "testdata", "report", "web-01.json")
	if code, out, errOut := runIn(t, ingest, "push", result, "--server", web.URL); code != ExitOK || !strings.Contains(out+errOut, "web-01") {
		t.Fatalf("push: %d %q %q", code, out, errOut)
	}
	if code, out, errOut := runIn(t, ingest, "push", filepath.Join("..", "output", "testdata", "report", "db-01.json"), "--server", web.URL); code == ExitOK {
		t.Errorf("a token bound to web-01 sent the result of db-01: %q %q", out, errOut)
	}
	if _, out, _ := srv("host", "list"); !strings.Contains(out, "web-01") {
		t.Errorf("host list: %q", out)
	}
	if _, out, _ := srv("stats"); !strings.Contains(out, "hosts: 1") || !strings.Contains(out, "scans: 1") {
		t.Errorf("stats: %q", out)
	}
	if code, out, _ := srv("verify"); code != ExitOK || !strings.Contains(out, "audit chain OK") {
		t.Errorf("verify: %d %q", code, out)
	}

	// A backup is private, is not written over an existing file, and holds the same data.
	backup := filepath.Join(dir, "b.db")
	if code, _, errOut := srv("backup", backup); code != ExitOK {
		t.Fatalf("backup: %d %q", code, errOut)
	}
	if fi, err := os.Stat(backup); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("the backup is readable by others: %v %v", fi, err)
	}
	if code, _, _ := srv("backup", backup); code == ExitOK {
		t.Error("a backup overwrote an existing file")
	}
	if _, out, _ := runIn(t, "", "server", "--db", backup, "stats"); !strings.Contains(out, "scans: 1") {
		t.Errorf("the backup does not hold the scan: %q", out)
	}

	// Nothing older than a long time is deleted, and the latest scan of a host is always kept.
	if code, out, _ := srv("prune", "--older-than", "1h"); code != ExitOK || !strings.Contains(out, "0 scans deleted") {
		t.Errorf("prune: %d %q", code, out)
	}

	// A host is deleted only when asked twice (--yes), and its results go with it.
	if code, _, _ := srv("host", "delete", "1"); code == ExitOK {
		t.Error("a host was deleted without --yes")
	}
	if code, _, errOut := srv("host", "delete", "1", "--yes"); code != ExitOK {
		t.Fatalf("host delete: %d %q", code, errOut)
	}
	if _, out, _ := srv("stats"); !strings.Contains(out, "hosts: 0") {
		t.Errorf("stats after the delete: %q", out)
	}

	// A revoked token stops working.
	if code, _, _ := srv("token", "revoke", "1"); code != ExitOK {
		t.Error("revoke failed")
	}
	if code, _, _ := runIn(t, ingest, "push", result, "--server", web.URL); code == ExitOK {
		t.Error("a revoked token was accepted")
	}
	if code, _, _ := srv("token", "revoke", "99"); code == ExitOK {
		t.Error("an unknown token was revoked")
	}
}

// Signed results through the commands: a key made by `key generate` binds a token, the host's results must carry that key's
// signature (an unsigned one is refused), `server verify` checks the stored signature, and reset-key replaces the registered key.
func TestServerSignedResultsAndResetKey(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "s.db")
	srv := func(args ...string) (int, string, string) {
		return runIn(t, "", append([]string{"server", "--db", db}, args...)...)
	}

	keyFile := filepath.Join(dir, "sign.key")
	code, out, errOut := run(context.Background(), t, "key", "generate", keyFile)
	pub := publicKeyOf(out + errOut)
	if code != ExitOK || pub == "" {
		t.Fatalf("key generate: %d %q %q", code, out, errOut)
	}
	if fi, err := os.Stat(keyFile); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("the private key is readable by others: %v %v", fi, err)
	}
	if code, _, _ := run(context.Background(), t, "key", "generate", keyFile); code == ExitOK {
		t.Error("a key was written over an existing key")
	}
	_, out, _ = srv("token", "create", "--name", "web-01", "--host", "web-01", "--key", pub)
	ingest := tokenRe.FindString(out)
	if ingest == "" {
		t.Fatalf("token: %q", out)
	}
	if code, _, _ := srv("token", "create", "--name", "bad", "--host", "web-01", "--key", "not-a-key"); code == ExitOK {
		t.Error("a token was bound to a key that is not one")
	}

	store, err := server.OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	web := httptest.NewServer(server.New(server.Config{Store: store, Rate: 100000}).Handler())
	t.Cleanup(func() { web.Close(); _ = store.Close() })
	result := filepath.Join("..", "output", "testdata", "report", "web-01.json")
	if code, out, errOut := runIn(t, ingest, "push", result, "--server", web.URL); code == ExitOK {
		t.Errorf("an unsigned result was accepted from a token bound to a key: %q %q", out, errOut)
	}
	if code, out, errOut := runIn(t, ingest, "push", result, "--server", web.URL, "--sign-key", keyFile); code != ExitOK {
		t.Fatalf("a signed result: %d %q %q", code, out, errOut)
	}
	if code, out, _ := srv("verify"); code != ExitOK || !strings.Contains(out, "1 signed scans verify") {
		t.Errorf("verify: %d %q", code, out)
	}
	if _, out, _ := srv("host", "list"); !strings.Contains(out, "web-01") {
		t.Errorf("host list: %q", out)
	}

	// reset-key: a malformed key is refused, a good one is registered at once.
	if code, _, _ := srv("host", "reset-key", "1", "--key", "nope"); code == ExitOK {
		t.Error("a malformed key was registered")
	}
	otherKey := filepath.Join(dir, "other.key")
	_, out, errOut = run(context.Background(), t, "key", "generate", otherKey)
	newPub := publicKeyOf(out + errOut)
	if code, _, errOut := srv("host", "reset-key", "1", "--key", newPub); code != ExitOK {
		t.Fatalf("reset-key: %d %q", code, errOut)
	}
	if code, _, _ := srv("host", "reset-key", "99", "--key", newPub); code == ExitOK {
		t.Error("the key of an unknown host was reset")
	}
}
