//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/server"
)

// fakeRoot builds a small mounted root: enough for every account check to
// decide without a live host.
func fakeRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"etc/os-release":   "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n",
		"etc/hostname":     "img-01\n",
		"etc/passwd":       "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\n",
		"etc/group":        "root:x:0:\n",
		"etc/login.defs":   "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nENCRYPT_METHOD SHA512\n",
		"etc/pam.d/passwd": "password requisite pam_pwquality.so retry=3\n",
		"etc/pam.d/login":  "auth required pam_unix.so\n",
	}
	for name, content := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestScanMountedRoot(t *testing.T) {
	root := fakeRoot(t)
	code, stdout, stderr := run(context.Background(), t, "scan", "--root", root, "--format", "json", "--label", "env=test")
	if code != ExitFail {
		t.Fatalf("exit %d, want %d (a second UID 0 account fails U-05); stderr %q", code, ExitFail, stderr)
	}
	var res engine.Result
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout)
	}
	status := map[string]engine.Status{}
	for _, c := range res.Controls {
		status[c.ID] = c.Status
	}
	if status["U-05"] != engine.StatusFail || res.Host.Hostname != "img-01" || res.Host.Labels["env"] != "test" || res.Scan.Target.Kind != "root" {
		t.Errorf("U-05 %s, host %+v, target %+v", status["U-05"], res.Host, res.Scan.Target)
	}

	// --fail-on high still fails (U-05 is high); --fail-on none never does.
	if code, _, _ := run(context.Background(), t, "scan", "--root", root, "--format", "json", "--fail-on", "none"); code != ExitOK {
		t.Errorf("--fail-on none: exit %d", code)
	}

	out := filepath.Join(t.TempDir(), "report.sarif")
	code, stdout, _ = run(context.Background(), t, "scan", "--root", root, "--format", "sarif", "--output", out, "--fail-on", "none")
	data, err := os.ReadFile(out)
	if code != ExitOK || err != nil || !strings.Contains(string(data), `"version": "2.1.0"`) || stdout != "" {
		t.Errorf("--output: exit %d, err %v, stdout %q", code, err, stdout)
	}
}

// A waiver in the configuration accepts a failing control; the exit code
// follows.
func TestScanWithConfig(t *testing.T) {
	root := fakeRoot(t)
	cfg := filepath.Join(t.TempDir(), "vmsctl.yaml")
	text := "waivers:\n  - check: accounts.uid0-only-root\n    reason: toor is a break-glass account\n    expires: 2099-12-31\n" +
		"  - check: accounts.password-max-age\n    reason: old\n    expires: 2020-01-01\n"
	if err := os.WriteFile(cfg, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(context.Background(), t, "scan", "--root", root, "--format", "json", "--config", cfg, "--fail-on", "high")
	var res engine.Result
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("exit %d, not JSON: %v\n%s%s", code, err, stdout, stderr)
	}
	for _, c := range res.Controls {
		if c.ID == "U-05" && c.Status != engine.StatusWaived {
			t.Errorf("U-05 = %s, want WAIVED", c.Status)
		}
	}
	if len(res.Waivers) != 1 || res.Waivers[0].Problem != "expired" {
		t.Errorf("waiver notes = %+v", res.Waivers)
	}
	// A bad configuration stops the scan.
	if err := os.WriteFile(cfg, []byte("waivers:\n  - check: no.such\n    reason: r\n    expires: 2099-01-01\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := run(context.Background(), t, "scan", "--root", root, "--config", cfg); code == ExitOK || !strings.Contains(stderr, `unknown check "no.such"`) {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}

// A directory that is not a system must not scan as one: absent files would
// read as passing checks.
func TestScanRootWithoutOS(t *testing.T) {
	code, stdout, stderr := run(context.Background(), t, "scan", "--root", t.TempDir(), "--format", "json", "--fail-on", "none")
	if code != ExitError || stdout != "" || !strings.Contains(stderr, "no operating system") {
		t.Errorf("exit %d, stdout %q, stderr %q; want exit %d and a note about the missing OS", code, stdout, stderr, ExitError)
	}
}

// U-10 decides on a host with thousands of accounts instead of running out
// of its evaluation budget.
func TestScanManyAccounts(t *testing.T) {
	root := fakeRoot(t)
	var b strings.Builder
	b.WriteString("root:x:0:0:root:/root:/bin/bash\n")
	for i := range 4000 {
		fmt.Fprintf(&b, "u%d:x:%d:%d::/home/u%d:/usr/sbin/nologin\n", i, 2000+i, 2000+i, i)
	}
	b.WriteString("clone:x:2000:2000::/home/clone:/usr/sbin/nologin\n")
	if err := os.WriteFile(filepath.Join(root, "etc/passwd"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stdout, stderr := run(context.Background(), t, "scan", "--root", root, "--format", "json", "--fail-on", "none")
	var res engine.Result
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("not JSON: %v\n%s%s", err, stdout, stderr)
	}
	found := false
	for _, c := range res.Controls {
		if c.ID == "U-10" {
			found = true
			if c.Status != engine.StatusFail {
				t.Errorf("U-10 = %s (%s), want FAIL for the shared UID 2000", c.Status, c.Reason)
			}
		}
	}
	if !found {
		t.Error("no U-10 in the result")
	}
}

// scan --push sends the result of the scan it just ran to a vmsctl server.
func TestScanPush(t *testing.T) {
	store, err := server.OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	srv := httptest.NewServer(server.New(server.Config{Store: store}).Handler())
	t.Cleanup(srv.Close)
	token, _, err := store.CreateCredential(context.Background(), server.ScopeIngest, "img", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VMSCTL_TOKEN", token)
	root := fakeRoot(t)

	code, stdout, stderr := run(context.Background(), t, "scan", "--root", root, "--push", srv.URL)
	if code != ExitFail || !strings.Contains(stderr, "result sent to "+srv.URL) {
		t.Fatalf("exit %d, stderr %q (a second UID 0 account fails U-05, so 1)", code, stderr)
	}
	if !strings.Contains(stdout, "U-05") {
		t.Errorf("the table was not printed: %q", stdout)
	}
	if st, err := store.Stats(context.Background()); err != nil || st.Scans != 1 {
		t.Errorf("stats %+v, %v", st, err)
	}
	// A server that refuses the token turns a good scan into an error (2), not a silent success.
	t.Setenv("VMSCTL_TOKEN", "hlt_ing_wrong")
	code, _, stderr = run(context.Background(), t, "scan", "--root", root, "--push", srv.URL, "--fail-on", "none")
	if code != ExitError || !strings.Contains(stderr, "the result was not sent") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
	// Without a token the scan does not even start; the options of --push need --push.
	t.Setenv("VMSCTL_TOKEN", "")
	if code, _, stderr = run(context.Background(), t, "scan", "--root", root, "--push", srv.URL); code != ExitError || !strings.Contains(stderr, "no token") {
		t.Errorf("without a token: exit %d, %q", code, stderr)
	}
	if code, _, stderr = run(context.Background(), t, "scan", "--root", root, "--pin", "sha256/x"); code != ExitError || !strings.Contains(stderr, "for --push") {
		t.Errorf("--pin alone: exit %d, %q", code, stderr)
	}
}

// scan --push --sign-key signs the result; the server registers the key.
func TestScanPushSigned(t *testing.T) {
	store, err := server.OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	srv := httptest.NewServer(server.New(server.Config{Store: store}).Handler())
	t.Cleanup(srv.Close)
	token, _, err := store.CreateCredential(context.Background(), server.ScopeIngest, "img", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VMSCTL_TOKEN", token)
	root := fakeRoot(t)
	keyPath := filepath.Join(t.TempDir(), "sign.key")
	if code, stdout, stderr := run(context.Background(), t, "key", "generate", keyPath); code != ExitOK || !strings.Contains(stdout, "fingerprint: SHA256:") {
		t.Fatalf("key generate: %d %q %q", code, stdout, stderr)
	}
	if code, _, stderr := run(context.Background(), t, "scan", "--root", root, "--push", srv.URL, "--sign-key", keyPath); code != ExitFail || !strings.Contains(stderr, "result sent") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	hosts, err := store.HostList(context.Background())
	if err != nil || len(hosts) != 1 || !hosts[0].Signed {
		t.Errorf("hosts %+v, %v", hosts, err)
	}
	// An unreadable-by-others rule: a key that others can read is refused before the scan.
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := run(context.Background(), t, "scan", "--root", root, "--push", srv.URL, "--sign-key", keyPath); code != ExitError || !strings.Contains(stderr, "read by other users") {
		t.Errorf("a readable key: exit %d, %q", code, stderr)
	}
	if code, _, stderr := run(context.Background(), t, "scan", "--root", root, "--sign-key", keyPath); code != ExitError || !strings.Contains(stderr, "for --push") {
		t.Errorf("--sign-key alone: exit %d, %q", code, stderr)
	}
}
