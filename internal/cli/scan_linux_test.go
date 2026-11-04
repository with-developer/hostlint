//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/engine"
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
	cfg := filepath.Join(t.TempDir(), "hostlint.yaml")
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
	for _, c := range res.Controls {
		if c.ID == "U-10" && (c.Status != engine.StatusFail) {
			t.Errorf("U-10 = %s (%s), want FAIL for the shared UID 2000", c.Status, c.Reason)
		}
	}
}
