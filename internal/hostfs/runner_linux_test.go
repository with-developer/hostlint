//go:build linux

package hostfs

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Commands used only by these tests; they are registered like real ones.
var (
	testTrue    = newCommand("test true", []string{"/usr/bin/true", "/bin/true"})
	testFalse   = newCommand("test false", []string{"/usr/bin/false", "/bin/false"})
	testEnv     = newCommand("test env", []string{"/usr/bin/env"})
	testCmdline = newCommand("test argv0", []string{"/bin/cat"}, "/proc/self/cmdline")
	testSignal  = newCommand("test signal", []string{"/bin/sh"}, "-c", "echo partial; kill -SEGV $$")
	testSleep   = newCommand("test sleep", []string{"/bin/sh"}, "-c", "echo partial; sleep 30 & sleep 30")
	testYes     = newCommand("test yes", []string{"/usr/bin/yes"})
	testMissing = newCommand("test missing", []string{"/nonexistent/prog"})
)

func TestExecRunner(t *testing.T) {
	ctx := context.Background()
	r := execRunner{}

	out, err := r.Run(ctx, testTrue)
	if err != nil || out.ExitCode != 0 {
		t.Errorf("true: %+v, %v", out, err)
	}
	out, err = r.Run(ctx, testFalse)
	if err != nil || out.ExitCode != 1 {
		t.Errorf("false: exit %d, %v; want exit 1 and no error", out.ExitCode, err)
	}

	t.Setenv("VMSCTL_TEST_SECRET", "leak")
	out, err = r.Run(ctx, testEnv)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(out.Stdout)); !equal(got, safeEnv) {
		t.Errorf("command environment = %v, want exactly %v", got, safeEnv)
	}

	// argv[0] is the configured path even when it is reached through a
	// symlink (/bin -> usr/bin), so multi-call binaries see the right name.
	out, err = r.Run(ctx, testCmdline)
	if err != nil || !bytes.HasPrefix(out.Stdout, []byte("/bin/cat\x00")) {
		t.Errorf("argv: %q, %v; want argv[0] /bin/cat", out.Stdout, err)
	}
}

func TestExecRunnerRefusesUnregisteredCommands(t *testing.T) {
	for _, c := range []Command{{}, {name: "test true"}, {name: "test true", paths: []string{"/bin/sh"}, args: []string{"-c", "id"}}} {
		if _, err := (execRunner{}).Run(context.Background(), c); !errors.Is(err, ErrUnregistered) {
			t.Errorf("Run(%+v) = %v, want ErrUnregistered", c, err)
		}
	}
}

func TestExecRunnerFailures(t *testing.T) {
	r := execRunner{}

	// A command killed by a signal produced partial output: never a result.
	out, err := r.Run(context.Background(), testSignal)
	if err == nil || !strings.Contains(err.Error(), "killed by signal") {
		t.Errorf("signal: %+v, %v; want an error", out, err)
	}

	slow := testSleep
	slow.timeout = 200 * time.Millisecond
	registry[slow.name] = slow
	start := time.Now()
	if _, err := r.Run(context.Background(), slow); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("slow command: %v, want a timeout", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("timeout took %s; the process group was not killed", d)
	}
	registry[testSleep.name] = testSleep

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	if _, err := r.Run(ctx, testSleep); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled command: %v, want context.Canceled", err)
	}

	// Endless output is stopped as soon as it exceeds the cap.
	start = time.Now()
	if _, err := r.Run(context.Background(), testYes); err == nil || !strings.Contains(err.Error(), "output larger") {
		t.Errorf("endless output: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("endless output ran for %s; it should be killed at the cap", d)
	}

	if _, err := r.Run(context.Background(), testMissing); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("missing program: %v, want ErrNotInstalled", err)
	}
}

// A program reachable through a directory or symlink that an unprivileged
// user can change could be swapped, so the runner refuses it.
func TestTrustedPath(t *testing.T) {
	if _, err := trustedPath("bin/true"); !errors.Is(err, ErrUntrusted) {
		t.Errorf("relative path: %v, want ErrUntrusted", err)
	}
	// The resolved name varies (e.g. /usr/bin/gnutrue through alternatives).
	if got, err := trustedPath("/bin/true"); err != nil || !filepath.IsAbs(got) {
		t.Errorf("trustedPath(/bin/true) = %q, %v", got, err)
	}
	// Anything under the world-writable /tmp is refused.
	link := filepath.Join(t.TempDir(), "sshd")
	if err := os.Symlink("/usr/bin/id", link); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedPath(link); !errors.Is(err, ErrUntrusted) {
		t.Errorf("program under /tmp: %v, want ErrUntrusted", err)
	}

	if os.Geteuid() != 0 {
		t.Skip("the remaining cases need a root-owned directory outside /tmp")
	}
	base, err := os.MkdirTemp("/", "vmsctl-trust-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	mk := func(name, target string, dirMode os.FileMode, owner int) string {
		dir := filepath.Join(base, name)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, dirMode); err != nil {
			t.Fatal(err)
		}
		l := filepath.Join(dir, "prog")
		if err := os.Symlink(target, l); err != nil {
			t.Fatal(err)
		}
		if err := os.Lchown(l, owner, owner); err != nil {
			t.Fatal(err)
		}
		return l
	}
	if _, err := trustedPath(mk("writable", "/usr/bin/id", 0o777, 0)); !errors.Is(err, ErrUntrusted) {
		t.Errorf("symlink in a world-writable directory: %v, want ErrUntrusted", err)
	}
	if _, err := trustedPath(mk("foreign", "/usr/bin/true", 0o755, 1000)); !errors.Is(err, ErrUntrusted) {
		t.Errorf("symlink owned by uid 1000: %v, want ErrUntrusted", err)
	}
	if _, err := trustedPath(mk("good", "/usr/bin/true", 0o755, 0)); err != nil {
		t.Errorf("root-owned symlink in a safe directory: %v", err)
	}
}
