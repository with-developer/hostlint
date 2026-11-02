//go:build linux

package hostfs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func cmd(name string, args ...string) Command {
	return Command{name: name, paths: []string{"/usr/bin/" + name, "/bin/" + name}, args: args}
}

func TestExecRunner(t *testing.T) {
	ctx := context.Background()
	r := execRunner{}

	out, err := r.Run(ctx, cmd("true"))
	if err != nil || out.ExitCode != 0 {
		t.Errorf("true: %+v, %v", out, err)
	}
	out, err = r.Run(ctx, cmd("false"))
	if err != nil || out.ExitCode != 1 {
		t.Errorf("false: exit %d, %v; want exit 1 and no error", out.ExitCode, err)
	}

	t.Setenv("HOSTLINT_TEST_SECRET", "leak")
	out, err = r.Run(ctx, cmd("env"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(out.Stdout)); !equal(got, safeEnv) {
		t.Errorf("command environment = %v, want exactly %v", got, safeEnv)
	}
}

func TestExecRunnerLimits(t *testing.T) {
	ctx := context.Background()
	r := execRunner{}

	slow := Command{name: "sleep", paths: []string{"/bin/sh", "/usr/bin/sh"}, args: []string{"-c", "sleep 30 & sleep 30"}, timeout: 200 * time.Millisecond}
	start := time.Now()
	if _, err := r.Run(ctx, slow); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("slow command: %v, want a timeout", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("timeout took %s; the process group was not killed", d)
	}

	big := Command{name: "head", paths: []string{"/usr/bin/head", "/bin/head"}, args: []string{"-c", "9000000", "/dev/zero"}}
	if _, err := r.Run(ctx, big); err == nil || !strings.Contains(err.Error(), "output larger") {
		t.Errorf("large output: %v", err)
	}

	missing := Command{name: "missing", paths: []string{"/nonexistent/prog"}}
	if _, err := r.Run(ctx, missing); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("missing program: %v, want ErrNotInstalled", err)
	}
}

// A program in a directory that an unprivileged user can write to could be
// swapped, so the runner refuses it.
func TestExecRunnerRefusesUntrustedProgram(t *testing.T) {
	src, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	prog := filepath.Join(dir, "true")
	if err := os.WriteFile(prog, src, 0o755); err != nil {
		t.Fatal(err)
	}
	c := Command{name: "untrusted", paths: []string{prog}}
	if _, err := (execRunner{}).Run(context.Background(), c); !errors.Is(err, ErrUntrusted) {
		t.Errorf("untrusted program: %v, want ErrUntrusted", err)
	}
}
