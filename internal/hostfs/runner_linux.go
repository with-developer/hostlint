//go:build linux

package hostfs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// safeEnv is the whole environment of every command: nothing from the
// caller's environment is passed on.
var safeEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}

// execRunner runs commands on the running system.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, c Command) (Output, error) {
	prog, err := findTrusted(c.paths)
	if err != nil {
		return Output{}, fmt.Errorf("%s: %w", c.name, err)
	}
	timeout := c.timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// prog and args come from the fixed Command definitions in this package.
	cmd := exec.CommandContext(ctx, prog, c.args...) //nolint:gosec // G204: fixed argv, see Command
	cmd.Env = safeEnv
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// Kill the process group this runner started, including any children.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) //nolint:forbidigo // only our own child process group
	}
	cmd.WaitDelay = time.Second
	stdout := &cappedBuffer{max: maxStdout}
	stderr := &cappedBuffer{max: maxStderr}
	cmd.Stdout, cmd.Stderr = stdout, stderr

	err = cmd.Run()
	out := Output{Stdout: stdout.buf, Stderr: stderr.buf}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out, fmt.Errorf("%s: timed out after %s", c.name, timeout)
	}
	if stdout.overflow {
		return out, fmt.Errorf("%s: output larger than %d bytes", c.name, maxStdout)
	}
	if exitErr := (*exec.ExitError)(nil); errors.As(err, &exitErr) {
		out.ExitCode = exitErr.ExitCode()
		return out, nil
	}
	if err != nil {
		return out, fmt.Errorf("%s: %w", c.name, err)
	}
	return out, nil
}

// findTrusted returns the first candidate program that exists, after checking
// that no unprivileged user could have replaced it.
func findTrusted(paths []string) (string, error) {
	for _, p := range paths {
		resolved, err := filepath.EvalSymlinks(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if err := checkTrusted(resolved); err != nil {
			return "", fmt.Errorf("%s: %w", p, err)
		}
		return resolved, nil
	}
	return "", ErrNotInstalled
}

// checkTrusted requires the program to be a regular file, and it and every
// directory above it to be owned by root and not writable by group or others.
func checkTrusted(prog string) error {
	for cur := prog; ; cur = filepath.Dir(cur) {
		var st unix.Stat_t
		if err := unix.Lstat(cur, &st); err != nil {
			return err
		}
		if cur == prog && st.Mode&unix.S_IFMT != unix.S_IFREG {
			return fmt.Errorf("%s is not a regular file: %w", cur, ErrUntrusted)
		}
		if st.Uid != 0 {
			return fmt.Errorf("%s is not owned by root: %w", cur, ErrUntrusted)
		}
		if st.Mode&0o022 != 0 {
			return fmt.Errorf("%s is writable by group or others: %w", cur, ErrUntrusted)
		}
		if cur == "/" {
			return nil
		}
	}
}
