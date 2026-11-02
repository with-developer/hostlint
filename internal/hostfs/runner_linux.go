//go:build linux

package hostfs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
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

func (execRunner) Run(parent context.Context, c Command) (Output, error) {
	if !registered(c) {
		return Output{}, fmt.Errorf("%q: %w", c.name, ErrUnregistered)
	}
	prog, argv0, err := findTrusted(c.paths)
	if err != nil {
		return Output{}, fmt.Errorf("%s: %w", c.name, err)
	}
	timeout := c.timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	// prog and args come from the registered Command; argv[0] keeps the
	// configured name so multi-call binaries (kmod, xtables) pick the right
	// applet.
	cmd := exec.CommandContext(ctx, prog, c.args...) //nolint:gosec // G204: fixed argv, see Command
	cmd.Args[0] = argv0
	cmd.Env = safeEnv
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error { return killGroup(cmd.Process.Pid) }
	cmd.WaitDelay = time.Second
	stdout := &cappedBuffer{max: maxStdout, onOverflow: cancel}
	stderr := &cappedBuffer{max: maxStderr}
	cmd.Stdout, cmd.Stderr = stdout, stderr

	err = cmd.Run()
	if cmd.Process != nil {
		_ = killGroup(cmd.Process.Pid) // anything the command left running
	}
	out := Output{Stdout: stdout.buf, Stderr: stderr.buf}
	switch {
	case stdout.overflow:
		return out, fmt.Errorf("%s: output larger than %d bytes", c.name, maxStdout)
	case parent.Err() != nil:
		return out, fmt.Errorf("%s: %w", c.name, parent.Err())
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return out, fmt.Errorf("%s: timed out after %s", c.name, timeout)
	}
	if exitErr := (*exec.ExitError)(nil); errors.As(err, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			// Partial output from a killed command is not a decided result.
			return out, fmt.Errorf("%s: killed by signal %s", c.name, ws.Signal())
		}
		out.ExitCode = exitErr.ExitCode()
		return out, nil
	}
	if err != nil {
		return out, fmt.Errorf("%s: %w", c.name, err)
	}
	return out, nil
}

// killGroup kills the process group this runner started for a command.
func killGroup(pid int) error {
	return syscall.Kill(-pid, syscall.SIGKILL) //nolint:forbidigo // only our own child's process group
}

// findTrusted returns the first candidate that exists, resolved, and the
// candidate path itself (for argv[0]), after checking that no unprivileged
// user could have replaced anything on the way to it.
func findTrusted(paths []string) (prog, argv0 string, err error) {
	for _, p := range paths {
		resolved, err := trustedPath(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", "", err
		}
		return resolved, p, nil
	}
	return "", "", ErrNotInstalled
}

// trustedPath resolves p one component at a time and requires every
// directory, symlink and the program on the way to be owned by root, and
// directories and the program not to be writable by group or others.
func trustedPath(p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("%s: not an absolute path: %w", p, ErrUntrusted)
	}
	var st unix.Stat_t
	if err := unix.Lstat("/", &st); err != nil {
		return "", err
	}
	if err := trustedNode("/", &st); err != nil {
		return "", err
	}
	cur, parts := "/", splitPath(p)
	for links := 0; len(parts) > 0; {
		comp := parts[0]
		parts = parts[1:]
		switch comp {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, comp)
		if err := unix.Lstat(next, &st); err != nil {
			return "", &fs.PathError{Op: "lstat", Path: next, Err: err}
		}
		if err := trustedNode(next, &st); err != nil {
			return "", err
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			if links++; links > maxSymlinks {
				return "", unix.ELOOP
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", err
			}
			if filepath.IsAbs(target) {
				cur = "/"
			}
			parts = append(splitPath(target), parts...)
			continue
		}
		if len(parts) > 0 && st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return "", &fs.PathError{Op: "lstat", Path: next, Err: fs.ErrNotExist}
		}
		cur = next
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", fmt.Errorf("%s is not a regular file: %w", cur, ErrUntrusted)
	}
	return cur, nil
}

func trustedNode(p string, st *unix.Stat_t) error {
	if st.Uid != 0 {
		return fmt.Errorf("%s is not owned by root: %w", p, ErrUntrusted)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFLNK && st.Mode&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others: %w", p, ErrUntrusted)
	}
	return nil
}
