package hostfs

import (
	"context"
	"errors"
	"fmt"
	"path"
	"reflect"
	"time"
)

// Command is one of the fixed commands vmsctl may run (ADR 0004). Its
// program and arguments are defined in this package and cannot be changed by
// callers, so rules and collectors can only choose which command to run.
type Command struct {
	name    string        // stable identifier, e.g. "sshd -T"
	paths   []string      // absolute candidate locations of the program
	args    []string      // fixed arguments
	timeout time.Duration // zero means defaultTimeout
}

// String returns the command's identifier.
func (c Command) String() string { return c.name }

// registry holds every command vmsctl may run. It is filled once, by the
// package-level newCommand calls, and only read afterwards.
var registry = map[string]Command{}

// newCommand defines a command. Every program path must be absolute.
func newCommand(name string, paths []string, args ...string) Command {
	for _, p := range paths {
		if !path.IsAbs(p) {
			panic(fmt.Sprintf("hostfs: command %q: program path %q is not absolute", name, p))
		}
	}
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("hostfs: command %q defined twice", name))
	}
	c := Command{name: name, paths: paths, args: args}
	registry[name] = c
	return c
}

// registered reports whether c is exactly a command defined with newCommand.
func registered(c Command) bool {
	r, ok := registry[c.name]
	return ok && reflect.DeepEqual(r, c)
}

// Output is what a command produced. A non-zero exit status is not an error.
type Output struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runner runs commands.
type Runner interface {
	Run(ctx context.Context, c Command) (Output, error)
}

var (
	// ErrUnavailable is returned when commands cannot be run on this target
	// (a mounted root, or a platform without command support).
	ErrUnavailable = errors.New("commands are not run on this target")
	// ErrNotInstalled is returned when none of a command's programs exists.
	ErrNotInstalled = errors.New("program not installed")
	// ErrUntrusted is returned when the program could be replaced by an
	// unprivileged user, so vmsctl refuses to run it.
	ErrUntrusted = errors.New("program is not safe to run")
	// ErrUnregistered is returned for a command that was not defined in this
	// package.
	ErrUnregistered = errors.New("not a registered command")
)

const (
	defaultTimeout = 10 * time.Second
	maxStdout      = 8 << 20
	maxStderr      = 64 << 10
)

// unavailableRunner refuses every command.
type unavailableRunner struct{ reason string }

func (r unavailableRunner) Run(_ context.Context, c Command) (Output, error) {
	return Output{}, fmt.Errorf("%s: %s: %w", c.name, r.reason, ErrUnavailable)
}

// RecordedRunner replays recorded command output, keyed by command name. It is
// meant for tests; a command without a recording fails with ErrUnavailable.
type RecordedRunner map[string]Recorded

// Recorded is the recorded result of one command.
type Recorded struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// Run implements Runner.
func (r RecordedRunner) Run(_ context.Context, c Command) (Output, error) {
	rec, ok := r[c.name]
	if !ok {
		return Output{}, fmt.Errorf("%s: no recorded output: %w", c.name, ErrUnavailable)
	}
	out := Output{Stdout: []byte(rec.Stdout), Stderr: []byte(rec.Stderr), ExitCode: rec.ExitCode}
	if rec.Err != nil {
		return out, fmt.Errorf("%s: %w", c.name, rec.Err)
	}
	return out, nil
}

// cappedBuffer keeps at most max bytes and remembers whether more arrived;
// onOverflow (if set) is called once when it does.
type cappedBuffer struct {
	buf        []byte
	max        int
	overflow   bool
	onOverflow func()
}

// Write keeps what fits and discards the rest; it reports the whole of p as
// written so the command is not killed by a short write.
func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if room := b.max - len(b.buf); n > room {
		if !b.overflow && b.onOverflow != nil {
			b.onOverflow()
		}
		b.overflow = true
		p = p[:max(room, 0)]
	}
	b.buf = append(b.buf, p...)
	return n, nil
}
