package engine

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/with-developer/hostlint/internal/hostfs"
)

// Access says what a collector observes (ADR 0006 §2).
type Access string

// Collector access kinds.
const (
	// AccessFilesystem collectors only read files, so they work on a mounted root.
	AccessFilesystem Access = "filesystem"
	// AccessLive collectors observe the running system (/proc, sockets,
	// commands) and are unavailable when scanning a mounted root.
	AccessLive Access = "live"
)

// Collector gathers the facts of one CEL variable.
type Collector interface {
	// Name is the variable rules use, e.g. "sshd".
	Name() string
	// Version is bumped when the facts' meaning changes.
	Version() int
	// Access says whether the collector needs a live host.
	Access() Access
	// Type is the Go struct type of the facts (not a pointer).
	Type() reflect.Type
	// Collect returns a pointer to a value of Type. It must honor ctx.
	Collect(ctx context.Context, h *hostfs.Host) (Facts, error)
}

// Facts is what a collector returns.
type Facts struct {
	// Value is a pointer to a struct of the collector's Type.
	Value any
	// Complete is false when the collector could not see everything (an
	// unreadable directory, a walk limit); Skipped says what was missed.
	Complete bool
	Skipped  []string
}

// collected is the outcome of one collector run.
type collected struct {
	run   CollectorRun
	facts Facts
	err   error // set when the collector failed or is unavailable
}

// ok reports whether facts are available (possibly incomplete).
func (c *collected) ok() bool { return c.err == nil }

// errCollectorUnavailable marks live collectors on a mounted root.
var errCollectorUnavailable = errors.New("needs a live host; not available when scanning a mounted root")

// defaultCollectorTimeout bounds each collector (ADR 0006 §12).
const defaultCollectorTimeout = 30 * time.Second

// runCollector runs c once, converting panics, timeouts and wrong result
// types into errors.
func runCollector(ctx context.Context, c Collector, h *hostfs.Host, timeout time.Duration) *collected {
	out := &collected{run: CollectorRun{Name: c.Name(), Version: c.Version(), Access: c.Access()}}
	if c.Access() == AccessLive && !h.Live {
		out.err = errCollectorUnavailable
		out.run.Status = "unavailable"
		out.run.Error = out.err.Error()
		return out
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type result struct {
		facts Facts
		err   error
	}
	done := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- result{err: fmt.Errorf("collector panicked: %v", r)}
			}
		}()
		f, err := c.Collect(ctx, h)
		done <- result{f, err}
	}()

	var r result
	select {
	case r = <-done:
	case <-ctx.Done():
		r.err = fmt.Errorf("collector did not finish: %w", ctx.Err())
	}
	out.run.DurationMs = time.Since(start).Milliseconds()
	if r.err == nil {
		if v := reflect.ValueOf(r.facts.Value); !v.IsValid() || v.Kind() != reflect.Pointer || v.IsNil() || v.Elem().Type() != c.Type() {
			r.err = fmt.Errorf("collector returned %T, want *%s", r.facts.Value, c.Type())
		}
	}
	if r.err != nil {
		out.err = r.err
		out.run.Status = "error"
		out.run.Error = r.err.Error()
		return out
	}
	out.facts = r.facts
	out.run.Status = "ok"
	out.run.Complete = r.facts.Complete
	out.run.Skipped = r.facts.Skipped
	return out
}
