package engine

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/with-developer/vmsctl/internal/hostfs"
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
	// Unknown lists fields (json names, dot-separated) whose values could not
	// be determined, while the rest is complete: rules reading them cannot
	// decide. Skipped says why.
	Unknown []string
	// Partial lists fields that hold only part of what exists (a list cut
	// short by a walk limit), while the rest is complete: like an incomplete
	// collector, but only for these fields. What they hold can fail a
	// check; it can never make one pass. Skipped says why.
	Partial []string
}

// timeoutCollector is a collector that needs longer than the scan's
// collector timeout, such as a filesystem walk.
type timeoutCollector interface {
	Timeout() time.Duration
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

const (
	// defaultCollectorTimeout bounds each collector (ADR 0006 §12).
	defaultCollectorTimeout = 30 * time.Second
	// collectorGrace is how long a collector that honors its context has,
	// after the timeout, to return what it observed.
	collectorGrace = time.Second
)

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
	if tc, ok := c.(timeoutCollector); ok {
		timeout = max(timeout, tc.Timeout())
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
		select {
		case r = <-done:
		case <-time.After(collectorGrace):
			r.err = ctx.Err()
		}
	}
	out.run.DurationMs = time.Since(start).Milliseconds()
	// A collector that saw its time run out and still returned complete facts may
	// have stopped early: the facts cannot be trusted to be everything.
	if r.err == nil && ctx.Err() != nil && r.facts.Complete && len(r.facts.Partial) == 0 && len(r.facts.Unknown) == 0 {
		r.facts.Complete = false
		r.facts.Skipped = append(r.facts.Skipped, "the collector's time ran out")
	}
	switch {
	case r.err != nil && ctx.Err() != nil:
		r.err = fmt.Errorf("collector did not finish: %w", r.err)
	case r.err != nil:
	case !isFacts(r.facts.Value, c.Type()):
		r.err = fmt.Errorf("collector returned %T, want *%s", r.facts.Value, c.Type())
	default:
		for _, f := range slices.Concat(r.facts.Unknown, r.facts.Partial) {
			if !hasField(c.Type(), f) {
				r.err = fmt.Errorf("collector marked %q unknown or partial, which is not a field of %s", f, c.Type())
			}
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
	out.run.Complete = r.facts.Complete && len(r.facts.Unknown) == 0 && len(r.facts.Partial) == 0
	out.run.Skipped = r.facts.Skipped
	return out
}

func isFacts(v any, t reflect.Type) bool {
	rv := reflect.ValueOf(v)
	return rv.IsValid() && rv.Kind() == reflect.Pointer && !rv.IsNil() && rv.Elem().Type() == t
}

// hasField reports whether the dot-separated json field path names a field
// of the struct type t.
func hasField(t reflect.Type, path string) bool {
	for name := range strings.SplitSeq(path, ".") {
		if t.Kind() == reflect.Map && t.Key().Kind() == reflect.String {
			t = t.Elem() // a key of a map field, such as pam.effective.su_wheel
			continue
		}
		if t.Kind() != reflect.Struct {
			return false
		}
		found := false
		for i := range t.NumField() {
			if f := t.Field(i); f.IsExported() && f.Tag.Get("json") == name {
				t, found = f.Type, true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
