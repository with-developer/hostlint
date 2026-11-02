package hostfs

import (
	"context"
	"errors"
	"testing"
)

func TestRecordedRunner(t *testing.T) {
	boom := errors.New("boom")
	r := RecordedRunner{
		"ok":     {Stdout: "out", Stderr: "err", ExitCode: 3},
		"failed": {Err: boom},
	}
	out, err := r.Run(context.Background(), Command{name: "ok"})
	if err != nil || string(out.Stdout) != "out" || string(out.Stderr) != "err" || out.ExitCode != 3 {
		t.Errorf("ok: %+v, %v", out, err)
	}
	if _, err := r.Run(context.Background(), Command{name: "failed"}); !errors.Is(err, boom) {
		t.Errorf("failed: %v", err)
	}
	if _, err := r.Run(context.Background(), Command{name: "missing"}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("missing: %v, want ErrUnavailable", err)
	}
}

func TestNewTestHost(t *testing.T) {
	rec := RecordedRunner{"x": {Stdout: "y"}}
	if _, err := NewTestHost(NewMemFS(), rec, true).Runner.Run(context.Background(), Command{name: "x"}); err != nil {
		t.Errorf("live test host: %v", err)
	}
	// A non-live host never runs commands, whatever runner it was given.
	if _, err := NewTestHost(NewMemFS(), rec, false).Runner.Run(context.Background(), Command{name: "x"}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("non-live test host: %v, want ErrUnavailable", err)
	}
}

func TestCappedBuffer(t *testing.T) {
	b := &cappedBuffer{max: 4}
	for _, chunk := range []string{"ab", "cdef", "gh"} {
		if n, err := b.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatalf("Write(%q) = %d, %v", chunk, n, err)
		}
	}
	if string(b.buf) != "abcd" || !b.overflow {
		t.Errorf("buf %q overflow %v", b.buf, b.overflow)
	}
}
