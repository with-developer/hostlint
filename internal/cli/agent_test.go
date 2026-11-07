package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/with-developer/hostlint/internal/push"
)

// fakeAgent drives the loop with no network and no clock: polls are scripted, and the loop ends when they are used up.
type fakeAgent struct {
	*agent
	polls   []func() (*push.Job, error)
	scanned []push.Job
	failed  map[int64]string
	slept   []time.Duration
	clock   time.Time
	scanErr error
	cancel  context.CancelFunc
}

func newFakeAgent(allow ...string) *fakeAgent {
	f := &fakeAgent{failed: map[int64]string{}, clock: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)}
	f.agent = &agent{
		allow: allow,
		poll: func(context.Context, []string) (*push.Job, error) {
			if len(f.polls) == 0 {
				f.cancel()
				return nil, context.Canceled
			}
			p := f.polls[0]
			f.polls = f.polls[1:]
			return p()
		},
		fail: func(_ context.Context, id int64, reason string) error { f.failed[id] = reason; return nil },
		scan: func(_ context.Context, j *push.Job) error {
			f.scanned = append(f.scanned, *j)
			return f.scanErr
		},
		now:   func() time.Time { return f.clock },
		sleep: func(_ context.Context, d time.Duration) { f.slept = append(f.slept, d) },
		log:   func(string, ...any) {},
	}
	return f
}

func (f *fakeAgent) run() {
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	f.agent.run(ctx)
}

func job(id int64, profile string) func() (*push.Job, error) {
	return func() (*push.Job, error) { return &push.Job{ID: id, Profile: profile}, nil }
}

func TestAgentScansAllowedProfileOnly(t *testing.T) {
	f := newFakeAgent("kisa-2026")
	f.polls = []func() (*push.Job, error){
		func() (*push.Job, error) { return nil, nil }, // nothing to do
		job(1, "kisa-2026"),
		job(2, "essentials"), // the server asked for what the agent does not allow
	}
	f.run()
	if len(f.scanned) != 1 || f.scanned[0].ID != 1 {
		t.Errorf("scanned %+v", f.scanned)
	}
	if got := f.failed[2]; !strings.Contains(got, "does not allow") {
		t.Errorf("job 2: %q", got)
	}
	if _, ok := f.failed[1]; ok {
		t.Error("a good job was reported as failed")
	}
}

func TestAgentScansAtMostOncePerMinute(t *testing.T) {
	f := newFakeAgent("kisa-2026")
	f.polls = []func() (*push.Job, error){
		job(1, "kisa-2026"),
		func() (*push.Job, error) { f.clock = f.clock.Add(30 * time.Second); return job(2, "kisa-2026")() },
		func() (*push.Job, error) { f.clock = f.clock.Add(31 * time.Second); return job(3, "kisa-2026")() },
	}
	f.run()
	if len(f.scanned) != 2 || f.scanned[0].ID != 1 || f.scanned[1].ID != 3 {
		t.Errorf("scanned %+v", f.scanned)
	}
	if got := f.failed[2]; !strings.Contains(got, "moment ago") {
		t.Errorf("job 2: %q", got)
	}
}

func TestAgentReportsFailedScans(t *testing.T) {
	f := newFakeAgent("kisa-2026")
	f.scanErr = errors.New("--root /x: no operating system\x1b[31m found " + strings.Repeat("x", 400))
	f.polls = []func() (*push.Job, error){job(7, "kisa-2026")}
	f.run()
	got := f.failed[7]
	if !strings.HasPrefix(got, "the scan failed: --root /x") || strings.ContainsRune(got, 0x1b) || len([]rune(got)) > 250 {
		t.Errorf("reason %q (%d)", got, len(got))
	}
}

func TestAgentBacksOffAndRecovers(t *testing.T) {
	f := newFakeAgent("kisa-2026")
	boom := func() (*push.Job, error) { return nil, errors.New("connection refused") }
	f.polls = []func() (*push.Job, error){boom, boom, boom, func() (*push.Job, error) { return nil, nil }, boom}
	f.run()
	if len(f.slept) != 4 {
		t.Fatalf("slept %v", f.slept)
	}
	// Doubling from 5 s with up to a quarter more; a success starts over.
	for i, base := range []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 5 * time.Second} {
		if f.slept[i] < base || f.slept[i] > base+base/4 {
			t.Errorf("wait %d = %s, want %s to %s", i, f.slept[i], base, base+base/4)
		}
	}
	if d := backoff(100); d < agentBackoffCap || d > agentBackoffCap+agentBackoffCap/4 {
		t.Errorf("backoff is not capped: %s", d)
	}
}

func TestAgentFlags(t *testing.T) {
	t.Setenv("HOSTLINT_TOKEN", "hlt_ing_x")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"agent"}, "--server is required"},
		{[]string{"agent", "--server", "https://x.example"}, "--allow-profile is required"},
		{[]string{"agent", "--server", "https://x.example", "--allow-profile", "nope"}, `"nope" is not a built-in profile`},
		{[]string{"agent", "--server", "https://x.example", "--allow-profile", "../x"}, "is not a built-in profile"},
	} {
		code, _, stderr := run(context.Background(), t, tc.args...)
		if code != ExitError || !strings.Contains(stderr, tc.want) {
			t.Errorf("%v: exit %d, %q (want %q)", tc.args, code, stderr, tc.want)
		}
	}
	t.Setenv("HOSTLINT_TOKEN", "")
	if code, _, stderr := run(context.Background(), t, "agent", "--server", "https://x.example", "--allow-profile", "kisa-2026"); code != ExitError || !strings.Contains(stderr, "no token") {
		t.Errorf("no token: exit %d, %q", code, stderr)
	}
}
