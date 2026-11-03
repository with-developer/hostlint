package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/with-developer/hostlint/internal/hostfs"
)

// scanOne scans fsys with a profile made of the single check c.
func scanOne(t *testing.T, c *Check, svc *fakeCollector, fsys hostfs.FS, timeout time.Duration) CheckResult {
	t.Helper()
	if c.Version == 0 {
		c.Version = 1
	}
	if c.Title == "" {
		c.Title = "T"
	}
	if c.Severity == "" {
		c.Severity = SeverityLow
	}
	content := &Content{
		Checks: map[string]*Check{c.ID: c},
		Profiles: map[string]*Profile{"p": {ID: "p", Revision: 1, Title: "P", Controls: []Control{
			{ID: "C-01", Title: "C", Severity: SeverityLow, Checks: []string{c.ID}},
		}}},
	}
	e, err := New(content, svc)
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.Scan(context.Background(), hostfs.NewTestHost(fsys, nil, false), Options{Profile: "p", CollectorTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	validateSchema(t, res)
	if len(res.Checks) != 1 {
		t.Fatalf("got %d check results", len(res.Checks))
	}
	return res.Checks[0]
}

func badModeHost() *hostfs.MemFS {
	return demoHost().AddFile("/etc/app.conf", "", 0o666, 0, 0)
}

func appConfCheck() *Check {
	return &Check{ID: "x.app-conf", File: &FileSpec{Paths: []string{"/etc/app.conf"}, Owner: []string{"root"}, Mode: "0644", Missing: "error"}}
}

// A file check honors applies like every other kind.
func TestFileCheckApplies(t *testing.T) {
	absent := demoSvc()
	absent.facts.Present = false
	tests := []struct {
		name    string
		applies string
		svc     *fakeCollector
		want    Status
		reason  string
	}{
		{"applies", "svc.present", demoSvc(), StatusFail, ""},
		{"does not apply", "svc.present", absent, StatusNotApplicable, "applies is false"},
		{"cannot tell", "svc.present", &fakeCollector{name: "svc", access: AccessFilesystem, err: errors.New("cannot read svc")}, StatusError, "cannot read svc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := appConfCheck()
			c.Applies = tt.applies
			got := scanOne(t, c, tt.svc, badModeHost(), time.Second)
			if got.Status != tt.want || !strings.Contains(got.Reason, tt.reason) {
				t.Errorf("status %s (%q), want %s mentioning %q", got.Status, got.Reason, tt.want, tt.reason)
			}
		})
	}
}

// A symbolic link to a missing target is not a missing file: it can fail,
// but never pass or be not applicable.
func TestFileCheckDanglingSymlink(t *testing.T) {
	tests := []struct {
		missing string
		link    bool
		want    Status
		text    string
	}{
		{"pass", false, StatusPass, "does not exist"},
		{"pass", true, StatusError, "symbolic link to /tmp/x, which does not exist"},
		{"not_applicable", true, StatusError, "symbolic link to /tmp/x"},
		{"fail", true, StatusFail, "symbolic link to /tmp/x"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("missing %s, link %v", tt.missing, tt.link), func(t *testing.T) {
			m := demoHost()
			if tt.link {
				m.AddSymlink("/etc/ld.so.preload", "/tmp/x")
			}
			c := &Check{ID: "x.preload", File: &FileSpec{Paths: []string{"/etc/ld.so.preload"}, Owner: []string{"root"}, Mode: "0644", Missing: tt.missing}}
			got := scanOne(t, c, demoSvc(), m, time.Second)
			text := got.Reason
			for _, ev := range got.Evidence {
				text += " " + ev.Text
			}
			if got.Status != tt.want || !strings.Contains(text, tt.text) {
				t.Errorf("status %s (%q), want %s mentioning %q", got.Status, text, tt.want, tt.text)
			}
		})
	}
}

// blockingFS hangs on one path, like a stat on a dead NFS mount.
type blockingFS struct {
	hostfs.FS
	path    string
	release chan struct{}
}

func (b *blockingFS) Stat(name string) (hostfs.FileInfo, error) {
	if name == b.path {
		<-b.release
	}
	return b.FS.Stat(name)
}

// File I/O happens in a collector, so a hung filesystem costs one collector
// timeout and an ERROR, not the whole scan.
func TestFileCheckIOIsBounded(t *testing.T) {
	fsys := &blockingFS{FS: badModeHost(), path: "/etc/app.conf", release: make(chan struct{})}
	t.Cleanup(func() { close(fsys.release) })
	start := time.Now()
	got := scanOne(t, appConfCheck(), demoSvc(), fsys, 100*time.Millisecond)
	if got.Status != StatusError || !strings.Contains(got.Reason, "did not finish") {
		t.Errorf("status %s (%q), want ERROR because the file collector did not finish", got.Status, got.Reason)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("scan took %s", d)
	}
}

// Many unobservable files give a short, deduplicated reason.
func TestFileCheckReasonIsBounded(t *testing.T) {
	m := demoHost()
	for i := range 300 {
		p := fmt.Sprintf("/etc/cron.d/job%03d", i)
		m.AddSymlink(p, "/etc/hostname").SetOwner(p, 1000, 1000)
	}
	c := &Check{ID: "x.cron", File: &FileSpec{Paths: []string{"/etc/cron.d/*"}, Owner: []string{"root"}, Mode: "0644", Missing: "error", NoMatch: "pass"}}
	got := scanOne(t, c, demoSvc(), m, time.Second)
	if got.Status != StatusError || len(got.Reason) > maxReasonLen || !strings.Contains(got.Reason, "and 295 more") {
		t.Errorf("status %s, reason (%d bytes) %q", got.Status, len(got.Reason), got.Reason)
	}
}

func TestExpectEvidence(t *testing.T) {
	tests := []struct {
		name, expect string
		want         Status
		evidence     []string
	}{
		{"absent map key", `has(svc.config.foo) && svc.config.foo.value == "x"`, StatusFail,
			[]string{"svc.config.foo.value: not set"}},
		{"map membership", `"PASS_MAX_DAYS" in svc.config && svc.present`, StatusPass,
			[]string{"svc.config has PASS_MAX_DAYS, permitrootlogin", "svc.present = true"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanOne(t, &Check{ID: "x.expect", Expect: tt.expect}, demoSvc(), demoHost(), time.Second)
			var texts []string
			for _, ev := range got.Evidence {
				texts = append(texts, ev.Text)
			}
			if got.Status != tt.want || strings.Join(texts, "|") != strings.Join(tt.evidence, "|") {
				t.Errorf("status %s, evidence %q; want %s, %q", got.Status, texts, tt.want, tt.evidence)
			}
		})
	}
}

func TestTruncateKeepsUTF8(t *testing.T) {
	s := strings.Repeat("가", 10) // 3 bytes each
	if got := truncate(s, 7); got != "가가…" {
		t.Errorf("truncate = %q", got)
	}
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate = %q", got)
	}
}

func TestReservedCollectorNames(t *testing.T) {
	for _, name := range []string{"files", "host"} {
		if _, err := New(&Content{Checks: map[string]*Check{}, Profiles: map[string]*Profile{}}, &fakeCollector{name: name}); err == nil {
			t.Errorf("collector %q accepted", name)
		}
	}
}
