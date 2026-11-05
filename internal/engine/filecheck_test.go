package engine

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/with-developer/hostlint/internal/hostfs"
)

// scanOne scans fsys with a profile made of the single check c.
func scanOne(t *testing.T, c *Check, svc *fakeCollector, fsys hostfs.FS) CheckResult {
	t.Helper()
	res := scanChecks(t, svc, fsys, time.Second, c)
	if len(res.Checks) != 1 {
		t.Fatalf("got %d check results", len(res.Checks))
	}
	return res.Checks[0]
}

// scanChecks scans fsys with a profile of one control per check.
func scanChecks(t *testing.T, svc *fakeCollector, fsys hostfs.FS, timeout time.Duration, checks ...*Check) *Result {
	t.Helper()
	content := &Content{Checks: map[string]*Check{}, Profiles: map[string]*Profile{"p": {ID: "p", Revision: 1, Title: "P"}}}
	for i, c := range checks {
		c.Version = max(c.Version, 1)
		c.Title = cmp.Or(c.Title, "T")
		c.Severity = cmp.Or(c.Severity, SeverityLow)
		content.Checks[c.ID] = c
		content.Profiles["p"].Controls = append(content.Profiles["p"].Controls,
			Control{ID: fmt.Sprintf("C-%02d", i+1), Title: "C", Severity: SeverityLow, Checks: []string{c.ID}})
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
	return res
}

func byID(res *Result) map[string]CheckResult {
	m := map[string]CheckResult{}
	for _, c := range res.Checks {
		m[c.ID] = c
	}
	return m
}

// text joins a result's reason and evidence texts.
func text(cr CheckResult) string {
	s := cr.Reason
	for _, ev := range cr.Evidence {
		s += " | " + ev.Key + ": " + ev.Text
	}
	return s
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
			got := scanOne(t, c, tt.svc, badModeHost())
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
			got := scanOne(t, c, demoSvc(), m)
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

// A link to /dev/null masks a file (systemd units, blanked configuration):
// it is absent in effect, and /dev/null's mode (0666) is not the file's. The
// link is recognized without /dev existing, as in a mounted image.
func TestFileCheckMasked(t *testing.T) {
	tests := []struct {
		name, path, target, missing string
		want                        Status
	}{
		{"masked unit", "/etc/systemd/system/getty.service", "/dev/null", "pass", StatusPass},
		{"relative link", "/etc/systemd/system/getty.service", "../../../dev/null", "pass", StatusPass},
		{"required file masked", "/etc/systemd/system/getty.service", "/dev/null", "fail", StatusFail},
		{"link to a writable file", "/etc/systemd/system/getty.service", "/srv/getty.service", "pass", StatusFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := demoHost().AddSymlink(tt.path, tt.target).AddFile("/srv/getty.service", "", 0o666, 0, 0)
			c := &Check{ID: "x.units", File: &FileSpec{Paths: []string{"/etc/systemd/system/*.service"}, Owner: []string{"root"}, Mode: "0755", Missing: tt.missing, NoMatch: "pass"}}
			got := scanOne(t, c, demoSvc(), m)
			if got.Status != tt.want {
				t.Errorf("status %s (%q), want %s", got.Status, text(got), tt.want)
			}
			if tt.target != "/srv/getty.service" && !strings.Contains(text(got), "masked") {
				t.Errorf("evidence %q does not say the file is masked", text(got))
			}
		})
	}
	// A device that is not reached through a link to /dev/null is a file
	// like any other.
	m := demoHost().AddSpecial("/etc/systemd/system/odd.service", fs.ModeDevice|fs.ModeCharDevice, 0o666, 0, 0)
	c := &Check{ID: "x.units", File: &FileSpec{Paths: []string{"/etc/systemd/system/*.service"}, Owner: []string{"root"}, Mode: "0755", Missing: "pass", NoMatch: "pass"}}
	if got := scanOne(t, c, demoSvc(), m); got.Status != StatusFail {
		t.Errorf("device: %s (%q), want FAIL", got.Status, text(got))
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

// File I/O happens in a collector, so a hung path costs one collector
// timeout and an ERROR for the checks that name it, not the whole scan.
func TestFileCheckIOIsBounded(t *testing.T) {
	m := badModeHost().AddFile("/etc/other.conf", "", 0o666, 0, 0)
	fsys := &blockingFS{FS: m, path: "/etc/app.conf", release: make(chan struct{})}
	t.Cleanup(func() { close(fsys.release) })
	other := &Check{ID: "x.other-conf", File: &FileSpec{Paths: []string{"/etc/other.conf"}, Mode: "0644", Missing: "error"}}
	start := time.Now()
	got := byID(scanChecks(t, demoSvc(), fsys, 100*time.Millisecond, appConfCheck(), other))
	if c := got["x.app-conf"]; c.Status != StatusError || !strings.Contains(c.Reason, "/etc/app.conf: not observed before the collector timeout") {
		t.Errorf("hung path: %s (%q), want ERROR", c.Status, c.Reason)
	}
	if c := got["x.other-conf"]; c.Status != StatusFail {
		t.Errorf("other path: %s (%q), want FAIL", c.Status, text(c))
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("scan took %s", d)
	}
}

// A symbolic link to a missing target on the way to a path, or to a glob's
// directory, is not a missing file: creating the target creates the file.
func TestFileCheckDanglingDirectory(t *testing.T) {
	m := demoHost().
		AddSymlink("/etc/sudoers.d", "/tmp/attacker").
		AddSymlink("/etc/cron.daily", "/tmp/attacker")
	tests := []struct {
		name string
		spec FileSpec
		want Status
		text string
	}{
		{"path, missing pass", FileSpec{Paths: []string{"/etc/sudoers.d/evil"}, Mode: "0440", Missing: "pass"}, StatusError,
			"/etc/sudoers.d/evil: /etc/sudoers.d is a symbolic link to /tmp/attacker, which does not exist"},
		{"path, not applicable", FileSpec{Paths: []string{"/etc/sudoers.d/evil"}, Mode: "0440", Missing: "not_applicable"}, StatusError, "/etc/sudoers.d is a symbolic link"},
		{"path, missing fail", FileSpec{Paths: []string{"/etc/sudoers.d/evil"}, Mode: "0440", Missing: "fail"}, StatusFail, "/etc/sudoers.d is a symbolic link"},
		{"glob, no match pass", FileSpec{Paths: []string{"/etc/cron.daily/*"}, Mode: "0755", Missing: "error", NoMatch: "pass"}, StatusError,
			"/etc/cron.daily: symbolic link to /tmp/attacker, which does not exist"},
		{"real missing directory", FileSpec{Paths: []string{"/etc/nothing.d/x"}, Mode: "0440", Missing: "pass"}, StatusPass, "does not exist"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := tt.spec
			got := scanOne(t, &Check{ID: "x.path", File: &spec}, demoSvc(), m)
			if got.Status != tt.want || !strings.Contains(text(got), tt.text) {
				t.Errorf("%s (%q), want %s mentioning %q", got.Status, text(got), tt.want, tt.text)
			}
		})
	}
}

// One check's bad pattern is rejected when rules load, and the files of
// other checks stay observable.
func TestFilePatternsAreValidated(t *testing.T) {
	p := &problems{file: "x"}
	validateFile(p, &FileSpec{Paths: []string{"/etc/[a/b]"}, Mode: "0644", Missing: "error", NoMatch: "pass"})
	if p.err() == nil {
		t.Error("an invalid glob element was accepted")
	}
}

// Owner and group names resolve from the host's files, whatever their
// size; without the files they cannot be resolved, which is not a FAIL.
func TestFileCheckNames(t *testing.T) {
	var members []string
	for i := range 9000 {
		members = append(members, fmt.Sprintf("user%05d", i))
	}
	long := demoHost().
		AddFile("/etc/passwd", "root:x:0:0::/root:/bin/bash\nsyslog:x:104:110::/:/usr/sbin/nologin\n", 0o644, 0, 0).
		AddFile("/etc/group", "root:x:0:\nadm:x:4:syslog\nstaff:x:50:"+strings.Join(members, ",")+"\n", 0o644, 0, 0).
		AddFile("/var/log/syslog", "", 0o640, 104, 4)
	noGroup := hostfs.NewMemFS().
		AddFile("/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n", 0o644, 0, 0).
		AddFile("/etc/passwd", "root:x:0:0::/root:/bin/bash\n", 0o644, 0, 0).
		AddFile("/var/log/syslog", "", 0o640, 0, 4)
	check := func() *Check {
		return &Check{ID: "x.syslog", File: &FileSpec{Paths: []string{"/var/log/syslog"}, Owner: []string{"root", "syslog"}, Group: []string{"adm"}, Missing: "error"}}
	}
	if got := scanOne(t, check(), demoSvc(), long); got.Status != StatusPass {
		t.Errorf("long group line: %s (%q)", got.Status, text(got))
	}
	res := scanChecks(t, demoSvc(), noGroup, time.Second, check())
	if got := res.Checks[0]; got.Status != StatusError || !strings.Contains(got.Reason, `cannot resolve "adm"`) {
		t.Errorf("no /etc/group: %s (%q), want ERROR", got.Status, text(got))
	}
	for _, run := range res.Collectors {
		if run.Name == "files" && (run.Complete || !strings.Contains(strings.Join(run.Skipped, ";"), "/etc/group")) {
			t.Errorf("files collector run %+v does not report the missing /etc/group", run)
		}
	}
}

// What the file collector could not see is reported in a stable order.
func TestFileCollectorSkippedIsDeterministic(t *testing.T) {
	var first string
	for range 20 {
		m := demoHost()
		var checks []*Check
		for _, d := range []string{"a", "b", "c", "d"} {
			m.AddDir("/srv/"+d, 0o755, 0, 0).SetError("/srv/"+d, fs.ErrPermission)
			checks = append(checks, &Check{ID: "x." + d, File: &FileSpec{Paths: []string{"/srv/" + d + "/*"}, Mode: "0644", Missing: "error", NoMatch: "pass"}})
		}
		for _, run := range scanChecks(t, demoSvc(), m, time.Second, checks...).Collectors {
			if run.Name != "files" {
				continue
			}
			got := strings.Join(run.Skipped, "|")
			if first == "" {
				first = got
			} else if got != first {
				t.Fatalf("skipped order changed:\n%s\n%s", first, got)
			}
		}
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
	got := scanOne(t, c, demoSvc(), m)
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
			[]string{"svc.config.foo: not set"}},
		{"a setting keeps its source", `svc.config.permitrootlogin.value == "yes"`, StatusFail,
			[]string{`svc.config.permitrootlogin = "no" (explicit)`}},
		{"map membership", `"PASS_MAX_DAYS" in svc.config && svc.present`, StatusPass,
			[]string{"svc.config has PASS_MAX_DAYS, permitrootlogin", "svc.present = true"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanOne(t, &Check{ID: "x.expect", Expect: tt.expect}, demoSvc(), demoHost())
			var texts []string
			for _, ev := range got.Evidence {
				texts = append(texts, ev.Text)
				if tt.name == "a setting keeps its source" && ev.Source != "/etc/svc.conf:3" {
					t.Errorf("source %q, want /etc/svc.conf:3", ev.Source)
				}
			}
			if got.Status != tt.want || strings.Join(texts, "|") != strings.Join(tt.evidence, "|") {
				t.Errorf("status %s, evidence %q; want %s, %q", got.Status, texts, tt.want, tt.evidence)
			}
		})
	}
}

// A "why" field is evidence only when it says something.
func TestExpectEvidenceSkipsEmptyWhy(t *testing.T) {
	for _, tt := range []struct {
		why  string
		want []string
	}{
		{"", []string{"svc.present = true"}},
		{"nothing counts a failed login", []string{"svc.present = true", `svc.why = "nothing counts a failed login"`}},
	} {
		svc := demoSvc()
		svc.facts.Why = tt.why
		got := scanOne(t, &Check{ID: "x.why", Expect: `svc.present && svc.why == ""`}, svc, demoHost())
		var texts []string
		for _, ev := range got.Evidence {
			texts = append(texts, ev.Text)
		}
		if !slices.Equal(texts, tt.want) {
			t.Errorf("why %q: evidence %q, want %q", tt.why, texts, tt.want)
		}
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
