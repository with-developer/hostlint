package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// svcFacts are the facts of the fake "svc" collector used by the demo rules.
type svcFacts struct {
	Present bool                     `json:"present"`
	Config  map[string]facts.Setting `json:"config"`
	Users   []svcUser                `json:"users"`
	Why     string                   `json:"why"`
}

type svcUser struct {
	Name string `json:"name"`
	UID  int64  `json:"uid"`
}

type fakeCollector struct {
	name     string
	access   Access
	facts    *svcFacts
	complete bool
	partial  []string
	err      error
	panics   bool
	hangs    bool
	delay    time.Duration // sleeps, ignoring the context, then returns complete facts
}

func (f *fakeCollector) Name() string       { return f.name }
func (f *fakeCollector) Version() int       { return 1 }
func (f *fakeCollector) Access() Access     { return f.access }
func (f *fakeCollector) Type() reflect.Type { return reflect.TypeFor[svcFacts]() }
func (f *fakeCollector) Collect(ctx context.Context, _ *hostfs.Host) (Facts, error) {
	switch {
	case f.panics:
		panic("boom")
	case f.hangs:
		<-ctx.Done()
		return Facts{}, ctx.Err()
	case f.delay > 0:
		time.Sleep(f.delay)
	case f.err != nil:
		return Facts{}, f.err
	}
	return Facts{Value: f.facts, Complete: f.complete, Partial: f.partial, Skipped: []string{"/etc/svc.d: permission denied"}}, nil
}

func loadDemo(t *testing.T) *Content {
	t.Helper()
	c, err := Load(os.DirFS("testdata/rules"), os.DirFS("testdata/profiles"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newDemoEngine(t *testing.T, svc *fakeCollector) *Engine {
	t.Helper()
	e, err := New(loadDemo(t), svc)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestRuleTests(t *testing.T) {
	e := newDemoEngine(t, &fakeCollector{name: "svc", access: AccessFilesystem})
	for _, f := range e.RunRuleTests(context.Background()) {
		t.Error(f)
	}
}

func demoHost() *hostfs.MemFS {
	return hostfs.NewMemFS().
		AddFile("/etc/os-release", "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n", 0o644, 0, 0).
		AddFile("/etc/hostname", "web-01\n", 0o644, 0, 0).
		AddFile("/etc/machine-id", "0123456789abcdef0123456789abcdef\n", 0o444, 0, 0).
		AddFile("/etc/passwd", "root:x:0:0::/root:/bin/bash\n", 0o644, 0, 0).
		AddFile("/etc/group", "root:x:0:\n", 0o644, 0, 0).
		AddFile("/etc/demo.conf", "", 0o664, 0, 0).
		AddDir("/etc/cron.d", 0o755, 0, 0)
}

func demoSvc() *fakeCollector {
	return &fakeCollector{name: "svc", access: AccessFilesystem, complete: true, facts: &svcFacts{
		Present: true,
		Config: map[string]facts.Setting{
			"permitrootlogin": {Value: "no", Explicit: true, Source: "/etc/svc.conf:3"},
			"PASS_MAX_DAYS":   {Value: "75", Explicit: true, Source: "/etc/svc.conf:9"},
		},
		Users: []svcUser{{"root", 0}, {"toor", 0}},
	}}
}

func scanDemo(t *testing.T, svc *fakeCollector, live bool) *Result {
	t.Helper()
	e := newDemoEngine(t, svc)
	h := hostfs.NewTestHost(demoHost(), nil, live)
	fixed := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	res, err := e.Scan(context.Background(), h, Options{
		Profile: "demo-1", Tool: ToolInfo{Name: "hostlint", Version: "v0.0.0-test"},
		Now: func() time.Time { return fixed }, CollectorTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func statuses(res *Result) map[string]Status {
	m := map[string]Status{}
	for _, c := range res.Controls {
		m[c.ID] = c.Status
	}
	for _, c := range res.Checks {
		m[c.Ref] = c.Status
	}
	return m
}

func TestScan(t *testing.T) {
	res := scanDemo(t, demoSvc(), false)
	got := statuses(res)
	want := map[string]Status{
		"D-01": StatusPass, "demo.root-login": StatusPass, "demo.both": StatusPass,
		// The profile tightens max_days to 60; 75 fails, and the ref carries the parameters.
		"D-02": StatusFail,
		"D-03": StatusFail, "demo.uid-zero": StatusFail,
		"D-04": StatusFail, "demo.conf-perms": StatusFail, "demo.cron-perms": StatusPass,
		"D-05": StatusManual, "demo.review": StatusManual,
		"D-06": StatusManual,
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %s, want %s", k, got[k], w)
		}
	}
	var maxDays *CheckResult
	for i := range res.Checks {
		if res.Checks[i].ID == "demo.max-days" {
			maxDays = &res.Checks[i]
		}
	}
	if maxDays == nil || !strings.HasPrefix(maxDays.Ref, "demo.max-days#") || maxDays.Params["max_days"] != int64(60) {
		t.Errorf("max-days result = %+v, want a parameterized ref with max_days 60", maxDays)
	}
	if res.Host.Hostname != "web-01" || res.Host.OS.ID != "ubuntu" || !res.Host.OS.Supported || len(res.Host.HostID) != 32 {
		t.Errorf("host = %+v", res.Host)
	}
	if res.Scan.Target.Kind != "root" {
		t.Errorf("target kind = %q, want root for a non-live host", res.Scan.Target.Kind)
	}
	if strings.Contains(mustJSON(t, res), "0123456789abcdef0123456789abcdef") {
		t.Error("the raw machine ID leaked into the result")
	}
	validateSchema(t, res)
}

func TestScanCollectorFailures(t *testing.T) {
	tests := []struct {
		name   string
		svc    *fakeCollector
		live   bool
		reason string
	}{
		{"error", &fakeCollector{name: "svc", access: AccessFilesystem, err: errors.New("cannot read /etc/svc.conf")}, true, "cannot read"},
		{"panic", &fakeCollector{name: "svc", access: AccessFilesystem, panics: true}, true, "panicked"},
		{"timeout", &fakeCollector{name: "svc", access: AccessFilesystem, hangs: true}, true, "did not finish"},
		{"live collector on a mounted root", &fakeCollector{name: "svc", access: AccessLive, facts: &svcFacts{}, complete: true}, false, "live host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := scanDemo(t, tt.svc, tt.live)
			for _, c := range res.Checks {
				if c.ID == "demo.conf-perms" || c.ID == "demo.cron-perms" {
					continue // file checks do not use the collector
				}
				if c.ID == "demo.review" {
					if c.Status != StatusManual || !strings.Contains(c.Reason, "evidence unavailable") {
						t.Errorf("%s: %s %q", c.ID, c.Status, c.Reason)
					}
					continue
				}
				if c.Status != StatusError || !strings.Contains(c.Reason, tt.reason) {
					t.Errorf("%s = %s (%q), want ERROR mentioning %q", c.ID, c.Status, c.Reason, tt.reason)
				}
			}
			validateSchema(t, res)
		})
	}
}

func TestScanIncompleteCollector(t *testing.T) {
	svc := demoSvc()
	svc.complete = false
	got := statuses(scanDemo(t, svc, false))
	// A violation that was seen still fails; nothing else can pass.
	want := map[string]Status{"demo.uid-zero": StatusFail, "demo.root-login": StatusError, "demo.both": StatusError}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %s, want %s", k, got[k], w)
		}
	}
}

// Without a known OS version, a check that depends on it errors; the rest run.
func TestScanUnknownOSVersion(t *testing.T) {
	e := newDemoEngine(t, demoSvc())
	m := demoHost().AddFile("/etc/os-release", "ID=debian\nPRETTY_NAME=\"Debian GNU/Linux forky/sid\"\n", 0o644, 0, 0)
	res, err := e.Scan(context.Background(), hostfs.NewTestHost(m, nil, false), Options{Profile: "demo-1"})
	if err != nil {
		t.Fatal(err)
	}
	got := statuses(res)
	if got["demo.modern"] != StatusError || got["demo.root-login"] != StatusPass {
		t.Errorf("modern %s, root-login %s; want ERROR and PASS", got["demo.modern"], got["demo.root-login"])
	}
	validateSchema(t, res)
}

func TestUnknownProfile(t *testing.T) {
	e := newDemoEngine(t, demoSvc())
	_, err := e.Scan(context.Background(), hostfs.NewTestHost(demoHost(), nil, false), Options{Profile: "nope"})
	if err == nil || !strings.Contains(err.Error(), "demo-1") {
		t.Errorf("err = %v, want it to list the available profiles", err)
	}
}

func TestAggregatePrecedence(t *testing.T) {
	tests := []struct {
		in   []Status
		want Status
	}{
		{[]Status{StatusPass, StatusPass}, StatusPass},
		{[]Status{StatusPass, StatusNotApplicable}, StatusPass},
		{[]Status{StatusNotApplicable, StatusNotApplicable}, StatusNotApplicable},
		{[]Status{StatusPass, StatusWaived}, StatusWaived},
		{[]Status{StatusWaived, StatusManual}, StatusManual},
		{[]Status{StatusManual, StatusError}, StatusError},
		{[]Status{StatusError, StatusFail}, StatusFail},
	}
	for _, tt := range tests {
		checks := map[string]*CheckResult{}
		var refs []string
		for i, st := range tt.in {
			ref := string(rune('a' + i))
			checks[ref] = &CheckResult{ID: ref, Status: st}
			refs = append(refs, ref)
		}
		if got := aggregate("p", Control{ID: "C"}, refs, checks).Status; got != tt.want {
			t.Errorf("aggregate(%v) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

func TestLoadRejectsInvalidContent(t *testing.T) {
	valid := "id: x.y\nversion: 1\ntitle: T\nseverity: low\nexpect: >-\n  svc.present\n" +
		"tests:\n  - {name: p, facts: {svc: {present: true}}, want: PASS}\n" +
		"  - {name: f, facts: {svc: {present: false}}, want: FAIL}\n" +
		"  - {name: u, input: unavailable, unavailable: [svc], want: ERROR}\n"
	tests := []struct {
		name, file, body, want string
	}{
		{"id does not match path", "x/z.yaml", valid, "must match its path"},
		{"unknown field", "x/y.yaml", valid + "shade: red\n", "field shade not found"},
		{"two kinds", "x/y.yaml", valid + "manual: {guidance: g}\n", "exactly one of"},
		{"failure on a file check", "x/y.yaml", "id: x.y\nversion: 1\ntitle: T\nseverity: low\nfailure: Nope.\nfile: {paths: [/etc/a], mode: \"0644\", missing: error}\n", "only for an expect check"},
		{"empty failure", "x/y.yaml", valid + "failure: \" \"\n", "only for an expect check"},
		{"bad severity", "x/y.yaml", strings.Replace(valid, "severity: low", "severity: urgent", 1), "severity must be"},
		{"bad platform", "x/y.yaml", valid + "platforms: [ubuntu]\n", "unknown platform"},
		{"missing tests", "x/y.yaml", "id: x.y\nversion: 1\ntitle: T\nseverity: low\nexpect: >-\n  svc.present\n", "tests need"},
		{"guarded case expecting PASS", "x/y.yaml", valid + "  - {name: g, input: incomplete, incomplete: [svc], want: PASS}\n", "must not expect PASS"},
		{"open range", "x/y.yaml", "id: x.y\nversion: 1\ntitle: T\nseverity: low\nsetting: {fact: svc.config.a, range: {max: 5}, absent: fail}\n", "both min and max"},
		{"unquoted mode", "x/y.yaml", "id: x.y\nversion: 1\ntitle: T\nseverity: low\nfile: {paths: [/etc/a], mode: 644x, missing: error}\n", "octal string"},
		{"glob without no_match", "x/y.yaml", "id: x.y\nversion: 1\ntitle: T\nseverity: low\nfile: {paths: [/etc/*], mode: \"0644\", missing: error}\n", "no_match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(fstest.MapFS{tt.file: {Data: []byte(tt.body)}}, fstest.MapFS{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
	t.Run("dangling profile reference", func(t *testing.T) {
		profiles := fstest.MapFS{"p.yaml": {Data: []byte("id: p\nrevision: 1\ntitle: P\ncontrols:\n  - {id: C, title: C, severity: low, checks: [x.missing]}\n")}}
		_, err := Load(fstest.MapFS{}, profiles)
		if err == nil || !strings.Contains(err.Error(), "unknown check x.missing") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestNewRejectsBadExpressions(t *testing.T) {
	tests := []struct{ name, expect, want string }{
		{"comprehension in expect", "svc.users.all(u, u.uid != 0)", "comprehensions"},
		{"type error", "svc.present == 1", "no matching overload"},
		{"unknown variable", "nosuch.present", "undeclared reference"},
		{"not a bool", "svc.users", "must be bool"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Content{Checks: map[string]*Check{"x.y": {ID: "x.y", Version: 1, Expect: tt.expect}}, Profiles: map[string]*Profile{}}
			_, err := New(c, demoSvc())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestFactTypesAreChecked(t *testing.T) {
	type withPointer struct {
		N *int64 `json:"n"`
	}
	type withUint struct {
		N uint `json:"n"`
	}
	type withTime struct {
		T time.Time `json:"t"`
	}
	type untagged struct {
		N int64
	}
	// A Setting field is never absent, so an unknown one would read as "".
	type settingField struct {
		S facts.Setting `json:"s"`
	}
	type settingList struct {
		S []facts.Setting `json:"s"`
	}
	// CEL sees the promoted fields of an unexported embedded struct.
	type common struct {
		N *int64 `json:"n"`
	}
	type embedded struct {
		common
		Name string `json:"name"`
	}
	// cel-go gives every anonymous struct type the same name.
	type anonymous struct {
		A []struct {
			Name string `json:"name"`
		} `json:"a"`
	}
	for _, typ := range []reflect.Type{
		reflect.TypeFor[withPointer](), reflect.TypeFor[withUint](), reflect.TypeFor[withTime](), reflect.TypeFor[untagged](),
		reflect.TypeFor[settingField](), reflect.TypeFor[settingList](), reflect.TypeFor[embedded](), reflect.TypeFor[anonymous](),
	} {
		if err := facts.CheckType(typ); err == nil {
			t.Errorf("CheckType(%s) accepted a forbidden field type", typ)
		}
	}
	if err := facts.CheckType(reflect.TypeFor[svcFacts]()); err != nil {
		t.Errorf("CheckType(svcFacts): %v", err)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// validateSchema checks a result against schema/result-v1.schema.json.
func validateSchema(t *testing.T, res *Result) {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	sch, err := c.Compile("../../schema/result-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(mustJSON(t, res))))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(doc); err != nil {
		t.Errorf("result does not match the schema: %v", err)
	}
}

var _ fs.FS = fstest.MapFS{}
