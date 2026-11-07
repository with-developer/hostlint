package engine

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// TestFailure is one rule test case whose result differs from its want.
type TestFailure struct {
	Check, Case string
	Want, Got   Status
	Detail      string
}

func (f TestFailure) Error() string {
	return fmt.Sprintf("%s / %s: got %s, want %s (%s)", f.Check, f.Case, f.Got, f.Want, f.Detail)
}

// testUsers are the accounts every rule test host has.
var testUsers = []struct {
	name string
	id   int64
}{{"root", 0}, {"bin", 1}, {"daemon", 2}, {"sys", 3}, {"adm", 4}, {"user", 1000}}

// RunRuleTests runs the tests embedded in every check (ADR 0006 §9) and
// returns the cases that failed. Each case evaluates the check against the
// fact documents it gives; collectors are not run.
func (e *Engine) RunRuleTests(ctx context.Context) []TestFailure {
	return e.RunRuleTestsFor(ctx, nil)
}

// RunRuleTestsFor runs the tests of the checks with these IDs, or of every check when ids is nil.
func (e *Engine) RunRuleTestsFor(ctx context.Context, ids []string) []TestFailure {
	var failures []TestFailure
	for _, id := range sortedKeys(e.compiled) {
		if ids != nil && !slices.Contains(ids, id) {
			continue
		}
		cc := e.compiled[id]
		for _, tc := range cc.check.Tests {
			got, detail, err := e.runCase(ctx, cc, tc)
			if err != nil {
				failures = append(failures, TestFailure{Check: id, Case: tc.Name, Want: tc.Want, Got: "", Detail: err.Error()})
				continue
			}
			if got != tc.Want {
				failures = append(failures, TestFailure{Check: id, Case: tc.Name, Want: tc.Want, Got: got, Detail: detail})
			}
		}
	}
	return failures
}

func (e *Engine) runCase(ctx context.Context, cc *compiledCheck, tc TestCase) (Status, string, error) {
	m, err := testHost(tc)
	if err != nil {
		return "", "", err
	}
	reads := map[string]bool{}
	for _, name := range cc.vars {
		reads[name] = true
	}
	if len(cc.check.Platforms) > 0 {
		reads["os"] = true // the platform gate reads the OS
	}
	unavailable, incomplete := map[string]bool{}, map[string]bool{}
	for _, name := range tc.Unavailable {
		if !reads[name] {
			return "", "", fmt.Errorf("unavailable: the check does not read %s", name)
		}
		unavailable[name] = true
	}
	for _, name := range tc.Incomplete {
		if !reads[name] {
			return "", "", fmt.Errorf("incomplete: the check does not read %s", name)
		}
		incomplete[name] = true
	}
	for _, name := range sortedKeys(tc.Facts) {
		if !reads[name] {
			return "", "", fmt.Errorf("facts for %s, which the check does not read", name)
		}
	}

	// The OS is facts.os, or the test host of the os family. Platforms are
	// decided from it as in a scan.
	osDoc, hasOS := tc.Facts["os"]
	if hasOS && tc.OS != "" {
		return "", "", errors.New("give os or facts.os, not both")
	}
	family := cmp.Or(tc.OS, hostfs.FamilyDebian)
	if family != hostfs.FamilyDebian && family != hostfs.FamilyRHEL {
		return "", "", fmt.Errorf("os must be debian or rhel, not %q", family)
	}
	var osValue any = osFacts(family)
	if hasOS {
		if osValue, err = decodeFacts(reflect.TypeFor[facts.OS](), osDoc); err != nil {
			return "", "", fmt.Errorf("facts os: %w", err)
		}
	}
	env := &evalEnv{ctx: ctx, collected: map[string]*collected{}, os: osFromFacts(osValue)}
	if unavailable["os"] {
		env.os = osFromFacts(nil) // not recognized, as when the os collector fails
	}
	if f := cc.check.File; f != nil {
		// File checks read the case's files through the real file collector.
		env.files = runCollector(ctx, &fileCollector{patterns: f.Paths}, hostfs.NewTestHost(m, nil, false), defaultCollectorTimeout)
	}
	for _, name := range cc.vars {
		var v any
		switch doc, ok := tc.Facts[name]; {
		case unavailable[name]:
			env.collected[name] = &collected{err: errors.New("unavailable in this test")}
			continue
		case name == "os":
			v = osValue
		case ok:
			if v, err = decodeFacts(e.collectors[name].Type(), doc); err != nil {
				return "", "", fmt.Errorf("facts %s: %w", name, err)
			}
		case name == "target":
			v = &facts.Target{Live: true} // a running system unless the case says otherwise
		default:
			return "", "", fmt.Errorf("the check reads %s: give its facts or list it as unavailable", name)
		}
		env.collected[name] = &collected{facts: Facts{Value: v, Complete: !incomplete[name], Skipped: []string{"test"}}}
	}
	params := effectiveParams(cc.check, nil)
	for name, v := range tc.Params {
		if err := checkParamValue(cc.check, name, v); err != nil {
			return "", "", err
		}
		if n, ok := v.(int); ok {
			v = int64(n)
		}
		params[name] = v
	}
	o := env.evaluate(cc, params)
	if o.showErr != "" {
		return "", "", fmt.Errorf("show: %s", o.showErr)
	}
	detail := o.reason
	for _, ev := range o.evidence {
		detail += "; " + ev.Text
	}
	return o.status, detail, nil
}

// decodeFacts decodes a fact document strictly into a new value of t: every
// key must be a field name exactly (encoding/json alone ignores case).
func decodeFacts(t reflect.Type, doc any) (any, error) {
	if err := checkKeys(t, doc, ""); err != nil {
		return nil, err
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	v := reflect.New(t)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v.Interface()); err != nil {
		return nil, err
	}
	return v.Interface(), nil
}

// checkKeys reports a key of doc that is not exactly a json field name of t.
// Values of the wrong shape are left to the JSON decoder.
func checkKeys(t reflect.Type, doc any, where string) error {
	switch t.Kind() {
	case reflect.Struct:
		m, ok := doc.(map[string]any)
		if !ok {
			return nil
		}
		fields := map[string]reflect.Type{}
		for i := range t.NumField() {
			if f := t.Field(i); f.IsExported() {
				name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
				fields[name] = f.Type
			}
		}
		for _, k := range sortedKeys(m) {
			ft, ok := fields[k]
			switch {
			case !ok && where == "":
				return fmt.Errorf("unknown field %q", k)
			case !ok:
				return fmt.Errorf("%s: unknown field %q", strings.TrimPrefix(where, "."), k)
			}
			if err := checkKeys(ft, m[k], where+"."+k); err != nil {
				return err
			}
		}
	case reflect.Map:
		m, ok := doc.(map[string]any)
		if !ok {
			return nil
		}
		for _, k := range sortedKeys(m) {
			if err := checkKeys(t.Elem(), m[k], where+"["+k+"]"); err != nil {
				return err
			}
		}
	case reflect.Slice:
		l, ok := doc.([]any)
		if !ok {
			return nil
		}
		for i, v := range l {
			if err := checkKeys(t.Elem(), v, fmt.Sprintf("%s[%d]", where, i)); err != nil {
				return err
			}
		}
	default:
	}
	return nil
}

// osFacts are the `os` facts of a test host of the given family.
func osFacts(family string) *facts.OS {
	if family == hostfs.FamilyRHEL {
		return &facts.OS{ID: "rocky", IDLike: []string{"rhel"}, VersionID: "9.4", VersionMajor: 9, Family: family, Supported: true}
	}
	return &facts.OS{ID: "debian", VersionID: "12", VersionMajor: 12, Family: family, Supported: true}
}

// testHost builds the in-memory host of a test case. Its /etc/passwd and
// /etc/group hold the test accounts; listing them in files changes their
// metadata only.
func testHost(tc TestCase) (*hostfs.MemFS, error) {
	m := hostfs.NewMemFS()
	var passwd, group string
	ids := map[string]int64{}
	var names []string
	for _, u := range testUsers {
		passwd += fmt.Sprintf("%s:x:%d:%d::/:/usr/sbin/nologin\n", u.name, u.id, u.id)
		group += fmt.Sprintf("%s:x:%d:\n", u.name, u.id)
		ids[u.name] = u.id
		names = append(names, u.name)
	}
	content := map[string]string{"/etc/passwd": passwd, "/etc/group": group}
	m.AddFile("/etc/passwd", passwd, 0o644, 0, 0)
	m.AddFile("/etc/group", group, 0o644, 0, 0)
	resolve := func(p, what, name string) (int64, error) {
		if id, ok := ids[cmp.Or(name, "root")]; ok {
			return id, nil
		}
		if n, err := strconv.ParseInt(name, 10, 64); err == nil && n >= 0 {
			return n, nil
		}
		return 0, fmt.Errorf("file %s: %s %q is not a number or a test account (%s)", p, what, name, strings.Join(names, ", "))
	}
	for _, p := range sortedKeys(tc.Files) {
		f := tc.Files[p]
		if !strings.HasPrefix(p, "/") || path.Clean(p) != p {
			return nil, fmt.Errorf("file %s: the path must be absolute and clean", p)
		}
		mode := uint64(0o644)
		if f.Mode != "" {
			var err error
			if mode, err = strconv.ParseUint(f.Mode, 8, 32); err != nil {
				return nil, fmt.Errorf("file %s: mode %q: %w", p, f.Mode, err)
			}
		}
		uid, err := resolve(p, "owner", f.Owner)
		if err != nil {
			return nil, err
		}
		gid, err := resolve(p, "group", f.Group)
		if err != nil {
			return nil, err
		}
		if (f.Type == "symlink") != (f.Target != "") {
			return nil, fmt.Errorf("file %s: a symlink needs a target, and only a symlink has one", p)
		}
		switch f.Type {
		case "", "file":
			m.AddFile(p, content[p], uint32(mode), uid, gid)
		case "dir":
			m.AddDir(p, uint32(mode), uid, gid)
		case "symlink":
			m.AddSymlink(p, f.Target)
		default:
			return nil, fmt.Errorf("file %s: unknown type %q", p, f.Type)
		}
		switch f.Error {
		case "":
		case "permission":
			m.SetError(p, fs.ErrPermission)
		default:
			return nil, fmt.Errorf("file %s: error must be permission, not %q", p, f.Error)
		}
	}
	return m, nil
}
