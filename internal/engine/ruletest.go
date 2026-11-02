package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"strconv"

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
	var failures []TestFailure
	for _, id := range sortedKeys(e.compiled) {
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
	family := tc.OS
	if family == "" {
		family = hostfs.FamilyDebian
	}
	if family != hostfs.FamilyDebian && family != hostfs.FamilyRHEL {
		return "", "", fmt.Errorf("os must be debian or rhel, not %q", family)
	}
	env := &evalEnv{
		ctx: ctx, host: hostfs.NewTestHost(m, nil, false), collected: map[string]*collected{},
		os: osFromFacts(osFacts(family)), ids: newIDMap(m),
	}
	unavailable := map[string]bool{}
	for _, name := range tc.Unavailable {
		unavailable[name] = true
	}
	incomplete := map[string]bool{}
	for _, name := range tc.Incomplete {
		incomplete[name] = true
	}
	for name := range tc.Facts {
		if _, ok := e.collectors[name]; !ok {
			return "", "", fmt.Errorf("facts for unknown collector %q", name)
		}
	}
	for _, name := range cc.vars {
		col := e.collectors[name]
		switch doc, ok := tc.Facts[name]; {
		case unavailable[name]:
			env.collected[name] = &collected{err: errors.New("unavailable in this test")}
		case ok:
			v, err := decodeFacts(col.Type(), doc)
			if err != nil {
				return "", "", fmt.Errorf("facts %s: %w", name, err)
			}
			env.collected[name] = &collected{facts: Facts{Value: v, Complete: !incomplete[name], Skipped: []string{"test"}}}
		case name == "os":
			env.collected[name] = &collected{facts: Facts{Value: osFacts(family), Complete: !incomplete[name], Skipped: []string{"test"}}}
		default:
			return "", "", fmt.Errorf("the check reads %s: give its facts or list it as unavailable", name)
		}
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
	detail := o.reason
	for _, ev := range o.evidence {
		detail += "; " + ev.Text
	}
	return o.status, detail, nil
}

// decodeFacts decodes a fact document strictly into a new value of t.
func decodeFacts(t reflect.Type, doc any) (any, error) {
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

// osFacts are the `os` facts of a test host of the given family.
func osFacts(family string) *facts.OS {
	if family == hostfs.FamilyRHEL {
		return &facts.OS{ID: "rocky", IDLike: []string{"rhel"}, VersionID: "9.4", VersionMajor: 9, Family: family, Supported: true}
	}
	return &facts.OS{ID: "debian", VersionID: "12", VersionMajor: 12, Family: family, Supported: true}
}

// testHost builds the in-memory host of a test case.
func testHost(tc TestCase) (*hostfs.MemFS, error) {
	m := hostfs.NewMemFS()
	var passwd, group string
	ids := map[string]int64{}
	for _, u := range testUsers {
		passwd += fmt.Sprintf("%s:x:%d:%d::/:/usr/sbin/nologin\n", u.name, u.id, u.id)
		group += fmt.Sprintf("%s:x:%d:\n", u.name, u.id)
		ids[u.name] = u.id
	}
	m.AddFile("/etc/passwd", passwd, 0o644, 0, 0)
	m.AddFile("/etc/group", group, 0o644, 0, 0)
	for _, p := range sortedKeys(tc.Files) {
		f := tc.Files[p]
		mode := uint64(0o644)
		if f.Mode != "" {
			var err error
			if mode, err = strconv.ParseUint(f.Mode, 8, 32); err != nil {
				return nil, fmt.Errorf("file %s: mode %q: %w", p, f.Mode, err)
			}
		}
		uid, gid := ids[orDefault(f.Owner, "root")], ids[orDefault(f.Group, "root")]
		switch f.Type {
		case "", "file":
			m.AddFile(p, "", uint32(mode), uid, gid)
		case "dir":
			m.AddDir(p, uint32(mode), uid, gid)
		case "symlink":
			m.AddSymlink(p, f.Target)
		default:
			return nil, fmt.Errorf("file %s: unknown type %q", p, f.Type)
		}
		if f.Error == "permission" {
			m.SetError(p, fs.ErrPermission)
		}
	}
	return m, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
