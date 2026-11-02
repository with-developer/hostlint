package engine

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/with-developer/hostlint/internal/hostfs"
	"github.com/with-developer/hostlint/internal/version"
)

// Engine evaluates the checks of a Content with a set of collectors.
type Engine struct {
	content    *Content
	collectors map[string]Collector
	compiled   map[string]*compiledCheck
}

// New compiles every check of content. It fails if any expression does not
// type-check against the collectors' facts, so broken rules fail CI.
func New(content *Content, collectors ...Collector) (*Engine, error) {
	e := &Engine{content: content, collectors: map[string]Collector{}, compiled: map[string]*compiledCheck{}}
	for _, c := range append([]Collector{osCollector{}}, collectors...) {
		if _, dup := e.collectors[c.Name()]; dup {
			return nil, fmt.Errorf("two collectors named %s", c.Name())
		}
		e.collectors[c.Name()] = c
	}
	base, err := newBaseEnv(e.collectors)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, id := range sortedKeys(content.Checks) {
		cc, err := compileCheck(base, e.collectors, content.Checks[id])
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
			continue
		}
		e.compiled[id] = cc
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return e, nil
}

// Options control one scan.
type Options struct {
	Profile          string
	Labels           map[string]string
	Tool             ToolInfo
	CollectorTimeout time.Duration
	// Now returns the current time; tests set it for stable output.
	Now func() time.Time
}

// instance is one check evaluated with one set of parameters.
type instance struct {
	ref    string
	cc     *compiledCheck
	params map[string]any
}

// Scan evaluates the profile's checks on the host.
func (e *Engine) Scan(ctx context.Context, h *hostfs.Host, opts Options) (*Result, error) {
	profile, ok := e.content.Profiles[opts.Profile]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q (available: %s)", opts.Profile, strings.Join(sortedKeys(e.content.Profiles), ", "))
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	timeout := opts.CollectorTimeout
	if timeout <= 0 {
		timeout = defaultCollectorTimeout
	}
	started := now()

	// Plan: one instance per distinct (check, parameters).
	instances := map[string]*instance{}
	controlRefs := make([][]string, len(profile.Controls))
	for i, ctl := range profile.Controls {
		for _, id := range ctl.Checks {
			cc := e.compiled[id]
			params := effectiveParams(cc.check, ctl.Params[id])
			ref := checkRef(cc.check, params)
			if instances[ref] == nil {
				instances[ref] = &instance{ref: ref, cc: cc, params: params}
			}
			controlRefs[i] = append(controlRefs[i], ref)
		}
	}

	// Collect: only what the planned checks need, each collector once.
	needed := map[string]bool{"os": true}
	for _, in := range instances {
		for _, v := range in.cc.vars {
			needed[v] = true
		}
	}
	env := &evalEnv{ctx: ctx, host: h, collected: map[string]*collected{}, ids: newIDMap(h.FS)}
	for _, name := range sortedKeys(needed) {
		env.collected[name] = runCollector(ctx, e.collectors[name], h, timeout)
	}
	if c := env.collected["os"]; c.ok() {
		env.os = osFromFacts(c.facts.Value)
	} else {
		env.os = hostfs.OS{ID: hostfs.FamilyUnknown, Family: hostfs.FamilyUnknown}
	}

	// Evaluate.
	checks := map[string]*CheckResult{}
	for _, ref := range sortedKeys(instances) {
		in := instances[ref]
		start := time.Now()
		o := env.evaluate(in.cc, in.params)
		cr := e.checkResult(in, o)
		cr.DurationMs = time.Since(start).Milliseconds()
		checks[ref] = cr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	res := &Result{
		SchemaVersion: SchemaVersion,
		Profiles:      []ProfileInfo{{ID: profile.ID, Revision: profile.Revision, Digest: profileDigest(profile), Title: profile.Title}},
		Summary:       map[string]ProfileSummary{},
		Controls:      []ControlResult{},
		Checks:        []CheckResult{},
		Collectors:    []CollectorRun{},
	}
	summary := ProfileSummary{Controls: map[Status]int{}, Checks: map[Status]int{}}
	for i, ctl := range profile.Controls {
		cr := aggregate(profile.ID, ctl, controlRefs[i], checks)
		summary.Controls[cr.Status]++
		res.Controls = append(res.Controls, cr)
	}
	for _, ref := range sortedKeys(checks) {
		summary.Checks[checks[ref].Status]++
		res.Checks = append(res.Checks, *checks[ref])
	}
	res.Summary[profile.ID] = summary
	for _, name := range sortedKeys(env.collected) {
		res.Collectors = append(res.Collectors, env.collected[name].run)
	}
	res.Host = hostInfo(h, env.os, opts.Labels)
	res.Scan = ScanInfo{
		ID:         newScanID(started),
		StartedAt:  started.UTC().Format(time.RFC3339),
		FinishedAt: now().UTC().Format(time.RFC3339),
		Tool:       opts.Tool,
		Target:     TargetInfo{Kind: "host", Root: h.Root},
		Privileges: Privileges{EUID: int64(os.Geteuid())},
	}
	if !h.Live {
		res.Scan.Target.Kind = "root"
	}
	if res.Scan.Tool.Name == "" {
		res.Scan.Tool.Name = "hostlint"
	}
	if res.Scan.Tool.Version == "" {
		info := version.Get()
		res.Scan.Tool.Version, res.Scan.Tool.Commit = info.Version, info.Commit
	}
	return res, nil
}

// checkResult turns an outcome into the result entry for an instance.
func (e *Engine) checkResult(in *instance, o outcome) *CheckResult {
	c := in.cc.check
	ev, omitted := limitEvidence(o.evidence)
	cr := &CheckResult{
		Ref: in.ref, ID: c.ID, Version: c.Version, Digest: checkDigest(c),
		Title: c.Title, TitleKo: c.TitleKo, Severity: c.Severity,
		Status: o.status, StatusSource: "observed", Reason: o.reason,
		Evidence: ev, EvidenceOmitted: omitted, Coverage: o.coverage,
	}
	if len(in.params) > 0 {
		cr.Params = in.params
	}
	return cr
}

// aggregate computes a control's status from its checks (ADR 0006 §7).
func aggregate(profileID string, ctl Control, refs []string, checks map[string]*CheckResult) ControlResult {
	cr := ControlResult{
		Profile: profileID, ID: ctl.ID, Title: ctl.Title, TitleKo: ctl.TitleKo,
		Severity: ctl.Severity, Checks: refs,
	}
	if cr.Checks == nil {
		cr.Checks = []string{}
	}
	if len(refs) == 0 {
		cr.Status, cr.Reason = StatusManual, ctl.Manual
		return cr
	}
	cr.Status = StatusNotApplicable
	for _, ref := range refs {
		if st := checks[ref].Status; st.precedence() > cr.Status.precedence() {
			cr.Status = st
		}
	}
	var reasons []string
	for _, ref := range refs {
		if ch := checks[ref]; ch.Status == cr.Status && ch.Reason != "" {
			reasons = append(reasons, ch.ID+": "+ch.Reason)
		}
	}
	if cr.Status != StatusPass && cr.Status != StatusFail {
		cr.Reason = strings.Join(reasons, "; ")
	}
	return cr
}

// effectiveParams merges check defaults with profile overrides; ints become
// int64 for CEL.
func effectiveParams(c *Check, overrides map[string]any) map[string]any {
	params := map[string]any{}
	for name, ps := range c.Params {
		v := ps.Default
		if o, ok := overrides[name]; ok {
			v = o
		}
		if n, ok := v.(int); ok {
			v = int64(n)
		}
		params[name] = v
	}
	return params
}

// checkRef is the check ID, plus a parameter digest when the parameters
// differ from the check's defaults (ADR 0006 §10).
func checkRef(c *Check, params map[string]any) string {
	if reflect.DeepEqual(params, effectiveParams(c, nil)) {
		return c.ID
	}
	return c.ID + "#" + digestHex(params)[:8]
}

// checkDigest covers a check's logic, not its prose.
func checkDigest(c *Check) string {
	return "sha256:" + digestHex(struct {
		Version    int
		Platforms  []string
		Applies    string
		Params     map[string]ParamSpec
		Setting    *SettingSpec
		File       *FileSpec
		Violations *ViolationsSpec
		Expect     string
		Manual     string
	}{c.Version, c.Platforms, c.Applies, c.Params, c.Setting, c.File, c.Violations, c.Expect, manualShow(c)})
}

func manualShow(c *Check) string {
	if c.Manual == nil {
		return ""
	}
	return c.Manual.Show
}

// profileDigest covers the mapping, not titles.
func profileDigest(p *Profile) string {
	type ctl struct {
		ID       string
		Severity Severity
		Checks   []string
		Manual   bool
		Params   map[string]map[string]any
	}
	ctls := make([]ctl, 0, len(p.Controls))
	for _, c := range p.Controls {
		ctls = append(ctls, ctl{c.ID, c.Severity, c.Checks, c.Manual != "", c.Params})
	}
	return "sha256:" + digestHex(struct {
		ID       string
		Revision int
		Controls []ctl
	}{p.ID, p.Revision, ctls})
}

func digestHex(v any) string {
	data, err := json.Marshal(v) // map keys are sorted, so this is canonical
	if err != nil {
		panic(fmt.Sprintf("digest: %v", err))
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// newScanID returns a UUIDv7.
func newScanID(t time.Time) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	binary.BigEndian.PutUint64(b[:8], uint64(t.UnixMilli())<<16|uint64(binary.BigEndian.Uint16(b[6:8])))
	b[6] = 0x70 | b[6]&0x0f // version 7
	b[8] = 0x80 | b[8]&0x3f // RFC 9562 variant
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// hostIDKey derives host IDs; the raw machine ID never leaves the host.
var hostIDKey = []byte("hostlint host id v1")

func hostInfo(h *hostfs.Host, o hostfs.OS, labels map[string]string) HostInfo {
	hi := HostInfo{
		OS:     OSInfo{ID: o.ID, VersionID: o.VersionID, Family: o.Family, Name: o.Name, Supported: o.Supported},
		Labels: labels,
	}
	if data, err := h.FS.ReadFile("/etc/hostname"); err == nil {
		hi.Hostname = strings.TrimSpace(string(data))
	}
	if h.Live {
		if name, err := os.Hostname(); err == nil {
			hi.Hostname = name
		}
		hi.Arch = runtime.GOARCH
	}
	if data, err := h.FS.ReadFile("/etc/machine-id"); err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			mac := hmac.New(sha256.New, hostIDKey)
			mac.Write([]byte(id))
			hi.HostID = hex.EncodeToString(mac.Sum(nil))[:32]
		}
	}
	return hi
}
