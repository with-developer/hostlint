package engine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
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
	for _, c := range append([]Collector{osCollector{}, targetCollector{}}, collectors...) {
		switch name := c.Name(); {
		case !identRe.MatchString(name) || name == "params":
			return nil, fmt.Errorf("collector name %q must be an identifier other than params", name)
		case name == fileCollectorName || name == hostCollectorName:
			return nil, fmt.Errorf("collector name %s is reserved for the engine", name)
		case e.collectors[name] != nil:
			return nil, fmt.Errorf("two collectors named %s", name)
		case c.Version() < 1:
			return nil, fmt.Errorf("collector %s: version must be 1 or more", name)
		case c.Access() != AccessFilesystem && c.Access() != AccessLive:
			return nil, fmt.Errorf("collector %s: access must be %s or %s, not %q", name, AccessFilesystem, AccessLive, c.Access())
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
	// Profile is the profile to scan with; Profiles names several, which are scanned together (the checks
	// they share are evaluated once). Profile is added to Profiles when it is not in it.
	Profile  string
	Profiles []string
	// Packs are the policy packs whose content was added to the engine's content; the result names them.
	Packs            []PackInfo
	Labels           map[string]string
	Tool             ToolInfo
	CollectorTimeout time.Duration
	// Now returns the current time; tests set it for stable output.
	Now func() time.Time
	// Params override check parameters (check ID → parameter → value);
	// each must be at least as strict as the profile's.
	Params map[string]map[string]any
	// Waivers accept results for a reason, until they expire.
	Waivers []Waiver
	// Attestations are human verdicts for MANUAL checks (ADR 0006 §6).
	Attestations []Attestation
}

// instance is one check evaluated with one set of parameters.
type instance struct {
	ref        string
	cc         *compiledCheck
	params     map[string]any
	customized bool // parameters overridden by the configuration
}

// Scan evaluates the profile's checks on the host.
func (e *Engine) Scan(ctx context.Context, h *hostfs.Host, opts Options) (*Result, error) {
	var profiles []*Profile
	var ids []string
	if opts.Profile != "" {
		ids = append(ids, opts.Profile)
	}
	for _, id := range opts.Profiles {
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	for _, id := range ids {
		profile, ok := e.content.Profiles[id]
		if !ok {
			return nil, fmt.Errorf("unknown profile %q (available: %s)", id, strings.Join(sortedKeys(e.content.Profiles), ", "))
		}
		profiles = append(profiles, profile)
	}
	if len(profiles) == 0 {
		return nil, errors.New("no profile to scan with")
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
	controlRefs := make([][][]string, len(profiles)) // profile → control → check refs
	for pi, profile := range profiles {
		controlRefs[pi] = make([][]string, len(profile.Controls))
		for i, ctl := range profile.Controls {
			for _, id := range ctl.Checks {
				cc := e.compiled[id]
				params := effectiveParams(cc.check, ctl.Params[id])
				customized := false
				if over := opts.Params[id]; len(over) > 0 {
					var err error
					if params, err = overrideParams(cc.check, params, over); err != nil {
						return nil, err
					}
					customized = true
				}
				ref := checkRef(cc.check, params)
				if instances[ref] == nil {
					instances[ref] = &instance{ref: ref, cc: cc, params: params, customized: customized}
				}
				controlRefs[pi][i] = append(controlRefs[pi][i], ref)
			}
		}
	}

	// Collect: only what the planned checks need, each collector once. All
	// I/O happens here, bounded per collector; evaluation below does none.
	// The OS comes first: checks for other platforms need nothing else.
	env := &evalEnv{ctx: ctx, collected: map[string]*collected{}}
	osc := runCollector(ctx, e.collectors["os"], h, timeout)
	env.collected["os"] = osc
	env.os = hostfs.OS{ID: hostfs.FamilyUnknown, Family: hostfs.FamilyUnknown}
	if osc.ok() {
		env.os = osFromFacts(osc.facts.Value)
	}
	needed := map[string]bool{}
	patterns := map[string]bool{}
	for _, in := range instances {
		if c := in.cc.check; len(c.Platforms) > 0 && !slices.Contains(c.Platforms, env.os.Family) {
			continue // not applicable, or an error if the OS is unknown
		}
		for _, v := range in.cc.vars {
			if v != "os" {
				needed[v] = true
			}
		}
		if f := in.cc.check.File; f != nil {
			for _, p := range f.Paths {
				patterns[p] = true
			}
		}
	}
	for _, name := range sortedKeys(needed) {
		env.collected[name] = runCollector(ctx, e.collectors[name], h, timeout)
	}
	if len(patterns) > 0 {
		env.files = runCollector(ctx, &fileCollector{patterns: sortedKeys(patterns)}, h, timeout)
	}
	hostc := runCollector(ctx, hostCollector{}, h, timeout)

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
		Profiles:      make([]ProfileInfo, 0, len(profiles)),
		Summary:       map[string]ProfileSummary{},
		Controls:      []ControlResult{},
		Checks:        []CheckResult{},
		Collectors:    []CollectorRun{},
	}
	res.Host = hostInfo(hostc, env.os, opts.Labels)
	today := now().UTC().Truncate(24 * time.Hour)
	res.Attestations = attestChecks(opts.Attestations, checks, res.Host.Hostname, today)
	notes := waiveChecks(opts.Waivers, checks, res.Host.Hostname, today)
	for pi, profile := range profiles {
		res.Profiles = append(res.Profiles, ProfileInfo{ID: profile.ID, Revision: profile.Revision, Digest: ProfileDigest(profile), Title: profile.Title})
		summary := ProfileSummary{Controls: map[Status]int{}, Checks: map[Status]int{}}
		profileChecks := map[string]bool{}
		for i, ctl := range profile.Controls {
			cr := aggregate(profile.ID, ctl, controlRefs[pi][i], checks)
			notes = append(notes, waiveControl(opts.Waivers, profile, &cr, checks, res.Host.Hostname, today)...)
			cr.Customized = slices.ContainsFunc(cr.Checks, func(ref string) bool { return checks[ref].Customized })
			summary.Controls[cr.Status]++
			res.Controls = append(res.Controls, cr)
			for _, ref := range controlRefs[pi][i] {
				profileChecks[ref] = true
			}
		}
		for _, ref := range sortedKeys(profileChecks) {
			summary.Checks[checks[ref].Status]++
			if checks[ref].Customized {
				summary.Customized++
			}
		}
		res.Summary[profile.ID] = summary
	}
	for _, ref := range sortedKeys(checks) {
		res.Checks = append(res.Checks, *checks[ref])
	}
	res.Waivers = notes
	runs := map[string]*collected{hostCollectorName: hostc}
	for name, c := range env.collected {
		runs[name] = c
	}
	if env.files != nil {
		runs[fileCollectorName] = env.files
	}
	for _, name := range sortedKeys(runs) {
		res.Collectors = append(res.Collectors, runs[name].run)
	}
	res.Scan = ScanInfo{
		ID:         newScanID(started),
		StartedAt:  started.UTC().Format(time.RFC3339),
		FinishedAt: now().UTC().Format(time.RFC3339),
		Tool:       opts.Tool,
		Target:     TargetInfo{Kind: "host", Root: h.Root},
		Privileges: Privileges{EUID: int64(os.Geteuid())},
		Packs:      slices.Clone(opts.Packs),
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
	ev, omitted := limitEvidence(o.evidence, o.omitted)
	cr := &CheckResult{
		Ref: in.ref, ID: c.ID, Version: c.Version, Digest: checkDigest(c),
		Title: c.Title, TitleKo: c.TitleKo, Severity: c.Severity,
		Status: o.status, StatusSource: "observed", Reason: truncate(o.reason, maxReasonLen),
		Evidence: ev, EvidenceOmitted: omitted, Coverage: o.coverage, EvidenceDigest: o.evidenceDigest,
		shows: c.Manual != nil && c.Manual.Show != "",
	}
	if len(in.params) > 0 {
		cr.Params = in.params
	}
	cr.Customized = in.customized
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
		cr.Reason = truncate(strings.Join(reasons, "; "), maxReasonLen)
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

// checkDigest covers a check's logic, not its prose (ADR 0006 §10).
func checkDigest(c *Check) string {
	type param struct {
		Type     string
		Default  any
		Stricter string
	}
	params := map[string]param{}
	for name, p := range c.Params {
		params[name] = param{p.Type, p.Default, p.Stricter}
	}
	return "sha256:" + digestHex(struct {
		Version    int
		Platforms  []string
		Applies    string
		Params     map[string]param
		Setting    *SettingSpec
		File       *FileSpec
		Violations *ViolationsSpec
		Expect     string
		Manual     string
	}{c.Version, c.Platforms, c.Applies, params, c.Setting, c.File, c.Violations, c.Expect, manualShow(c)})
}

func manualShow(c *Check) string {
	if c.Manual == nil {
		return ""
	}
	return c.Manual.Show
}

// profileDigest covers the mapping, not titles.
// ProfileDigest is the digest of a profile's mapping: what a result records and a waiver of a pack's
// control names.
func ProfileDigest(p *Profile) string {
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
