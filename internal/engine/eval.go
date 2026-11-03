package engine

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"

	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// Evidence and reason bounds (ADR 0006 §8).
const (
	maxEvidence     = 50
	maxEvidenceText = 300
	maxReasonItems  = 5
	maxReasonLen    = 1000
	maxSkipped      = 50
	maxShownKeys    = 20
)

// evalEnv is what checks are evaluated against on one host. Evaluation reads
// only collected facts; it does no I/O.
type evalEnv struct {
	ctx       context.Context
	os        hostfs.OS
	collected map[string]*collected
	// files holds the file collector's observations; nil when no planned
	// check is a file check.
	files *collected
}

// outcome is a check's result before waivers and attestations.
type outcome struct {
	status   Status
	reason   string
	evidence []Evidence
	coverage *Coverage
}

func errorOutcome(format string, args ...any) outcome {
	return outcome{status: StatusError, reason: fmt.Sprintf(format, args...)}
}

// activations builds the two activations of ADR 0006 §5 step 2: complete
// facts only (failed, unavailable and incomplete collectors are unknown),
// and all available facts including incomplete ones.
func (e *evalEnv) activations(cc *compiledCheck, params map[string]any) (strict, partial map[string]any, failed, incomplete []string) {
	strictVars := map[string]any{}
	partialVars := map[string]any{}
	for name, v := range params {
		strictVars["params."+name] = v
		partialVars["params."+name] = v
	}
	for _, name := range cc.vars {
		c := e.collected[name]
		switch {
		case c == nil || !c.ok():
			failed = append(failed, name)
		case !c.facts.Complete:
			incomplete = append(incomplete, name)
			partialVars[name] = c.facts.Value
		default:
			strictVars[name] = c.facts.Value
			partialVars[name] = c.facts.Value
		}
	}
	return strictVars, partialVars, failed, incomplete
}

// unknownReason explains an undetermined result.
func (e *evalEnv) unknownReason(failed, incomplete []string) string {
	var parts []string
	for _, name := range failed {
		if c := e.collected[name]; c != nil && c.err != nil {
			parts = append(parts, fmt.Sprintf("%s: %v", name, c.err))
		} else {
			parts = append(parts, name+": not collected")
		}
	}
	for _, name := range incomplete {
		c := e.collected[name]
		parts = append(parts, fmt.Sprintf("%s: incomplete observation (%s)", name, summarize(c.facts.Skipped)))
	}
	return strings.Join(parts, "; ")
}

// eval evaluates p with vars; collector variables missing from vars are
// CEL unknowns.
func (e *evalEnv) eval(env *cel.Env, p *program, vars map[string]any) (ref.Val, error) {
	act, err := env.PartialVars(vars)
	if err != nil {
		return nil, err
	}
	v, _, err := p.prg.ContextEval(e.ctx, act)
	return v, err
}

// evaluate runs one check instance (ADR 0006 §5).
func (e *evalEnv) evaluate(cc *compiledCheck, params map[string]any) outcome {
	c := cc.check
	if len(c.Platforms) > 0 {
		if e.os.Family == hostfs.FamilyUnknown || e.os.Family == "" {
			return errorOutcome("operating system not recognized; this check applies to %s", strings.Join(c.Platforms, ", "))
		}
		if !slices.Contains(c.Platforms, e.os.Family) {
			return outcome{status: StatusNotApplicable, reason: fmt.Sprintf("applies to %s, not %s", strings.Join(c.Platforms, ", "), e.os.Family)}
		}
	}
	strict, partial, failed, incomplete := e.activations(cc, params)

	if cc.applies != nil {
		v, err := e.eval(cc.env, cc.applies, strict)
		switch {
		case err != nil:
			return errorOutcome("applies: %v", err)
		case types.IsUnknown(v):
			return errorOutcome("cannot decide whether the check applies: %s", e.unknownReason(failed, incomplete))
		case v == types.False:
			return outcome{status: StatusNotApplicable, reason: "applies is false: " + cc.applies.source}
		}
	}

	switch {
	case c.File != nil:
		return e.evalFile(c.File)
	case cc.setting != nil:
		return e.evalSetting(cc, params, strict, failed, incomplete)
	case cc.expect != nil:
		v, err := e.eval(cc.env, cc.expect, strict)
		switch {
		case err != nil:
			return errorOutcome("expect: %v", err)
		case types.IsUnknown(v):
			return errorOutcome("%s", e.unknownReason(failed, incomplete))
		}
		o := outcome{status: StatusFail, evidence: e.pathEvidence(cc, strict)}
		if v == types.True {
			o.status = StatusPass
		}
		return o
	case cc.over != nil:
		return e.evalViolations(cc, strict, partial, failed, incomplete)
	case c.Manual != nil:
		o := outcome{status: StatusManual, reason: c.Manual.Guidance}
		if cc.show != nil {
			v, err := e.eval(cc.env, cc.show, strict)
			switch {
			case err != nil:
				o.reason += " (evidence unavailable: " + err.Error() + ")"
			case types.IsUnknown(v):
				o.reason += " (evidence unavailable: " + e.unknownReason(failed, incomplete) + ")"
			default:
				o.evidence = listEvidence("show", v)
			}
		}
		return o
	}
	return errorOutcome("check has no kind")
}

func (e *evalEnv) evalSetting(cc *compiledCheck, params, act map[string]any, failed, incomplete []string) outcome {
	spec := cc.check.Setting
	v, err := e.eval(cc.env, cc.setting, act)
	switch {
	case err != nil:
		return errorOutcome("setting.fact: %v", err)
	case types.IsUnknown(v):
		// The unreadable part may hold the value that matters: never decide.
		return errorOutcome("%s", e.unknownReason(failed, incomplete))
	}
	opt, ok := v.(*types.Optional)
	if !ok {
		return errorOutcome("setting.fact: unexpected value %v", v)
	}
	key := spec.Fact
	want := describeWant(spec, params)
	if !opt.HasValue() {
		switch spec.Absent {
		case "fail":
			return outcome{status: StatusFail, evidence: []Evidence{{Key: key, Text: "not set; expected " + want}}}
		default:
			return errorOutcome("%s is not set and its default is not known", key)
		}
	}
	s, ok := opt.GetValue().Value().(facts.Setting)
	if !ok {
		return errorOutcome("setting.fact: %s is not a Setting", key)
	}
	state := "explicit"
	if !s.Explicit {
		state = "default"
		switch spec.Absent {
		case "fail":
			return outcome{status: StatusFail, evidence: []Evidence{{Key: key,
				Text: fmt.Sprintf("not set (default %q); expected %s", s.Value, want), Source: s.Source}}}
		case "error":
			return errorOutcome("%s is not set explicitly", key)
		}
	}
	pass, err := compareSetting(spec, params, s.Value)
	if err != nil {
		return errorOutcome("%s: %v", key, err)
	}
	o := outcome{status: StatusFail, evidence: []Evidence{{Key: key,
		Text: fmt.Sprintf("%q (%s); expected %s", s.Value, state, want), Source: s.Source}}}
	if pass {
		o.status = StatusPass
	}
	return o
}

func compareSetting(spec *SettingSpec, params map[string]any, value string) (bool, error) {
	switch {
	case len(spec.In) > 0:
		return slices.Contains(spec.In, value), nil
	case spec.Range != nil:
		n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return false, fmt.Errorf("value %q is not an integer", value)
		}
		lo, hi := spec.Range.Min.resolve(params), spec.Range.Max.resolve(params)
		return n >= lo && n <= hi, nil
	default:
		re, err := regexp.Compile(`^(?:` + spec.Matches + `)$`)
		if err != nil {
			return false, err
		}
		return re.MatchString(value), nil
	}
}

func (b *Bound) resolve(params map[string]any) int64 {
	if b.Param != "" {
		v, _ := params[b.Param].(int64)
		return v
	}
	return b.Value
}

func describeWant(spec *SettingSpec, params map[string]any) string {
	switch {
	case len(spec.In) > 0:
		return "one of [" + strings.Join(spec.In, ", ") + "]"
	case spec.Range != nil:
		return fmt.Sprintf("%d–%d", spec.Range.Min.resolve(params), spec.Range.Max.resolve(params))
	}
	return "a value matching " + spec.Matches
}

// pathEvidence reports the values of the fact paths an expect expression reads.
func (e *evalEnv) pathEvidence(cc *compiledCheck, act map[string]any) []Evidence {
	var ev []Evidence
	for _, p := range cc.evidencePaths {
		v, err := e.eval(cc.env, p.prog, act)
		item := Evidence{Key: p.path}
		switch {
		case err != nil && p.mapKey:
			// Selecting a fact path only fails on a map key the host does not have.
			item.Text = p.path + ": not set"
		case err != nil:
			item.Text = p.path + ": " + err.Error()
		case types.IsUnknown(v):
			continue
		default:
			item.Text, item.Source = describeValue(p.path, v)
		}
		ev = append(ev, item)
	}
	return ev
}

// describeValue renders one fact value as evidence text: settings with their
// state and source, maps as their keys, anything else as a literal.
func describeValue(path string, v ref.Val) (text, source string) {
	if s, ok := v.Value().(facts.Setting); ok {
		state := "explicit"
		if !s.Explicit {
			state = "default"
		}
		return fmt.Sprintf("%s = %q (%s)", path, s.Value, state), s.Source
	}
	if m, ok := v.(traits.Mapper); ok {
		var keys []string
		for it := m.Iterator(); it.HasNext() == types.True; {
			keys = append(keys, fmt.Sprint(it.Next().Value()))
		}
		if len(keys) == 0 {
			return path + " is empty", ""
		}
		sort.Strings(keys)
		return path + " has " + strings.Join(boundList(keys, maxShownKeys), ", "), ""
	}
	return path + " = " + render(v), ""
}

func (e *evalEnv) evalViolations(cc *compiledCheck, strict, partial map[string]any, failed, incomplete []string) outcome {
	spec := cc.check.Violations
	over, err := e.eval(cc.env, cc.over, strict)
	if err != nil {
		return errorOutcome("violations.over: %v", err)
	}
	if types.IsUnknown(over) {
		if len(failed) > 0 {
			return errorOutcome("%s", e.unknownReason(failed, incomplete))
		}
		// Only incomplete facts: what was seen can still fail the check.
		if over, err = e.eval(cc.env, cc.over, partial); err != nil || types.IsUnknown(over) {
			return errorOutcome("%s", e.unknownReason(failed, incomplete))
		}
		o := e.matchViolations(cc, over, partial, failed, incomplete)
		if o.status != StatusFail {
			return errorOutcome("%s", e.unknownReason(failed, incomplete))
		}
		return o
	}
	o := e.matchViolations(cc, over, strict, failed, incomplete)
	if o.status == StatusPass && o.coverage.Count == 0 && !spec.AllowEmpty {
		return errorOutcome("%s is empty, so there was nothing to check", spec.Over)
	}
	return o
}

// matchViolations evaluates where for every element of the population.
func (e *evalEnv) matchViolations(cc *compiledCheck, over ref.Val, act map[string]any, failed, incomplete []string) outcome {
	spec := cc.check.Violations
	list, ok := over.(traits.Lister)
	if !ok {
		return errorOutcome("violations.over is not a list")
	}
	n := int(list.Size().(types.Int))
	o := outcome{status: StatusPass, coverage: &Coverage{Population: spec.Over, Count: n}}
	var firstErr error
	undecided := false
	for i := 0; i < n; i++ {
		elemVars := make(map[string]any, len(act)+1)
		for k, v := range act {
			elemVars[k] = v
		}
		elemVars[spec.As] = list.Get(types.Int(i))
		v, err := e.eval(cc.elemEnv, cc.where, elemVars)
		switch {
		case err != nil:
			if firstErr == nil {
				firstErr = err
			}
			continue
		case types.IsUnknown(v):
			undecided = true
			continue
		case v != types.True:
			continue
		}
		key, kerr := e.eval(cc.elemEnv, cc.key, elemVars)
		text, terr := e.eval(cc.elemEnv, cc.text, elemVars)
		if kerr != nil || terr != nil || types.IsUnknown(key) || types.IsUnknown(text) {
			return errorOutcome("violations key/text: %v", errors.Join(kerr, terr))
		}
		o.status = StatusFail
		o.evidence = append(o.evidence, Evidence{Key: fmt.Sprint(key.Value()), Text: fmt.Sprint(text.Value())})
	}
	switch {
	case o.status == StatusFail:
		return o
	case firstErr != nil:
		return errorOutcome("violations.where: %v", firstErr)
	case undecided:
		return errorOutcome("%s", e.unknownReason(failed, incomplete))
	}
	return o
}

// render formats a CEL value for evidence.
func render(v ref.Val) string {
	switch x := v.Value().(type) {
	case string:
		return strconv.Quote(x)
	case facts.Setting:
		return strconv.Quote(x.Value)
	}
	if l, ok := v.(traits.Lister); ok {
		n := int(l.Size().(types.Int))
		parts := make([]string, 0, n)
		for i := 0; i < n; i++ {
			parts = append(parts, render(l.Get(types.Int(i))))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return fmt.Sprint(v.Value())
}

// listEvidence turns a show value into evidence items, one per list element.
func listEvidence(key string, v ref.Val) []Evidence {
	if l, ok := v.(traits.Lister); ok {
		n := int(l.Size().(types.Int))
		ev := make([]Evidence, 0, n)
		for i := 0; i < n; i++ {
			ev = append(ev, Evidence{Key: fmt.Sprintf("%s[%d]", key, i), Text: strings.Trim(render(l.Get(types.Int(i))), `"`)})
		}
		return ev
	}
	return []Evidence{{Key: key, Text: render(v)}}
}

// evalFile evaluates a file check from the file collector's metadata
// (ADR 0006 §3).
func (e *evalEnv) evalFile(spec *FileSpec) outcome {
	switch {
	case e.files == nil:
		return errorOutcome("file metadata was not collected")
	case !e.files.ok():
		return errorOutcome("files: %v", e.files.err)
	}
	ff, ok := e.files.facts.Value.(*fileFacts)
	if !ok {
		return errorOutcome("files: unexpected facts %T", e.files.facts.Value)
	}
	type pathResult struct {
		status Status
		ev     Evidence
	}
	var results []pathResult
	var problems []string
	add := func(st Status, key, text string) {
		results = append(results, pathResult{st, Evidence{Key: key, Text: text, Source: key}})
	}
	for _, pattern := range spec.Paths {
		paths := []string{pattern}
		if isGlob(pattern) {
			g, ok := ff.Globs[pattern]
			if !ok {
				problems = append(problems, pattern+": not collected")
				continue
			}
			problems = append(problems, g.Problems...)
			if len(g.Matches) == 0 {
				if len(g.Problems) == 0 {
					add(outcomeStatus(spec.NoMatch), pattern, pattern+": no matching files")
				}
				continue
			}
			paths = g.Matches
		}
		for _, p := range paths {
			obs, ok := ff.Files[p]
			switch {
			case !ok:
				problems = append(problems, p+": not collected")
			case obs.Err != "":
				problems = append(problems, obs.Err)
			case obs.DanglingTarget != "":
				// Not missing: the file appears as soon as the target is
				// created, so this can fail but never pass.
				text := fmt.Sprintf("%s: symbolic link to %s, which does not exist", p, obs.DanglingTarget)
				if outcomeStatus(spec.Missing) == StatusFail {
					add(StatusFail, p, text)
				} else {
					problems = append(problems, text)
				}
			case obs.Missing:
				add(outcomeStatus(spec.Missing), p, p+": does not exist")
			default:
				st, text, err := checkFile(spec, obs.Info, ff.IDs)
				if err != nil {
					problems = append(problems, err.Error())
					continue
				}
				add(st, p, text)
			}
		}
	}
	o := outcome{status: StatusNotApplicable}
	for _, r := range results {
		if r.status.precedence() > o.status.precedence() {
			o.status = r.status
		}
	}
	for _, r := range results {
		if r.status == o.status || o.status == StatusPass {
			o.evidence = append(o.evidence, r.ev)
		}
	}
	switch {
	case o.status == StatusFail:
		return o // what was seen fails, whatever could not be seen
	case len(problems) > 0:
		return errorOutcome("%s", summarize(problems))
	case o.status == StatusNotApplicable:
		o.reason = "no matching files exist"
	case o.status == StatusError:
		o.reason = "a required file does not exist"
	}
	return o
}

func outcomeStatus(s string) Status {
	switch s {
	case "pass":
		return StatusPass
	case "fail":
		return StatusFail
	case "not_applicable":
		return StatusNotApplicable
	}
	return StatusError
}

// checkFile compares one file's owner, group and mode with the spec.
func checkFile(spec *FileSpec, fi hostfs.FileInfo, ids *idMap) (Status, string, error) {
	var bad []string
	if len(spec.Owner) > 0 {
		ok, err := ids.matches(spec.Owner, fi.UID, false)
		if err != nil {
			return "", "", err
		}
		if !ok {
			bad = append(bad, fmt.Sprintf("owner %s is not %s", ids.userName(fi.UID), strings.Join(spec.Owner, " or ")))
		}
	}
	if len(spec.Group) > 0 {
		ok, err := ids.matches(spec.Group, fi.GID, true)
		if err != nil {
			return "", "", err
		}
		if !ok {
			bad = append(bad, fmt.Sprintf("group %s is not %s", ids.groupName(fi.GID), strings.Join(spec.Group, " or ")))
		}
	}
	if spec.Mode != "" {
		maxMode, _ := strconv.ParseUint(spec.Mode, 8, 32)
		if perm := fi.Perm(); perm&^uint32(maxMode) != 0 {
			bad = append(bad, fmt.Sprintf("mode %04o exceeds %04o", perm, maxMode))
		}
	}
	desc := fmt.Sprintf("%s: %s:%s %04o", fi.Path, ids.userName(fi.UID), ids.groupName(fi.GID), fi.Perm())
	if len(bad) > 0 {
		return StatusFail, desc + " — " + strings.Join(bad, ", "), nil
	}
	return StatusPass, desc, nil
}

// limitEvidence sorts evidence by key and bounds its size.
func limitEvidence(ev []Evidence) ([]Evidence, int) {
	sort.SliceStable(ev, func(i, j int) bool { return ev[i].Key < ev[j].Key })
	omitted := 0
	if len(ev) > maxEvidence {
		omitted = len(ev) - maxEvidence
		ev = ev[:maxEvidence]
	}
	for i := range ev {
		ev[i].Text = truncate(ev[i].Text, maxEvidenceText)
	}
	if ev == nil {
		ev = []Evidence{}
	}
	return ev, omitted
}

// summarize joins the distinct items, showing at most maxReasonItems.
func summarize(items []string) string {
	seen := map[string]bool{}
	var distinct []string
	for _, s := range items {
		if !seen[s] {
			seen[s] = true
			distinct = append(distinct, s)
		}
	}
	return strings.Join(boundList(distinct, maxReasonItems), "; ")
}

// boundList keeps the first n items and says how many were left out.
func boundList(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	return append(items[:n:n], fmt.Sprintf("and %d more", len(items)-n))
}

// truncate shortens s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
