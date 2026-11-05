package engine

import (
	"cmp"
	"context"
	"fmt"
	"regexp"
	"slices"
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
	omitted  int // evidence items not built
	coverage *Coverage
	// evidenceDigest is the digest of the full value a MANUAL check shows.
	evidenceDigest string
	// showErr is a runtime error in a manual check's show expression; the
	// reason mentions it, and rule tests treat it as a failure.
	showErr string
}

func errorOutcome(format string, args ...any) outcome {
	return outcome{status: StatusError, reason: fmt.Sprintf(format, args...)}
}

// bindings are the variables of one check evaluation (ADR 0006 §5 step 2).
// strict binds complete facts only: failed, unavailable and incomplete
// collectors, and the fields a collector could not determine, are CEL
// unknowns. partial also binds the facts of incomplete collectors.
type bindings struct {
	strict, partial               cel.PartialActivation
	strictUnknown, partialUnknown []*cel.AttributePatternType
	failed, incomplete            []string // collectors
	unknownFields, partialFields  []string // collector.field
}

func (e *evalEnv) bind(cc *compiledCheck, params map[string]any) (*bindings, error) {
	b := &bindings{}
	strictVars, partialVars := map[string]any{}, map[string]any{}
	for name, v := range params {
		strictVars["params."+name] = v
		partialVars["params."+name] = v
	}
	for _, name := range cc.vars {
		c := e.collected[name]
		if c == nil || !c.ok() {
			b.failed = append(b.failed, name)
			b.strictUnknown = append(b.strictUnknown, cel.AttributePattern(name))
			b.partialUnknown = append(b.partialUnknown, cel.AttributePattern(name))
			continue
		}
		partialVars[name] = c.facts.Value
		if c.facts.Complete {
			strictVars[name] = c.facts.Value
		} else {
			b.incomplete = append(b.incomplete, name)
			b.strictUnknown = append(b.strictUnknown, cel.AttributePattern(name))
		}
		for _, field := range c.facts.Unknown {
			pat := fieldPattern(name, field)
			b.strictUnknown = append(b.strictUnknown, pat)
			b.partialUnknown = append(b.partialUnknown, pat)
			b.unknownFields = append(b.unknownFields, name+"."+field)
		}
		for _, field := range c.facts.Partial {
			// Unknown to the strict activation only: the partial pass of a
			// violations check sees what the field holds.
			b.strictUnknown = append(b.strictUnknown, fieldPattern(name, field))
			b.partialFields = append(b.partialFields, name+"."+field)
		}
	}
	var err error
	if b.strict, err = cel.PartialVars(strictVars, b.strictUnknown...); err != nil {
		return nil, err
	}
	if b.partial, err = cel.PartialVars(partialVars, b.partialUnknown...); err != nil {
		return nil, err
	}
	return b, nil
}

// fieldPattern matches the dot-separated field of a collector variable.
func fieldPattern(name, field string) *cel.AttributePatternType {
	pat := cel.AttributePattern(name)
	for q := range strings.SplitSeq(field, ".") {
		pat = pat.QualString(q)
	}
	return pat
}

// unknownReason explains an undetermined result v. It names the collectors
// v depends on when v says which; otherwise every unknown input.
func (e *evalEnv) unknownReason(b *bindings, v ref.Val) string {
	vars := unknownVars(v)
	parts := e.unknownParts(b, vars)
	if len(parts) == 0 && vars != nil {
		parts = e.unknownParts(b, nil)
	}
	return strings.Join(parts, "; ")
}

func (e *evalEnv) unknownParts(b *bindings, vars map[string]bool) []string {
	relevant := func(name string) bool { return vars == nil || vars[name] }
	var parts []string
	for _, name := range b.failed {
		switch c := e.collected[name]; {
		case !relevant(name):
		case c != nil && c.err != nil:
			parts = append(parts, fmt.Sprintf("%s: %v", name, c.err))
		default:
			parts = append(parts, name+": not collected")
		}
	}
	for _, name := range b.incomplete {
		if relevant(name) {
			parts = append(parts, fmt.Sprintf("%s: incomplete observation (%s)", name, summarize(e.collected[name].facts.Skipped)))
		}
	}
	for _, field := range b.unknownFields {
		name, _, _ := strings.Cut(field, ".")
		if relevant(name) {
			parts = append(parts, fmt.Sprintf("%s: not determined (%s)", field, summarize(e.collected[name].facts.Skipped)))
		}
	}
	for _, field := range b.partialFields {
		name, _, _ := strings.Cut(field, ".")
		if relevant(name) {
			parts = append(parts, fmt.Sprintf("%s: incomplete observation (%s)", field, summarize(e.collected[name].facts.Skipped)))
		}
	}
	return parts
}

// unknownVars returns the variables an unknown value depends on, or nil.
func unknownVars(v ref.Val) map[string]bool {
	u, ok := v.(*types.Unknown)
	if !ok {
		return nil
	}
	vars := map[string]bool{}
	for _, id := range u.IDs() {
		trails, _ := u.GetAttributeTrails(id)
		for _, t := range trails {
			vars[t.Variable()] = true
		}
	}
	if len(vars) == 0 {
		return nil
	}
	return vars
}

// eval evaluates p and reports its cost.
func (e *evalEnv) eval(p *program, act cel.Activation) (ref.Val, uint64, error) {
	v, det, err := p.prg.ContextEval(e.ctx, act)
	var cost uint64
	if c := det.ActualCost(); c != nil {
		cost = *c
	}
	return v, cost, err
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
	b, err := e.bind(cc, params)
	if err != nil {
		return errorOutcome("%v", err)
	}

	if cc.applies != nil {
		v, _, err := e.eval(cc.applies, b.strict)
		switch {
		case err != nil:
			return errorOutcome("applies: %v", err)
		case types.IsUnknown(v):
			return errorOutcome("cannot decide whether the check applies: %s", e.unknownReason(b, v))
		case v == types.False:
			return outcome{status: StatusNotApplicable, reason: "applies is false: " + cc.applies.source,
				evidence: e.pathEvidence(cc.appliesPaths, b.strict)}
		}
	}

	switch {
	case c.File != nil:
		return e.evalFile(c.File)
	case cc.setting != nil:
		return e.evalSetting(cc, params, b)
	case cc.expect != nil:
		v, _, err := e.eval(cc.expect, b.strict)
		switch {
		case err != nil:
			return errorOutcome("expect: %v", err)
		case types.IsUnknown(v):
			return errorOutcome("%s", e.unknownReason(b, v))
		}
		o := outcome{status: StatusFail, evidence: e.pathEvidence(cc.evidencePaths, b.strict)}
		if v == types.True {
			o.status = StatusPass
		} else if c.Failure != "" {
			o.evidence = append([]Evidence{{Key: "failure", Text: c.Failure}}, o.evidence...)
		}
		return o
	case cc.over != nil:
		return e.evalViolations(cc, b)
	case c.Manual != nil:
		o := outcome{status: StatusManual, reason: c.Manual.Guidance}
		if cc.show != nil {
			v, _, err := e.eval(cc.show, b.strict)
			switch {
			case err != nil:
				o.reason += " (evidence unavailable: " + err.Error() + ")"
				o.showErr = err.Error()
			case types.IsUnknown(v):
				o.reason += " (evidence unavailable: " + e.unknownReason(b, v) + ")"
			default:
				o.evidence, o.omitted = listEvidence("show", v)
				o.evidenceDigest, _ = showDigest(v)
			}
		}
		return o
	}
	return errorOutcome("check has no kind")
}

func (e *evalEnv) evalSetting(cc *compiledCheck, params map[string]any, b *bindings) outcome {
	spec := cc.check.Setting
	var lo, hi int64
	if r := spec.Range; r != nil {
		var err error
		if lo, err = r.Min.resolve(params); err == nil {
			hi, err = r.Max.resolve(params)
		}
		if err != nil {
			return errorOutcome("setting.range: %v", err)
		}
	}
	v, _, err := e.eval(cc.setting, b.strict)
	switch {
	case err != nil:
		return errorOutcome("setting.fact: %v", err)
	case types.IsUnknown(v):
		// The unreadable part may hold the value that matters: never decide.
		return errorOutcome("%s", e.unknownReason(b, v))
	}
	opt, ok := v.(*types.Optional)
	if !ok {
		return errorOutcome("setting.fact: unexpected value %v", v)
	}
	key := spec.Fact
	want := describeWant(spec, lo, hi)
	if !opt.HasValue() {
		switch spec.Absent {
		case "fail":
			return outcome{status: StatusFail, evidence: []Evidence{{Key: key, Text: "not set; expected " + want}}}
		default:
			return errorOutcome("%s is not set and its default is not known", key)
		}
	}
	s, ok := asSetting(opt.GetValue())
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
	pass, err := compareSetting(spec, lo, hi, s.Value)
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

func compareSetting(spec *SettingSpec, lo, hi int64, value string) (bool, error) {
	if facts.IsInvalid(value) {
		// A value the program cannot read (login.defs "090") makes it fall
		// back to its default: it never satisfies a check, and it is not an
		// evaluation error. The checks that read such settings want values
		// the default does not meet; a check whose range includes the default
		// would need to compare it instead.
		return false, nil
	}
	switch {
	case len(spec.In) > 0:
		return slices.Contains(spec.In, value), nil
	case spec.Range != nil:
		n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return false, fmt.Errorf("value %q is not an integer", value)
		}
		return n >= lo && n <= hi, nil
	default:
		re, err := regexp.Compile(`^(?:` + spec.Matches + `)$`)
		if err != nil {
			return false, err
		}
		return re.MatchString(value), nil
	}
}

// resolve returns the bound's value; a parameter must be an int.
func (b *Bound) resolve(params map[string]any) (int64, error) {
	if b.Param == "" {
		return b.Value, nil
	}
	v, ok := params[b.Param].(int64)
	if !ok {
		return 0, fmt.Errorf("params.%s is not an integer", b.Param)
	}
	return v, nil
}

func describeWant(spec *SettingSpec, lo, hi int64) string {
	switch {
	case len(spec.In) > 0:
		return "one of [" + strings.Join(spec.In, ", ") + "]"
	case spec.Range != nil:
		return fmt.Sprintf("%d–%d", lo, hi)
	}
	return "a value matching " + spec.Matches
}

// pathEvidence reports the values of fact paths an expression reads.
func (e *evalEnv) pathEvidence(paths []evidencePath, act cel.Activation) []Evidence {
	var ev []Evidence
	for _, p := range paths {
		v, _, err := e.eval(p.prog, act)
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
			if s, ok := v.Value().(string); ok && s == "" && strings.HasSuffix(p.path, ".why") {
				continue // a "why" says what is wrong, so there is nothing to show without one
			}
			item.Text, item.Source = describeValue(p.path, v)
		}
		ev = append(ev, item)
	}
	return ev
}

// describeValue renders one fact value as evidence text: settings with their
// state and source, maps as their keys, anything else as a literal.
func describeValue(path string, v ref.Val) (text, source string) {
	if s, ok := asSetting(v); ok {
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
		slices.Sort(keys)
		return path + " has " + strings.Join(boundList(keys, maxShownKeys), ", "), ""
	}
	return path + " = " + render(v), ""
}

func (e *evalEnv) evalViolations(cc *compiledCheck, b *bindings) outcome {
	spec := cc.check.Violations
	over, _, err := e.eval(cc.over, b.strict)
	if err != nil {
		return errorOutcome("violations.over: %v", err)
	}
	if !types.IsUnknown(over) {
		o := e.matchViolations(cc, b, over)
		if o.status == StatusPass && o.coverage.Count == 0 && !spec.AllowEmpty {
			return errorOutcome("%s is empty, so there was nothing to check", spec.Over)
		}
		return o
	}
	reason := e.unknownReason(b, over)
	for name := range unknownVars(over) {
		if slices.Contains(b.failed, name) {
			return errorOutcome("%s", reason)
		}
	}
	// Only incomplete facts: the elements that were seen can still fail the
	// check (ADR 0006 §5). matchViolations judges them with complete facts
	// only, so a guess about what was not seen never makes one fail.
	if over, _, err = e.eval(cc.over, b.partial); err != nil || types.IsUnknown(over) {
		return errorOutcome("%s", reason)
	}
	o := e.matchViolations(cc, b, over)
	if o.status != StatusFail {
		return errorOutcome("%s", reason)
	}
	return o
}

// elemActivation binds the violations element on top of the check's other
// variables, so they are bound once per check rather than once per element.
type elemActivation struct {
	base cel.Activation
	name string
	val  ref.Val
}

func (a *elemActivation) ResolveName(name string) (any, bool) {
	if name == a.name {
		return a.val, true
	}
	return a.base.ResolveName(name)
}

func (a *elemActivation) Parent() cel.Activation { return nil }

// matchViolations evaluates where for every element of the population, with
// complete facts only. Together, the evaluations may cost at most
// celCheckBudget.
func (e *evalEnv) matchViolations(cc *compiledCheck, b *bindings, over ref.Val) outcome {
	spec := cc.check.Violations
	list, ok := over.(traits.Lister)
	if !ok {
		return errorOutcome("violations.over is not a list")
	}
	n := int(list.Size().(types.Int))
	elem := &elemActivation{base: b.strict, name: spec.As}
	act, err := cel.PartialVars(elem, b.strictUnknown...)
	if err != nil {
		return errorOutcome("%v", err)
	}
	var spent uint64
	eval := func(p *program) (ref.Val, error) {
		v, cost, err := e.eval(p, act)
		spent += cost
		return v, err
	}
	o := outcome{status: StatusPass}
	var firstErr error
	var firstUnknown ref.Val
	checked := 0
	for ; checked < n && spent <= celCheckBudget; checked++ {
		elem.val = list.Get(types.Int(checked))
		v, err := eval(cc.where)
		switch {
		case err != nil:
			if firstErr == nil {
				firstErr = err
			}
			continue
		case types.IsUnknown(v):
			if firstUnknown == nil {
				firstUnknown = v
			}
			continue
		case v != types.True:
			continue
		}
		o.status = StatusFail
		if len(o.evidence) == maxEvidence {
			o.omitted++
			continue
		}
		o.evidence = append(o.evidence, violation(cc, checked, eval))
	}
	o.coverage = &Coverage{Population: spec.Over, Count: checked}
	switch {
	case o.status == StatusFail:
		return o // what matched fails, whatever else could not be decided
	case checked < n:
		return errorOutcome("stopped after %d of %d elements of %s: the evaluation cost limit was reached", checked, n, spec.Over)
	case firstErr != nil:
		return errorOutcome("violations.where: %v", firstErr)
	case firstUnknown != nil:
		return errorOutcome("%s", e.unknownReason(b, firstUnknown))
	}
	return o
}

// violation is the evidence of one matching element. A key or text that
// cannot be evaluated does not undo the match.
func violation(cc *compiledCheck, i int, eval func(*program) (ref.Val, error)) Evidence {
	ev := Evidence{Key: fmt.Sprintf("%s[%d]", cc.check.Violations.Over, i)}
	if k, err := eval(cc.key); err == nil && !types.IsUnknown(k) {
		ev.Key = fmt.Sprint(k.Value())
	}
	switch t, err := eval(cc.text); {
	case err != nil:
		ev.Text = "matched; its text could not be evaluated: " + err.Error()
	case types.IsUnknown(t):
		ev.Text = "matched; its text depends on facts that were not observed"
	default:
		ev.Text = fmt.Sprint(t.Value())
	}
	return ev
}

// asSetting returns v as a Setting: map entries hold Setting values, struct
// fields come back as pointers.
func asSetting(v ref.Val) (facts.Setting, bool) {
	switch x := v.Value().(type) {
	case facts.Setting:
		return x, true
	case *facts.Setting:
		if x != nil {
			return *x, true
		}
	}
	return facts.Setting{}, false
}

// render formats a CEL value for evidence; it shows at most maxShownKeys
// elements of a list.
func render(v ref.Val) string {
	if s, ok := asSetting(v); ok {
		return strconv.Quote(s.Value)
	}
	if x, ok := v.Value().(string); ok {
		return strconv.Quote(x)
	}
	if l, ok := v.(traits.Lister); ok {
		n := int(l.Size().(types.Int))
		parts := make([]string, 0, min(n, maxShownKeys))
		for i := range min(n, maxShownKeys) {
			parts = append(parts, render(l.Get(types.Int(i))))
		}
		if n > maxShownKeys {
			parts = append(parts, fmt.Sprintf("and %d more", n-maxShownKeys))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return fmt.Sprint(v.Value())
}

// listEvidence turns a show value into evidence items, one per list element
// up to maxEvidence; strings are shown as they are.
func listEvidence(key string, v ref.Val) ([]Evidence, int) {
	l, ok := v.(traits.Lister)
	if !ok {
		return []Evidence{{Key: key, Text: render(v)}}, 0
	}
	n := int(l.Size().(types.Int))
	ev := make([]Evidence, 0, min(n, maxEvidence))
	for i := range min(n, maxEvidence) {
		item := l.Get(types.Int(i))
		text, ok := item.Value().(string)
		if !ok {
			text = render(item)
		}
		ev = append(ev, Evidence{Key: fmt.Sprintf("%s[%d]", key, i), Text: text})
	}
	return ev, n - len(ev)
}

// evalFile evaluates a file check from the file collector's metadata
// (ADR 0006 §3). Only the check's own patterns matter: what the collector
// could not observe elsewhere does not affect it.
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
		po, ok := ff.Patterns[pattern]
		switch {
		case !ok:
			problems = append(problems, pattern+notObserved)
			continue
		case po.Err != "":
			problems = append(problems, po.Err)
			continue
		}
		problems = append(problems, po.Problems...)
		if isGlob(pattern) && len(po.Files) == 0 {
			if len(po.Problems) == 0 {
				add(outcomeStatus(spec.NoMatch), pattern, pattern+": no matching files")
			}
			continue
		}
		for _, obs := range po.Files {
			p := obs.Path
			switch {
			case obs.Err != "":
				problems = append(problems, obs.Err)
			case obs.DanglingLink != "":
				// Not missing: the file appears as soon as the target is
				// created, so this can fail but never pass.
				text := fmt.Sprintf("%s: symbolic link to %s, which does not exist", p, obs.DanglingTarget)
				if obs.DanglingLink != p {
					text = fmt.Sprintf("%s: %s is a symbolic link to %s, which does not exist", p, obs.DanglingLink, obs.DanglingTarget)
				}
				if outcomeStatus(spec.Missing) == StatusFail {
					add(StatusFail, p, text)
				} else {
					problems = append(problems, text)
				}
			case obs.Missing:
				add(outcomeStatus(spec.Missing), p, p+": does not exist")
			case obs.Masked:
				add(outcomeStatus(spec.Missing), p, p+": masked (a symbolic link to /dev/null)")
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

// limitEvidence sorts evidence by key (ADR 0006 §8) and bounds its size;
// omitted counts items left out before.
func limitEvidence(ev []Evidence, omitted int) ([]Evidence, int) {
	slices.SortStableFunc(ev, func(a, b Evidence) int { return compareKeys(a.Key, b.Key) })
	if len(ev) > maxEvidence {
		omitted += len(ev) - maxEvidence
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

// compareKeys orders evidence keys, comparing list indexes as numbers:
// show[2] comes before show[10].
func compareKeys(a, b string) int {
	pa, ia, oka := splitIndex(a)
	pb, ib, okb := splitIndex(b)
	if !oka || !okb || pa != pb {
		return strings.Compare(a, b)
	}
	return cmp.Or(cmp.Compare(len(ia), len(ib)), strings.Compare(ia, ib))
}

// splitIndex splits "name[12]" into "name" and "12".
func splitIndex(key string) (prefix, index string, ok bool) {
	i := strings.LastIndexByte(key, '[')
	if i < 0 || !strings.HasSuffix(key, "]") {
		return "", "", false
	}
	index = strings.TrimLeft(key[i+1:len(key)-1], "0")
	for _, r := range key[i+1 : len(key)-1] {
		if r < '0' || r > '9' {
			return "", "", false
		}
	}
	return key[:i], index, i+2 < len(key)
}

// summarize joins the distinct items, showing at most maxReasonItems.
func summarize(items []string) string {
	return strings.Join(boundList(distinct(items), maxReasonItems), "; ")
}

// distinct returns items without repeats, in their first order.
func distinct(items []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range items {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
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
