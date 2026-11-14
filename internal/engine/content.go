// Package engine loads checks and profiles, runs collectors, evaluates checks
// with CEL and aggregates them into control results (ADR 0003, ADR 0006).
package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/with-developer/vmsctl/internal/hostfs"
)

// Severity of a check or control.
type Severity string

// Severities, lowest first.
const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

func (s Severity) valid() bool {
	return s == SeverityLow || s == SeverityMedium || s == SeverityHigh
}

// Rank orders severities: low 1, medium 2, high 3, anything else 0.
func (s Severity) Rank() int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	}
	return 0
}

// Check is one check, loaded from rules/<area>/<name>.yaml.
type Check struct {
	ID          string   `yaml:"id"`
	Version     int      `yaml:"version"`
	Title       string   `yaml:"title"`
	TitleKo     string   `yaml:"title_ko"`
	Severity    Severity `yaml:"severity"`
	Description string   `yaml:"description"`
	Rationale   string   `yaml:"rationale"`
	Remediation string   `yaml:"remediation"`
	// The Korean text of the same three: optional, shown where the reader asked for Korean (explain --lang ko, the
	// dashboard, a report) and replaced by the English where a check has none. Prose, like the English: not in the digest.
	DescriptionKo string               `yaml:"description_ko"`
	RationaleKo   string               `yaml:"rationale_ko"`
	RemediationKo string               `yaml:"remediation_ko"`
	Platforms     []string             `yaml:"platforms"`
	Applies       string               `yaml:"applies"`
	Params        map[string]ParamSpec `yaml:"params"`

	// Exactly one kind is set.
	Setting    *SettingSpec    `yaml:"setting"`
	File       *FileSpec       `yaml:"file"`
	Violations *ViolationsSpec `yaml:"violations"`
	Expect     string          `yaml:"expect"`
	Manual     *ManualSpec     `yaml:"manual"`
	// Failure is a sentence an expect check shows first when it fails, for an
	// expression whose own evidence (the values of the paths it reads) does not
	// say what is wrong. It is prose, like the title, and not part of the digest.
	Failure string `yaml:"failure"`

	Tests []TestCase `yaml:"tests"`
}

// ParamSpec declares a tunable parameter.
type ParamSpec struct {
	Type        string `yaml:"type"` // "int" or "string"
	Default     any    `yaml:"default"`
	Stricter    string `yaml:"stricter"` // for int: "lower" or "higher"
	Description string `yaml:"description"`
}

// SettingSpec compares one Setting fact.
type SettingSpec struct {
	Fact    string     `yaml:"fact"`
	In      []string   `yaml:"in"`
	Range   *RangeSpec `yaml:"range"`
	Matches string     `yaml:"matches"`
	Absent  string     `yaml:"absent"` // fail | error | default
}

// RangeSpec is a closed integer range; both ends are required.
type RangeSpec struct {
	Min *Bound `yaml:"min"`
	Max *Bound `yaml:"max"`
}

// Bound is an integer literal or a reference to an int parameter.
type Bound struct {
	Value int64
	Param string
}

// UnmarshalYAML accepts an integer or "params.<name>".
func (b *Bound) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode && n.Tag == "!!int" {
		v, err := strconv.ParseInt(n.Value, 0, 64)
		b.Value = v
		return err
	}
	if name, ok := strings.CutPrefix(n.Value, "params."); ok && n.Kind == yaml.ScalarNode && name != "" {
		b.Param = name
		return nil
	}
	return fmt.Errorf("line %d: a bound must be an integer or params.<name>", n.Line)
}

// FileSpec checks ownership and permissions of files.
type FileSpec struct {
	Paths   []string `yaml:"paths"`
	Owner   []string `yaml:"owner"`
	Group   []string `yaml:"group"`
	Mode    string   `yaml:"mode"`     // maximum mode, octal string
	Missing string   `yaml:"missing"`  // pass | fail | not_applicable | error
	NoMatch string   `yaml:"no_match"` // same values; required when a path has a glob
}

// ViolationsSpec lists the elements of a population that match a condition.
type ViolationsSpec struct {
	Over       string `yaml:"over"`
	As         string `yaml:"as"`
	Where      string `yaml:"where"`
	Key        string `yaml:"key"`
	Text       string `yaml:"text"`
	AllowEmpty bool   `yaml:"allow_empty"`
}

// ManualSpec is a check that needs a human.
type ManualSpec struct {
	Guidance   string `yaml:"guidance"`
	GuidanceKo string `yaml:"guidance_ko"`
	Show       string `yaml:"show"`
}

// TestCase is one rule test (ADR 0006 §9).
type TestCase struct {
	Name string `yaml:"name"`
	// Input marks what the case exercises: "" (normal), "absent",
	// "unavailable" or "incomplete".
	Input       string              `yaml:"input"`
	Facts       map[string]any      `yaml:"facts"`
	Files       map[string]TestFile `yaml:"files"`
	OS          string              `yaml:"os"` // family; default "debian"
	Incomplete  []string            `yaml:"incomplete"`
	Unavailable []string            `yaml:"unavailable"`
	Params      map[string]any      `yaml:"params"`
	Want        Status              `yaml:"want"`
}

// TestFile describes one file of a rule test's in-memory host.
type TestFile struct {
	Type   string `yaml:"type"` // file (default), dir, symlink
	Mode   string `yaml:"mode"`
	Owner  string `yaml:"owner"`
	Group  string `yaml:"group"`
	Target string `yaml:"target"`
	// Error "permission": reading it, or looking anything up through it,
	// fails (its own metadata stays visible, as on Linux).
	Error string `yaml:"error"`
}

// Profile maps one standard edition's controls to checks.
type Profile struct {
	ID       string `yaml:"id"`
	Revision int    `yaml:"revision"`
	Title    string `yaml:"title"`
	TitleKo  string `yaml:"title_ko"`
	// OS names the operating systems the profile is for, as ID-VERSION_ID of /etc/os-release (ubuntu-22.04). On any other host every
	// control is NOT_APPLICABLE, with the reason: a standard written for one distribution says nothing true about another. Empty: any.
	OS       []string  `yaml:"os"`
	Controls []Control `yaml:"controls"`
}

// Control is one control of a profile.
type Control struct {
	ID       string                    `yaml:"id"`
	Title    string                    `yaml:"title"`
	TitleKo  string                    `yaml:"title_ko"`
	Severity Severity                  `yaml:"severity"`
	Checks   []string                  `yaml:"checks"`
	Manual   string                    `yaml:"manual"`
	ManualKo string                    `yaml:"manual_ko"`
	Params   map[string]map[string]any `yaml:"params"` // check ID → param → value
}

// Content is the validated set of checks and profiles.
type Content struct {
	Checks   map[string]*Check
	Profiles map[string]*Profile
}

var (
	checkIDRe   = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*\.[a-z0-9]+(-[a-z0-9]+)*$`)
	profileIDRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	profileOSRe = regexp.MustCompile(`^[a-z0-9_.]+-[0-9][0-9.]*$`)
	paramRe     = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	identRe     = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)
	factPathRe  = regexp.MustCompile(`^[a-z_][a-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+(\["[^"\\]+"\])?$|^[a-z_][a-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*\["[^"\\]+"\]$`)
	modeRe      = regexp.MustCompile(`^0?[0-7]{3,4}$`)
	platforms   = map[string]bool{"debian": true, "rhel": true}
	outcomes    = map[string]bool{"pass": true, "fail": true, "not_applicable": true, "error": true}
	absents     = map[string]bool{"fail": true, "error": true, "default": true}
	testInputs  = map[string]bool{"": true, "absent": true, "unavailable": true, "incomplete": true}
)

// Load reads and validates checks from rules (<area>/<name>.yaml) and
// profiles (<id>.yaml). It reports every problem it finds, not just the first.
func Load(rules, profiles fs.FS) (*Content, error) {
	c := &Content{Checks: map[string]*Check{}, Profiles: map[string]*Profile{}}
	var errs []error

	checkFiles, err := fs.Glob(rules, "*/*.yaml")
	if err != nil {
		return nil, err
	}
	for _, name := range checkFiles {
		var ch Check
		if err := decodeFile(rules, name, &ch); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := validateCheck(name, &ch); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, dup := c.Checks[ch.ID]; dup {
			errs = append(errs, fmt.Errorf("%s: duplicate check id %s", name, ch.ID))
			continue
		}
		c.Checks[ch.ID] = &ch
	}

	profileFiles, err := fs.Glob(profiles, "*.yaml")
	if err != nil {
		return nil, err
	}
	for _, name := range profileFiles {
		var p Profile
		if err := decodeFile(profiles, name, &p); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := validateProfile(name, &p, c.Checks); err != nil {
			errs = append(errs, err)
			continue
		}
		c.Profiles[p.ID] = &p
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// decodeFile decodes exactly one YAML document, rejecting unknown fields.
func decodeFile(fsys fs.FS, name string, v any) error {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: more than one YAML document", name)
	}
	return nil
}

// problems collects validation errors for one file.
type problems struct {
	file string
	errs []string
}

func (p *problems) add(format string, args ...any) {
	p.errs = append(p.errs, fmt.Sprintf(format, args...))
}

func (p *problems) err() error {
	if len(p.errs) == 0 {
		return nil
	}
	return fmt.Errorf("%s: %s", p.file, strings.Join(p.errs, "; "))
}

func validateCheck(file string, c *Check) error {
	p := &problems{file: file}
	wantID := strings.TrimSuffix(strings.ReplaceAll(file, "/", "."), ".yaml")
	switch {
	case !checkIDRe.MatchString(c.ID):
		p.add("id %q must be <area>.<name> in lowercase kebab case", c.ID)
	case c.ID != wantID:
		p.add("id %q must match its path (%s)", c.ID, wantID)
	}
	if c.Version < 1 {
		p.add("version must be 1 or more")
	}
	if strings.TrimSpace(c.Title) == "" {
		p.add("title is required")
	}
	if !c.Severity.valid() {
		p.add("severity must be low, medium or high")
	}
	for _, pl := range c.Platforms {
		if !platforms[pl] {
			p.add("unknown platform %q (use debian or rhel)", pl)
		}
	}
	kinds := 0
	for _, set := range []bool{c.Setting != nil, c.File != nil, c.Violations != nil, c.Expect != "", c.Manual != nil} {
		if set {
			kinds++
		}
	}
	if kinds != 1 {
		p.add("exactly one of setting, file, violations, expect or manual is required")
	}
	for name, ps := range c.Params {
		validateParam(p, name, ps)
	}
	if c.Failure != "" && (c.Expect == "" || strings.TrimSpace(c.Failure) == "" || len(c.Failure) > 300) {
		p.add("failure is a sentence of at most 300 characters, and only for an expect check")
	}
	switch {
	case c.Setting != nil:
		validateSetting(p, c)
	case c.File != nil:
		validateFile(p, c.File)
	case c.Violations != nil:
		v := c.Violations
		if !factPathRe.MatchString(v.Over) {
			p.add("violations.over must be a fact path")
		}
		if !identRe.MatchString(v.As) || v.As == "params" {
			p.add("violations.as must be an identifier other than params")
		}
		if v.Where == "" || v.Key == "" || v.Text == "" {
			p.add("violations needs where, key and text")
		}
	case c.Manual != nil:
		if strings.TrimSpace(c.Manual.Guidance) == "" {
			p.add("manual.guidance is required")
		}
	}
	validateTests(p, c)
	return p.err()
}

func validateParam(p *problems, name string, ps ParamSpec) {
	if !paramRe.MatchString(name) {
		p.add("parameter name %q must be lowercase snake case", name)
	}
	switch ps.Type {
	case "int":
		if _, ok := ps.Default.(int); !ok {
			p.add("parameter %s: default must be an integer", name)
		}
		if ps.Stricter != "lower" && ps.Stricter != "higher" {
			p.add("parameter %s: stricter must be lower or higher", name)
		}
	case "string":
		if _, ok := ps.Default.(string); !ok {
			p.add("parameter %s: default must be a string", name)
		}
		if ps.Stricter != "" {
			p.add("parameter %s: stricter applies to int parameters only", name)
		}
	default:
		p.add("parameter %s: type must be int or string", name)
	}
}

func validateSetting(p *problems, c *Check) {
	s := c.Setting
	if !factPathRe.MatchString(s.Fact) {
		p.add("setting.fact must be a fact path")
	}
	comparisons := 0
	if len(s.In) > 0 {
		comparisons++
	}
	if s.Range != nil {
		comparisons++
		if s.Range.Min == nil || s.Range.Max == nil {
			p.add("setting.range needs both min and max")
		}
		for _, b := range []*Bound{s.Range.Min, s.Range.Max} {
			if b != nil && b.Param != "" {
				if ps, ok := c.Params[b.Param]; !ok || ps.Type != "int" {
					p.add("setting.range refers to params.%s, which is not an int parameter", b.Param)
				}
			}
		}
	}
	if s.Matches != "" {
		comparisons++
		if _, err := regexp.Compile(s.Matches); err != nil {
			p.add("setting.matches: %v", err)
		}
	}
	if comparisons != 1 {
		p.add("setting needs exactly one of in, range or matches")
	}
	if !absents[s.Absent] {
		p.add("setting.absent must be fail, error or default")
	}
}

func validateFile(p *problems, f *FileSpec) {
	if len(f.Paths) == 0 {
		p.add("file.paths is required")
	}
	glob := false
	for _, fp := range f.Paths {
		// The same validation as hostfs.Glob, which reads the pattern.
		if err := hostfs.CheckPattern(fp); err != nil {
			p.add("file path %q must be absolute, clean and a valid pattern: %v", fp, err)
		}
		glob = glob || isGlob(fp)
	}
	if f.Mode != "" && !modeRe.MatchString(f.Mode) {
		p.add("file.mode %q must be an octal string such as \"0644\"", f.Mode)
	}
	if f.Mode == "" && len(f.Owner) == 0 && len(f.Group) == 0 {
		p.add("file needs at least one of owner, group or mode")
	}
	if !outcomes[f.Missing] {
		p.add("file.missing must be pass, fail, not_applicable or error")
	}
	if glob && !outcomes[f.NoMatch] {
		p.add("file.no_match must be pass, fail, not_applicable or error when a path is a glob")
	}
	if !glob && f.NoMatch != "" {
		p.add("file.no_match only applies to globs")
	}
}

func validateTests(p *problems, c *Check) {
	var pass, fail, guarded bool
	for i, tc := range c.Tests {
		if tc.Name == "" {
			p.add("test %d needs a name", i+1)
		}
		if !testInputs[tc.Input] {
			p.add("test %q: input must be absent, unavailable or incomplete", tc.Name)
		}
		if !tc.Want.valid() {
			p.add("test %q: want must be a status", tc.Name)
		}
		switch {
		case tc.Want == StatusPass:
			pass = true
			if tc.Input != "" {
				p.add("test %q: a test with %s input must not expect PASS", tc.Name, tc.Input)
			}
		case tc.Want == StatusFail && tc.Input == "":
			fail = true
		}
		if tc.Input != "" {
			guarded = true
		}
		// The input label must describe the case, or the gate below proves
		// nothing.
		fileError := false
		for _, f := range tc.Files {
			fileError = fileError || (c.File != nil && f.Error != "")
		}
		switch {
		case tc.Input == "unavailable" && len(tc.Unavailable) == 0 && !fileError:
			p.add("test %q: input unavailable needs an unavailable collector or, in a file check, a file with an error", tc.Name)
		case tc.Input == "incomplete" && len(tc.Incomplete) == 0 && !fileError:
			p.add("test %q: input incomplete needs an incomplete collector or, in a file check, a file with an error", tc.Name)
		case tc.Input == "" && len(tc.Unavailable)+len(tc.Incomplete) > 0:
			p.add("test %q: a case with unavailable or incomplete collectors needs input unavailable or incomplete", tc.Name)
		}
	}
	if c.Manual != nil {
		return
	}
	if !pass || !fail || !guarded {
		p.add("tests need at least one PASS case, one FAIL case and one absent, unavailable or incomplete case (ADR 0006)")
	}
}

func validateProfile(file string, pr *Profile, checks map[string]*Check) error {
	p := &problems{file: file}
	if !profileIDRe.MatchString(pr.ID) || pr.ID+".yaml" != path.Base(file) {
		p.add("id %q must be lowercase kebab case and match the file name", pr.ID)
	}
	if pr.Revision < 1 {
		p.add("revision must be 1 or more")
	}
	if strings.TrimSpace(pr.Title) == "" {
		p.add("title is required")
	}
	for _, os := range pr.OS {
		if !profileOSRe.MatchString(os) {
			p.add("os %q must be ID-VERSION_ID such as ubuntu-22.04", os)
		}
	}
	seen := map[string]bool{}
	for _, ctl := range pr.Controls {
		if ctl.ID == "" || seen[ctl.ID] {
			p.add("control id %q is empty or duplicated", ctl.ID)
		}
		seen[ctl.ID] = true
		if strings.TrimSpace(ctl.Title) == "" {
			p.add("%s: title is required", ctl.ID)
		}
		if !ctl.Severity.valid() {
			p.add("%s: severity must be low, medium or high", ctl.ID)
		}
		if (len(ctl.Checks) == 0) == (ctl.Manual == "") {
			p.add("%s: exactly one of checks or manual is required", ctl.ID)
		}
		listed := map[string]bool{}
		for _, id := range ctl.Checks {
			if checks[id] == nil {
				p.add("%s: unknown check %s", ctl.ID, id)
			}
			listed[id] = true
		}
		for id, params := range ctl.Params {
			ch := checks[id]
			if !listed[id] || ch == nil {
				p.add("%s: params for %s, which the control does not list", ctl.ID, id)
				continue
			}
			for name, v := range params {
				if err := checkParamValue(ch, name, v); err != nil {
					p.add("%s: %v", ctl.ID, err)
				}
			}
		}
	}
	return p.err()
}

// checkParamValue verifies v suits the declared parameter.
func checkParamValue(c *Check, name string, v any) error {
	ps, ok := c.Params[name]
	if !ok {
		return fmt.Errorf("%s has no parameter %s", c.ID, name)
	}
	switch ps.Type {
	case "int":
		if _, ok := v.(int); !ok {
			return fmt.Errorf("%s: parameter %s must be an integer", c.ID, name)
		}
	case "string":
		if _, ok := v.(string); !ok {
			return fmt.Errorf("%s: parameter %s must be a string", c.ID, name)
		}
	}
	return nil
}

// sortedKeys returns the keys of m in order.
func sortedKeys[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }
