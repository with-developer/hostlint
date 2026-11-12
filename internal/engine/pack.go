package engine

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/with-developer/vmsctl/internal/hostfs"
)

// PackPrefix starts the area of every check and the ID of every profile of a policy pack (ADR 0012).
// Built-in content never uses it, so a check reference tells a pack's check from a built-in one.
const PackPrefix = "x-"

// PackSource is the content of a policy pack: its checks (<area>/<name>.yaml) and its profiles
// (<id>.yaml), as for the built-in content.
type PackSource struct {
	Name            string
	Rules, Profiles fs.FS
}

// PackContent says what a pack added to the content.
type PackContent struct {
	Name     string
	Checks   []string // IDs
	Profiles []string // IDs
	// Notes are things the author should know that are not errors, such as a control whose severity
	// was raised to that of the checks it maps.
	Notes []string
}

// Extend adds the checks and profiles of a pack to the content (ADR 0012). The pack is validated as the
// built-in content is, and held to more: a check's area and a profile's ID start with PackPrefix and
// collide with nothing, a profile does not take the title of another one, a parameter it sets for a check
// is as strict as the check's default or stricter, and a control is at least as severe as the checks it
// maps, because `--fail-on` gates on the severity of the control.
func (c *Content) Extend(p PackSource) (*PackContent, error) {
	pc := &PackContent{Name: p.Name}
	var errs []error
	checks := map[string]*Check{}
	if p.Rules != nil {
		files, err := fs.Glob(p.Rules, "*/*.yaml")
		if err != nil {
			return nil, err
		}
		for _, name := range files {
			var ch Check
			if err := decodeFile(p.Rules, name, &ch); err != nil {
				errs = append(errs, err)
				continue
			}
			if err := validateCheck(name, &ch); err != nil {
				errs = append(errs, err)
				continue
			}
			area, _, _ := strings.Cut(ch.ID, ".")
			if err := plainText(&ch, nil); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
				continue
			}
			if err := limitFileSpec(&ch); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
				continue
			}
			switch {
			case !strings.HasPrefix(area, PackPrefix):
				errs = append(errs, fmt.Errorf("%s: the area of a pack's check starts with %q (x-%s.%s), so that it cannot be taken for a built-in one", name, PackPrefix, area, strings.TrimPrefix(ch.ID, area+"."))) //nolint:perfsprint // a sentence with the suggested name
				continue
			case c.Checks[ch.ID] != nil:
				errs = append(errs, fmt.Errorf("%s: check %s exists already", name, ch.ID))
				continue
			}
			checks[ch.ID] = &ch
		}
	}
	merged := make(map[string]*Check, len(c.Checks)+len(checks))
	for id, ch := range c.Checks {
		merged[id] = ch
	}
	for id, ch := range checks {
		merged[id] = ch
	}

	profiles := map[string]*Profile{}
	if p.Profiles != nil {
		files, err := fs.Glob(p.Profiles, "*.yaml")
		if err != nil {
			return nil, err
		}
		titles := map[string]bool{}
		for _, pr := range c.Profiles {
			titles[normalizeTitle(pr.Title)] = true
		}
		for _, name := range files {
			var pr Profile
			if err := decodeFile(p.Profiles, name, &pr); err != nil {
				errs = append(errs, err)
				continue
			}
			if err := validateProfile(name, &pr, merged); err != nil {
				errs = append(errs, err)
				continue
			}
			switch {
			case !strings.HasPrefix(pr.ID, PackPrefix):
				errs = append(errs, fmt.Errorf("%s: the ID of a pack's profile starts with %q (x-%s)", name, PackPrefix, pr.ID))
				continue
			case c.Profiles[pr.ID] != nil:
				errs = append(errs, fmt.Errorf("%s: profile %s exists already", name, pr.ID))
				continue
			case titles[normalizeTitle(pr.Title)]:
				errs = append(errs, fmt.Errorf("%s: the title %q is the title of another profile", name, pr.Title))
				continue
			}
			if err := plainText(nil, &pr); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
				continue
			}
			notes, err := holdProfile(name, &pr, merged)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			titles[normalizeTitle(pr.Title)] = true
			pc.Notes = append(pc.Notes, notes...)
			profiles[pr.ID] = &pr
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	for id, ch := range checks {
		c.Checks[id] = ch
		pc.Checks = append(pc.Checks, id)
	}
	for id, pr := range profiles {
		c.Profiles[id] = pr
		pc.Profiles = append(pc.Profiles, id)
	}
	slices.Sort(pc.Checks)
	slices.Sort(pc.Profiles)
	slices.Sort(pc.Notes)
	return pc, nil
}

// Limits on what a pack's file check may look at: a wide glob walks a lot of the host, and the kernel's
// interfaces are not files of the host.
const (
	maxPackFilePaths     = 10
	maxPackGlobWildcards = 2
)

// limitFileSpec holds the paths of a pack's file check to those limits (ADR 0012).
func limitFileSpec(c *Check) error {
	if c.File == nil {
		return nil
	}
	if len(c.File.Paths) > maxPackFilePaths {
		return fmt.Errorf("a file check of a pack lists at most %d paths", maxPackFilePaths)
	}
	for _, p := range c.File.Paths {
		wild := 0
		for _, el := range strings.Split(strings.Trim(p, "/"), "/") {
			if hostfs.HasMeta(el) {
				wild++
			}
		}
		if wild > maxPackGlobWildcards {
			return fmt.Errorf("path %q has more than %d wildcard elements", p, maxPackGlobWildcards)
		}
		for _, banned := range []string{"/proc", "/sys", "/dev"} {
			if p == banned || strings.HasPrefix(p, banned+"/") {
				return fmt.Errorf("path %q is under %s, which a pack's check does not list", p, banned)
			}
		}
	}
	return nil
}

// plainText refuses control characters in the text of a pack that reaches a terminal or a log: IDs and
// titles (one line, no control character at all), and guidance (line breaks and tabs are fine).
func plainText(c *Check, p *Profile) error {
	line := func(what, s string) error {
		if strings.ContainsFunc(s, isControl) {
			return fmt.Errorf("%s has a control character", what)
		}
		return nil
	}
	prose := func(what, s string) error {
		if strings.ContainsFunc(s, func(r rune) bool { return r != '\n' && r != '\t' && isControl(r) }) {
			return fmt.Errorf("%s has a control character", what)
		}
		return nil
	}
	var errs []error
	if c != nil {
		errs = append(errs, line("title", c.Title), line("title_ko", c.TitleKo), prose("failure", c.Failure), prose("remediation", c.Remediation),
			prose("description_ko", c.DescriptionKo), prose("rationale_ko", c.RationaleKo), prose("remediation_ko", c.RemediationKo))
		if c.Manual != nil {
			errs = append(errs, prose("manual.guidance", c.Manual.Guidance), prose("manual.guidance_ko", c.Manual.GuidanceKo))
		}
	}
	if p != nil {
		errs = append(errs, line("title", p.Title), line("title_ko", p.TitleKo))
		for _, ctl := range p.Controls {
			errs = append(errs, line("control id", ctl.ID), line("control "+ctl.ID+" title", ctl.Title), line("control "+ctl.ID+" title_ko", ctl.TitleKo), prose("control "+ctl.ID+" manual", ctl.Manual), prose("control "+ctl.ID+" manual_ko", ctl.ManualKo))
		}
	}
	return errors.Join(errs...)
}

func isControl(r rune) bool { return r < 0x20 || (r >= 0x7f && r < 0xa0) }

func normalizeTitle(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), " ")) }

// holdProfile applies what a pack's profile may not do to the checks it maps: weaken a parameter, or
// rate a control below its checks. It raises the severity of a control in place and says so.
func holdProfile(file string, pr *Profile, checks map[string]*Check) ([]string, error) {
	var notes []string
	var errs []error
	for i := range pr.Controls {
		ctl := &pr.Controls[i]
		for _, id := range sortedKeys(ctl.Params) {
			ch := checks[id]
			for _, name := range sortedKeys(ctl.Params[id]) {
				spec := ch.Params[name]
				if err := notWeaker(ch, name, spec, ctl.Params[id][name]); err != nil {
					errs = append(errs, fmt.Errorf("%s: %s: %w", file, ctl.ID, err))
				}
			}
		}
		top := ctl.Severity
		for _, id := range ctl.Checks {
			if ch := checks[id]; ch != nil && ch.Severity.Rank() > top.Rank() {
				top = ch.Severity
			}
		}
		if top != ctl.Severity {
			notes = append(notes, fmt.Sprintf("%s %s: severity raised from %s to %s, the severity of the checks it maps", pr.ID, ctl.ID, ctl.Severity, top))
			ctl.Severity = top
		}
	}
	return notes, errors.Join(errs...)
}

// notWeaker reports whether a profile's value for a parameter weakens the check: only the strict direction
// of an integer parameter may differ from the default, and a value of any other kind has to be the default
// (to accept a weaker setting, write a check of your own).
func notWeaker(ch *Check, name string, spec ParamSpec, v any) error {
	if spec.Type == "int" {
		n, ok1 := asInt64(v)
		def, ok2 := asInt64(spec.Default)
		if !ok1 || !ok2 {
			return fmt.Errorf("%s: parameter %s must be an integer", ch.ID, name)
		}
		if spec.Stricter == "lower" && n > def || spec.Stricter == "higher" && n < def {
			return fmt.Errorf("%s: %s %d is weaker than the check's own %d; write a check of your own to accept a weaker setting", ch.ID, name, n, def)
		}
		return nil
	}
	if fmt.Sprint(v) != fmt.Sprint(spec.Default) {
		return fmt.Errorf("%s: %s can only have its default %v (only integer parameters have a stricter direction)", ch.ID, name, spec.Default)
	}
	return nil
}

func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
}

// Uses lists the collectors (the variables of the facts) a check's expressions read, for a reviewer.
func (e *Engine) Uses(checkID string) []string {
	cc := e.compiled[checkID]
	if cc == nil {
		return nil
	}
	return slices.Clone(cc.vars)
}
