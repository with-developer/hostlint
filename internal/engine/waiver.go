package engine

import (
	"fmt"
	"maps"
	"path"
	"slices"
	"strings"
	"time"
)

// Waiver accepts the result of a check or of a control for a reason, until
// it expires (ADR 0006 §6). Waived checks are still evaluated: the result
// keeps its original status.
type Waiver struct {
	Check   string // a check ID; or
	Control string // a control ID of a scanned profile
	// Profile names the profile of a control waiver when several are scanned and the ID is in more than one.
	Profile string
	// Revision is the profile revision a control waiver was written for; it
	// goes stale when the profile changes.
	Revision int
	// Digest is the digest of the profile a waiver of a control of a pack's profile was written for: a
	// pack author can change a mapping without changing the revision, so the waiver is bound to the
	// content (Content.ProfileDigest, shown by `vmsctl pack show`).
	Digest string
	Reason string
	// Expires is the last day the waiver applies (a date, UTC).
	Expires time.Time
	// Errors makes the waiver cover ERROR too: a deliberate decision that
	// the check cannot run here.
	Errors bool
	// Hosts are hostname globs; empty means every host.
	Hosts []string
}

// WaiverNote is a waiver that did not apply, with why.
type WaiverNote struct {
	Scope   string `json:"scope"` // check or control
	ID      string `json:"id"`
	Reason  string `json:"reason"`
	Expires string `json:"expires"`
	Problem string `json:"problem"`
}

const dateLayout = "2006-01-02"

// hostMatches reports whether a list of hostname globs covers the host; an
// empty list covers every host.
func hostMatches(globs []string, hostname string) bool {
	if len(globs) == 0 {
		return true
	}
	return slices.ContainsFunc(globs, func(glob string) bool {
		ok, _ := path.Match(glob, hostname)
		return ok
	})
}

// appliesTo reports whether w is for this host.
func (w Waiver) appliesTo(hostname string) bool { return hostMatches(w.Hosts, hostname) }

func (w Waiver) expired(today time.Time) bool { return w.Expires.Before(today) }

func (w Waiver) of(scope string) *WaiverOf {
	return &WaiverOf{Reason: w.Reason, Expires: w.Expires.Format(dateLayout), Scope: scope, Errors: w.Errors}
}

func (w Waiver) note(problem string) WaiverNote {
	scope, id := "check", w.Check
	if w.Control != "" {
		scope, id = "control", w.Control
	}
	return WaiverNote{Scope: scope, ID: id, Reason: w.Reason, Expires: w.Expires.Format(dateLayout), Problem: problem}
}

// waivable reports whether a waiver may change status st.
func waivable(st Status, errors bool) bool {
	return st == StatusFail || st == StatusManual || (st == StatusError && errors)
}

// waiveChecks applies check waivers to the check results; it returns the
// waivers that did not apply.
func waiveChecks(waivers []Waiver, checks map[string]*CheckResult, hostname string, today time.Time) []WaiverNote {
	var notes []WaiverNote
	for _, w := range waivers {
		switch {
		case w.Check == "" || !w.appliesTo(hostname):
			continue
		case w.expired(today):
			notes = append(notes, w.note("expired"))
			continue
		}
		found, applied, blocked := false, false, ""
		for _, ref := range slices.Sorted(maps.Keys(checks)) {
			cr := checks[ref]
			if cr.ID != w.Check {
				continue
			}
			found = true
			if !waivable(cr.Status, w.Errors) {
				if cr.Status == StatusError {
					blocked = "not applied: the check is ERROR here; set errors: true to accept that it cannot run"
				}
				continue
			}
			cr.OriginalStatus, cr.Status = cr.Status, StatusWaived
			cr.Waiver = w.of("check")
			cr.Reason = "waived: " + w.Reason
			applied = true
		}
		switch {
		case !found:
			notes = append(notes, w.note("not applied: the check is not in the scanned profile"))
		case !applied && blocked != "":
			notes = append(notes, w.note(blocked))
		}
	}
	return notes
}

// waiveControl applies control waivers to one aggregated control. A control
// waiver does not apply while any of the control's checks is ERROR, and
// goes stale when the profile revision changes.
func waiveControl(waivers []Waiver, profile *Profile, digest string, cr *ControlResult, checks map[string]*CheckResult, hostname string, today time.Time) []WaiverNote {
	var notes []WaiverNote
	for _, w := range waivers {
		switch {
		case w.Control != cr.ID || (w.Profile != "" && w.Profile != profile.ID) || !w.appliesTo(hostname):
			continue
		case w.expired(today):
			notes = append(notes, w.note("expired"))
			continue
		case w.Revision != profile.Revision:
			notes = append(notes, w.note(fmt.Sprintf("stale: written for revision %d of %s, which is now at %d", w.Revision, profile.ID, profile.Revision)))
			continue
		case strings.HasPrefix(profile.ID, PackPrefix) && w.Digest == "":
			notes = append(notes, w.note("not applied: a waiver of a control of a pack's profile names the digest of the profile (digest: "+digest+")"))
			continue
		case w.Digest != "" && w.Digest != digest:
			notes = append(notes, w.note("stale: written for another content of "+profile.ID+" than the one scanned (its digest is now "+digest+")"))
			continue
		}
		erroring := slices.ContainsFunc(cr.Checks, func(ref string) bool { return checks[ref].Status == StatusError })
		if erroring {
			notes = append(notes, w.note("not applied: a check of the control is ERROR"))
			continue
		}
		if cr.Status == StatusFail || cr.Status == StatusManual {
			cr.Status, cr.Waiver = StatusWaived, w.of("control")
			cr.Reason = "waived: " + w.Reason
		}
	}
	return notes
}

// overrideParams applies a configuration's parameter overrides to the
// parameters a profile gives a check: each must be of the declared type and
// at least as strict as the profile's value (ADR 0006 §4).
func overrideParams(c *Check, params, overrides map[string]any) (map[string]any, error) {
	out := maps.Clone(params)
	for name, v := range overrides {
		ps, ok := c.Params[name]
		if !ok {
			return nil, fmt.Errorf("%s has no parameter %s", c.ID, name)
		}
		if ps.Type != "int" {
			return nil, fmt.Errorf("%s: parameter %s can only be set by the profile (only integer parameters have a stricter direction)", c.ID, name)
		}
		n, ok := v.(int)
		if !ok {
			return nil, fmt.Errorf("%s: parameter %s must be an integer", c.ID, name)
		}
		profileValue, _ := params[name].(int64)
		weaker := ps.Stricter == "lower" && int64(n) > profileValue || ps.Stricter == "higher" && int64(n) < profileValue
		if weaker {
			return nil, fmt.Errorf("%s: %s %d is weaker than the profile's %d; use a waiver to accept a weaker setting", c.ID, name, n, profileValue)
		}
		out[name] = int64(n)
	}
	return out, nil
}
