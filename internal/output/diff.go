package output

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
)

// DiffSide names one of the two results a diff compares.
type DiffSide struct {
	File     string `json:"file"`
	Host     string `json:"host"`
	Scanned  string `json:"scanned"`
	Tool     string `json:"tool"`
	Profiles string `json:"profiles"`
}

// CheckChange is a check whose status differs between the two results. An
// empty status means the check is not in that result.
type CheckChange struct {
	Ref   string        `json:"ref"`
	Title string        `json:"title"`
	Old   engine.Status `json:"old"`
	New   engine.Status `json:"new"`
}

// ControlChange is a control whose status differs, or that is in one result only.
type ControlChange struct {
	Profile  string          `json:"profile"`
	ID       string          `json:"id"`
	Title    string          `json:"title"`
	Severity engine.Severity `json:"severity"`
	Old      engine.Status   `json:"old"`
	New      engine.Status   `json:"new"`
	Checks   []CheckChange   `json:"checks"`
}

// Diff is what changed between two scans of a host.
type Diff struct {
	SchemaVersion int             `json:"schemaVersion"`
	Old           DiffSide        `json:"old"`
	New           DiffSide        `json:"new"`
	Notes         []string        `json:"notes"`
	Regressed     []ControlChange `json:"regressed"`
	Fixed         []ControlChange `json:"fixed"`
	Changed       []ControlChange `json:"changed"`
	Added         []ControlChange `json:"added"`
	Removed       []ControlChange `json:"removed"`
	Unchanged     int             `json:"unchanged"`
}

// bad is a status that says something is wrong or could not be decided.
func bad(s engine.Status) bool { return s == engine.StatusFail || s == engine.StatusError }

// DiffResults compares an older and a newer result. A control regressed when it is FAIL
// or ERROR now and was not before, or when a check of it went wrong while the control's
// status stayed the same; it is fixed when it was FAIL or ERROR and is not any more. A
// waiver added or removed, and every other change of status, is a change. Controls found in one result only are added or removed
// (a profile revision adds and removes controls).
func DiffResults(oldName string, older *engine.Result, newName string, newer *engine.Result) *Diff {
	d := &Diff{
		SchemaVersion: 1,
		Old:           diffSide(oldName, older),
		New:           diffSide(newName, newer),
		Notes:         []string{},
		// Never nil: the JSON has [] for a list without entries, and readers can count it.
		Regressed: []ControlChange{}, Fixed: []ControlChange{}, Changed: []ControlChange{}, Added: []ControlChange{}, Removed: []ControlChange{},
	}
	if older.Host.Hostname != newer.Host.Hostname {
		d.Notes = append(d.Notes, fmt.Sprintf("the results are of different hosts (%s and %s)", oneLine(older.Host.Hostname), oneLine(newer.Host.Hostname)))
	}
	if older.Host.HostID != "" && newer.Host.HostID != "" && older.Host.HostID != newer.Host.HostID && older.Host.Hostname == newer.Host.Hostname {
		d.Notes = append(d.Notes, "the results have the same host name but different host IDs: they may be different machines")
	}
	if (older.Scan.Privileges.EUID == 0) != (newer.Scan.Privileges.EUID == 0) {
		d.Notes = append(d.Notes, "one scan ran as root and the other did not: controls that need protected files report ERROR or MANUAL without root")
	}
	if older.Scan.Target != newer.Scan.Target {
		d.Notes = append(d.Notes, "the scans have different targets (a running host and a mounted root, or two roots)")
	}
	if older.Scan.Tool.Version != newer.Scan.Tool.Version {
		d.Notes = append(d.Notes, fmt.Sprintf("hostlint versions differ (%s and %s): new or changed checks can move results", oneLine(older.Scan.Tool.Version), oneLine(newer.Scan.Tool.Version)))
	}
	if scanTime(newer).Before(scanTime(older)) {
		d.Notes = append(d.Notes, "the first file is newer than the second: the changes read backwards")
	}
	revisions := map[string]int{}
	for _, p := range older.Profiles {
		revisions[p.ID] = p.Revision
	}
	for _, p := range newer.Profiles {
		if rev, ok := revisions[p.ID]; ok && rev != p.Revision {
			d.Notes = append(d.Notes, fmt.Sprintf("profile %s changed from revision %d to %d: controls and checks may differ for that reason", oneLine(p.ID), rev, p.Revision))
		}
	}

	oldChecks, newChecks := map[string]engine.CheckResult{}, map[string]engine.CheckResult{}
	for _, c := range older.Checks {
		oldChecks[c.Ref] = c
	}
	for _, c := range newer.Checks {
		newChecks[c.Ref] = c
	}
	key := func(c engine.ControlResult) string { return c.Profile + "\x00" + c.ID }
	oldControls := map[string]engine.ControlResult{}
	for _, c := range older.Controls {
		oldControls[key(c)] = c
	}
	seen := map[string]bool{}
	for _, nc := range newer.Controls {
		seen[key(nc)] = true
		oc, existed := oldControls[key(nc)]
		change := ControlChange{Profile: nc.Profile, ID: nc.ID, Title: nc.Title, Severity: nc.Severity, New: nc.Status, Checks: []CheckChange{}}
		if !existed {
			d.Added = append(d.Added, change)
			continue
		}
		change.Old = oc.Status
		change.Checks = checkChanges(oc.Checks, nc.Checks, oldChecks, newChecks)
		switch {
		case oc.Status == nc.Status && len(change.Checks) == 0:
			d.Unchanged++
		case oc.Status == nc.Status:
			// The same status, but a check moved: a check that went wrong is a regression
			// even when the control was already failing.
			if slices.ContainsFunc(change.Checks, func(c CheckChange) bool { return bad(c.New) && !bad(c.Old) }) {
				d.Regressed = append(d.Regressed, change)
			} else {
				d.Changed = append(d.Changed, change)
			}
		case oc.Status == engine.StatusWaived || nc.Status == engine.StatusWaived:
			// A waiver added, removed or expired is not a change of the host.
			d.Changed = append(d.Changed, change)
		case bad(nc.Status) && !bad(oc.Status):
			d.Regressed = append(d.Regressed, change)
		case bad(oc.Status) && !bad(nc.Status):
			d.Fixed = append(d.Fixed, change)
		default:
			d.Changed = append(d.Changed, change)
		}
	}
	for _, oc := range older.Controls {
		if !seen[key(oc)] {
			d.Removed = append(d.Removed, ControlChange{Profile: oc.Profile, ID: oc.ID, Title: oc.Title, Severity: oc.Severity, Old: oc.Status, Checks: []CheckChange{}})
		}
	}
	for _, list := range [][]ControlChange{d.Regressed, d.Fixed, d.Changed, d.Added, d.Removed} {
		slices.SortStableFunc(list, func(a, b ControlChange) int {
			if a.Profile != b.Profile {
				return strings.Compare(a.Profile, b.Profile)
			}
			return naturalCompare(a.ID, b.ID)
		})
	}
	return d
}

// checkChanges lists the checks of a control whose status differs between the two results.
func checkChanges(oldRefs, newRefs []string, oldChecks, newChecks map[string]engine.CheckResult) []CheckChange {
	out := []CheckChange{}
	refs := slices.Clone(newRefs)
	for _, r := range oldRefs {
		if !slices.Contains(refs, r) {
			refs = append(refs, r)
		}
	}
	for _, ref := range refs {
		oc, inOld := oldChecks[ref]
		nc, inNew := newChecks[ref]
		if inOld && inNew && oc.Status == nc.Status {
			continue
		}
		ch := CheckChange{Ref: ref, Title: nc.Title}
		if !inNew {
			ch.Title = oc.Title
		}
		if inOld {
			ch.Old = oc.Status
		}
		if inNew {
			ch.New = nc.Status
		}
		out = append(out, ch)
	}
	return out
}

func diffSide(name string, r *engine.Result) DiffSide {
	profiles := make([]string, 0, len(r.Profiles))
	for _, p := range r.Profiles {
		profiles = append(profiles, fmt.Sprintf("%s r%d", p.ID, p.Revision))
	}
	return DiffSide{File: name, Host: r.Host.Hostname, Scanned: r.Scan.StartedAt, Tool: r.Scan.Tool.Version, Profiles: strings.Join(profiles, ", ")}
}

// WriteDiff renders d in format ("table" or "json").
func WriteDiff(w io.Writer, d *Diff, format string, opts Options) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(d)
	case "table":
		return writeDiffTable(w, d, opts)
	}
	return fmt.Errorf("unknown diff format %q (use table or json)", format)
}

func writeDiffTable(w io.Writer, d *Diff, opts Options) error {
	p := painter{on: opts.Color}
	var b strings.Builder
	host := oneLine(d.New.Host)
	if host == "" {
		host = "(no host name)"
	}
	fmt.Fprintf(&b, "%s %s\n", p.paint(bold, "hostlint diff"), host)
	fmt.Fprintf(&b, "%s\n", p.paint(dim, fmt.Sprintf("%s (%s, %s)", oneLine(d.Old.File), oneLine(d.Old.Scanned), oneLine(d.Old.Profiles))))
	fmt.Fprintf(&b, "%s\n", p.paint(dim, fmt.Sprintf("→ %s (%s, %s)", oneLine(d.New.File), oneLine(d.New.Scanned), oneLine(d.New.Profiles))))
	for _, n := range d.Notes {
		fmt.Fprintf(&b, "%s\n", p.paint(yellow, oneLine(n)))
	}
	b.WriteString("\n")

	profiles := map[string]bool{}
	for _, list := range [][]ControlChange{d.Regressed, d.Fixed, d.Changed, d.Added, d.Removed} {
		for _, c := range list {
			profiles[c.Profile] = true
		}
	}
	name := func(c ControlChange) string {
		if len(profiles) > 1 {
			return oneLine(c.Profile) + " " + oneLine(c.ID)
		}
		return oneLine(c.ID)
	}
	section := func(title, color string, list []ControlChange, arrows bool) {
		if len(list) == 0 {
			return
		}
		fmt.Fprintf(&b, "%s\n", p.paint(color, fmt.Sprintf("%s (%d)", title, len(list))))
		for _, c := range list {
			fmt.Fprintf(&b, "  %-6s %s %s  %s\n", name(c), oneLine(c.Title), p.paint(dim, "["+string(c.Severity)+"]"), statusArrow(p, c.Old, c.New, arrows))
			for _, ch := range c.Checks {
				fmt.Fprintf(&b, "      %s %s  %s\n", oneLine(ch.Ref), p.paint(dim, "— "+oneLine(ch.Title)), statusArrow(p, ch.Old, ch.New, true))
			}
		}
		b.WriteString("\n")
	}
	section("Regressed", red, d.Regressed, true)
	section("Fixed", green, d.Fixed, true)
	section("Changed", yellow, d.Changed, true)
	section("Added controls", dim, d.Added, false)
	section("Removed controls", dim, d.Removed, false)

	fmt.Fprintf(&b, "%d regressed, %d fixed, %d changed, %d added, %d removed, %d unchanged\n",
		len(d.Regressed), len(d.Fixed), len(d.Changed), len(d.Added), len(d.Removed), d.Unchanged)
	_, err := io.WriteString(w, b.String())
	return err
}

// statusArrow renders "OLD → NEW", or just the status when only one side has it.
func statusArrow(p painter, oldS, newS engine.Status, both bool) string {
	paint := func(s engine.Status) string {
		if s == "" {
			return p.paint(dim, "(none)")
		}
		return p.paint(statusStyle[s].color, string(s))
	}
	if oldS == newS && oldS != "" {
		return paint(newS) + p.paint(dim, " (checks changed)")
	}
	if !both || oldS == "" {
		if newS != "" {
			return paint(newS)
		}
		return paint(oldS)
	}
	return paint(oldS) + " → " + paint(newS)
}

// WriteDiffFile renders d into the file at path, as WriteFile does for a result.
func WriteDiffFile(path string, d *Diff, format string, opts Options) error {
	return writeFile(path, func(w io.Writer) error { return WriteDiff(w, d, format, opts) })
}

// Regressions is how many controls got worse: those that regressed, and controls
// new in the later result that are FAIL or ERROR.
func (d *Diff) Regressions() int {
	n := len(d.Regressed)
	for _, c := range d.Added {
		if bad(c.New) {
			n++
		}
	}
	return n
}
