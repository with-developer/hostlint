// Package config reads vmsctl.yaml: the profile to scan with, stricter
// check parameters, and waivers (ADR 0006 §4, §6). It is vmsctl's own
// configuration on the machine that runs it, not a file of the scanned host,
// so it is read directly rather than through internal/hostfs.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/hostfs"
)

// File is the content of vmsctl.yaml.
type File struct {
	// Profile is the profile to scan with when --profile is not given.
	Profile string `yaml:"profile"`
	// Params override check parameters: check ID → parameter → value. An
	// override may only make a check stricter than the profile.
	Params map[string]map[string]any `yaml:"params"`
	// Waivers accept results for a reason, until they expire.
	Waivers []Waiver `yaml:"waivers"`
	// Attestations are human verdicts for MANUAL checks.
	Attestations []Attestation `yaml:"attestations"`
}

// Attestation is a human verdict (PASS or FAIL) for a MANUAL check. It is
// bound to the check's logic digest and to the digest of the value the check
// shows, both read from a scan's JSON result (checks[].digest and
// checks[].evidenceDigest), and stops applying when either changes.
type Attestation struct {
	Check  string `yaml:"check"`
	Status string `yaml:"status"`
	// Digest is the check's logic digest.
	Digest string `yaml:"digest"`
	// EvidenceDigest is the digest of the full value the check shows; leave it
	// out for a check with nothing to show.
	EvidenceDigest string `yaml:"evidence_digest"`
	By             string `yaml:"by"`
	// At is the day the verdict was given, and Expires the last day it applies,
	// as YYYY-MM-DD.
	At      string `yaml:"at"`
	Expires string `yaml:"expires"`
	Reason  string `yaml:"reason"`
	// Hosts limits the attestation to hostnames matching these globs.
	Hosts []string `yaml:"hosts"`
}

// Waiver accepts the result of one check or one control.
type Waiver struct {
	Check   string `yaml:"check"`
	Control string `yaml:"control"`
	// Profile names the profile of a control waiver, when several are scanned and the ID is in more than one.
	Profile string `yaml:"profile"`
	// Revision is the profile revision a control waiver was written for.
	Revision int `yaml:"revision"`
	// Digest is the digest of the profile a waiver of a control of a policy pack's profile was written for.
	Digest string `yaml:"digest"`
	Reason string `yaml:"reason"`
	// Expires is the last day the waiver applies, as YYYY-MM-DD.
	Expires string `yaml:"expires"`
	// Errors also covers ERROR results.
	Errors bool `yaml:"errors"`
	// Hosts limits the waiver to hostnames matching these globs.
	Hosts []string `yaml:"hosts"`
}

// Locations are searched in order when no file is named. Each place lists the name of the file there and, after
// it, the name it had before the project was renamed (ADR 0017).
var Locations = [][]string{
	{"vmsctl.yaml", "hostlint.yaml"},
	{"/etc/vmsctl/vmsctl.yaml", "/etc/hostlint/hostlint.yaml"},
}

// LegacyName reports whether a configuration file has the name it had before the rename.
func LegacyName(name string) bool { return path.Base(name) == "hostlint.yaml" }

// Find returns the configuration file to use: explicit when given (it must
// exist), else the first place of Locations that has one, else "". A place that
// has both the new name and the old one uses the new one: the old file may be
// there for hosts that still run a release before v0.27.0, which read only that
// name.
func Find(explicit string) (string, error) {
	path, _, err := FindNotes(explicit)
	return path, err
}

// FindNotes is Find, and also the files it did not use because the new name of the same place won.
func FindNotes(explicit string) (path string, unused []string, err error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", nil, fmt.Errorf("--config: %w", err)
		}
		return explicit, nil, nil
	}
	for _, place := range Locations {
		var found []string
		for _, p := range place {
			switch _, err := os.Stat(p); {
			case err == nil:
				found = append(found, p)
			case !errors.Is(err, fs.ErrNotExist):
				return "", nil, err
			}
		}
		if len(found) > 0 {
			return found[0], found[1:], nil
		}
	}
	return "", nil, nil
}

// maxFile is the largest configuration file.
const maxFile = 1 << 20

// Load reads a configuration file strictly: unknown keys are errors. Waivers
// can hide findings, so the file must be one nobody else could have planted
// or changed: a regular file owned by root or by the user running vmsctl,
// not writable by group or others. The check is made on the open file.
func Load(name string) (*File, error) {
	// Opening a FIFO blocks until a writer appears, so look before opening.
	if pre, err := os.Stat(name); err == nil && !pre.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", name)
	}
	fd, err := os.Open(name) //nolint:gosec // G304: the --config path the user gave, or a fixed location
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	fi, err := fd.Stat()
	if err != nil {
		return nil, err
	}
	if err := trusted(name, fi); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(fd, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFile {
		return nil, fmt.Errorf("%s: larger than %d bytes", name, maxFile)
	}
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	// A second document would be waivers that nothing reads: refuse it.
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, fmt.Errorf("%s: only one YAML document is read; remove the second one", name)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &f, nil
}

// Validate checks the file against the built-in content and the profile
// being scanned, reporting every problem.
func (f *File) Validate(content *engine.Content, profileID string) error {
	return f.ValidateProfiles(content, []string{profileID})
}

// ValidateProfiles is Validate for a scan of several profiles at once.
func (f *File) ValidateProfiles(content *engine.Content, profileIDs []string) error {
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	// The file's profile matters only when it is the one scanned: --profile
	// overrides it.
	if f.Profile != "" && slices.Contains(profileIDs, f.Profile) && content.Profiles[f.Profile] == nil {
		add("profile %q does not exist", f.Profile)
	}
	for id, params := range f.Params {
		c := content.Checks[id]
		if c == nil {
			add("params: unknown check %q", id)
			continue
		}
		for name, v := range params {
			ps, ok := c.Params[name]
			switch {
			case !ok:
				add("params: %s has no parameter %q", id, name)
			case ps.Type != "int":
				add("params: %s.%s is not an integer parameter and cannot be overridden", id, name)
			default:
				if n, isInt := v.(int); !isInt {
					add("params: %s.%s must be an integer", id, name)
				} else if n < 1 {
					// Every integer parameter counts something (days, failures,
					// characters): zero or less would disable the check, not
					// tighten it.
					add("params: %s.%s must be 1 or more", id, name)
				}
			}
		}
	}
	for i, w := range f.Waivers {
		where := fmt.Sprintf("waivers[%d]", i)
		// The profile a control waiver is for: the one it names, else the scanned one that has the control
		// (when two have it, the waiver has to say which: it is checked against one and applied to one).
		var profile *engine.Profile
		holding := 0
		for _, id := range profileIDs {
			if pr := content.Profiles[id]; pr != nil && (w.Profile == "" || w.Profile == id) && hasControl(pr, w.Control) {
				if profile == nil {
					profile = pr
				}
				holding++
			}
		}
		switch {
		case (w.Check == "") == (w.Control == ""):
			add("%s: give exactly one of check and control", where)
		case w.Check != "" && content.Checks[w.Check] == nil:
			add("%s: unknown check %q", where, w.Check)
		case w.Control != "" && profile == nil:
			add("%s: the scanned profile(s) %s have no control %q", where, strings.Join(profileIDs, ", "), w.Control)
		case w.Control != "" && holding > 1:
			add("%s: more than one scanned profile has the control %q: say which one (profile: ...)", where, w.Control)
		case w.Control != "" && w.Revision < 1:
			add("%s: a control waiver needs the profile revision it was written for (revision: %d)", where, revisionOf(profile))
		case w.Check != "" && (w.Revision != 0 || w.Profile != "" || w.Digest != ""):
			add("%s: revision, profile and digest only apply to control waivers", where)
		case w.Control != "" && strings.HasPrefix(profile.ID, engine.PackPrefix) && w.Digest == "":
			add("%s: a waiver of a control of the pack's profile %s needs its digest (digest: %s, shown in the result and by vmsctl pack show)", where, profile.ID, content.ProfileDigest(profile))
		}
		if w.Control != "" && w.Errors {
			add("%s: errors applies to check waivers; a control with an ERROR check is not waived (waive its checks with errors: true)", where)
		}
		if strings.TrimSpace(w.Reason) == "" {
			add("%s: reason is required", where)
		}
		if _, err := time.Parse("2006-01-02", w.Expires); err != nil {
			add("%s: expires must be a date such as 2027-06-30", where)
		}
		for _, h := range w.Hosts {
			if _, err := path.Match(h, ""); err != nil {
				add("%s: host pattern %q: %v", where, h, err)
			}
		}
	}
	for i, a := range f.Attestations {
		where := fmt.Sprintf("attestations[%d]", i)
		// Whether the check is still MANUAL, and whether it shows a value, can
		// change with a release: that makes the attestation stale at scan
		// time, and the scan lists it, instead of refusing the whole file.
		if content.Checks[a.Check] == nil {
			add("%s: unknown check %q", where, a.Check)
		}
		if a.Status != "PASS" && a.Status != "FAIL" {
			add("%s: status must be PASS or FAIL", where)
		}
		if !digestRe.MatchString(a.Digest) {
			add("%s: digest is required (checks[].digest in a JSON result)", where)
		}
		if a.EvidenceDigest != "" && !digestRe.MatchString(a.EvidenceDigest) {
			add("%s: evidence_digest must look like sha256:<64 hex digits>", where)
		}
		if strings.TrimSpace(a.By) == "" {
			add("%s: by is required", where)
		}
		if strings.TrimSpace(a.Reason) == "" {
			add("%s: reason is required", where)
		}
		at, atErr := time.Parse("2006-01-02", a.At)
		expires, expErr := time.Parse("2006-01-02", a.Expires)
		switch {
		case atErr != nil:
			add("%s: at must be a date such as 2026-11-05", where)
		case expErr != nil:
			add("%s: expires must be a date such as 2027-06-30", where)
		case expires.Before(at):
			add("%s: expires is before at", where)
		}
		for _, h := range a.Hosts {
			if _, err := path.Match(h, ""); err != nil {
				add("%s: host pattern %q: %v", where, h, err)
			}
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}

var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// EngineAttestations returns the attestations as engine options. Call it
// after Validate.
func (f *File) EngineAttestations() []engine.Attestation {
	out := make([]engine.Attestation, 0, len(f.Attestations))
	for _, a := range f.Attestations {
		at, _ := time.Parse("2006-01-02", a.At)
		expires, _ := time.Parse("2006-01-02", a.Expires)
		out = append(out, engine.Attestation{
			Check: a.Check, Status: engine.Status(a.Status), Digest: a.Digest, EvidenceDigest: a.EvidenceDigest,
			By: a.By, At: at, Expires: expires, Note: a.Reason, Hosts: a.Hosts,
		})
	}
	return out
}

// Engine returns the parameter overrides and waivers as engine options.
// Call it after Validate.
func (f *File) Engine() (map[string]map[string]any, []engine.Waiver) {
	waivers := make([]engine.Waiver, 0, len(f.Waivers))
	for _, w := range f.Waivers {
		expires, _ := time.Parse("2006-01-02", w.Expires)
		waivers = append(waivers, engine.Waiver{
			Check: w.Check, Control: w.Control, Profile: w.Profile, Revision: w.Revision, Digest: w.Digest, Reason: w.Reason,
			Expires: expires, Errors: w.Errors, Hosts: w.Hosts,
		})
	}
	return f.Params, waivers
}

func hasControl(p *engine.Profile, id string) bool {
	for _, c := range p.Controls {
		if c.ID == id {
			return true
		}
	}
	return false
}

func revisionOf(p *engine.Profile) int {
	if p == nil {
		return 0
	}
	return p.Revision
}

// trusted reports whether a configuration file could only have been written
// by root or the current user.
func trusted(name string, fi os.FileInfo) error {
	switch {
	case !fi.Mode().IsRegular():
		return fmt.Errorf("%s: not a regular file", name)
	case fi.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%s: writable by group or others (mode %04o); vmsctl does not trust it", name, fi.Mode().Perm())
	}
	if uid, ok := hostfs.Owner(fi); ok && uid != 0 && int64(uid) != int64(os.Getuid()) {
		return fmt.Errorf("%s: owned by uid %d, neither root nor you; vmsctl does not trust it", name, uid)
	}
	return nil
}
