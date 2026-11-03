// Package config reads hostlint.yaml: the profile to scan with, stricter
// check parameters, and waivers (ADR 0006 §4, §6). It is hostlint's own
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
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// File is the content of hostlint.yaml.
type File struct {
	// Profile is the profile to scan with when --profile is not given.
	Profile string `yaml:"profile"`
	// Params override check parameters: check ID → parameter → value. An
	// override may only make a check stricter than the profile.
	Params map[string]map[string]any `yaml:"params"`
	// Waivers accept results for a reason, until they expire.
	Waivers []Waiver `yaml:"waivers"`
}

// Waiver accepts the result of one check or one control.
type Waiver struct {
	Check   string `yaml:"check"`
	Control string `yaml:"control"`
	// Revision is the profile revision a control waiver was written for.
	Revision int    `yaml:"revision"`
	Reason   string `yaml:"reason"`
	// Expires is the last day the waiver applies, as YYYY-MM-DD.
	Expires string `yaml:"expires"`
	// Errors also covers ERROR results.
	Errors bool `yaml:"errors"`
	// Hosts limits the waiver to hostnames matching these globs.
	Hosts []string `yaml:"hosts"`
}

// Locations are searched in order when no file is named.
var Locations = []string{"hostlint.yaml", "/etc/hostlint/hostlint.yaml"}

// Find returns the configuration file to use: explicit when given (it must
// exist), else the first of Locations that exists, else "".
func Find(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("--config: %w", err)
		}
		return explicit, nil
	}
	for _, p := range Locations {
		switch _, err := os.Stat(p); {
		case err == nil:
			return p, nil
		case !errors.Is(err, fs.ErrNotExist):
			return "", err
		}
	}
	return "", nil
}

// Load reads a configuration file strictly: unknown keys are errors. Waivers
// can hide findings, so the file must be one nobody else could have planted
// or changed: a regular file owned by root or by the user running hostlint,
// not writable by group or others. The check is made on the open file.
func Load(name string) (*File, error) {
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
	data, err := io.ReadAll(io.LimitReader(fd, 1<<20))
	if err != nil {
		return nil, err
	}
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &f, nil
}

// Validate checks the file against the built-in content and the profile
// being scanned, reporting every problem.
func (f *File) Validate(content *engine.Content, profileID string) error {
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	if f.Profile != "" && content.Profiles[f.Profile] == nil {
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
				if _, isInt := v.(int); !isInt {
					add("params: %s.%s must be an integer", id, name)
				}
			}
		}
	}
	profile := content.Profiles[profileID]
	for i, w := range f.Waivers {
		where := fmt.Sprintf("waivers[%d]", i)
		switch {
		case (w.Check == "") == (w.Control == ""):
			add("%s: give exactly one of check and control", where)
		case w.Check != "" && content.Checks[w.Check] == nil:
			add("%s: unknown check %q", where, w.Check)
		case w.Control != "" && (profile == nil || !hasControl(profile, w.Control)):
			add("%s: profile %s has no control %q", where, profileID, w.Control)
		case w.Control != "" && w.Revision < 1:
			add("%s: a control waiver needs the profile revision it was written for (revision: %d)", where, revisionOf(profile))
		case w.Check != "" && w.Revision != 0:
			add("%s: revision only applies to control waivers", where)
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
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}

// Engine returns the parameter overrides and waivers as engine options.
// Call it after Validate.
func (f *File) Engine() (map[string]map[string]any, []engine.Waiver) {
	waivers := make([]engine.Waiver, 0, len(f.Waivers))
	for _, w := range f.Waivers {
		expires, _ := time.Parse("2006-01-02", w.Expires)
		waivers = append(waivers, engine.Waiver{
			Check: w.Check, Control: w.Control, Revision: w.Revision, Reason: w.Reason,
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
		return fmt.Errorf("%s: writable by group or others (mode %04o); hostlint does not trust it", name, fi.Mode().Perm())
	}
	if uid, ok := hostfs.Owner(fi); ok && uid != 0 && int64(uid) != int64(os.Getuid()) {
		return fmt.Errorf("%s: owned by uid %d, neither root nor you; hostlint does not trust it", name, uid)
	}
	return nil
}
