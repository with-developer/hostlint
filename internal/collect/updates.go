package collect

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// Updates are the `updates` facts: the configuration of the tools that install updates by themselves. Whether their units
// (timers, services) are enabled is in the `services` facts, and whether a package is installed in `packages`.
type Updates struct {
	// Apt is what apt's configuration says about periodic runs (unattended-upgrades).
	Apt AptPeriodic `json:"apt"`
	// Dnf is /etc/dnf/automatic.conf (dnf-automatic) and Yum is /etc/yum/yum-cron.conf (yum-cron).
	Dnf Automatic `json:"dnf_automatic"`
	Yum Automatic `json:"yum_cron"`
}

// AptPeriodic are the APT::Periodic settings of /etc/apt/apt.conf.d/* and /etc/apt/apt.conf, in the order apt reads them
// (the last one wins). A setting no file makes is absent from Settings: Enable is 1 and the others are 0 then. A value is
// the number of days, as text ("1", "7"); "0" is off.
type AptPeriodic struct {
	// Present is true when a file of the apt configuration directory or /etc/apt/apt.conf exists.
	Present bool `json:"present"`
	// Settings has "enable", "update_package_lists" and "unattended_upgrade" (APT::Periodic::Enable and so on).
	Settings map[string]facts.Setting `json:"settings"`
}

// Automatic is the configuration of dnf-automatic or yum-cron: the [commands] section.
type Automatic struct {
	Present bool `json:"present"`
	// Settings has "apply_updates", "yes" or "no" (yes, true, on and 1 are yes; the other spellings of no are no), and
	// "upgrade_type", what is installed: "security" or "default" (everything); for yum-cron it is update_cmd, which has the same usual values.
	Settings map[string]facts.Setting `json:"settings"`
}

type updatesCollector struct{}

func (updatesCollector) Name() string          { return "updates" }
func (updatesCollector) Version() int          { return 1 }
func (updatesCollector) Access() engine.Access { return engine.AccessFilesystem }
func (updatesCollector) Type() reflect.Type    { return reflect.TypeFor[Updates]() }

const (
	aptConfDir   = "/etc/apt/apt.conf.d"
	aptConfFile  = "/etc/apt/apt.conf"
	dnfAutomatic = "/etc/dnf/automatic.conf"
	yumCron      = "/etc/yum/yum-cron.conf"
)

// aptFileName is what apt reads in apt.conf.d: letters, digits, "-" and "_", with no extension or ".conf" (apt-config(5)).
var aptFileName = regexp.MustCompile(`^[A-Za-z0-9_-]+(\.conf)?$`)

func (updatesCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	u := &Updates{Apt: AptPeriodic{Settings: map[string]facts.Setting{}}, Dnf: Automatic{Settings: map[string]facts.Setting{}}, Yum: Automatic{Settings: map[string]facts.Setting{}}}
	var skipped []string

	// apt: the files in the order of their names, then apt.conf.
	var files []string
	entries, err := h.FS.ReadDir(aptConfDir)
	switch {
	case hostfs.IsMissing(err):
	case err != nil:
		skipped = append(skipped, fmt.Sprintf("%s: %v", aptConfDir, err))
	default:
		for _, e := range entries {
			if hostfs.RegularFile(h.FS, e) && aptFileName.MatchString(path.Base(e.Path)) {
				files = append(files, e.Path)
			}
		}
		slices.Sort(files)
		u.Apt.Present = len(entries) > 0
	}
	files = append(files, aptConfFile)
	for _, file := range files {
		data, err := h.FS.ReadFile(file)
		switch {
		case hostfs.IsMissing(err):
			continue
		case err != nil:
			skipped = append(skipped, fmt.Sprintf("%s: %v", file, err))
			continue
		}
		u.Apt.Present = true
		skipped = append(skipped, parseAptPeriodic(file, data, &u.Apt)...)
	}

	// dnf-automatic and yum-cron.
	for _, c := range []struct {
		file string
		into *Automatic
		keys [2]string
	}{
		{dnfAutomatic, &u.Dnf, [2]string{"apply_updates", "upgrade_type"}},
		{yumCron, &u.Yum, [2]string{"apply_updates", "update_cmd"}},
	} {
		data, err := h.FS.ReadFile(c.file)
		switch {
		case hostfs.IsMissing(err):
			continue
		case err != nil:
			skipped = append(skipped, fmt.Sprintf("%s: %v", c.file, err))
			continue
		}
		c.into.Present = true
		parseAutomatic(c.file, data, c.keys, c.into)
	}
	return engine.Facts{Value: u, Complete: len(skipped) == 0, Skipped: skipped}, nil
}

var (
	aptStatement = regexp.MustCompile(`(?i)^\s*APT::Periodic::(Enable|Update-Package-Lists|Unattended-Upgrade)\s+"([^"]*)"\s*;`)
	aptBlock     = regexp.MustCompile(`(?i)\bAPT::Periodic\s*\{|^\s*Periodic\s*\{`)
)

// parseAptPeriodic reads the statements of one apt configuration file into a: later statements replace earlier ones.
// apt's block form (APT::Periodic { ... };) is not read: what it sets is not known, so the problem is returned and the
// facts are incomplete (a check then cannot decide, instead of reading an old value).
func parseAptPeriodic(file string, data []byte, a *AptPeriodic) (problems []string) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if i := strings.Index(text, "//"); i >= 0 {
			text = text[:i]
		}
		if t := strings.TrimSpace(text); t == "" || t[0] == '#' {
			continue
		}
		if aptBlock.MatchString(text) {
			problems = append(problems, fmt.Sprintf("%s:%d: the block form of APT::Periodic is not read", file, line))
			continue
		}
		m := aptStatement.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		set := facts.Setting{Value: aptDays(m[2]), Explicit: true, Source: fmt.Sprintf("%s:%d", file, line)}
		switch strings.ToLower(m[1]) {
		case "enable":
			a.Settings["enable"] = set
		case "update-package-lists":
			a.Settings["update_package_lists"] = set
		case "unattended-upgrade":
			a.Settings["unattended_upgrade"] = set
		}
	}
	return problems
}

// aptDays is a Periodic value as a number of days in text: "1", "7"; "0" for off and for what is not a number, which apt
// reads as 0 too ("true" is not a number to it).
func aptDays(v string) string {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return "0"
	}
	return strconv.Itoa(n)
}

// parseAutomatic reads the [commands] section of an INI file for the two keys: the last line of a key wins.
func parseAutomatic(file string, data []byte, keys [2]string, into *Automatic) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	inCommands := false
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || text[0] == '#' || text[0] == ';' {
			continue
		}
		if text[0] == '[' {
			inCommands = strings.EqualFold(text, "[commands]")
			continue
		}
		if !inCommands {
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if i := strings.Index(value, " #"); i >= 0 {
			value = value[:i]
		}
		value = strings.ToLower(strings.Trim(strings.TrimSpace(value), `"'`))
		set := facts.Setting{Explicit: true, Source: fmt.Sprintf("%s:%d", file, line)}
		switch key {
		case keys[0]:
			set.Value = yesNo(value)
			into.Settings["apply_updates"] = set
		case keys[1]:
			set.Value = value
			into.Settings["upgrade_type"] = set
		}
	}
}

// yesNo is the boolean of an INI value as "yes" or "no"; what is neither (a typo) is kept as it is, so it is not taken
// for either.
func yesNo(v string) string {
	switch v {
	case "yes", "true", "on", "1":
		return "yes"
	case "no", "false", "off", "0":
		return "no"
	}
	return v
}
