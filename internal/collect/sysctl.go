package collect

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"reflect"
	"slices"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// Sysctl are the `sysctl` facts: the kernel parameters that checks read (sysctlKeys, not every parameter).
type Sysctl struct {
	// Live is true when the values are what the running kernel reports (/proc/sys). Otherwise they are what
	// the configuration files set at boot, and a parameter they do not set is absent: the kernel's own
	// default is not known. A container image shares the kernel of its host, so it has no values at all
	// (the checks do not apply to it).
	Live bool `json:"live"`
	// Params are keyed by the parameter's name with dots, e.g. kernel.kptr_restrict.
	Params map[string]facts.Setting `json:"params"`
}

// sysctlKeys are the only parameters the collector reads: a fixed list, so that no path of /proc/sys is
// chosen by a rule or by what a configuration says.
var sysctlKeys = []string{
	"fs.protected_hardlinks",
	"fs.protected_symlinks",
	"fs.suid_dumpable",
	"kernel.dmesg_restrict",
	"kernel.kptr_restrict",
	"kernel.randomize_va_space",
	"kernel.yama.ptrace_scope",
	"net.ipv4.conf.all.accept_redirects",
	"net.ipv4.conf.all.accept_source_route",
	"net.ipv4.conf.all.rp_filter",
	"net.ipv4.conf.all.send_redirects",
	"net.ipv4.conf.default.accept_redirects",
	"net.ipv4.icmp_echo_ignore_broadcasts",
	"net.ipv4.tcp_syncookies",
}

// sysctlDirs are the directories of sysctl.d(5) in the order of precedence: a file of a name in a directory
// before another hides the file of that name in the later one.
var sysctlDirs = []string{"/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d", "/lib/sysctl.d"}

type sysctlCollector struct{}

func (sysctlCollector) Name() string          { return "sysctl" }
func (sysctlCollector) Version() int          { return 1 }
func (sysctlCollector) Access() engine.Access { return engine.AccessFilesystem }
func (sysctlCollector) Type() reflect.Type    { return reflect.TypeFor[Sysctl]() }

func (sysctlCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	s := &Sysctl{Live: h.Live, Params: map[string]facts.Setting{}}
	if h.Image {
		return engine.Facts{Value: s, Complete: true}, nil
	}
	if h.Live {
		var skipped []string
		for _, key := range sysctlKeys {
			file := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
			data, err := h.FS.ReadFile(file)
			switch {
			case err == nil:
				s.Params[key] = facts.Setting{Value: sysctlValue(string(data)), Source: file}
			case hostfs.IsMissing(err):
				// The kernel has no such parameter (a module that is not loaded, no Yama): absent, so a check
				// that needs it cannot decide.
			default:
				skipped = append(skipped, fmt.Sprintf("%s: %v", file, err))
			}
		}
		if len(skipped) > 0 {
			return engine.Facts{Value: s, Complete: false, Skipped: skipped}, nil
		}
		return engine.Facts{Value: s, Complete: true}, nil
	}

	// A mounted root: what systemd-sysctl would set at boot. The files of every directory, by name, a file of
	// an earlier directory hiding the one of the same name later (and a link to /dev/null masking it); in
	// the order of the names; /etc/sysctl.conf last. The last value of a parameter wins.
	byName := map[string]string{}
	masked := map[string]bool{}
	var skipped []string
	for _, dir := range sysctlDirs {
		matches, problems, err := hostfs.Glob(h.FS, dir+"/*.conf")
		if err != nil {
			return engine.Facts{}, err
		}
		skipped = append(skipped, problems...)
		for _, m := range matches {
			name := path.Base(m)
			if _, seen := byName[name]; seen || masked[name] {
				continue
			}
			if li, err := h.FS.Lstat(m); err == nil && li.IsSymlink() {
				if target, err := h.FS.ReadLink(m); err == nil && target == "/dev/null" {
					masked[name] = true
					continue
				}
			}
			byName[name] = m
		}
	}
	files := make([]string, 0, len(byName)+1)
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		files = append(files, byName[name])
	}
	files = append(files, "/etc/sysctl.conf")
	for _, file := range files {
		data, err := h.FS.ReadFile(file)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			skipped = append(skipped, fmt.Sprintf("%s: %v", file, err))
			continue
		}
		for key, set := range parseSysctl(file, data) {
			s.Params[key] = set
		}
	}
	if len(skipped) > 0 {
		return engine.Facts{Value: s, Complete: false, Skipped: skipped}, nil
	}
	return engine.Facts{Value: s, Complete: true}, nil
}

// sysctlValue is what a parameter holds as one line of text: runs of white space are one space.
func sysctlValue(s string) string { return strings.Join(strings.Fields(s), " ") }

// parseSysctl reads one file of sysctl.d(5): "key = value" lines, "#" and ";" comments, a leading "-" on the
// key (an error to ignore), "/" or "." between the parts of a key. It returns the parameters of sysctlKeys
// that the file sets, the last line of a key winning. A key with a wildcard sets many parameters at the
// time it is applied, so it is not read as setting any of them.
func parseSysctl(file string, data []byte) map[string]facts.Setting {
	wanted := map[string]bool{}
	for _, k := range sysctlKeys {
		wanted[k] = true
	}
	out := map[string]facts.Setting{}
	for i, line := range strings.Split(string(data), "\n") {
		text := strings.TrimSpace(line)
		if text == "" || text[0] == '#' || text[0] == ';' {
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok {
			continue
		}
		key = strings.TrimPrefix(strings.TrimSpace(key), "-")
		key = strings.ReplaceAll(key, "/", ".")
		if !wanted[key] {
			continue
		}
		out[key] = facts.Setting{Value: sysctlValue(value), Explicit: true, Source: fmt.Sprintf("%s:%d", file, i+1)}
	}
	return out
}
