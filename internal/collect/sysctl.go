package collect

import (
	"context"
	"fmt"
	"maps"
	"path"
	"reflect"
	"slices"
	"strings"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/facts"
	"github.com/with-developer/vmsctl/internal/hostfs"
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
	"net.ipv4.conf.default.send_redirects",
	"net.ipv4.icmp_echo_ignore_broadcasts",
	"net.ipv4.tcp_syncookies",
}

// sysctlDirs are the directories of sysctl.d(5) in the order of precedence: a file of a name in a directory
// before another hides the file of that name in the later one.
var sysctlDirs = []string{"/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d", "/lib/sysctl.d"}

// sysctlWanted is sysctlKeys as a set; it is never changed.
var sysctlWanted = func() map[string]bool {
	m := map[string]bool{}
	for _, k := range sysctlKeys {
		m[k] = true
	}
	return m
}()

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
				s.Params[key] = facts.Setting{Value: sysctlValue(string(data)), Explicit: true, Source: file} // what the kernel holds, from /proc/sys
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
				if target, err := h.FS.ReadLink(m); err == nil && isDevNull(path.Dir(m), target) {
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
		case hostfs.IsMissing(err):
			continue
		case err != nil:
			skipped = append(skipped, fmt.Sprintf("%s: %v", file, err))
			continue
		}
		set, invalid := parseSysctl(file, data)
		for _, key := range invalid {
			delete(s.Params, key) // a wildcard after an earlier value: what it set is not known
		}
		for key, v := range set {
			s.Params[key] = v
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
// that the file sets, the last line of a key winning, and the parameters that a wildcard key (net.ipv4.conf.*.rp_filter)
// set after any earlier value: the wildcard changed them to something that is not read from it, so what an earlier file
// said about them is no longer known.
func parseSysctl(file string, data []byte) (set map[string]facts.Setting, invalid []string) {
	set = map[string]facts.Setting{}
	invalidated := map[string]bool{}
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
		if strings.ContainsAny(key, "*?[") {
			for _, k := range sysctlKeys {
				if ok, _ := path.Match(strings.ReplaceAll(key, ".", "/"), strings.ReplaceAll(k, ".", "/")); ok {
					delete(set, k)
					invalidated[k] = true
				}
			}
			continue
		}
		if !sysctlWanted[key] {
			continue
		}
		set[key] = facts.Setting{Value: sysctlValue(value), Explicit: true, Source: fmt.Sprintf("%s:%d", file, i+1)}
		delete(invalidated, key)
	}
	for _, k := range sysctlKeys {
		if invalidated[k] {
			invalid = append(invalid, k)
		}
	}
	return set, invalid
}

// isDevNull reports whether a link in dir with this target leads to /dev/null, however it is written.
func isDevNull(dir, target string) bool {
	if !path.IsAbs(target) {
		target = path.Join(dir, target)
	}
	return path.Clean(target) == "/dev/null"
}
