package collect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// LoginDefs are the `login_defs` facts: /etc/login.defs (shadow-utils).
type LoginDefs struct {
	// Present is false when /etc/login.defs does not exist; the built-in
	// defaults below still apply then.
	Present bool `json:"present"`
	// Settings are keyed by the exact (upper-case) key, e.g. PASS_MAX_DAYS.
	Settings map[string]facts.Setting `json:"settings"`
}

// loginDefsDefaults are the values shadow-utils uses when a key is absent
// (login.defs(5); useradd falls back to -1, "no restriction", for the
// password aging keys). Keys without a documented default stay unknown.
var loginDefsDefaults = map[string]string{
	"PASS_MAX_DAYS": "-1",
	"PASS_MIN_DAYS": "-1",
	"PASS_WARN_AGE": "-1",
	"UMASK":         "022",
}

// loginDefsNumeric are the keys shadow-utils reads as numbers, with C's
// strtol in base 0 (getdef.c): "010" is octal 8 and "0x10" is 16, while a
// value that is not entirely a number ("090", "90 days") is a configuration
// error and the key falls back to its default. Their values are stored in
// decimal, or as facts.Invalid(value) so that no check accepts them.
var loginDefsNumeric = map[string]bool{
	"PASS_MAX_DAYS": true, "PASS_MIN_DAYS": true, "PASS_WARN_AGE": true,
	"PASS_MIN_LEN": true, "PASS_MAX_LEN": true,
	"UID_MIN": true, "UID_MAX": true, "GID_MIN": true, "GID_MAX": true,
	"SYS_UID_MIN": true, "SYS_UID_MAX": true, "SYS_GID_MIN": true, "SYS_GID_MAX": true,
	"LOGIN_RETRIES": true, "LOGIN_TIMEOUT": true,
	"SHA_CRYPT_MIN_ROUNDS": true, "SHA_CRYPT_MAX_ROUNDS": true, "YESCRYPT_COST_FACTOR": true,
}

// parseCLong parses s as C's strtol does in base 0 (an optional sign, then
// 0x for hexadecimal or a leading 0 for octal) and requires all of s to be
// the number.
func parseCLong(s string) (int64, bool) {
	neg := false
	switch {
	case strings.HasPrefix(s, "-"):
		neg, s = true, s[1:]
	case strings.HasPrefix(s, "+"):
		s = s[1:]
	}
	base := 10
	switch {
	case strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X"):
		base, s = 16, s[2:]
	case len(s) > 1 && s[0] == '0':
		base, s = 8, s[1:]
	}
	n, err := strconv.ParseInt(s, base, 64)
	if err != nil || s == "" || s[0] == '+' || s[0] == '-' {
		return 0, false
	}
	if neg {
		n = -n
	}
	return n, true
}

type loginDefsCollector struct{}

func (loginDefsCollector) Name() string          { return "login_defs" }
func (loginDefsCollector) Version() int          { return 1 }
func (loginDefsCollector) Access() engine.Access { return engine.AccessFilesystem }
func (loginDefsCollector) Type() reflect.Type    { return reflect.TypeFor[LoginDefs]() }

func (loginDefsCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	ld := &LoginDefs{Settings: map[string]facts.Setting{}}
	econf := usesLibeconf(h.FS)
	main := "/etc/login.defs"
	if econf && !exists(h.FS, main) {
		main = "/usr/etc/login.defs" // libeconf's vendor file
	}
	files := []string{main}
	if econf {
		dropIns, err := loginDefsDropIns(h.FS)
		if err != nil {
			return engine.Facts{}, err
		}
		files = append(files, dropIns...)
	}
	for _, file := range files {
		data, err := h.FS.ReadFile(file)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return engine.Facts{}, err
		}
		ld.Present = true
		// shadow-utils keeps the last value of a key; built with libeconf
		// (RHEL 10) it keeps the first within a file, and later files
		// (drop-ins) override earlier ones.
		seen := map[string]bool{}
		for _, d := range parseLoginDefs(file, data) {
			if econf && seen[d.key] {
				continue
			}
			seen[d.key] = true
			ld.Settings[d.key] = d.setting
		}
	}
	for key, value := range loginDefsDefaults {
		if _, ok := ld.Settings[key]; !ok {
			ld.Settings[key] = facts.Setting{Value: value, Source: "default (login.defs(5))"}
		}
	}
	return engine.Facts{Value: ld, Complete: true}, nil
}

type loginDef struct {
	key     string
	setting facts.Setting
}

// parseLoginDefs reads definitions as shadow-utils' getdef.c does: the key
// is the first word; a line with only a key defines nothing; the value
// starts after spaces, tabs and quotes and ends at the next quote. Only
// ASCII whitespace separates or is trimmed.
func parseLoginDefs(file string, data []byte) []loginDef {
	var out []loginDef
	for i, line := range strings.Split(string(data), "\n") {
		text := strings.TrimRight(line, asciiSpace)
		text = strings.TrimLeft(text, " \t")
		if text == "" || text[0] == '#' {
			continue
		}
		end := strings.IndexAny(text, " \t")
		if end < 0 {
			continue // a key without a value
		}
		key := text[:end]
		value := strings.TrimLeft(text[end:], " \"\t")
		if q := strings.IndexByte(value, '"'); q >= 0 {
			value = value[:q]
		}
		if loginDefsNumeric[key] {
			if n, ok := parseCLong(value); ok {
				value = strconv.FormatInt(n, 10)
			} else {
				value = facts.Invalid(value)
			}
		}
		out = append(out, loginDef{key, facts.Setting{Value: value, Explicit: true, Source: fmt.Sprintf("%s:%d", file, i+1)}})
	}
	return out
}

// usesLibeconf reports whether shadow-utils is built with libeconf, which
// changes how login.defs is read.
func usesLibeconf(fsys hostfs.FS) bool {
	for _, prog := range []string{"/usr/sbin/useradd", "/sbin/useradd"} {
		if data, err := fsys.ReadFile(prog); err == nil {
			return bytes.Contains(data, []byte("libeconf.so"))
		}
	}
	return false
}

// loginDefsDropIns lists libeconf's drop-ins in the order they apply: by
// file name, a file in /etc replacing one of the same name in /usr/etc.
func loginDefsDropIns(fsys hostfs.FS) ([]string, error) {
	byName := map[string]string{}
	for _, dir := range []string{"/usr/etc/login.defs.d", "/etc/login.defs.d"} {
		matches, problems, err := hostfs.Glob(fsys, dir+"/*.defs")
		if err != nil {
			return nil, err
		}
		if len(problems) > 0 {
			return nil, errors.New(strings.Join(problems, "; "))
		}
		for _, m := range matches {
			byName[path.Base(m)] = m
		}
	}
	var out []string
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		out = append(out, byName[name])
	}
	return out, nil
}

func exists(fsys hostfs.FS, name string) bool {
	_, err := fsys.Stat(name)
	return err == nil
}
