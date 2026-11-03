package collect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
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
// decimal, or as "invalid: <value>" so that no range check accepts them.
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
	const path = "/etc/login.defs"
	ld := &LoginDefs{Settings: map[string]facts.Setting{}}
	data, err := h.FS.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return engine.Facts{}, err
	default:
		ld.Present = true
		sc := bufio.NewScanner(bytes.NewReader(data))
		for line := 1; sc.Scan(); line++ {
			text := strings.TrimSpace(sc.Text())
			if text == "" || strings.HasPrefix(text, "#") {
				continue
			}
			key, value := text, ""
			if i := strings.IndexAny(text, " \t"); i >= 0 {
				key, value = text[:i], strings.TrimSpace(text[i+1:])
			}
			value = strings.Trim(value, `"`)
			if loginDefsNumeric[key] {
				if n, ok := parseCLong(value); ok {
					value = strconv.FormatInt(n, 10)
				} else {
					value = "invalid: " + value
				}
			}
			// A later line replaces an earlier one (shadow-utils getdef.c).
			ld.Settings[key] = facts.Setting{Value: value, Explicit: true, Source: fmt.Sprintf("%s:%d", path, line)}
		}
		if err := sc.Err(); err != nil {
			return engine.Facts{}, err
		}
	}
	for key, value := range loginDefsDefaults {
		if _, ok := ld.Settings[key]; !ok {
			ld.Settings[key] = facts.Setting{Value: value, Source: "default (login.defs(5))"}
		}
	}
	return engine.Facts{Value: ld, Complete: true}, nil
}
