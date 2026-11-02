package collect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
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
