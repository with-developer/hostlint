package collect

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// Firewall are the `firewall` facts: what the configuration of the host firewalls says, where the state of the unit is not
// enough. ufw is the case: its unit is enabled by installing the package, while the firewall is on only when
// /etc/ufw/ufw.conf says ENABLED=yes. (Whether a unit is enabled is in the `services` facts.)
type Firewall struct {
	Ufw Ufw `json:"ufw"`
}

// Ufw is /etc/ufw/ufw.conf.
type Ufw struct {
	// Present is true when the file exists.
	Present bool `json:"present"`
	// Settings has "enabled", the ENABLED of the file: "yes" or "no" (case and quotes do not matter); absent when the file
	// does not set it.
	Settings map[string]facts.Setting `json:"settings"`
}

type firewallCollector struct{}

func (firewallCollector) Name() string          { return "firewall" }
func (firewallCollector) Version() int          { return 1 }
func (firewallCollector) Access() engine.Access { return engine.AccessFilesystem }
func (firewallCollector) Type() reflect.Type    { return reflect.TypeFor[Firewall]() }

const ufwConf = "/etc/ufw/ufw.conf"

func (firewallCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	f := &Firewall{Ufw: Ufw{Settings: map[string]facts.Setting{}}}
	data, err := h.FS.ReadFile(ufwConf)
	switch {
	case hostfs.IsMissing(err):
		return engine.Facts{Value: f, Complete: true}, nil
	case err != nil:
		return engine.Facts{Value: f, Complete: false, Skipped: []string{fmt.Sprintf("%s: %v", ufwConf, err)}}, nil
	}
	f.Ufw.Present = true
	if v, ok := ufwEnabled(data); ok {
		f.Ufw.Settings["enabled"] = v
	}
	return engine.Facts{Value: f, Complete: true}, nil
}

// ufwEnabled reads ENABLED from ufw.conf: shell-style KEY=value lines, "#" comments. The last line of the key wins (the
// file is sourced by a shell). A value that is not yes or no is kept as it is, so a check does not take it for either.
func ufwEnabled(data []byte) (facts.Setting, bool) {
	var out facts.Setting
	found := false
	for i, line := range strings.Split(string(data), "\n") {
		text := strings.TrimSpace(line)
		if text == "" || text[0] == '#' {
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok || strings.TrimSpace(key) != "ENABLED" {
			continue
		}
		value = strings.ToLower(strings.Trim(strings.TrimSpace(value), `"'`))
		out = facts.Setting{Value: value, Explicit: true, Source: fmt.Sprintf("%s:%d", ufwConf, i+1)}
		found = true
	}
	return out, found
}
