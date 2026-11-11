package collect

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/facts"
	"github.com/with-developer/vmsctl/internal/hostfs"
)

// MAC are the `mac` facts: the configuration of mandatory access control where a package or a unit alone does not say it. SELinux
// is the case: the mode it starts in is the SELINUX of /etc/selinux/config. (AppArmor has no such file for it: it is on when its
// package is installed and its unit is enabled, which are the `packages` and `services` facts.) The file says what the next boot
// does, not what the running kernel does.
type MAC struct {
	Selinux Selinux `json:"selinux"`
}

// Selinux is /etc/selinux/config.
type Selinux struct {
	// Present is true when the file exists.
	Present bool `json:"present"`
	// Settings has "mode", the SELINUX of the file ("enforcing", "permissive" or "disabled": case and quotes do not matter) and
	// "type", its SELINUXTYPE ("targeted", "minimum", "mls"); a key the file does not set is absent.
	Settings map[string]facts.Setting `json:"settings"`
}

type macCollector struct{}

func (macCollector) Name() string          { return "mac" }
func (macCollector) Version() int          { return 1 }
func (macCollector) Access() engine.Access { return engine.AccessFilesystem }
func (macCollector) Type() reflect.Type    { return reflect.TypeFor[MAC]() }

const selinuxConfig = "/etc/selinux/config"

func (macCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	f := &MAC{Selinux: Selinux{Settings: map[string]facts.Setting{}}}
	data, err := h.FS.ReadFile(selinuxConfig)
	switch {
	case hostfs.IsMissing(err):
		return engine.Facts{Value: f, Complete: true}, nil
	case err != nil:
		return engine.Facts{Value: f, Complete: false, Skipped: []string{fmt.Sprintf("%s: %v", selinuxConfig, err)}}, nil
	}
	f.Selinux.Present = true
	if v, ok := shellAssignment(selinuxConfig, data, "SELINUX"); ok {
		f.Selinux.Settings["mode"] = v
	}
	if v, ok := shellAssignment(selinuxConfig, data, "SELINUXTYPE"); ok {
		f.Selinux.Settings["type"] = v
	}
	return engine.Facts{Value: f, Complete: true}, nil
}

// shellAssignment reads KEY=value from a file a shell sources: "#" comments, the last line of the key wins, quotes and case do
// not matter (the value is lower case). A value is kept as it is when it is not one a check expects, so a check does not take it
// for another.
func shellAssignment(file string, data []byte, key string) (facts.Setting, bool) {
	var out facts.Setting
	found := false
	for i, line := range strings.Split(string(data), "\n") {
		text := strings.TrimSpace(line)
		if text == "" || text[0] == '#' {
			continue
		}
		k, value, ok := strings.Cut(text, "=")
		if !ok || strings.TrimSpace(k) != key {
			continue
		}
		value = strings.ToLower(strings.Trim(strings.TrimSpace(stripInlineComment(value)), `"'`))
		out = facts.Setting{Value: value, Explicit: true, Source: fmt.Sprintf("%s:%d", file, i+1)}
		found = true
	}
	return out, found
}
