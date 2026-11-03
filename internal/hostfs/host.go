package hostfs

import (
	"os"
	"strings"
)

// Host is everything hostlint may use to observe one scan target.
type Host struct {
	// FS reads the target's files.
	FS FS
	// Runner runs the fixed commands; it refuses everything when the target
	// is not the running system.
	Runner Runner
	// Root is the target's root on the scanning system: "/" for the running
	// system, or the directory given with --root.
	Root string
	// Live is true when the target is the running system, so live state
	// (/proc, sockets, commands) describes it.
	Live bool

	close func() error
}

// Hostname returns the target's hostname: the kernel's for the running
// system, otherwise the first name in /etc/hostname (hostname(5): lines
// starting with "#" are comments). It is "" when neither is available.
func (h *Host) Hostname() string {
	if h.Live {
		if name, err := os.Hostname(); err == nil {
			return name
		}
	}
	data, err := h.FS.ReadFile("/etc/hostname")
	if err != nil {
		return ""
	}
	for line := range strings.Lines(string(data)) {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			return line
		}
	}
	return ""
}

// Close releases the host's resources.
func (h *Host) Close() error {
	if h.close == nil {
		return nil
	}
	return h.close()
}

// NewTestHost returns a Host backed by fsys and runner, for tests. With live
// false, the runner is replaced by one that refuses every command, as for a
// mounted root.
func NewTestHost(fsys FS, runner Runner, live bool) *Host {
	if !live || runner == nil {
		runner = unavailableRunner{reason: "not a live host"}
	}
	return &Host{FS: fsys, Runner: runner, Root: "/", Live: live}
}
