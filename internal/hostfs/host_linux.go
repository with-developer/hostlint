//go:build linux

package hostfs

import "os"

// Open opens the scan target rooted at root; "/" is the running system.
// Commands run only on the running system: with any other root they would
// describe the scanning system, and hostlint never runs the target's own
// binaries.
func Open(root string) (*Host, error) {
	o, err := newOSFS(root)
	if err != nil {
		return nil, err
	}
	h := &Host{FS: o, Root: o.root, Live: o.live, close: o.close}
	// hostlint's own mount table: for a mounted root it also lists what is
	// mounted inside the root (a chroot's /proc, a bind-mounted /dev).
	if data, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		h.Mounts, _ = ParseMountinfo(data, o.root)
	}
	if o.live {
		h.Runner = execRunner{}
	} else {
		h.Runner = unavailableRunner{reason: "scanning a mounted root"}
	}
	return h, nil
}
