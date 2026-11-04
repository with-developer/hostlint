package hostfs

import (
	"bufio"
	"bytes"
	"fmt"
	"path"
	"strconv"
	"strings"
)

// Mount is one filesystem mounted in the target.
type Mount struct {
	// Path is the mount point as a target path ("/" is the target's root).
	Path string
	// Type is the filesystem type, e.g. ext4, proc, nfs4, fuse.sshfs.
	Type   string
	Source string
}

// ParseMountinfo reads /proc/<pid>/mountinfo (proc(5)) and returns the
// mounts at or below root, with their mount points as target paths, in the
// order they were mounted. Later mounts on the same point hide earlier ones.
func ParseMountinfo(data []byte, root string) ([]Mount, error) {
	var out []Mount
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for line := 1; sc.Scan(); line++ {
		// ID parent major:minor root mount-point options [optional...] - type source super-options
		f := strings.Fields(sc.Text())
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if len(f) < 7 || sep < 0 || sep+2 >= len(f) {
			return nil, fmt.Errorf("mountinfo line %d: unexpected format", line)
		}
		point, err := unescapeMountPath(f[4])
		if err != nil {
			return nil, fmt.Errorf("mountinfo line %d: %w", line, err)
		}
		rel, ok := belowRoot(point, root)
		if !ok {
			continue
		}
		out = append(out, Mount{Path: rel, Type: f[sep+1], Source: f[sep+2]})
	}
	return out, sc.Err()
}

// belowRoot returns p as a path relative to root, if it is root or below.
func belowRoot(p, root string) (string, bool) {
	root = path.Clean(root)
	switch {
	case root == "/":
		return p, true
	case p == root:
		return "/", true
	case strings.HasPrefix(p, root+"/"):
		return p[len(root):], true
	}
	return "", false
}

// unescapeMountPath undoes the octal escapes (\040 for a space) of
// mountinfo paths.
func unescapeMountPath(s string) (string, error) {
	if !strings.Contains(s, `\`) {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+4 > len(s) {
			return "", fmt.Errorf("bad escape in %q", s)
		}
		n, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			return "", fmt.Errorf("bad escape in %q", s)
		}
		b.WriteByte(byte(n))
		i += 3
	}
	return b.String(), nil
}
