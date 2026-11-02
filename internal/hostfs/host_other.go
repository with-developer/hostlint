//go:build !linux

package hostfs

import (
	"errors"
	"runtime"
)

// Open fails on platforms other than Linux: hostlint scans Linux hosts. Other
// platforms can still read results (hostlint report).
func Open(string) (*Host, error) {
	return nil, errors.New("scanning is supported on Linux only, not " + runtime.GOOS)
}
