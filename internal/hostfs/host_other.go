//go:build !linux

package hostfs

import (
	"errors"
	"runtime"
)

// Open fails on platforms other than Linux: vmsctl scans Linux hosts. Other
// platforms can still read results (vmsctl report).
func Open(string) (*Host, error) {
	return nil, errors.New("scanning is supported on Linux only, not " + runtime.GOOS)
}
