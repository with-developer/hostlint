package collect

import (
	"errors"

	"github.com/with-developer/vmsctl/internal/hostfs"
)

// maxBigFile is the most readBig reads.
const maxBigFile = 256 << 20

// readBig reads a file that is usually small but may pass hostfs.MaxReadSize (the dpkg
// status file of a big install, /proc/net/tcp on a host with very many connections).
func readBig(fsys hostfs.FS, name string) ([]byte, error) {
	data, err := fsys.ReadFile(name)
	if errors.Is(err, hostfs.ErrTooLarge) {
		return hostfs.ReadLargeFile(fsys, name, maxBigFile)
	}
	return data, err
}
