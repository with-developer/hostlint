//go:build unix

package hostfs

import (
	"io/fs"
	"syscall"
)

// Owner returns the user ID owning the file that fi describes, for a
// FileInfo from the os package (os.Stat, (*os.File).Stat). It is for
// hostlint's own files, such as its configuration; files of the scanned host
// are described by FS.
func Owner(fi fs.FileInfo) (uid uint32, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
