//go:build !unix

package hostfs

import "io/fs"

// Owner reports that file ownership is unknown on this platform.
func Owner(fs.FileInfo) (uid uint32, ok bool) { return 0, false }
