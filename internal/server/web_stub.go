//go:build !web

package server

import "io/fs"

// webAssets is nil in a build without the dashboard (a plain `go build` or `go install`): the
// server then serves the API only. Release builds use the `web` tag.
func webAssets() fs.FS { return nil }
