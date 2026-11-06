//go:build web

package server

import (
	"embed"
	"io/fs"
)

// webdist is the built dashboard (web/, `make web`).
//
//go:embed all:webdist
var webdist embed.FS

func webAssets() fs.FS {
	sub, err := fs.Sub(webdist, "webdist")
	if err != nil {
		return nil
	}
	// Built with the tag but without the dashboard (make web was not run): say so at run time.
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil
	}
	return sub
}
