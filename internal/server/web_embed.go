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
	return sub
}
