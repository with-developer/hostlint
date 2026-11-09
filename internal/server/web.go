package server

import (
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

// dashboardCSP is what the dashboard's HTML is served with: scripts and styles only from
// the server itself, nothing inline, no frames, no other origin to talk to.
const dashboardCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// postOnly lists the API paths that only answer POST.
var postOnly = map[string]bool{"/api/v1/results": true, "/api/v1/login": true, "/api/v1/logout": true}

// contentType knows the types of a built dashboard even where the system has no mime table.
func contentType(name string) string {
	switch path.Ext(name) {
	case ".html":
		return "text/html; charset=utf-8"
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".json", ".map":
		return "application/json"
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".ico":
		return "image/x-icon"
	case ".woff2":
		return "font/woff2"
	case ".webmanifest":
		return "application/manifest+json"
	}
	return mime.TypeByExtension(path.Ext(name))
}

// webHandler serves the dashboard: files by path, index.html for any other path without an
// extension (the application routes in the browser), and a plain notice when the build has no
// dashboard. /api/ paths that match no route are 404, not index.html.
func (s *Server) webHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
			// A known endpoint reached with the wrong method says so; anything else is not there.
			if postOnly[r.URL.Path] {
				w.Header().Set("Allow", "POST")
				writeError(w, http.StatusMethodNotAllowed, "use POST")
				return
			}
			writeError(w, http.StatusNotFound, "no such endpoint")
			return
		}
		if s.cfg.Web == nil {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, "vmsctl server: this build has no dashboard; the API is at /api/v1 (see docs/fleet.md)\n")
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" {
			name = "index.html"
		}
		data, err := fs.ReadFile(s.cfg.Web, name)
		if err != nil {
			if path.Ext(name) != "" || name == "assets" || strings.HasPrefix(name, "assets/") {
				http.NotFound(w, r) // a missing asset is not the application
				return
			}
			name = "index.html"
			if data, err = fs.ReadFile(s.cfg.Web, name); err != nil {
				http.NotFound(w, r)
				return
			}
		}
		h := w.Header()
		if ct := contentType(name); ct != "" {
			h.Set("Content-Type", ct)
		}
		if strings.HasSuffix(name, ".html") {
			h.Set("Content-Security-Policy", dashboardCSP)
			h.Set("Cache-Control", "no-cache")
		} else if strings.HasPrefix(name, "assets/") {
			h.Set("Cache-Control", "public, max-age=31536000, immutable") // the file names carry a hash
		}
		_, _ = w.Write(data) //nolint:gosec // the dashboard's own built files, not user input
	})
}
