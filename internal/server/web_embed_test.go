//go:build web

package server

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// A build with the `web` tag must carry the built dashboard, and it must work under the CSP the
// server sends: scripts and styles from files, none inline.
func TestEmbeddedDashboard(t *testing.T) {
	web := webAssets()
	if web == nil {
		t.Fatal("built with the web tag but without the dashboard: run `make web` first")
	}
	index, err := fs.ReadFile(web, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(index)
	if !strings.Contains(html, `<div id="root">`) || !strings.Contains(html, `src="/assets/`) {
		t.Errorf("index.html is not the dashboard:\n%s", html)
	}
	if regexp.MustCompile(`(?s)<script(\s[^>]*)?>[^<]+</script>`).MatchString(html) || strings.Contains(html, "<style") || regexp.MustCompile(`\sstyle=`).MatchString(html) {
		t.Errorf("index.html has inline script or style, which the CSP blocks:\n%s", html)
	}
	for _, m := range regexp.MustCompile(`(?:src|href)="(/assets/[^"]+)"`).FindAllStringSubmatch(html, -1) {
		if _, err := fs.Stat(web, strings.TrimPrefix(m[1], "/")); err != nil {
			t.Errorf("index.html refers to %s, which is not embedded", m[1])
		}
	}
}
