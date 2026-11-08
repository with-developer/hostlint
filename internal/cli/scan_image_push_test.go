package cli

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/server"
)

// An image scan is sent to a fleet server as an asset of its own (ADR 0016): named by its repository, with the tag and
// the image ID of every scan recorded, so the tags of one image are one history.
func TestPushAnImage(t *testing.T) {
	store, err := server.OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	srv := httptest.NewServer(server.New(server.Config{Store: store, Rate: 100000}).Handler())
	t.Cleanup(srv.Close)
	ctx := context.Background()
	// the token of an organization's CI: bound to a prefix
	tok, _, err := store.CreateCredential(ctx, server.ScopeIngest, "ci", "ghcr.io/acme/*", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOSTLINT_TOKEN", tok)
	files := map[string]string{"etc/os-release": "ID=debian\nVERSION_ID=\"12\"\n"}
	for _, tag := range []string{"ghcr.io/acme/app:1.4", "ghcr.io/acme/app:1.5"} {
		if tag == "ghcr.io/acme/app:1.5" {
			files["etc/extra"] = "changes the image ID"
		}
		code, _, stderr := run(ctx, t, "scan", "--image-tar", imageArchive(t, tag, files), "--push", srv.URL, "--fail-on", "none")
		if code != ExitOK || !strings.Contains(stderr, "result sent to "+srv.URL) {
			t.Fatalf("%s: exit %d, stderr %q", tag, code, stderr)
		}
	}
	images, total, err := store.Hosts(ctx, server.HostFilter{Kind: "image"})
	if err != nil || total != 1 {
		t.Fatalf("images: %v %d %v", images, total, err)
	}
	if images[0].Name != "ghcr.io/acme/app" || images[0].Kind != "image" || images[0].HostID != "" {
		t.Errorf("the image: %+v", images[0])
	}
	d, err := store.Host(ctx, images[0].ID, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Scans) != 2 || d.Scans[0].ImageRef != "ghcr.io/acme/app:1.5" || d.Scans[1].ImageRef != "ghcr.io/acme/app:1.4" || d.Scans[0].ImageDigest == d.Scans[1].ImageDigest || !strings.HasPrefix(d.Scans[0].ImageDigest, "sha256:") {
		t.Errorf("the history of the image: %+v", d.Scans)
	}
	// An archive that names no image needs a name; with one it goes.
	untagged := imageArchive(t, "", files)
	if code, _, stderr := run(ctx, t, "scan", "--image-tar", untagged, "--push", srv.URL, "--fail-on", "none"); code != ExitError || !strings.Contains(stderr, "--name") {
		t.Errorf("untagged: exit %d, stderr %q", code, stderr)
	}
	if code, _, stderr := run(ctx, t, "scan", "--image-tar", untagged, "--name", "ghcr.io/acme/untagged", "--push", srv.URL, "--fail-on", "none"); code != ExitOK {
		t.Errorf("untagged with a name: exit %d, stderr %q", code, stderr)
	}
	// The prefix of the token is checked by the server.
	if code, _, stderr := run(ctx, t, "scan", "--image-tar", imageArchive(t, "docker.io/other/app:1", files), "--push", srv.URL, "--fail-on", "none"); code != ExitError || !strings.Contains(stderr, "token is for host") {
		t.Errorf("outside the prefix: exit %d, stderr %q", code, stderr)
	}
}
