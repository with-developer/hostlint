//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/with-developer/vmsctl/internal/server"
)

// A scan with a policy pack is sent to the fleet server like any other (ADR 0016): the result is stored as it is, the pack's
// profile is one the dashboard can choose, and the host's page names the pack.
func TestPushWithAPack(t *testing.T) {
	store, err := server.OpenStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	srv := httptest.NewServer(server.New(server.Config{Store: store, Rate: 100000}).Handler())
	t.Cleanup(srv.Close)
	ctx := context.Background()
	ingest, _, err := store.CreateCredential(ctx, server.ScopeIngest, "img", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	api, _, err := store.CreateCredential(ctx, server.ScopeAPI, "read", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VMSCTL_TOKEN", ingest)
	root := fakeRoot(t)
	pack := copyExamplePack(t)

	code, _, stderr := run(ctx, t, "scan", "--root", root, "--pack", pack, "-p", "x-acme-baseline", "--push", srv.URL, "--fail-on", "none")
	if code != ExitOK || !strings.Contains(stderr, "result sent to "+srv.URL) {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	get := func(path string, into any) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+api)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, resp.StatusCode, body)
		}
		if err := json.Unmarshal(body, into); err != nil {
			t.Fatalf("GET %s: %v\n%s", path, err, body)
		}
	}
	var profiles struct {
		Profiles []server.ProfileUse `json:"profiles"`
	}
	get("/api/v1/profiles", &profiles)
	if len(profiles.Profiles) != 1 || profiles.Profiles[0].ID != "x-acme-baseline" {
		t.Errorf("profiles: %+v", profiles.Profiles)
	}
	var host server.HostDetail
	get("/api/v1/hosts/1?profile=x-acme-baseline", &host)
	if len(host.Packs) != 1 || host.Packs[0].Name != "acme" || !strings.HasPrefix(host.Packs[0].Digest, "sha256:") {
		t.Errorf("packs of the host: %+v", host.Packs)
	}
	if len(host.Controls) == 0 {
		t.Error("the host has none of the pack's controls")
	}
}
