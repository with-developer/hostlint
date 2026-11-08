package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

const imageDigest1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
const imageDigest2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

// imageDoc is the result of a scan of an image archive: a name with no host ID, and the image the scan was of.
func imageDoc(t *testing.T, name, ref, digest, scanID string, startMinute int) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(fixture(t, "web-01.json"), &doc); err != nil {
		t.Fatal(err)
	}
	host := doc["host"].(map[string]any)
	host["hostname"] = name
	delete(host, "hostId")
	scan := doc["scan"].(map[string]any)
	scan["id"] = scanID
	scan["startedAt"] = fmt.Sprintf("2026-11-02T12:%02d:00Z", startMinute)
	scan["target"] = map[string]any{"kind": "root", "root": "image:" + ref, "image": map[string]any{"ref": ref, "digest": digest}}
	out, _ := json.Marshal(doc)
	return out
}

func listKind(t *testing.T, f *apiFixture, kind string) []HostSummary {
	t.Helper()
	var out struct {
		Hosts []HostSummary `json:"hosts"`
		Total int           `json:"total"`
	}
	path := "/api/v1/hosts"
	if kind != "" {
		path += "?kind=" + kind
	}
	f.json(t, path, &out)
	return out.Hosts
}

// An image is an asset of its own: it has its own list, and it is not one of the fleet's hosts (its numbers are not the
// fleet's, and it is never stale: nothing reports for an image on a schedule).
func TestImagesAreAssetsOfTheirOwn(t *testing.T) {
	f := newAPIFixture(t)
	ingest := token(t, f.store, ScopeIngest, "")
	before := len(listKind(t, f, ""))
	for i, tag := range []struct{ ref, digest string }{{"ghcr.io/acme/app:1.4", imageDigest1}, {"ghcr.io/acme/app:1.5", imageDigest2}} {
		f.clock = f.clock.Add(time.Minute)
		code, out := post(t, f.srv, ingest, imageDoc(t, "ghcr.io/acme/app", tag.ref, tag.digest, fmt.Sprintf("img-%d", i), 10+i))
		if code != http.StatusCreated {
			t.Fatalf("%s: %d %v", tag.ref, code, out)
		}
	}
	images := listKind(t, f, "image")
	if len(images) != 1 || images[0].Name != "ghcr.io/acme/app" || images[0].Kind != "image" || images[0].HostID != "" {
		t.Fatalf("images: %+v", images)
	}
	if len(images[0].Trend) != 2 {
		t.Errorf("the two tags are the image's history: trend %v", images[0].Trend)
	}
	if got := listKind(t, f, ""); len(got) != before {
		t.Errorf("the host list has %d entries, was %d: an image is not a host", len(got), before)
	}
	for _, h := range listKind(t, f, "host") {
		if h.Kind != "host" {
			t.Errorf("%s is of kind %q in the host list", h.Name, h.Kind)
		}
	}
	// The fleet's numbers do not include it.
	var ov Overview
	f.json(t, "/api/v1/overview", &ov)
	if ov.Hosts != before || ov.HostsStale != 0 {
		t.Errorf("overview: %d hosts (want %d), %d stale", ov.Hosts, before, ov.HostsStale)
	}
	points, err := f.store.Trend(t.Context(), 2, "")
	if err != nil {
		t.Fatal(err)
	}
	if points[len(points)-1].Hosts != before {
		t.Errorf("the trend counts %d hosts, want %d", points[len(points)-1].Hosts, before)
	}
	var matrix Matrix
	f.json(t, "/api/v1/matrix", &matrix)
	for _, h := range matrix.Hosts {
		if strings.Contains(h.Name, "acme") {
			t.Errorf("an image in the matrix: %s", h.Name)
		}
	}
	// Its page says which image each scan was of: the history is the sequence of tags and digests.
	var d HostDetail
	f.json(t, "/api/v1/hosts/"+itoa(images[0].ID), &d)
	if d.Kind != "image" || len(d.Scans) != 2 || d.Scans[0].ImageRef != "ghcr.io/acme/app:1.5" || d.Scans[0].ImageDigest != imageDigest2 || d.Scans[1].ImageRef != "ghcr.io/acme/app:1.4" {
		t.Errorf("image page: kind %q, scans %+v", d.Kind, d.Scans)
	}
	if code, _ := f.get(t, f.api, "/api/v1/hosts?kind=nope"); code != http.StatusBadRequest {
		t.Errorf("an unknown kind: %d", code)
	}
}

func TestImageIdentity(t *testing.T) {
	f := newAPIFixture(t)
	ingest := token(t, f.store, ScopeIngest, "")
	good := imageDoc(t, "ghcr.io/acme/app", "ghcr.io/acme/app:1", imageDigest1, "img-0", 10)
	if code, out := post(t, f.srv, ingest, good); code != http.StatusCreated {
		t.Fatalf("%d %v", code, out)
	}
	// A host cannot take the name of an image, and an image cannot take the name of a host.
	var doc map[string]any
	if err := json.Unmarshal(fixture(t, "web-01.json"), &doc); err != nil {
		t.Fatal(err)
	}
	doc["host"].(map[string]any)["hostname"] = "ghcr.io/acme/app"
	doc["scan"].(map[string]any)["id"] = "as-a-host"
	asHost, _ := json.Marshal(doc)
	if code, out := post(t, f.srv, ingest, asHost); code != http.StatusConflict {
		t.Errorf("a host with an image's name: %d %v", code, out)
	}
	if code, out := post(t, f.srv, ingest, imageDoc(t, "web-01", "web-01:1", imageDigest1, "as-an-image", 11)); code != http.StatusConflict {
		t.Errorf("an image with a host's name: %d %v", code, out)
	}
	for name, mod := range map[string]func(map[string]any){
		"a host ID": func(d map[string]any) { d["host"].(map[string]any)["hostId"] = "0123" },
		"a digest that is not one": func(d map[string]any) {
			d["scan"].(map[string]any)["target"].(map[string]any)["image"].(map[string]any)["digest"] = "sha256:x"
		},
		"no digest": func(d map[string]any) {
			delete(d["scan"].(map[string]any)["target"].(map[string]any)["image"].(map[string]any), "digest")
		},
		"a long reference": func(d map[string]any) {
			d["scan"].(map[string]any)["target"].(map[string]any)["image"].(map[string]any)["ref"] = strings.Repeat("a", maxImageRef+1)
		},
		"an escape in the reference": func(d map[string]any) {
			d["scan"].(map[string]any)["target"].(map[string]any)["image"].(map[string]any)["ref"] = "app:1\x1b[2J"
		},
	} {
		var d map[string]any
		_ = json.Unmarshal(imageDoc(t, "ghcr.io/acme/other", "ghcr.io/acme/other:1", imageDigest1, "bad-"+strings.ReplaceAll(name, " ", "-"), 12), &d)
		mod(d)
		body, _ := json.Marshal(d)
		if code, _ := post(t, f.srv, ingest, body); code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d, want 422", name, code)
		}
	}
}

// A token may be bound to a prefix (an organization's CI pushing many images), checked on every result.
func TestTokenBoundToAPrefix(t *testing.T) {
	f := newAPIFixture(t)
	for _, bad := range []string{"*", "a*", "ab*", "ghcr.io/*/app*", "ghcr.io/ac*me", "**", "ghcr.io/acme*", "web*"} {
		if _, _, err := f.store.CreateCredential(t.Context(), ScopeIngest, "ci", bad, 0); err == nil {
			t.Errorf("a token bound to %q was made", bad)
		}
	}
	if _, _, err := f.store.CreateCredential(t.Context(), ScopeAPI, "read", "ghcr.io/acme/*", 0); err == nil {
		t.Error("a read token bound to a prefix was made")
	}
	tok, _, err := f.store.CreateCredential(t.Context(), ScopeIngest, "ci", "ghcr.io/acme/*", 0)
	if err != nil {
		t.Fatal(err)
	}
	if code, out := post(t, f.srv, tok, imageDoc(t, "ghcr.io/acme/app", "ghcr.io/acme/app:1", imageDigest1, "p-0", 10)); code != http.StatusCreated {
		t.Errorf("an image under the prefix: %d %v", code, out)
	}
	if code, out := post(t, f.srv, tok, imageDoc(t, "ghcr.io/evil/app", "ghcr.io/evil/app:1", imageDigest1, "p-1", 11)); code != http.StatusConflict {
		t.Errorf("an image outside the prefix: %d %v", code, out)
	}
	if code, out := post(t, f.srv, tok, fixture(t, "web-01.json")); code != http.StatusConflict {
		t.Errorf("a host with a prefix token: %d %v", code, out)
	}
	// A prefix token is for images: a host result under the prefix is refused, though its name matches.
	var hostDoc map[string]any
	if err := json.Unmarshal(fixture(t, "web-01.json"), &hostDoc); err != nil {
		t.Fatal(err)
	}
	hostDoc["host"].(map[string]any)["hostname"] = "ghcr.io/acme/looks-like-a-host"
	hostDoc["scan"].(map[string]any)["id"] = "p-host"
	asHost, _ := json.Marshal(hostDoc)
	if code, out := post(t, f.srv, tok, asHost); code != http.StatusConflict || !strings.Contains(fmt.Sprint(out["error"]), "bound to a prefix is for images") {
		t.Errorf("a host result with a prefix token: %d %v", code, out)
	}
	// A prefix is not an agent's identity: an agent speaks for one host.
	cred := mustAuth(t, f.store, tok)
	if _, err := f.store.AgentSeen(t.Context(), cred, []string{"kisa-2026"}); err == nil {
		t.Error("a prefix token served as an agent's")
	}
}

// Nothing reports for an image on a schedule: it is never stale, however long since its last scan; the images are listed
// newest scan first.
func TestImagesAreNeverStaleAndNewestFirst(t *testing.T) {
	f := newAPIFixture(t)
	ingest := token(t, f.store, ScopeIngest, "")
	for i, name := range []string{"ghcr.io/acme/old", "ghcr.io/acme/new"} {
		f.clock = f.clock.Add(time.Hour)
		if code, out := post(t, f.srv, ingest, imageDoc(t, name, name+":1", imageDigest1, fmt.Sprintf("s-%d", i), 20+i)); code != http.StatusCreated {
			t.Fatalf("%d %v", code, out)
		}
	}
	f.clock = f.clock.Add(30 * 24 * time.Hour)
	var out struct {
		Hosts []HostSummary `json:"hosts"`
	}
	f.json(t, "/api/v1/hosts?kind=image&sort=recent", &out)
	if len(out.Hosts) != 2 || out.Hosts[0].Name != "ghcr.io/acme/new" || out.Hosts[1].Name != "ghcr.io/acme/old" {
		t.Fatalf("newest first: %+v", out.Hosts)
	}
	for _, h := range out.Hosts {
		if h.Stale {
			t.Errorf("%s is stale after a month", h.Name)
		}
	}
	f.json(t, "/api/v1/hosts?kind=image&status=stale", &out)
	if len(out.Hosts) != 0 {
		t.Errorf("images listed as stale: %+v", out.Hosts)
	}
	// the hosts of the fixture are stale after that month
	f.json(t, "/api/v1/hosts?status=stale", &out)
	if len(out.Hosts) == 0 {
		t.Error("the hosts are not stale after a month")
	}
	var ov Overview
	f.json(t, "/api/v1/overview", &ov)
	if ov.HostsStale != len(out.Hosts) {
		t.Errorf("the overview counts %d stale hosts, the list %d", ov.HostsStale, len(out.Hosts))
	}
}
