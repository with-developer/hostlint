package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

const goodDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func packDoc(t *testing.T, packs any, profile string) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(fixture(t, "web-01.json"), &doc); err != nil {
		t.Fatal(err)
	}
	doc["scan"].(map[string]any)["packs"] = packs
	if profile != "" {
		for _, c := range doc["controls"].([]any) {
			c.(map[string]any)["profile"] = profile
		}
		namePackProfile(doc, profile)
	}
	out, _ := json.Marshal(doc)
	return out
}

// namePackProfile adds a profile to the result's list of profiles: a result whose controls name a profile it does not
// list is refused when it is read.
func namePackProfile(doc map[string]any, profile string) {
	profiles := doc["profiles"].([]any)
	first := profiles[0].(map[string]any)
	copyOf := map[string]any{}
	for k, v := range first {
		copyOf[k] = v
	}
	copyOf["id"] = profile
	if summary, ok := doc["summary"].(map[string]any); ok {
		if s0, ok := summary[first["id"].(string)]; ok {
			summary[profile] = s0
		}
	}
	doc["profiles"] = append(profiles, copyOf)
}

func onePack(name, version, digest string) map[string]string {
	return map[string]string{"name": name, "version": version, "digest": digest}
}

// The packs a received result names come from the host and are shown on its page: a few, short, plain text, and each with
// the digest that is its identity.
func TestIngestBoundsTheNamedPacks(t *testing.T) {
	srv, store := newTestServer(t)
	wild := token(t, store, ScopeIngest, "")
	many := make([]any, 0, maxPacks+1)
	for i := range maxPacks + 1 {
		many = append(many, onePack(fmt.Sprintf("p%d", i), "1", goodDigest))
	}
	for name, packs := range map[string]any{
		"an escape sequence":       []any{onePack("acme\x1b[2J", "1", goodDigest)},
		"a bidi override":          []any{onePack("acme\u202e", "1", goodDigest)},
		"a long name":              []any{onePack(strings.Repeat("a", maxPackText+1), "1", goodDigest)},
		"no name":                  []any{onePack("", "1", goodDigest)},
		"no digest":                []any{onePack("acme", "1", "")},
		"a digest that is not one": []any{onePack("acme", "1", "sha256:x")},
		"too many packs":           many,
	} {
		if code, _ := post(t, srv, wild, packDoc(t, packs, "")); code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d, want 422", name, code)
		}
	}
	if code, out := post(t, srv, wild, packDoc(t, []any{onePack("acme", "1.2.0", goodDigest)}, "")); code != http.StatusCreated {
		t.Fatalf("a good pack: %d %v", code, out)
	}
}

// A result of a pack's profile (an x- ID) has to name the pack it came from.
func TestResultOfAPackProfileNamesThePack(t *testing.T) {
	srv, store := newTestServer(t)
	wild := token(t, store, ScopeIngest, "")
	if code, _ := post(t, srv, wild, packDoc(t, nil, "x-acme-baseline")); code != http.StatusUnprocessableEntity {
		t.Errorf("pack controls and no pack: %d, want 422", code)
	}
	if code, out := post(t, srv, wild, packDoc(t, []any{onePack("acme", "1", goodDigest)}, "x-acme-baseline")); code != http.StatusCreated {
		t.Errorf("pack controls and the pack: %d %v", code, out)
	}
}

// The host's page names the packs for the views of a pack's profile and of every profile, not on a built-in profile's page;
// a scan with no pack has an empty list, not null.
func TestHostPacks(t *testing.T) {
	srv, store := newTestServer(t)
	wild := token(t, store, ScopeIngest, "")
	// two profiles in one result: the built-in one and a pack's
	var doc map[string]any
	if err := json.Unmarshal(packDoc(t, []any{onePack("acme", "1.2.0", goodDigest)}, ""), &doc); err != nil {
		t.Fatal(err)
	}
	controls := doc["controls"].([]any)
	for i, c := range controls {
		if i%2 == 1 {
			c.(map[string]any)["profile"] = "x-acme-baseline"
		}
	}
	namePackProfile(doc, "x-acme-baseline")
	body, _ := json.Marshal(doc)
	if code, out := post(t, srv, wild, body); code != http.StatusCreated {
		t.Fatalf("%d %v", code, out)
	}
	for profile, want := range map[string]int{"": 1, "x-acme-baseline": 1, "kisa-2026": 0} {
		d, err := store.Host(t.Context(), 1, 0, profile)
		if err != nil {
			t.Fatal(err)
		}
		if len(d.Packs) != want {
			t.Errorf("profile %q: %d packs, want %d", profile, len(d.Packs), want)
		}
		if want == 1 && (d.Packs[0].Name != "acme" || d.Packs[0].Version != "1.2.0" || d.Packs[0].Digest != goodDigest) {
			t.Errorf("profile %q: %+v", profile, d.Packs)
		}
	}
	// another host with no pack: an empty list
	other := token(t, store, ScopeIngest, "")
	nopack := strings.ReplaceAll(string(fixture(t, "db-01.json")), `"hostname": "db-01"`, `"hostname": "db-02"`)
	if code, out := post(t, srv, other, []byte(nopack)); code != http.StatusCreated {
		t.Fatalf("%d %v", code, out)
	}
	hosts, _, err := store.Hosts(t.Context(), HostFilter{Query: "db-02"})
	if err != nil || len(hosts) != 1 {
		t.Fatalf("%v %v", hosts, err)
	}
	d, err := store.Host(t.Context(), hosts[0].ID, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Packs == nil || len(d.Packs) != 0 {
		t.Errorf("a scan with no pack: %v", d.Packs)
	}
	j, _ := json.Marshal(d)
	if !strings.Contains(string(j), `"packs":[]`) {
		t.Errorf("the JSON of a host with no pack: %s", j)
	}
}
