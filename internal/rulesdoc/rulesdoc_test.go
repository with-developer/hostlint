package rulesdoc

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/with-developer/vmsctl/internal/collect"
	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/profiles"
	"github.com/with-developer/vmsctl/rules"
)

var update = flag.Bool("update", false, "rewrite docs/rules.md")

// docs/rules.md is what Render makes of the built-in content. After changing
// a rule or a profile, run `make docs`.
func TestRulesDocIsUpToDate(t *testing.T) {
	content, err := engine.Load(rules.FS, profiles.FS)
	if err != nil {
		t.Fatal(err)
	}
	got := Render(content)
	path := filepath.Join("..", "..", "docs", "rules.md")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v; run `make docs`", err)
	}
	if string(want) != got {
		t.Error("docs/rules.md is out of date; run `make docs`")
	}
}

// docs/facts.md is what RenderFacts makes of the fact types of the collectors. After changing one, run `make docs`.
func TestFactsDocIsUpToDate(t *testing.T) {
	content, err := engine.Load(rules.FS, profiles.FS)
	if err != nil {
		t.Fatal(err)
	}
	e, err := engine.New(content, collect.All()...)
	if err != nil {
		t.Fatal(err)
	}
	got, err := RenderFacts(e, os.DirFS(filepath.Join("..", "..")), "internal/collect", "internal/facts")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "docs", "facts.md")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v; run `make docs`", err)
	}
	if string(want) != got {
		t.Error("docs/facts.md is out of date; run `make docs`")
	}
	// The comments of the Go fields are attached: a known one is in its row.
	for _, doc := range []string{"| `sshd.config` | map of setting | Config holds the effective global settings", "| `sshd.config{}.explicit` | bool | Explicit is true when the value is set in a configuration file"} {
		if !strings.Contains(got, doc) {
			t.Errorf("the reference lacks the description %q", doc)
		}
	}
	for _, name := range []string{"## `sshd`", "`sshd.config`", "`login_defs`"} {
		if !strings.Contains(got, name) {
			t.Errorf("the reference lacks %s", name)
		}
	}
}

func TestRenderCoversEveryControlAndCheck(t *testing.T) {
	content, err := engine.Load(rules.FS, profiles.FS)
	if err != nil {
		t.Fatal(err)
	}
	out := Render(content)
	for _, p := range content.Profiles {
		for _, c := range p.Controls {
			if !strings.Contains(out, "| "+c.ID+" |") {
				t.Errorf("control %s is missing", c.ID)
			}
			for _, ref := range c.Checks {
				if !strings.Contains(out, "#### `"+ref+"`") {
					t.Errorf("check %s is missing", ref)
				}
			}
		}
	}
	if Render(content) != out {
		t.Error("Render is not deterministic")
	}
}

func TestFactDocsRefuseTwoTypesOfOneName(t *testing.T) {
	src := fstest.MapFS{
		"a/a.go": {Data: []byte("package a\n\n// T is one.\ntype T struct {\n\t// X is x.\n\tX string `json:\"x\"`\n}\n")},
		"b/b.go": {Data: []byte("package b\n\n// T is another.\ntype T struct{}\n")},
	}
	if _, err := fieldDocs(src, []string{"a", "b"}); err == nil || !strings.Contains(err.Error(), "declared twice") {
		t.Errorf("err = %v", err)
	}
	// A group comment is nobody's comment.
	grouped := fstest.MapFS{"c/c.go": {Data: []byte("package c\n\n// The group.\ntype (\n\tA struct{}\n\tB struct{}\n)\n")}}
	docs, err := fieldDocs(grouped, []string{"c"})
	if err != nil || docs["A"] != "" || docs["B"] != "" {
		t.Errorf("docs = %v %v", docs, err)
	}
}
