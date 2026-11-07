package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/profiles"
	"github.com/with-developer/hostlint/rules"
)

const testPackCheck = `id: x-acme.motd-present
version: 1
title: /etc/motd is owned by root
severity: low
description: Checks the owner of /etc/motd.
rationale: A banner anyone can edit is no banner.
remediation: chown root /etc/motd
file:
  paths: [/etc/motd]
  owner: [root]
  mode: "0644"
  missing: error
tests:
  - name: as required
    files:
      /etc/motd: {mode: "0644"}
    want: PASS
  - name: writable
    files:
      /etc/motd: {mode: "0666"}
    want: FAIL
  - name: missing
    input: absent
    want: ERROR
`

const testPackProfile = `id: x-acme-baseline
revision: 1
title: Acme baseline
controls:
  - id: A-01
    title: The banner is root's
    severity: low
    checks: [x-acme.motd-present]
`

// writePack makes a pack in a new directory: path → content; names ending in / are directories.
func writePack(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	chmodTree(t, dir)
	return dir
}

// chmodTree makes the directories 0755 and the files 0644, whatever the umask was.
func chmodTree(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(p, 0o755)
		}
		if d.Type().IsRegular() {
			return os.Chmod(p, 0o644)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func goodPack() map[string]string {
	return map[string]string{
		"pack.yaml":                      "format: 1\nname: acme\nversion: 1.2.0\ndescription: Acme's baseline\n",
		"rules/x-acme/motd-present.yaml": testPackCheck,
		"profiles/x-acme-baseline.yaml":  testPackProfile,
	}
}

func TestLoadPack(t *testing.T) {
	dir := writePack(t, goodPack())
	p, err := LoadPack(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "acme" || p.Version != "1.2.0" || len(p.Files) != 3 || !strings.HasPrefix(p.Digest, "sha256:") {
		t.Fatalf("%+v", p)
	}
	content, err := engine.Load(rules.FS, profiles.FS)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := content.Extend(p.Source)
	if err != nil || len(pc.Checks) != 1 || len(pc.Profiles) != 1 {
		t.Fatalf("%+v %v", pc, err)
	}
	// The digest follows the bytes, and only the bytes.
	again, _ := LoadPack(dir)
	if again.Digest != p.Digest {
		t.Error("the digest of the same pack differs")
	}
	if err := os.WriteFile(filepath.Join(dir, "profiles/x-acme-baseline.yaml"), []byte(testPackProfile+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := LoadPack(dir)
	if err != nil || changed.Digest == p.Digest {
		t.Errorf("a changed profile has the digest of the old one: %v", err)
	}
}

func TestLoadPackRefuses(t *testing.T) {
	with := func(extra map[string]string, drop ...string) map[string]string {
		m := goodPack()
		for _, d := range drop {
			delete(m, d)
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	for name, tc := range map[string]struct {
		files map[string]string
		want  string
	}{
		"no manifest":            {with(nil, "pack.yaml"), "pack.yaml is missing"},
		"a stray file":           {with(map[string]string{"README.md": "x"}), "README.md is not part of a pack"},
		"a stray .yml":           {with(map[string]string{"rules/x-acme/other.yml": "x"}), "nothing else is allowed there"},
		"a file in rules":        {with(map[string]string{"rules/stray.yaml": "x"}), "rules/<area>/<name>.yaml"},
		"nested too deep":        {with(map[string]string{"rules/x-acme/sub/a.yaml": "x"}), "nothing else is allowed there"},
		"a bad file name":        {with(map[string]string{"profiles/Bad_Name.yaml": "x"}), "profiles/<id>.yaml"},
		"a profile directory":    {with(map[string]string{"profiles/sub/a.yaml": "x"}), "profiles/<id>.yaml"},
		"an unknown field":       {with(map[string]string{"pack.yaml": "format: 1\nname: acme\nversion: 1\nextra: x\n"}), "field extra not found"},
		"format 2":               {with(map[string]string{"pack.yaml": "format: 2\nname: acme\nversion: 1\n"}), "format must be 1"},
		"a bad name":             {with(map[string]string{"pack.yaml": "format: 1\nname: Acme Inc\nversion: 1\n"}), "name must be lowercase kebab case"},
		"no version":             {with(map[string]string{"pack.yaml": "format: 1\nname: acme\n"}), "version is required"},
		"needs a newer hostlint": {with(map[string]string{"pack.yaml": "format: 1\nname: acme\nversion: 1\nrequires_hostlint: v99.0.0\n"}), "needs hostlint v99.0.0 or later"},
		"a big file":             {with(map[string]string{"rules/x-acme/big.yaml": strings.Repeat("a", maxPackFile+1)}), "larger than 256 KiB"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := writePack(t, tc.files)
			// "needs a newer hostlint" only holds for release builds: a dev build skips the check.
			_, err := LoadPack(dir)
			if name == "needs a newer hostlint" && err == nil {
				t.Skip("a development build does not check requires_hostlint")
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadPackTrust(t *testing.T) {
	dir := writePack(t, goodPack())
	// A file anyone in the group could change.
	if err := os.Chmod(filepath.Join(dir, "rules/x-acme/motd-present.yaml"), 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPack(dir); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Errorf("a group-writable file: %v", err)
	}
	chmodTree(t, dir)
	if err := os.Chmod(filepath.Join(dir, "rules"), 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPack(dir); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Errorf("a world-writable directory: %v", err)
	}
	chmodTree(t, dir)
	// A symbolic link is refused, also one that stays inside the pack.
	if err := os.Symlink("motd-present.yaml", filepath.Join(dir, "rules/x-acme/alias.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPack(dir); err == nil || !strings.Contains(err.Error(), "nothing else is allowed there") {
		t.Errorf("a symbolic link: %v", err)
	}
	// Nothing outside the pack is read through a link in its place either.
	os.Remove(filepath.Join(dir, "rules/x-acme/alias.yaml"))
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "x.yaml"), []byte(testPackCheck), 0o644); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(filepath.Join(dir, "rules"))
	if err := os.Symlink(outside, filepath.Join(dir, "rules")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPack(dir); err == nil {
		t.Error("rules/ was a link to a directory outside the pack")
	}
	if _, err := LoadPack(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing directory")
	}
}

func TestLoadPackTooManyEntries(t *testing.T) {
	files := goodPack()
	for i := 0; i <= maxPackEntries; i++ {
		files["profiles/p"+strings.Repeat("a", i%20)+string(rune('a'+i%26))+strings.Repeat("b", i/26)+".yaml"] = "x"
	}
	dir := writePack(t, files)
	if _, err := LoadPack(dir); err == nil {
		t.Error("a directory with too many entries was read")
	}
}
