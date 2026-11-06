//go:build e2e

// Package e2e runs hostlint in containers of every supported distribution,
// as shipped (stock) and after harden.sh (hardened), and compares each result
// with a golden summary in testdata/. It needs Docker, and network access to
// pull the images and to install the hardening packages.
//
//	make e2e                                      # every case
//	make e2e E2E_RUN=debian-12 E2E_UPDATE=1       # one distribution, rewrite its goldens
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/with-developer/hostlint/internal/engine"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// distros are the supported distributions (docs/ROADMAP.md, v0.1 scope),
// pinned by digest so that a golden changes only when we change something.
var distros = []struct{ name, image string }{
	{"ubuntu-22.04", "ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11"},
	{"ubuntu-24.04", "ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852"},
	{"ubuntu-26.04", "ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c"},
	{"debian-12", "debian:12@sha256:d74df7598108a173a621eda4d58a2adbf850b2d9a9d81bc2cca1a6c21174a880"},
	{"debian-13", "debian:13@sha256:2dc419c6d7fe3dad0a2f9fd469c34cc90b0f9ba642d8fde837fe3d7d34a0e7f1"},
	{"rocky-9", "rockylinux/rockylinux:9@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f"},
	{"rocky-10", "rockylinux/rockylinux:10@sha256:827d37bc128288ccf160ee318bb3cb92d591164cb217e92f8bc61e3982ae1834"},
	{"almalinux-9", "almalinux:9@sha256:245f8aab832fe800aa42bdab5fad75ebbd8e0b4c9f24820a83c638b177857ae2"},
	{"almalinux-10", "almalinux:10@sha256:5a4b41a427c9717be8f4ac2a32aa22efbae5f9124fbcb79a6765394f312acfe8"},
	{"amazonlinux-2023", "amazonlinux:2023@sha256:3ccfbe800f864982b0a4e124a614b2382518cbd04b3c1cd35202bd46f392675b"},
	{"centos-7", "centos:7@sha256:be65f488b7764ad3638f236b7b515b3678369a5124c47b8d32916d6487418ea4"},
}

func TestE2E(t *testing.T) {
	bin := buildHostlint(t)
	for _, d := range distros {
		for _, variant := range []string{"stock", "hardened"} {
			name := d.name + "-" + variant
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				image := d.image
				if variant == "hardened" {
					image = buildHardened(t, d.name, d.image)
				}
				res := scan(t, installed(t, bin, image, name))
				got := summary(res)
				golden := filepath.Join("testdata", name+".golden")
				if *update {
					if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
						t.Fatal(err)
					}
					return
				}
				want, err := os.ReadFile(golden)
				if err != nil {
					t.Fatalf("%v (run make e2e E2E_RUN=%s E2E_UPDATE=1)", err, d.name)
				}
				if got != string(want) {
					t.Errorf("%s differs from %s; review the change and run make e2e E2E_RUN=%s E2E_UPDATE=1\n%s",
						name, golden, d.name, diff(string(want), got))
				}
			})
		}
	}
}

// buildHostlint builds hostlint for the Docker server's architecture.
func buildHostlint(t *testing.T) string {
	t.Helper()
	arch := strings.TrimSpace(run(t, "docker", "version", "--format", "{{.Server.Arch}}"))
	dir := t.TempDir()
	cmd := exec.Command("go", "build", "-trimpath", "-o", filepath.Join(dir, "hostlint"), "../cmd/hostlint")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return dir
}

func buildHardened(t *testing.T, name, base string) string {
	t.Helper()
	tag := "hostlint-e2e/" + name + ":hardened"
	run(t, "docker", "build", "--quiet", "--build-arg", "BASE="+base, "--tag", tag, "--file", "hardened.Dockerfile", ".")
	return tag
}

// installed returns image with hostlint installed as a real host has it:
// /usr/local/bin/hostlint, owned by root. A bind mount would show the
// builder's uid (1001 on CI runners), which the image does not know, as an
// unowned file.
func installed(t *testing.T, bin, image, name string) string {
	t.Helper()
	tag := "hostlint-e2e/" + name + ":scan"
	dockerfile := "FROM " + image + "\nCOPY --chown=0:0 hostlint /usr/local/bin/hostlint\n"
	runInput(t, dockerfile, "docker", "build", "--quiet", "--tag", tag, "--file", "-", bin)
	return tag
}

// scan runs hostlint in a container without network access and returns
// its result.
func scan(t *testing.T, image string) *engine.Result {
	t.Helper()
	out := run(t, "docker", "run", "--rm", "--network", "none", "--hostname", "e2e-host",
		image, "/usr/local/bin/hostlint", "scan", "--format", "json", "--fail-on", "none")
	var res engine.Result
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("result: %v\n%.500s", err, out)
	}
	return &res
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	return runInput(t, "", name, args...)
}

// dockerSlots limits the docker commands that run at once: the subtests run
// in parallel, and many simultaneous package installs and image pulls
// exhaust mirrors and registry rate limits.
var dockerSlots = make(chan struct{}, 4)

// runInput runs a command with stdin and returns its standard output.
func runInput(t *testing.T, stdin, name string, args ...string) string {
	t.Helper()
	if name == "docker" {
		dockerSlots <- struct{}{}
		defer func() { <-dockerSlots }()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String()
}

// archNames are the parts of a result that depend on the architecture the
// container runs on; the goldens hold the amd64 spelling.
var archNames = strings.NewReplacer("aarch64-linux-gnu", "x86_64-linux-gnu", ".aarch64", ".x86_64", "CentOS Linux 7 (AltArch)", "CentOS Linux 7 (Core)")

var spaces = regexp.MustCompile(`[ \t]+\n`)

// summary is the part of a result that the goldens compare: the OS, every
// control and check with its status, reason and evidence, and the
// collectors that did not see everything. Times, IDs and versions are left
// out.
// maxGoldenEvidence is how many evidence lines of a check the goldens keep.
const maxGoldenEvidence = 8

func summary(r *engine.Result) string {
	var b strings.Builder
	o := r.Host.OS
	fmt.Fprintf(&b, "os: %s (id %s, version %s, family %s, supported %v)\n", o.Name, o.ID, o.VersionID, o.Family, o.Supported)
	for _, p := range r.Profiles {
		s := r.Summary[p.ID]
		fmt.Fprintf(&b, "profile %s revision %d:", p.ID, p.Revision)
		for _, st := range engine.Statuses() {
			if n := s.Controls[st]; n > 0 {
				fmt.Fprintf(&b, " %s %d", st, n)
			}
		}
		b.WriteByte('\n')
	}
	for _, c := range r.Collectors {
		if c.Status != "ok" || !c.Complete {
			fmt.Fprintf(&b, "collector %s: %s, complete %v %s %v\n", c.Name, c.Status, c.Complete, c.Error, c.Skipped)
		}
	}
	checks := map[string]engine.CheckResult{}
	for _, c := range r.Checks {
		checks[c.Ref] = c
	}
	for _, c := range r.Controls {
		fmt.Fprintf(&b, "\n%s %s\n", c.ID, c.Status)
		for _, ref := range c.Checks {
			k := checks[ref]
			fmt.Fprintf(&b, "  %s %s", k.ID, k.Status)
			if k.Reason != "" {
				fmt.Fprintf(&b, ": %s", oneLine(k.Reason))
			}
			b.WriteByte('\n')
			// The first evidence lines only: a long list (every unit file of a
			// directory) differs between architectures, and its length is not
			// what the golden is for.
			for i, e := range k.Evidence {
				if i == maxGoldenEvidence {
					break
				}
				fmt.Fprintf(&b, "    - %s", oneLine(e.Text))
				if e.Source != "" {
					fmt.Fprintf(&b, "  [%s]", e.Source)
				}
				b.WriteByte('\n')
			}
			if len(k.Evidence) > maxGoldenEvidence || k.EvidenceOmitted > 0 {
				b.WriteString("    - …\n")
			}
		}
	}
	return spaces.ReplaceAllString(archNames.Replace(b.String()), "\n")
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// diff shows the lines that differ, with a little context.
func diff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	var b strings.Builder
	shown := 0
	for i := 0; i < max(len(w), len(g)) && shown < 40; i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			fmt.Fprintf(&b, "line %d:\n  want: %s\n  got:  %s\n", i+1, wl, gl)
			shown++
		}
	}
	return b.String()
}
