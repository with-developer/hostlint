package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/engine"
)

func packImage(t *testing.T, motdMode int64) string {
	t.Helper()
	return imageArchiveModes(t, "app:1",
		map[string]string{"etc/os-release": "ID=debian\nVERSION_ID=\"12\"\nNAME=\"Debian GNU/Linux\"\n", "etc/motd": "hello\n", "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"},
		map[string]int64{"etc/motd": motdMode})
}

func scanJSON(t *testing.T, args ...string) (*engine.Result, string) {
	t.Helper()
	code, out, stderr := run(context.Background(), t, append([]string{"scan", "--format", "json", "--fail-on", "none"}, args...)...)
	if code != ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	var res engine.Result
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("%v\n%.300s", err, out)
	}
	return &res, stderr
}

func TestScanWithAPack(t *testing.T) {
	pack := copyExamplePack(t)
	img := packImage(t, 0o666)
	res, stderr := scanJSON(t, "--image-tar", img, "--pack", pack, "-p", "x-acme-baseline")
	if len(res.Scan.Packs) != 1 || res.Scan.Packs[0].Name != "acme" || res.Scan.Packs[0].Version != "1.0.0" || !strings.HasPrefix(res.Scan.Packs[0].Digest, "sha256:") {
		t.Errorf("packs = %+v", res.Scan.Packs)
	}
	if len(res.Profiles) != 1 || res.Profiles[0].ID != "x-acme-baseline" {
		t.Errorf("profiles = %+v", res.Profiles)
	}
	statuses := map[string]engine.Status{}
	for _, c := range res.Controls {
		statuses[c.ID] = c.Status
	}
	if statuses["ACME-03"] != engine.StatusFail || len(statuses) != 3 {
		t.Errorf("controls = %v", statuses)
	}
	// ACME-02 sets max_days 60: stricter than the check's 90, and recorded.
	var sawStricter bool
	for _, c := range res.Checks {
		if c.ID == "accounts.password-max-age" && c.Params["max_days"] == float64(60) {
			sawStricter = true
		}
	}
	if !sawStricter {
		t.Error("the parameter of the pack's profile did not reach the check")
	}
	if !strings.Contains(stderr, "using pack acme 1.0.0 (sha256:") {
		t.Errorf("stderr = %q", stderr)
	}
	// The same through the environment, and the pack's compliant file passes.
	t.Setenv("HOSTLINT_PACK", pack)
	res, _ = scanJSON(t, "--image-tar", packImage(t, 0o644), "-p", "x-acme-baseline")
	for _, c := range res.Controls {
		if c.ID == "ACME-03" && c.Status != engine.StatusPass {
			t.Errorf("ACME-03 = %s", c.Status)
		}
	}
}

func TestScanSeveralProfiles(t *testing.T) {
	res, _ := scanJSON(t, "--image-tar", packImage(t, 0o644), "-p", "kisa-2026", "-p", "essentials")
	if len(res.Profiles) != 2 || res.Summary["kisa-2026"].Controls == nil || res.Summary["essentials"].Controls == nil {
		t.Fatalf("profiles %+v summary %+v", res.Profiles, res.Summary)
	}
	n := map[string]int{}
	for _, c := range res.Controls {
		n[c.Profile]++
	}
	if n["kisa-2026"] != 67 || n["essentials"] != 20 {
		t.Errorf("controls per profile = %v", n)
	}
	// A profile twice is one profile.
	res, _ = scanJSON(t, "--image-tar", packImage(t, 0o644), "-p", "essentials", "-p", "essentials")
	if len(res.Profiles) != 1 {
		t.Errorf("profiles = %+v", res.Profiles)
	}
}

func TestScanPackRefusals(t *testing.T) {
	pack := copyExamplePack(t)
	img := packImage(t, 0o644)
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no profile of the pack":  {[]string{"--pack", pack}, "none of its profiles is selected: add --profile x-acme-baseline"},
		"only another profile":    {[]string{"--pack", pack, "-p", "essentials"}, "none of its profiles is selected"},
		"verify without a pack":   {[]string{"--verify-pack"}, "--verify-pack is for --pack"},
		"a directory that is not": {[]string{"--pack", t.TempDir(), "-p", "x-acme-baseline"}, "pack.yaml is missing"},
		"an unknown profile":      {[]string{"-p", "x-nothing"}, "unknown profile"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := run(context.Background(), t, append([]string{"scan", "--image-tar", img, "--fail-on", "none"}, tc.args...)...)
			if code != ExitError || !strings.Contains(stderr, tc.want) {
				t.Errorf("exit %d, stderr %q; want %q", code, stderr, tc.want)
			}
		})
	}
}

func TestVerifyPackStopsABrokenPack(t *testing.T) {
	pack := copyExamplePack(t)
	check := filepath.Join(pack, "rules", "x-acme", "motd-owned-by-root.yaml")
	data, _ := os.ReadFile(check)
	broken := strings.Replace(string(data), "/etc/motd: {mode: \"0666\"}\n    want: FAIL", "/etc/motd: {mode: \"0644\"}\n    want: FAIL", 1)
	if err := os.WriteFile(check, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	img := packImage(t, 0o644)
	code, out, stderr := run(context.Background(), t, "scan", "--image-tar", img, "--pack", pack, "-p", "x-acme-baseline", "--fail-on", "none", "--verify-pack")
	if code != ExitError || !strings.Contains(stderr, "fails 1 of its own tests: not scanning with it") || out != "" {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, stderr)
	}
	// Without --verify-pack the scan goes on: the tests are for the pack's own CI.
	if code, _, _ := run(context.Background(), t, "scan", "--image-tar", img, "--pack", pack, "-p", "x-acme-baseline", "--fail-on", "none"); code != ExitOK {
		t.Errorf("exit %d", code)
	}
}

func TestPackControlWaiversNameTheDigest(t *testing.T) {
	pack := copyExamplePack(t)
	img := packImage(t, 0o666) // ACME-03 fails
	dir := t.TempDir()
	cfg := func(extra string) string {
		p := filepath.Join(dir, "hostlint.yaml")
		body := "waivers:\n  - control: ACME-03\n    revision: 1\n    reason: the banner is managed elsewhere\n    expires: 2099-01-01\n" + extra
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	args := func(config string) []string {
		return []string{"scan", "--image-tar", img, "--pack", pack, "-p", "x-acme-baseline", "--fail-on", "none", "--config", config}
	}
	// Without the digest the configuration is refused, and the message gives the digest to use.
	code, _, stderr := run(context.Background(), t, args(cfg(""))...)
	if code != ExitError || !strings.Contains(stderr, "needs its digest (digest: sha256:") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	digest := stderr[strings.Index(stderr, "digest: sha256:")+len("digest: "):][:len("sha256:")+64]
	res := scanWithConfig(t, args(cfg("    digest: "+digest+"\n")))
	var waived bool
	for _, c := range res.Controls {
		waived = waived || (c.ID == "ACME-03" && c.Status == engine.StatusWaived)
	}
	if !waived {
		t.Error("the waiver with the right digest did not apply")
	}
	// A waiver for another content of the profile is stale, and the control still fails.
	wrong := "sha256:" + strings.Repeat("0", 64)
	res = scanWithConfig(t, args(cfg("    digest: "+wrong+"\n")))
	var stale bool
	for _, w := range res.Waivers {
		stale = stale || strings.Contains(w.Problem, "stale: written for another content")
	}
	if !stale {
		t.Errorf("waivers = %+v", res.Waivers)
	}
}

func scanWithConfig(t *testing.T, args []string) *engine.Result {
	t.Helper()
	code, out, stderr := run(context.Background(), t, append(args, "--format", "json")...)
	if code != ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	var res engine.Result
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	return &res
}

func TestPushWithAPackIsRefused(t *testing.T) {
	t.Setenv("HOSTLINT_TOKEN", "hlt_ing_x")
	code, _, stderr := run(context.Background(), t, "scan", "--pack", copyExamplePack(t), "-p", "x-acme-baseline", "--push", "https://x.example")
	if code != ExitError || !strings.Contains(stderr, "not for a scan with a policy pack") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}
