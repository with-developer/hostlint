package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/with-developer/vmsctl/internal/engine"
)

// imageArchive writes a docker save archive of one layer with the given files.
func imageArchive(t *testing.T, tag string, files map[string]string) string {
	t.Helper()
	return imageArchiveModes(t, tag, files, nil)
}

// imageArchiveModes is imageArchive with the mode of some files (0644 for the others).
func imageArchiveModes(t *testing.T, tag string, files map[string]string, modes map[string]int64) string {
	t.Helper()
	var layer bytes.Buffer
	lw := tar.NewWriter(&layer)
	for name, body := range files {
		mode := int64(0o644)
		if m, ok := modes[name]; ok {
			mode = m
		}
		if err := lw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		_, _ = lw.Write([]byte(body))
	}
	_ = lw.Close()
	sum := sha256.Sum256(layer.Bytes())
	cfg, _ := json.Marshal(map[string]any{"os": "linux", "rootfs": map[string]any{"diff_ids": []string{"sha256:" + hex.EncodeToString(sum[:])}}})
	man, _ := json.Marshal([]map[string]any{{"Config": "c.json", "RepoTags": []string{tag}, "Layers": []string{"l/layer.tar"}}})
	var out bytes.Buffer
	ow := tar.NewWriter(&out)
	for _, f := range []struct {
		name string
		body []byte
	}{{"l/layer.tar", layer.Bytes()}, {"c.json", cfg}, {"manifest.json", man}} {
		_ = ow.WriteHeader(&tar.Header{Name: f.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(f.body))})
		_, _ = ow.Write(f.body)
	}
	_ = ow.Close()
	p := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(p, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestScanImage(t *testing.T) {
	osRelease := "ID=debian\nVERSION_ID=\"12\"\nNAME=\"Debian GNU/Linux\"\n"
	p := imageArchive(t, "app:1", map[string]string{"etc/os-release": osRelease, "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n", "etc/machine-id": "0123456789abcdef0123456789abcdef\n"})
	code, stdout, stderr := run(context.Background(), t, "scan", "--image-tar", p, "--format", "json", "--fail-on", "none")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var res engine.Result
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("%v\n%.300s", err, stdout)
	}
	if res.Scan.Target.Kind != "root" || res.Scan.Target.Root != "image:app:1" || res.Host.Hostname != "app:1" {
		t.Errorf("target %+v host %q", res.Scan.Target, res.Host.Hostname)
	}
	if res.Host.HostID != "" {
		t.Errorf("an image has no machine ID, got host ID %q", res.Host.HostID)
	}
	if res.Host.OS.ID != "debian" {
		t.Errorf("os %+v", res.Host.OS)
	}
}

func TestScanImageRefusals(t *testing.T) {
	scratch := imageArchive(t, "scratch:1", map[string]string{"app": "binary"})
	good := imageArchive(t, "app:1", map[string]string{"etc/os-release": "ID=debian\nVERSION_ID=\"12\"\n"})
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"scan", "--image-tar", scratch, "--fail-on", "none"}, "no operating system"},
		{[]string{"scan", "--image-tar", good, "--root", "/mnt"}, "exclude each other"},
		{[]string{"scan", "--root", "/", "--name", "x"}, "--name is for --image-tar"},
		{[]string{"scan", "--image-tar", good, "--name", "bad name"}, "--name is letters"},
		{[]string{"scan", "--image-tar", filepath.Join(t.TempDir(), "missing.tar")}, "--image-tar"},
	} {
		code, _, stderr := run(context.Background(), t, tc.args...)
		if code != ExitError || !strings.Contains(stderr, tc.want) {
			t.Errorf("%v: exit %d, stderr %q; want %q", tc.args, code, stderr, tc.want)
		}
	}
}

func TestScanImageErrorsDoNotCarryControlCharacters(t *testing.T) {
	p := imageArchive(t, "app:1", map[string]string{"a": "1", "a/\x1b]0;pwned\x07/x": "2"})
	code, _, stderr := run(context.Background(), t, "scan", "--image-tar", p)
	if code != ExitError || strings.ContainsAny(stderr, "\x1b\x07") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}

func TestScanMarkdown(t *testing.T) {
	p := imageArchive(t, "app:1", map[string]string{"etc/os-release": "ID=debian\nVERSION_ID=\"12\"\nNAME=\"Debian GNU/Linux\"\n"})
	code, stdout, stderr := run(context.Background(), t, "scan", "--image-tar", p, "--format", "markdown", "--fail-on", "none")
	if code != ExitOK || !strings.HasPrefix(stdout, "## vmsctl: app&#58;1") || !strings.Contains(stdout, "| Profile | Controls |") {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
}

// What an image goes by on a fleet server: --name, else the repository of the archive's reference (no tag, no digest,
// but a registry port stays); an archive that names no image needs --name.
func TestAssetName(t *testing.T) {
	for _, tc := range []struct {
		flag, ref, want string
		wantErr         bool
	}{
		{"", "app:1.4", "app", false},
		{"", "ghcr.io/acme/app:1.4", "ghcr.io/acme/app", false},
		{"", "localhost:5000/app", "localhost:5000/app", false},
		{"", "localhost:5000/app:2", "localhost:5000/app", false},
		{"", "ghcr.io/acme/app@sha256:abcd", "ghcr.io/acme/app", false},
		{"", "ghcr.io/acme/app:1.4@sha256:abcd", "ghcr.io/acme/app", false},
		{"my/app", "ghcr.io/acme/app:1.4", "my/app", false},
		{"my/app", "", "my/app", false},
		{"", "", "", true},
		{"bad name", "app:1", "", true},
		{"-lead", "app:1", "", true},
		{"a\nb", "app:1", "", true},
	} {
		got, err := assetName(tc.flag, tc.ref)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("assetName(%q, %q) = %q, %v; want %q (error %v)", tc.flag, tc.ref, got, err, tc.want, tc.wantErr)
		}
	}
}
