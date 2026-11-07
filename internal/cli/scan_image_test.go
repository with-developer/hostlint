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

	"github.com/with-developer/hostlint/internal/engine"
)

// imageArchive writes a docker save archive of one layer with the given files.
func imageArchive(t *testing.T, tag string, files map[string]string) string {
	t.Helper()
	var layer bytes.Buffer
	lw := tar.NewWriter(&layer)
	for name, body := range files {
		if err := lw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
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
	p := imageArchive(t, "app:1", map[string]string{"etc/os-release": osRelease, "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"})
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
		{[]string{"scan", "--image-tar", good, "--push", "https://x.example"}, "no host identity"},
		{[]string{"scan", "--image-tar", filepath.Join(t.TempDir(), "missing.tar")}, "--image-tar"},
	} {
		code, _, stderr := run(context.Background(), t, tc.args...)
		if code != ExitError || !strings.Contains(stderr, tc.want) {
			t.Errorf("%v: exit %d, stderr %q; want %q", tc.args, code, stderr, tc.want)
		}
	}
}
