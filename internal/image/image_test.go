package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/hostfs"
)

type ent struct {
	name string
	typ  byte // 0 means a regular file, or a directory when the name ends in "/"
	body string
	link string
	mode int64
	uid  int
}

// layerTar makes the tar of one layer.
func layerTar(t testing.TB, entries ...ent) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
			if strings.HasSuffix(e.name, "/") {
				typ = tar.TypeDir
			}
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
			if typ == tar.TypeDir {
				mode = 0o755
			}
		}
		h := &tar.Header{Name: e.name, Typeflag: typ, Mode: mode, Uid: e.uid, Linkname: e.link}
		if typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gz(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

func hexsum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

type file struct {
	name string
	body []byte
	link string
}

func outer(t testing.TB, files ...file) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		h := &tar.Header{Name: f.name, Mode: 0o644, Typeflag: tar.TypeReg, Size: int64(len(f.body))}
		if f.link != "" {
			h = &tar.Header{Name: f.name, Typeflag: tar.TypeSymlink, Linkname: f.link, Mode: 0o777}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if f.link == "" {
			_, _ = tw.Write(f.body)
		}
	}
	_ = tw.Close()
	return buf.Bytes()
}

func jsonOf(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// dockerArchive is what docker save writes: layer files, a configuration, manifest.json last.
func dockerArchive(t testing.TB, tags []string, layers ...[]byte) []byte {
	t.Helper()
	var files []file
	var names, diffs []string
	for i, l := range layers {
		name := string(rune('a'+i)) + "/layer.tar"
		files = append(files, file{name: name, body: l})
		names = append(names, name)
		unpacked := l
		if zr, err := gzip.NewReader(bytes.NewReader(l)); err == nil {
			var out bytes.Buffer
			_, _ = out.ReadFrom(zr)
			unpacked = out.Bytes()
		}
		diffs = append(diffs, "sha256:"+hexsum(unpacked))
	}
	cfg := jsonOf(t, map[string]any{"architecture": "amd64", "os": "linux", "rootfs": map[string]any{"type": "layers", "diff_ids": diffs}})
	files = append(files, file{name: "config.json", body: cfg})
	files = append(files, file{name: "manifest.json", body: jsonOf(t, []map[string]any{{"Config": "config.json", "RepoTags": tags, "Layers": names}})})
	return outer(t, files...)
}

// ociArchive is an OCI layout: blobs by digest, index.json.
func ociArchive(t testing.TB, layers ...[]byte) []byte {
	t.Helper()
	return ociArchiveAnnotated(t, map[string]string{"org.opencontainers.image.ref.name": "app:1"}, layers...)
}

// ociArchiveAnnotated is ociArchive with the annotations of the manifest entry in index.json.
func ociArchiveAnnotated(t testing.TB, annotations map[string]string, layers ...[]byte) []byte {
	t.Helper()
	var files []file
	var descs []map[string]any
	var diffs []string
	for _, l := range layers {
		files = append(files, file{name: "blobs/sha256/" + hexsum(l), body: l})
		descs = append(descs, map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:" + hexsum(l), "size": len(l)})
		unpacked := l
		if zr, err := gzip.NewReader(bytes.NewReader(l)); err == nil {
			var out bytes.Buffer
			_, _ = out.ReadFrom(zr)
			unpacked = out.Bytes()
		}
		diffs = append(diffs, "sha256:"+hexsum(unpacked))
	}
	cfg := jsonOf(t, map[string]any{"architecture": "amd64", "os": "linux", "rootfs": map[string]any{"type": "layers", "diff_ids": diffs}})
	files = append(files, file{name: "blobs/sha256/" + hexsum(cfg), body: cfg})
	manifest := jsonOf(t, map[string]any{"schemaVersion": 2, "config": map[string]any{"digest": "sha256:" + hexsum(cfg)}, "layers": descs})
	files = append(files, file{name: "blobs/sha256/" + hexsum(manifest), body: manifest})
	files = append(files, file{name: "index.json", body: jsonOf(t, map[string]any{"schemaVersion": 2, "manifests": []map[string]any{{
		"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + hexsum(manifest),
		"annotations": annotations,
	}}})})
	return outer(t, files...)
}

func load(t *testing.T, archive []byte) (*Image, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(p, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(context.Background(), p)
}

func mustLoad(t *testing.T, archive []byte) *Image {
	t.Helper()
	img, err := load(t, archive)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func read(t *testing.T, img *Image, name string) string {
	t.Helper()
	b, err := img.FS.ReadFile(name)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return string(b)
}

func missing(t *testing.T, img *Image, name string) {
	t.Helper()
	if _, err := img.FS.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s should be gone: %v", name, err)
	}
}

func TestDockerSaveAndOCIAreTheSameImage(t *testing.T) {
	l1 := layerTar(t,
		ent{name: "etc/", mode: 0o755}, ent{name: "etc/os-release", body: "ID=debian\n"},
		ent{name: "usr/bin/", mode: 0o755}, ent{name: "usr/bin/su", body: "x", mode: 0o4755},
		ent{name: "bin", typ: tar.TypeSymlink, link: "usr/bin"},
		ent{name: "dev/null", typ: tar.TypeChar},
	)
	l2 := layerTar(t, ent{name: "etc/os-release", body: "ID=debian\nVERSION_ID=12\n"}, ent{name: "bin/extra", body: "e"})
	for name, archive := range map[string][]byte{
		"docker":      dockerArchive(t, []string{"app:1"}, l1, l2),
		"docker gzip": dockerArchive(t, []string{"app:1"}, gz(t, l1), gz(t, l2)),
		"oci":         ociArchive(t, gz(t, l1), gz(t, l2)),
		"oci plain":   ociArchive(t, l1, l2),
	} {
		t.Run(name, func(t *testing.T) {
			img := mustLoad(t, archive)
			if img.Label != "app:1" && !strings.HasPrefix(name, "oci") {
				t.Errorf("label %q", img.Label)
			}
			if img.Layers != 2 {
				t.Errorf("layers %d", img.Layers)
			}
			if got := read(t, img, "/etc/os-release"); got != "ID=debian\nVERSION_ID=12\n" {
				t.Errorf("os-release = %q", got)
			}
			fi, err := img.FS.Stat("/usr/bin/su")
			if err != nil || fi.Perm() != 0o4755 {
				t.Errorf("su: %+v %v", fi, err)
			}
			// /bin is a link to usr/bin: a file added through it lands in usr/bin.
			if got := read(t, img, "/usr/bin/extra"); got != "e" {
				t.Errorf("extra = %q", got)
			}
			if li, err := img.FS.Lstat("/dev/null"); err != nil || li.Mode&fs.ModeCharDevice == 0 {
				t.Errorf("null: %+v %v", li, err)
			}
			if tgt, err := img.FS.ReadLink("/bin"); err != nil || tgt != "usr/bin" {
				t.Errorf("link %q %v", tgt, err)
			}
		})
	}
}

func TestWhiteoutsOnlyRemoveWhatLowerLayersHave(t *testing.T) {
	l1 := layerTar(t,
		ent{name: "a/"}, ent{name: "a/keep", body: "1"}, ent{name: "a/gone", body: "2"},
		ent{name: "d/"}, ent{name: "d/x", body: "3"},
		ent{name: "o/"}, ent{name: "o/old", body: "4"},
		ent{name: "w/"}, ent{name: "w/old", body: "5"},
	)
	l2 := layerTar(t,
		ent{name: "a/.wh.gone"},
		ent{name: ".wh.d"},                                         // the whole directory goes
		ent{name: "o/new", body: "6"}, ent{name: "o/.wh..wh..opq"}, // opaque after the layer's own entry: it stays
		ent{name: "w/fresh", body: "7"}, ent{name: ".wh.w"}, // a directory with entries of this layer stays
		ent{name: ".wh..wh.plnk/", mode: 0o700},
	)
	img := mustLoad(t, dockerArchive(t, nil, l1, l2))
	if read(t, img, "/a/keep") != "1" {
		t.Error("a/keep")
	}
	missing(t, img, "/a/gone")
	missing(t, img, "/d")
	missing(t, img, "/d/x")
	if read(t, img, "/o/new") != "6" {
		t.Error("o/new went with the opaque marker of its own layer")
	}
	missing(t, img, "/o/old")
	if read(t, img, "/w/fresh") != "7" {
		t.Error("w/fresh")
	}
	missing(t, img, "/w/old")
	// A whiteout in a later layer takes the directory of an earlier one with its entries.
	l3 := layerTar(t, ent{name: ".wh.o"})
	img = mustLoad(t, dockerArchive(t, nil, l1, l2, l3))
	missing(t, img, "/o")
}

func TestReplacedEntries(t *testing.T) {
	l1 := layerTar(t, ent{name: "x/"}, ent{name: "x/inner", body: "1"}, ent{name: "y", body: "file"}, ent{name: "z", typ: tar.TypeSymlink, link: "y"})
	l2 := layerTar(t, ent{name: "x", body: "now a file"}, ent{name: "y/"}, ent{name: "y/child", body: "2"}, ent{name: "z", body: "not a link"})
	img := mustLoad(t, dockerArchive(t, nil, l1, l2))
	if read(t, img, "/x") != "now a file" {
		t.Error("a file over a directory")
	}
	missing(t, img, "/x/inner")
	if read(t, img, "/y/child") != "2" {
		t.Error("a directory over a file")
	}
	if li, _ := img.FS.Lstat("/z"); li.IsSymlink() || read(t, img, "/z") != "not a link" {
		t.Error("a file over a link")
	}
}

func TestHardLinks(t *testing.T) {
	l1 := layerTar(t,
		ent{name: "etc/"}, ent{name: "etc/shadow", body: "root:$6$hash::", mode: 0o640},
		ent{name: "usr/bin/"}, ent{name: "usr/bin/su", body: "binary", mode: 0o4755},
	)
	l2 := layerTar(t,
		ent{name: "tmp/"},
		ent{name: "tmp/su", typ: tar.TypeLink, link: "usr/bin/su", mode: 0o644}, // the header's mode does not count
		ent{name: "tmp/leak", typ: tar.TypeLink, link: "/etc/shadow"},
	)
	img := mustLoad(t, dockerArchive(t, nil, l1, l2))
	fi, err := img.FS.Stat("/tmp/su")
	if err != nil || fi.Perm() != 0o4755 || fi.Nlink != 2 {
		t.Errorf("link: %+v %v", fi, err)
	}
	if read(t, img, "/tmp/su") != "binary" {
		t.Error("content of a link")
	}
	if _, err := img.FS.ReadFile("/tmp/leak"); !errors.Is(err, hostfs.ErrDenied) {
		t.Errorf("a hard link to the shadow file was readable: %v", err)
	}
	// A link to nothing, or to a directory, is not an image.
	for _, bad := range []ent{{name: "l", typ: tar.TypeLink, link: "nowhere"}, {name: "l", typ: tar.TypeLink, link: "etc"}} {
		if _, err := load(t, dockerArchive(t, nil, l1, layerTar(t, bad))); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
}

func TestBigFilesAreNotAbsent(t *testing.T) {
	big := strings.Repeat("x", hostfs.ImageKeepSize+1)
	l := layerTar(t, ent{name: "etc/"}, ent{name: "etc/big.conf", body: big}, ent{name: "var/lib/dpkg/"}, ent{name: "var/lib/dpkg/status", body: big}, ent{name: "etc/empty"})
	img := mustLoad(t, dockerArchive(t, nil, l))
	fi, err := img.FS.Stat("/etc/big.conf")
	if err != nil || fi.Size != int64(len(big)) {
		t.Fatalf("size: %+v %v", fi, err)
	}
	if _, err := img.FS.ReadFile("/etc/big.conf"); !errors.Is(err, hostfs.ErrTooLarge) {
		t.Errorf("a file whose contents were not kept: %v", err)
	}
	if got, err := hostfs.ReadLargeFile(img.FS, "/var/lib/dpkg/status", 1<<30); err != nil || len(got) != len(big) {
		t.Errorf("the package database: %d %v", len(got), err)
	}
	if got, err := img.FS.ReadFile("/etc/empty"); err != nil || got == nil || len(got) != 0 {
		t.Errorf("an empty file: %v %v", got, err)
	}
}

func TestStrictRefusals(t *testing.T) {
	ok := layerTar(t, ent{name: "etc/"}, ent{name: "etc/os-release", body: "ID=x\n"})
	zstd := append([]byte{0x28, 0xb5, 0x2f, 0xfd}, make([]byte, 64)...)
	wrongDiff := func() []byte {
		a := dockerArchive(t, nil, ok)
		return bytes.Replace(a, []byte(hexsum(ok)), []byte(strings.Repeat("0", 64)), 1)
	}
	two := outer(t, file{name: "manifest.json", body: jsonOf(t, []map[string]any{{"Config": "c", "RepoTags": []string{"a:1"}, "Layers": []string{}}, {"Config": "c", "RepoTags": []string{"b:1"}, "Layers": []string{}}})})
	windows := outer(t, file{name: "c", body: jsonOf(t, map[string]any{"os": "windows", "rootfs": map[string]any{"diff_ids": []string{}}})}, file{name: "manifest.json", body: jsonOf(t, []map[string]any{{"Config": "c", "Layers": []string{}}})})
	missingLayer := outer(t, file{name: "c", body: jsonOf(t, map[string]any{"os": "linux", "rootfs": map[string]any{"diff_ids": []string{"sha256:" + hexsum(ok)}}})}, file{name: "manifest.json", body: jsonOf(t, []map[string]any{{"Config": "c", "Layers": []string{"nope/layer.tar"}}})})
	for name, tc := range map[string]struct {
		archive []byte
		want    string
	}{
		"not a tar":             {[]byte(strings.Repeat("hello ", 200)), "tar"},
		"gzip outer":            {gz(t, dockerArchive(t, nil, ok)), "gzip-compressed"},
		"neither manifest":      {outer(t, file{name: "x", body: []byte("y")}), "neither manifest.json"},
		"two images":            {two, "2 images"},
		"zstd layer":            {dockerArchive(t, nil, zstd), "zstd"},
		"digest in config":      {wrongDiff(), "does not match"},
		"windows":               {windows, "windows"},
		"missing layer":         {missingLayer, "missing"},
		"escape":                {dockerArchive(t, nil, layerTar(t, ent{name: "../evil", body: "x"})), "climbs out"},
		"escape through a dir":  {dockerArchive(t, nil, layerTar(t, ent{name: "a/../../evil", body: "x"})), "climbs out"},
		"unsupported type":      {dockerArchive(t, nil, layerTar(t, ent{name: "f", typ: tar.TypeCont})), "not supported"},
		"empty whiteout":        {dockerArchive(t, nil, layerTar(t, ent{name: ".wh."})), "whiteout"},
		"link loop as a parent": {dockerArchive(t, nil, layerTar(t, ent{name: "a", typ: tar.TypeSymlink, link: "b"}, ent{name: "b", typ: tar.TypeSymlink, link: "a"}, ent{name: "a/x", body: "1"})), "symbolic links"},
		"a file as a parent":    {dockerArchive(t, nil, layerTar(t, ent{name: "f", body: "1"}, ent{name: "f/x", body: "2"})), "not a directory"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, tc.archive)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := Load(context.Background(), filepath.Join(t.TempDir(), "missing.tar")); err == nil {
		t.Error("a missing file")
	}
	if _, err := Load(context.Background(), t.TempDir()); err == nil {
		t.Error("a directory")
	}
}

func TestOuterLinksAndDuplicates(t *testing.T) {
	l := layerTar(t, ent{name: "etc/"}, ent{name: "etc/os-release", body: "ID=x\n"})
	cfg := jsonOf(t, map[string]any{"os": "linux", "rootfs": map[string]any{"diff_ids": []string{"sha256:" + hexsum(l)}}})
	man := jsonOf(t, []map[string]any{{"Config": "c.json", "Layers": []string{"b/layer.tar"}}})
	// docker save links layers that several images share.
	img := mustLoad(t, outer(t, file{name: "a/layer.tar", body: l}, file{name: "b/layer.tar", link: "../a/layer.tar"}, file{name: "c.json", body: cfg}, file{name: "manifest.json", body: man}))
	if read(t, img, "/etc/os-release") != "ID=x\n" {
		t.Error("a linked layer")
	}
	if _, err := load(t, outer(t, file{name: "a/layer.tar", body: l}, file{name: "a/layer.tar", body: l}, file{name: "c.json", body: cfg}, file{name: "manifest.json", body: man})); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a name twice: %v", err)
	}
	if _, err := load(t, outer(t, file{name: "b/layer.tar", link: "../../outside"}, file{name: "c.json", body: cfg}, file{name: "manifest.json", body: man})); err == nil {
		t.Error("a link out of the archive")
	}
}

func TestOCIRefusals(t *testing.T) {
	l := layerTar(t, ent{name: "etc/"})
	a := ociArchive(t, l)
	// A blob that does not match its name.
	bad := bytes.Replace(a, []byte(`"layers"`), []byte(`"layerz"`), 1)
	if _, err := load(t, bad); err == nil {
		t.Error("a changed manifest")
	}
	idx := outer(t, file{name: "index.json", body: jsonOf(t, map[string]any{"manifests": []map[string]any{{"digest": "sha256:" + hexsum(l)}, {"digest": "sha256:" + hexsum(l)}}})})
	if _, err := load(t, idx); err == nil || !strings.Contains(err.Error(), "2 manifests") {
		t.Errorf("two manifests: %v", err)
	}
	multi := outer(t, file{name: "index.json", body: jsonOf(t, map[string]any{"manifests": []map[string]any{{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": "sha256:" + hexsum(l)}}})})
	if _, err := load(t, multi); err == nil || !strings.Contains(err.Error(), "multi-platform") {
		t.Errorf("a nested index: %v", err)
	}
}

func TestLabelsAreCleaned(t *testing.T) {
	img := mustLoad(t, dockerArchive(t, []string{"evil\n::error::x\x1b[31m:1"}, layerTar(t, ent{name: "etc/"})))
	if strings.ContainsAny(img.Label, "\n\x1b ") {
		t.Errorf("label %q", img.Label)
	}
}

func TestInterrupted(t *testing.T) {
	p := filepath.Join(t.TempDir(), "i.tar")
	if err := os.WriteFile(p, dockerArchive(t, nil, layerTar(t, ent{name: "etc/"}, ent{name: "etc/a", body: "x"})), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Load(ctx, p); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func FuzzLoad(f *testing.F) {
	f.Add([]byte("not a tar"))
	l1 := layerTar(f, ent{name: "etc/"}, ent{name: "etc/os-release", body: "ID=x\n"}, ent{name: "bin", typ: tar.TypeSymlink, link: "usr/bin"}, ent{name: "usr/bin/"},
		ent{name: "usr/bin/su", body: "x", mode: 0o4755}, ent{name: "etc/shadow", body: "root:x"}, ent{name: "tmp/su", typ: tar.TypeLink, link: "usr/bin/su"})
	l2 := layerTar(f, ent{name: ".wh.etc"}, ent{name: "usr/bin/.wh..wh..opq"}, ent{name: "a/"}, ent{name: "a/../b", body: "1"}, ent{name: "dev/null", typ: tar.TypeChar})
	f.Add(dockerArchive(f, []string{"app:1"}, l1, l2))
	f.Add(dockerArchive(f, nil, gz(f, l1)))
	f.Add(ociArchive(f, gz(f, l1), l2))
	f.Add(ociArchive(f, l1))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(t.TempDir(), "f.tar")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Skip()
		}
		if img, err := Load(context.Background(), p); err == nil && img.FS == nil {
			t.Fatal("no filesystem and no error")
		}
	})
}

// A tar whose first name begins with the letters of the bzip2 magic is a tar.
func TestPlainTarStartingWithBZh(t *testing.T) {
	l := layerTar(t, ent{name: "BZh-cache/"}, ent{name: "BZh-cache/x", body: "1"}, ent{name: "etc/"}, ent{name: "etc/os-release", body: "ID=x\n"})
	img := mustLoad(t, dockerArchive(t, nil, l))
	if read(t, img, "/BZh-cache/x") != "1" {
		t.Error("the layer was not read")
	}
	if _, err := load(t, append([]byte("BZh91AY&SY"), make([]byte, 600)...)); err == nil || !strings.Contains(err.Error(), "bzip2") {
		t.Errorf("a real bzip2 header: %v", err)
	}
}

func TestHostileNamesDoNotReachTheTerminalRaw(t *testing.T) {
	_, err := load(t, dockerArchive(t, nil, layerTar(t, ent{name: "\x1b]0;pwned\x07", typ: tar.TypeCont})))
	if err == nil || strings.ContainsAny(err.Error(), "\x1b\x07") {
		t.Errorf("err = %q", err)
	}
}

// What an archive names the image with: a reference (repository, with or without a tag) is the image's name; a bare tag, as
// OCI layouts often have in ref.name, is only a label; and the containerd annotation, which holds the full reference, wins.
func TestImageReference(t *testing.T) {
	layer := layerTar(t, ent{name: "etc/", mode: 0o755}, ent{name: "etc/os-release", body: "ID=debian\n"})
	for name, tc := range map[string]struct {
		archive   []byte
		ref, want string
	}{
		"docker save":                  {dockerArchive(t, []string{"ghcr.io/acme/app:1.4"}, layer), "ghcr.io/acme/app:1.4", "ghcr.io/acme/app:1.4"},
		"docker save without a tag":    {dockerArchive(t, nil, layer), "", ""},
		"docker save, an empty tag":    {dockerArchive(t, []string{""}, layer), "", ""},
		"docker save, <none>":          {dockerArchive(t, []string{"<none>:<none>"}, layer), "", ""},
		"oci, a reference in ref.name": {ociArchiveAnnotated(t, map[string]string{"org.opencontainers.image.ref.name": "app:1"}, layer), "app:1", "app:1"},
		"oci, a bare tag":              {ociArchiveAnnotated(t, map[string]string{"org.opencontainers.image.ref.name": "latest"}, layer), "", ""},
		"oci, containerd wins":         {ociArchiveAnnotated(t, map[string]string{"org.opencontainers.image.ref.name": "latest", "io.containerd.image.name": "docker.io/library/nginx:latest"}, layer), "docker.io/library/nginx:latest", "docker.io/library/nginx:latest"},
		"oci, no annotation":           {ociArchiveAnnotated(t, nil, layer), "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			img := mustLoad(t, tc.archive)
			if img.Ref != tc.ref {
				t.Errorf("Ref = %q, want %q", img.Ref, tc.ref)
			}
			if tc.ref != "" && img.Label != tc.want {
				t.Errorf("Label = %q, want %q", img.Label, tc.want)
			}
			if !strings.HasPrefix(img.Digest, "sha256:") || len(img.Digest) != len("sha256:")+64 {
				t.Errorf("Digest = %q", img.Digest)
			}
		})
	}
}
