// Package image reads a container image archive (what `docker save` or `skopeo copy oci-archive:`
// writes) into a merged in-memory filesystem that the scan reads like a mounted root (ADR 0011).
//
// The archive is untrusted input. Anything ambiguous, over a limit or different from what a container
// runtime would see refuses the whole scan: a partial filesystem would make checks for absent files pass.
// Nothing is written to disk and nothing is run.
package image

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	"github.com/with-developer/vmsctl/internal/hostfs"
)

// Limits on what an archive may do. A hostile archive is bounded by these, whatever it claims.
const (
	maxOuterEntries = 100_000
	maxJSON         = 8 << 20
	maxEntries      = 3_000_000       // entries over all layers
	maxBytes        = int64(16) << 30 // decompressed bytes over all layers
	maxOuterLinks   = 8
)

// Image is a loaded image.
type Image struct {
	// FS is the merged filesystem of the layers.
	FS *hostfs.ImageFS
	// Label names the image in the report: its reference when the archive has one, else the file name.
	Label string
	// Layers is how many layers were applied.
	Layers int
	// Ref is the reference (repository and tag) the archive names the image with, "" when it names none (then Label is
	// the file name). Digest is the image ID: the sha256 of its configuration, as `docker images --no-trunc` shows it.
	Ref    string
	Digest string
}

// Load reads the archive at file. It honors ctx while it reads.
func Load(ctx context.Context, file string) (img *Image, err error) {
	defer func() {
		if r := recover(); r != nil {
			img, err = nil, fmt.Errorf("the image archive could not be read (internal error: %v)", r)
		}
	}()
	f, err := os.Open(file) //nolint:forbidigo,gosec // the archive the user named, not the scanned host (G304)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file: an image archive is read from a file, not a pipe or a device", file)
	}
	var magic [8]byte
	if _, err := io.ReadFull(f, magic[:]); err == nil {
		if kind := compression(magic[:]); kind != "" {
			return nil, fmt.Errorf("%s is %s-compressed: unpack it first (the archive of docker save is a plain tar)", file, kind)
		}
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	idx, err := indexOuter(f)
	if err != nil {
		return nil, err
	}
	p, err := readPlan(f, idx, strings.TrimSuffix(path.Base(file), path.Ext(file)))
	if err != nil {
		return nil, err
	}
	b := hostfs.NewImageBuilder()
	st := &state{ctx: ctx}
	for i, l := range p.layers {
		b.BeginLayer()
		_, e, err := resolveOuter(idx, l.name)
		if err != nil {
			return nil, err
		}
		var diff string
		if i < len(p.diffIDs) {
			diff = p.diffIDs[i]
		}
		if err := applyLayer(io.NewSectionReader(f, e.off, e.size), b, st, l.digest, diff); err != nil {
			return nil, fmt.Errorf("layer %d (%q): %w", i+1, l.name, err)
		}
	}
	loaded := &Image{FS: b.Finish(), Label: p.label, Layers: len(p.layers), Digest: p.configDigest}
	if p.fromRef {
		loaded.Ref = p.label
	}
	return loaded, nil
}

func compression(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte{0x1f, 0x8b}):
		return "gzip"
	case bytes.HasPrefix(b, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return "zstd"
	case bytes.HasPrefix(b, []byte{0xfd, '7', 'z', 'X', 'Z', 0}):
		return "xz"
	case len(b) >= 6 && bytes.HasPrefix(b, []byte("BZh")) && b[3] >= '1' && b[3] <= '9' && b[4] == 0x31 && b[5] == 0x41:
		return "bzip2" // "BZh", the block size, and the start of the first block (0x314159265359)
	}
	return ""
}

// outerEntry is a file of the archive: where its data is, or the link it is.
type outerEntry struct {
	off, size int64
	link      string
}

// indexOuter lists the files of the archive with the offset of their data, so any of them can be read
// later (docker save puts manifest.json after the layers).
func indexOuter(f *os.File) (map[string]outerEntry, error) {
	idx := map[string]outerEntry{}
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("this is not a tar archive: %w", err)
		}
		if len(idx) >= maxOuterEntries {
			return nil, fmt.Errorf("more than %d files in the archive: %w", maxOuterEntries, hostfs.ErrImageLimit)
		}
		var e outerEntry
		switch hdr.Typeflag {
		case tar.TypeReg:
			off, err := f.Seek(0, io.SeekCurrent) // tar reads no more than the header before the data
			if err != nil {
				return nil, err
			}
			e = outerEntry{off: off, size: hdr.Size}
		case tar.TypeSymlink:
			e = outerEntry{link: hdr.Linkname}
		default:
			continue // directories and the rest do not matter here
		}
		name, err := cleanName(hdr.Name)
		if err != nil || name == "/" {
			return nil, fmt.Errorf("the archive has a file named %q", hdr.Name)
		}
		name = strings.TrimPrefix(name, "/")
		if _, dup := idx[name]; dup {
			return nil, fmt.Errorf("the archive has %q twice", name)
		}
		idx[name] = e
	}
	if len(idx) == 0 {
		return nil, errors.New("the archive is empty")
	}
	return idx, nil
}

// resolveOuter follows links of the archive that stay inside it (docker save links shared layers).
func resolveOuter(idx map[string]outerEntry, name string) (string, outerEntry, error) {
	for range maxOuterLinks {
		e, ok := idx[name]
		if !ok {
			return "", outerEntry{}, fmt.Errorf("%q is not in the archive", name)
		}
		if e.link == "" {
			return name, e, nil
		}
		next := e.link
		if !path.IsAbs(next) {
			next = path.Join(path.Dir(name), next)
		}
		next, err := cleanName(next)
		if err != nil {
			return "", outerEntry{}, fmt.Errorf("%q links out of the archive", name)
		}
		name = strings.TrimPrefix(next, "/")
	}
	return "", outerEntry{}, fmt.Errorf("%q: too many links", name)
}

// readOuter returns a small file of the archive (a manifest, a configuration).
func readOuter(f *os.File, idx map[string]outerEntry, name string) ([]byte, error) {
	found, e, err := resolveOuter(idx, name)
	if err != nil {
		return nil, err
	}
	if e.size > maxJSON {
		return nil, fmt.Errorf("%q is %d bytes: %w", found, e.size, hostfs.ErrImageLimit)
	}
	return io.ReadAll(io.NewSectionReader(f, e.off, e.size))
}

type layerRef struct {
	name   string
	digest string // hex sha256 of the layer as stored, when the archive says
}

type plan struct {
	label        string
	fromRef      bool   // the label is a reference the archive names, not the file name
	configDigest string // "sha256:" and the hex of the image configuration: the image ID
	layers       []layerRef
	diffIDs      []string // hex sha256 of each layer unpacked, from the image configuration
}

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	URLs        []string          `json:"urls"`
	Annotations map[string]string `json:"annotations"`
}

type imageConfig struct {
	OS     string `json:"os"`
	RootFS struct {
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

// readPlan finds out which layers make the image, in which order, and what to check them against.
func readPlan(f *os.File, idx map[string]outerEntry, fallbackLabel string) (*plan, error) {
	var p plan
	var configName string
	if _, ok := idx["manifest.json"]; ok {
		raw, err := readOuter(f, idx, "manifest.json")
		if err != nil {
			return nil, err
		}
		var entries []struct {
			Config   string
			RepoTags []string
			Layers   []string
		}
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, fmt.Errorf("manifest.json: %w", err)
		}
		if len(entries) != 1 {
			var tags []string
			for _, e := range entries {
				tags = append(tags, e.RepoTags...)
			}
			return nil, fmt.Errorf("the archive holds %d images (%q): save one image per archive", len(entries), tags)
		}
		e := entries[0]
		configName = e.Config
		p.label = fallbackLabel
		if len(e.RepoTags) > 0 && e.RepoTags[0] != "" && e.RepoTags[0] != "<none>:<none>" {
			p.label = e.RepoTags[0]
			p.fromRef = true
		}
		for _, l := range e.Layers {
			ref := layerRef{name: strings.TrimPrefix(path.Clean("/"+l), "/")}
			if hex, ok := blobHex(ref.name); ok {
				ref.digest = hex
			}
			p.layers = append(p.layers, ref)
		}
	} else if _, ok := idx["index.json"]; ok {
		if err := readOCI(f, idx, &p, &configName, fallbackLabel); err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("this is not an image archive: it has neither manifest.json (docker save) nor index.json (OCI)")
	}
	p.label = sanitizeLabel(p.label)
	for _, l := range p.layers {
		if _, _, err := resolveOuter(idx, l.name); err != nil {
			return nil, fmt.Errorf("a layer is missing from the archive: %w", err)
		}
	}
	if configName == "" {
		return nil, errors.New("the image has no configuration")
	}
	raw, err := readOuter(f, idx, strings.TrimPrefix(path.Clean("/"+configName), "/"))
	if err != nil {
		return nil, fmt.Errorf("the image configuration: %w", err)
	}
	if hex, ok := blobHex(strings.TrimPrefix(path.Clean("/"+configName), "/")); ok && hex != sum(raw) {
		return nil, errors.New("the image configuration does not match its digest")
	}
	p.configDigest = "sha256:" + sum(raw)
	var cfg imageConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("the image configuration: %w", err)
	}
	if cfg.OS != "" && cfg.OS != "linux" {
		return nil, fmt.Errorf("the image is for %q: only linux images can be scanned", cfg.OS)
	}
	if len(cfg.RootFS.DiffIDs) != len(p.layers) {
		return nil, fmt.Errorf("the image configuration lists %d layers, the manifest %d", len(cfg.RootFS.DiffIDs), len(p.layers))
	}
	for _, d := range cfg.RootFS.DiffIDs {
		hex, ok := strings.CutPrefix(d, "sha256:")
		if !ok {
			return nil, fmt.Errorf("layer digest %q: only sha256 is supported", d)
		}
		p.diffIDs = append(p.diffIDs, hex)
	}
	return &p, nil
}

// readOCI reads an OCI layout: index.json names one manifest, the manifest names the layers.
func readOCI(f *os.File, idx map[string]outerEntry, p *plan, configName *string, fallbackLabel string) error {
	raw, err := readOuter(f, idx, "index.json")
	if err != nil {
		return err
	}
	var index struct {
		Manifests []descriptor `json:"manifests"`
	}
	if err := json.Unmarshal(raw, &index); err != nil {
		return fmt.Errorf("index.json: %w", err)
	}
	if len(index.Manifests) != 1 {
		return fmt.Errorf("index.json lists %d manifests: save one image, for one platform, per archive", len(index.Manifests))
	}
	d := index.Manifests[0]
	if strings.Contains(d.MediaType, "index") || strings.Contains(d.MediaType, "manifest.list") {
		return errors.New("the archive holds a multi-platform index: save the image for one platform")
	}
	mname, err := blobName(d.Digest)
	if err != nil {
		return err
	}
	mraw, err := readOuter(f, idx, mname)
	if err != nil {
		return err
	}
	if hex, _ := blobHex(mname); hex != sum(mraw) {
		return errors.New("the manifest does not match its digest")
	}
	var m struct {
		Config descriptor   `json:"config"`
		Layers []descriptor `json:"layers"`
	}
	if err := json.Unmarshal(mraw, &m); err != nil {
		return fmt.Errorf("the manifest: %w", err)
	}
	if *configName, err = blobName(m.Config.Digest); err != nil {
		return err
	}
	for _, l := range m.Layers {
		if len(l.URLs) > 0 {
			return errors.New("a layer is not in the archive (it has to be fetched from a URL)")
		}
		name, err := blobName(l.Digest)
		if err != nil {
			return err
		}
		hex, _ := blobHex(name)
		p.layers = append(p.layers, layerRef{name: name, digest: hex})
	}
	p.label = fallbackLabel
	// io.containerd.image.name holds the full reference; ref.name is often only a tag ("latest"), which is a label to
	// show but not a name for the image.
	for _, key := range []string{"io.containerd.image.name", "org.opencontainers.image.ref.name"} {
		if v := d.Annotations[key]; v != "" {
			p.label = v
			p.fromRef = strings.ContainsAny(v, ":/@") // a repository, or a tag with one
			break
		}
	}
	return nil
}

func blobName(digest string) (string, error) {
	hex, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(hex) != 64 || strings.Trim(hex, "0123456789abcdef") != "" {
		return "", fmt.Errorf("digest %q: only sha256 is supported", digest)
	}
	return "blobs/sha256/" + hex, nil
}

// blobHex is the digest in the name of a blob of an OCI layout.
func blobHex(name string) (string, bool) {
	hex, ok := strings.CutPrefix(name, "blobs/sha256/")
	if !ok || len(hex) != 64 || strings.Trim(hex, "0123456789abcdef") != "" {
		return "", false
	}
	return hex, true
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// sanitizeLabel keeps the label printable: it goes into the report and onto terminals and CI logs.
func sanitizeLabel(s string) string {
	var out strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("._:/@+-", r):
			out.WriteRune(r)
		default:
			out.WriteByte('_')
		}
		if out.Len() >= 200 {
			break
		}
	}
	if out.Len() == 0 {
		return "image"
	}
	return out.String()
}

// cleanName makes a name from a tar header absolute and clean, like a container runtime reads it ("./a",
// "/a", "a//b" and "a/./b" are alike), and refuses one that climbs out of the image.
func cleanName(name string) (string, error) {
	if strings.ContainsRune(name, 0) {
		return "", errors.New("a name with a NUL byte")
	}
	var parts []string
	for _, c := range strings.Split(name, "/") {
		switch c {
		case "", ".":
		case "..":
			if len(parts) == 0 {
				return "", fmt.Errorf("%q climbs out of the image", name)
			}
			parts = parts[:len(parts)-1]
		default:
			parts = append(parts, c)
		}
	}
	return "/" + strings.Join(parts, "/"), nil
}

// state is what the layers share: the bounds are over the whole image.
type state struct {
	ctx     context.Context
	bytes   int64
	entries int
}

// countReader bounds the decompressed bytes and stops when the scan is interrupted.
type countReader struct {
	r  io.Reader
	st *state
}

func (c *countReader) Read(p []byte) (int, error) {
	if err := c.st.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.r.Read(p)
	if c.st.bytes += int64(n); c.st.bytes > maxBytes {
		return n, fmt.Errorf("more than %d GiB unpacked: %w", maxBytes>>30, hostfs.ErrImageLimit)
	}
	return n, err
}

// applyLayer unpacks one layer into the builder and checks it against its digests.
func applyLayer(r io.Reader, b *hostfs.ImageBuilder, st *state, wantStored, wantUnpacked string) error {
	stored, unpacked := sha256.New(), sha256.New()
	br := bufio.NewReaderSize(io.TeeReader(r, stored), 64<<10)
	head, _ := br.Peek(8)
	var dec io.Reader = br
	switch kind := compression(head); kind {
	case "":
	case "gzip":
		zr, err := gzip.NewReader(br)
		if err != nil {
			return fmt.Errorf("gzip: %w", err)
		}
		defer zr.Close()
		dec = zr
	default:
		return fmt.Errorf("the layer is %s-compressed, which is not supported: save the image with gzip or uncompressed layers", kind)
	}
	u := &countReader{r: dec, st: st}
	tr := tar.NewReader(io.TeeReader(u, unpacked))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if st.entries++; st.entries > maxEntries {
			return fmt.Errorf("more than %d entries: %w", maxEntries, hostfs.ErrImageLimit)
		}
		if err := applyEntry(tr, hdr, b); err != nil {
			return err
		}
	}
	// What follows the end of the archive still counts: it is hashed, and it is bounded.
	if _, err := io.Copy(io.Discard, io.TeeReader(u, unpacked)); err != nil {
		return err
	}
	if _, err := io.Copy(io.Discard, br); err != nil {
		return err
	}
	if wantStored != "" && hex.EncodeToString(stored.Sum(nil)) != wantStored {
		return errors.New("the layer does not match its digest")
	}
	if wantUnpacked != "" && hex.EncodeToString(unpacked.Sum(nil)) != wantUnpacked {
		return errors.New("the layer does not match the digest in the image configuration")
	}
	return nil
}

func applyEntry(tr *tar.Reader, hdr *tar.Header, b *hostfs.ImageBuilder) error {
	if hdr.Typeflag == tar.TypeXGlobalHeader {
		return nil
	}
	abs, err := cleanName(hdr.Name)
	if err != nil {
		return err
	}
	if hdr.Uid < 0 || hdr.Gid < 0 || int64(hdr.Uid) > 1<<32-1 || int64(hdr.Gid) > 1<<32-1 {
		return fmt.Errorf("%q: an owner that is not a user ID", abs)
	}
	dir, base := path.Dir(abs), path.Base(abs)
	if abs != "/" && strings.HasPrefix(base, ".wh.") {
		switch {
		case base == ".wh..wh..opq":
			return b.Opaque(dir)
		case strings.HasPrefix(base, ".wh..wh."):
			return nil // the reserved names of AUFS
		case base == ".wh.":
			return errors.New("a whiteout of nothing")
		}
		return b.Whiteout(path.Join(dir, strings.TrimPrefix(base, ".wh.")))
	}
	e := hostfs.ImageEntry{Path: abs, Perm: uint32(hdr.Mode & 0o7777), UID: int64(hdr.Uid), GID: int64(hdr.Gid), ModTime: hdr.ModTime.UTC()}
	switch hdr.Typeflag {
	case tar.TypeDir:
		e.Type = hostfs.ImageDir
	case tar.TypeReg:
		e.Type, e.Size = hostfs.ImageFile, hdr.Size
		if e.Keep = hostfs.ImageKeeps(abs, hdr.Size); e.Keep {
			if !b.Fits(hdr.Size) {
				return fmt.Errorf("more than %d MiB of file contents: %w", hostfs.MaxImageContent>>20, hostfs.ErrImageLimit)
			}
			e.Data = make([]byte, hdr.Size)
			if _, err := io.ReadFull(tr, e.Data); err != nil {
				return fmt.Errorf("%q: %w", abs, err)
			}
		}
	case tar.TypeSymlink:
		e.Type, e.Target = hostfs.ImageSymlink, hdr.Linkname
	case tar.TypeLink:
		target, err := cleanName(hdr.Linkname)
		if err != nil {
			return fmt.Errorf("%q: %w", abs, err)
		}
		e.Type, e.Target = hostfs.ImageHardlink, target
	case tar.TypeChar:
		e.Type, e.Special = hostfs.ImageSpecial, fs.ModeDevice|fs.ModeCharDevice
	case tar.TypeBlock:
		e.Type, e.Special = hostfs.ImageSpecial, fs.ModeDevice
	case tar.TypeFifo:
		e.Type, e.Special = hostfs.ImageSpecial, fs.ModeNamedPipe
	default:
		return fmt.Errorf("%q: an entry of type %q, which is not supported", abs, string(hdr.Typeflag))
	}
	if e.ModTime.Before(time.Unix(0, 0)) {
		e.ModTime = time.Unix(0, 0).UTC()
	}
	return b.Add(e)
}
