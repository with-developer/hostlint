package hostfs

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"
)

func file(p string, data string, perm uint32) ImageEntry {
	return ImageEntry{Path: p, Type: ImageFile, Perm: perm, Size: int64(len(data)), Data: []byte(data), Keep: true, ModTime: time.Unix(1700000000, 0)}
}

func dir(p string) ImageEntry { return ImageEntry{Path: p, Type: ImageDir, Perm: 0o755} }

func build(t *testing.T, entries ...ImageEntry) *ImageFS {
	t.Helper()
	b := NewImageBuilder()
	b.BeginLayer()
	for _, e := range entries {
		if err := b.Add(e); err != nil {
			t.Fatalf("%+v: %v", e, err)
		}
	}
	return b.Finish()
}

func TestImageFSBehavesLikeARoot(t *testing.T) {
	f := build(t,
		dir("/etc"), file("/etc/passwd", "root:x:0:0\n", 0o644), file("/etc/shadow", "root:$6$h:::", 0o640),
		ImageEntry{Path: "/etc/shadow-link", Type: ImageSymlink, Target: "shadow"},
		ImageEntry{Path: "/abs", Type: ImageSymlink, Target: "/etc"},
		ImageEntry{Path: "/loop", Type: ImageSymlink, Target: "loop"},
		ImageEntry{Path: "/up", Type: ImageSymlink, Target: "../../../etc"}, // never above the root
	)
	if got, err := f.ReadFile("/abs/passwd"); err != nil || string(got) != "root:x:0:0\n" {
		t.Errorf("through an absolute link: %q %v", got, err)
	}
	if got, err := f.ReadFile("/up/passwd"); err != nil || len(got) == 0 {
		t.Errorf("a link that climbs: %q %v", got, err)
	}
	if _, err := f.ReadFile("/etc/shadow"); !errors.Is(err, ErrDenied) {
		t.Errorf("shadow: %v", err)
	}
	if _, err := f.ReadFile("/etc/shadow-link"); !errors.Is(err, ErrDenied) {
		t.Errorf("a link to the shadow file: %v", err)
	}
	if got, err := f.readSensitive("/etc/shadow"); err != nil || len(got) == 0 {
		t.Errorf("a parser reads it: %v", err)
	}
	if _, err := f.Stat("/loop"); err == nil {
		t.Error("a link loop")
	}
	if _, err := f.ReadFile("/etc"); !errors.Is(err, ErrNotRegular) {
		t.Errorf("a directory: %v", err)
	}
	if _, err := f.ReadFile("/etc/passwd/x"); !IsMissing(err) {
		t.Errorf("below a file: %v", err)
	}
	if _, err := f.ReadFile("etc/passwd"); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("a relative path: %v", err)
	}
	// Read the file twice: what is returned is a copy.
	a, _ := f.ReadFile("/etc/passwd")
	a[0] = 'X'
	if b, _ := f.ReadFile("/etc/passwd"); b[0] != 'r' {
		t.Error("the contents of the image were changed through a read")
	}
}

func TestImageFSWalk(t *testing.T) {
	f := build(t, dir("/a"), dir("/a/b"), file("/a/b/c", "1", 0o4755), file("/a/d", "2", 0o644), file("/z", "3", 0o644),
		ImageEntry{Path: "/a/link", Type: ImageSymlink, Target: "/a"})
	var seen []string
	res, err := Walk(context.Background(), f, "/", WalkOptions{}, func(fi FileInfo) error {
		seen = append(seen, fi.Path)
		return nil
	})
	if err != nil || !res.Complete {
		t.Fatalf("%+v %v", res, err)
	}
	if got := strings.Join(seen, " "); got != "/ /a /a/b /a/b/c /a/d /a/link /z" {
		t.Errorf("walked %s", got)
	}
	// Skip and the limit of entries per directory.
	es, truncated, err := f.readDirN("/a", 1, func(p string) bool { return p == "/a/b" })
	if err != nil || !truncated || len(es) != 1 || es[0].Path != "/a/d" {
		t.Errorf("%+v %v %v", es, truncated, err)
	}
}

func TestImageBuilderLimitsAndErrors(t *testing.T) {
	b := NewImageBuilder()
	b.BeginLayer()
	for _, bad := range []ImageEntry{
		{Path: "relative", Type: ImageDir},
		{Path: "/a/../b", Type: ImageDir},
		{Path: "/x\x00y", Type: ImageFile, Keep: true},
		{Path: "/" + strings.Repeat("n", 300), Type: ImageDir},
		{Path: "/l", Type: ImageSymlink},
		{Path: "/", Type: ImageFile},
	} {
		if err := b.Add(bad); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
	if err := b.Add(ImageEntry{Path: "/f", Type: ImageFile, Keep: true, Size: 3, Data: []byte("ab")}); err == nil {
		t.Error("a file shorter than its size")
	}
	// Contents past the budget refuse the image, and a replaced file gives its share back.
	big := make([]byte, 100<<20)
	for i := range 5 {
		if err := b.Add(ImageEntry{Path: "/big", Type: ImageFile, Keep: true, Size: int64(len(big)), Data: big}); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
	}
	var err error
	for i := range 6 {
		err = b.Add(ImageEntry{Path: "/big" + string(rune('a'+i)), Type: ImageFile, Keep: true, Size: int64(len(big)), Data: big})
		if err != nil {
			break
		}
	}
	if !errors.Is(err, ErrImageLimit) {
		t.Errorf("the budget was not enforced: %v", err)
	}
}

func TestImageKeeps(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int64
		want bool
	}{
		{"/etc/passwd", 100, true},
		{"/usr/bin/bash", ImageKeepSize + 1, false},
		{"/var/lib/dpkg/status", 5 << 20, true},
		{"/var/lib/rpm/rpmdb.sqlite", 40 << 20, true},
		{"/usr/lib/sysimage/rpm/Packages.db", 40 << 20, true},
		{"/var/lib/rpm/huge", MaxImageContent + 1, false},
	} {
		if got := ImageKeeps(tc.name, tc.size); got != tc.want {
			t.Errorf("%s %d: %v", tc.name, tc.size, got)
		}
	}
	_ = fs.ErrNotExist
}

func TestHardLinksOfFilesWithoutContents(t *testing.T) {
	b := NewImageBuilder()
	b.BeginLayer()
	if err := b.Add(ImageEntry{Path: "/big", Type: ImageFile, Perm: 0o755, Size: 5 << 20}); err != nil {
		t.Fatal(err)
	}
	if err := b.Add(ImageEntry{Path: "/also", Type: ImageHardlink, Target: "/big"}); err != nil {
		t.Fatal(err)
	}
	f := b.Finish()
	if fi, err := f.Lstat("/also"); err != nil || fi.Nlink != 2 || fi.Size != 5<<20 {
		t.Errorf("%+v %v", fi, err)
	}
	if !NewImageBuilder().Fits(MaxImageContent) || NewImageBuilder().Fits(MaxImageContent+1) {
		t.Error("Fits")
	}
}
