package collect

import (
	"context"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/hostfs"
)

const (
	fsPasswd = "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
	fsGroup  = "root:x:0:\ntty:x:5:\nalice:x:1000:\n"
)

func fsTree() *hostfs.MemFS {
	return hostfs.NewMemFS().
		AddFile("/etc/passwd", fsPasswd, 0o644, 0, 0).
		AddFile("/etc/group", fsGroup, 0o644, 0, 0).
		AddFile("/usr/bin/passwd", "", 0o4755, 0, 0).
		AddFile("/usr/bin/wall", "", 0o2755, 0, 5).
		AddFile("/usr/bin/ls", "", 0o755, 0, 0).
		AddDir("/tmp", 0o1777, 0, 0).
		AddFile("/srv/open.txt", "", 0o666, 1000, 1000).
		AddDir("/srv/drop", 0o777, 0, 0).
		AddFile("/home/gone/notes", "", 0o600, 1500, 1500).
		AddSpecial("/dev/null", fs.ModeDevice|fs.ModeCharDevice, 0o666, 0, 0).
		AddFile("/dev/.backdoor", "", 0o755, 0, 0).
		AddFile("/dev/shm/segment", "", 0o666, 1000, 1000).
		AddFile("/proc/1/status", "", 0o444, 0, 0).
		AddFile("/var/lib/docker/overlay2/x/diff/bin/su", "", 0o4755, 0, 0).
		AddFile("/mnt/nfs/share/tool", "", 0o4755, 0, 0)
}

func collectFS(t *testing.T, h *hostfs.Host) engine.Facts {
	t.Helper()
	f, err := filesystemCollector{}.Collect(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func paths(entries []FileEntry) string {
	var out []string
	for _, e := range entries {
		out = append(out, e.Path+" "+e.Mode+" "+e.Owner+":"+e.Group)
	}
	return strings.Join(out, ", ")
}

func TestFilesystem(t *testing.T) {
	h := hostfs.NewTestHost(fsTree(), nil, false)
	h.Mounts = []hostfs.Mount{{Path: "/", Type: "ext4"}, {Path: "/proc", Type: "proc"}, {Path: "/proc/sys", Type: "proc"}, {Path: "/mnt/nfs", Type: "nfs4"}, {Path: "/tmp", Type: "tmpfs"}}
	f := collectFS(t, h)
	if !f.Complete || len(f.Partial) != 0 || len(f.Unknown) != 0 {
		t.Fatalf("complete %v, partial %v, unknown %v, skipped %v", f.Complete, f.Partial, f.Unknown, f.Skipped)
	}
	got := f.Value.(*Filesystem)
	checks := []struct{ name, got, want string }{
		{"setid", paths(got.SetID), "/usr/bin/passwd 4755 root:root, /usr/bin/wall 2755 root:tty"},
		{"world_writable", paths(got.WorldWritable), "/srv/drop 0777 root:root, /srv/open.txt 0666 alice:alice, /tmp 1777 root:root"},
		{"unowned", paths(got.Unowned), "/home/gone/notes 0600 :"},
		{"dev_files", paths(got.DevFiles), "/dev/.backdoor 0755 root:root"},
		{"excluded", strings.Join(got.Excluded, ", "), "/dev (walked separately), /mnt/nfs (nfs4), /proc (proc), /sys (sysfs), /var/lib/containerd (container storage), /var/lib/containers (container storage), /var/lib/docker (container storage)"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, c.got, c.want)
		}
	}
}

// What the walk could not see makes the lists partial, never silently short.
func TestFilesystemIncomplete(t *testing.T) {
	m := fsTree().SetError("/srv", fs.ErrPermission)
	f := collectFS(t, hostfs.NewTestHost(m, nil, false))
	if strings.Join(f.Partial, " ") != "log_files odd_names setid unowned world_writable" || f.Complete != true {
		t.Errorf("partial %v, complete %v", f.Partial, f.Complete)
	}
	if !strings.Contains(strings.Join(f.Skipped, "; "), "/srv") {
		t.Errorf("skipped %v", f.Skipped)
	}

	// Lists are bounded.
	defer func(n int) { walkMaxListed = n }(walkMaxListed)
	walkMaxListed = 1
	f = collectFS(t, hostfs.NewTestHost(fsTree(), nil, false))
	if strings.Join(f.Partial, " ") != "setid world_writable" {
		t.Errorf("partial %v with lists of one", f.Partial)
	}
}

// Without /etc/passwd, which files are unowned is unknown, not "none".
func TestFilesystemNoPasswd(t *testing.T) {
	m := fsTree().SetError("/etc/passwd", fs.ErrPermission)
	f := collectFS(t, hostfs.NewTestHost(m, nil, false))
	if len(f.Unknown) != 1 || f.Unknown[0] != "unowned" || len(f.Value.(*Filesystem).Unowned) != 0 {
		t.Errorf("unknown %v, unowned %v", f.Unknown, f.Value.(*Filesystem).Unowned)
	}
}

// The last mount on a point decides whether it is walked.
func TestFilesystemHiddenMounts(t *testing.T) {
	m := fsTree().AddFile("/data/set", "", 0o4755, 0, 0)
	for name, mounts := range map[string][]hostfs.Mount{
		"local over network": {{Path: "/data", Type: "nfs4"}, {Path: "/data", Type: "ext4"}},
		"network over local": {{Path: "/data", Type: "ext4"}, {Path: "/data", Type: "nfs4"}},
	} {
		h := hostfs.NewTestHost(m, nil, false)
		h.Mounts = mounts
		got := collectFS(t, h).Value.(*Filesystem)
		walked := strings.Contains(paths(got.SetID), "/data/set")
		if want := name == "local over network"; walked != want {
			t.Errorf("%s: /data walked %v, want %v", name, walked, want)
		}
	}
}

// A walk of /dev cut short makes dev_files partial, not empty.
func TestFilesystemDevInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f, err := filesystemCollector{}.Collect(ctx, hostfs.NewTestHost(fsTree(), nil, false))
	if err != nil || !slices.Contains(f.Partial, "dev_files") {
		t.Errorf("partial %v, err %v; want dev_files partial", f.Partial, err)
	}
}

// Names made only of dots and spaces, and the files of /var/log that root does
// not own, are listed; ordinary hidden names and root's logs are not.
func TestFilesystemOddNamesAndLogFiles(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/passwd", fsPasswd, 0o644, 0, 0).
		AddFile("/etc/group", fsGroup, 0o644, 0, 0).
		AddFile("/home/alice/.bashrc", "", 0o644, 1000, 1000).
		AddDir("/home/alice/...", 0o755, 1000, 1000).
		AddFile("/var/tmp/. ", "", 0o644, 0, 0).
		AddFile("/var/tmp/.. ", "", 0o644, 0, 0).
		AddFile("/var/tmp/.a", "", 0o644, 0, 0).
		AddFile("/var/tmp/ ", "", 0o644, 0, 0).
		AddFile("/var/log/syslog", "", 0o640, 0, 0).
		AddFile("/var/log/app.log", "", 0o640, 1000, 1000).
		AddDir("/var/log/app", 0o750, 1000, 5).
		SetOwner("/var/log", 1000, 1000)
	got := collectFS(t, hostfs.NewTestHost(m, nil, false)).Value.(*Filesystem)
	for _, c := range []struct{ name, got, want string }{
		{"odd_names", paths(got.OddNames), "/home/alice/... 0755 alice:alice, /var/tmp/  0644 root:root, /var/tmp/.  0644 root:root, /var/tmp/..  0644 root:root"},
		{"log_files", paths(got.LogFiles), "/var/log 0755 alice:alice, /var/log/app 0750 alice:tty, /var/log/app.log 0640 alice:alice"},
	} {
		if c.got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, c.got, c.want)
		}
	}
}

func TestIsOddName(t *testing.T) {
	for name, want := range map[string]bool{
		"...": true, "....": true, ". ": true, ".. ": true, " ": true, "  ": true,
		".": false, "..": false, "": false, ".bashrc": false, "..a": false, ". a": false, "a ": false, "...a": false,
	} {
		if got := isOddName(name); got != want {
			t.Errorf("isOddName(%q) = %v, want %v", name, got, want)
		}
	}
}

// A directory named "..." in /dev is found as well.
func TestFilesystemOddNameInDev(t *testing.T) {
	m := fsTree().AddDir("/dev/...", 0o755, 0, 0)
	got := collectFS(t, hostfs.NewTestHost(m, nil, false)).Value.(*Filesystem)
	if !strings.Contains(paths(got.OddNames), "/dev/...") {
		t.Errorf("odd names = %s", paths(got.OddNames))
	}
}
