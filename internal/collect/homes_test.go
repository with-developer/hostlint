package collect

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/hostfs"
)

func TestHomes(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n"+
			"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"+
			"alice:x:1000:1000::/home/alice:/bin/bash\n"+
			"bob:x:1001:1001::/home/bob:/bin/bash\n"+
			"carol:x:1002:1002::/home/carol:/bin/bash\n", 0o644, 0, 0).
		AddDir("/root", 0o700, 0, 0).
		AddFile("/root/.bashrc", "", 0o644, 0, 0).
		AddDir("/home/alice", 0o750, 1000, 1000).
		AddFile("/home/alice/.profile", "", 0o664, 1000, 1000).
		AddSymlink("/home/alice/.bashrc", "/tmp/missing").
		AddDir("/home/bob", 0o777, 0, 0).
		AddFile("/home/bob/.zshrc", "", 0o644, 1001, 1001)
	f, err := homesCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	if !f.Complete {
		t.Errorf("incomplete: %v", f.Skipped)
	}
	var got []string
	for _, h := range f.Value.(*Homes).Accounts {
		var files []string
		for _, sf := range h.StartupFiles {
			files = append(files, fmt.Sprintf("%s %d %s %v", sf.Path, sf.UID, sf.Mode, sf.Dangling))
		}
		got = append(got, fmt.Sprintf("%s login=%v %s exists=%v owner=%d mode=%s [%s]", h.User, h.LoginShell, h.Path, h.Exists, h.OwnerUID, h.Mode, strings.Join(files, "; ")))
	}
	want := []string{
		"root login=true /root exists=true owner=0 mode=0700 [/root/.bashrc 0 0644 false]",
		"daemon login=false /usr/sbin exists=false owner=0 mode= []",
		"alice login=true /home/alice exists=true owner=1000 mode=0750 [/home/alice/.profile 1000 0664 false; /home/alice/.bashrc 0  true]",
		"bob login=true /home/bob exists=true owner=0 mode=0777 [/home/bob/.zshrc 1001 0644 false]",
		"carol login=true /home/carol exists=false owner=0 mode= []",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("homes:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// What cannot be observed makes the facts incomplete.
	f, err = homesCollector{}.Collect(context.Background(), hostfs.NewTestHost(m.SetError("/home/alice", fs.ErrPermission), nil, false))
	if err != nil || f.Complete {
		t.Errorf("complete %v, err %v", f.Complete, err)
	}
}

// A startup file linked to /dev/null is blanked, not world-writable; shared
// homes are looked at once; more startup files are covered.
func TestHomesNullLinksSharedHomesAndMoreFiles(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/passwd", "alice:x:1000:1000::/home/alice:/bin/bash\n"+
			"sys1:x:2:2::/var/empty:/usr/sbin/nologin\nsys2:x:3:3::/var/empty:/usr/sbin/nologin\n", 0o644, 0, 0).
		AddFile("/dev/null", "", 0o666, 0, 0).
		AddDir("/home/alice", 0o750, 1000, 1000).
		AddSymlink("/home/alice/.bash_logout", "/dev/null").
		AddSymlink("/home/alice/.bashrc", "../alice/../../dev/null").
		AddFile("/home/alice/.tcshrc", "", 0o666, 1000, 1000).
		AddDir("/var/empty", 0o755, 0, 0).
		AddFile("/var/empty/.profile", "", 0o644, 0, 0)
	f, err := homesCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil || !f.Complete {
		t.Fatalf("complete %v, err %v, skipped %v", f.Complete, err, f.Skipped)
	}
	accounts := f.Value.(*Homes).Accounts
	if n := len(accounts[0].StartupFiles); n != 1 || accounts[0].StartupFiles[0].Path != "/home/alice/.tcshrc" || accounts[0].StartupFiles[0].Mode != "0666" {
		t.Errorf("alice's startup files = %+v, want only .tcshrc", accounts[0].StartupFiles)
	}
	if len(accounts[1].StartupFiles) != 1 || len(accounts[2].StartupFiles) != 1 || accounts[2].Mode != "0755" {
		t.Errorf("shared home: %+v and %+v", accounts[1], accounts[2])
	}
}

// One startup file that cannot be looked at is reported, and the files after it are still seen.
func TestHomesOneUnreadableFileDoesNotHideTheRest(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/passwd", "alice:x:1000:1000::/home/alice:/bin/bash\n", 0o644, 0, 0).
		AddDir("/home/alice", 0o750, 1000, 1000).
		AddSymlink("/home/alice/.profile", "/home/alice/.profile"). // a loop: stat fails
		AddFile("/home/alice/.zshrc", "", 0o666, 1000, 1000)
	f, err := homesCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil || f.Complete {
		t.Fatalf("complete %v, err %v", f.Complete, err)
	}
	files := f.Value.(*Homes).Accounts[0].StartupFiles
	if len(files) != 1 || files[0].Path != "/home/alice/.zshrc" || files[0].Mode != "0666" {
		t.Errorf("startup files = %+v", files)
	}
}
