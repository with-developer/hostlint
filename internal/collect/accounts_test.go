package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// Fixtures follow the stock files of the two families.
const (
	debianPasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash
legacy:$1$abcdefgh$ijklmnopqrstuvwxyz0123:1001:1001::/home/legacy:
`
	debianGroup = `root:x:0:
sudo:x:27:alice
alice:x:1000:
wheel:x:10:alice, bob
`
	rhelShadow = `root:$6$abcdefgh$ijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq:19700:0:99999:7:::
bin:*:19700:0:99999:7:::
alice:!!:19701:0:99999:7:::
`
)

func collect(t *testing.T, c engine.Collector, m *hostfs.MemFS) (engine.Facts, error) {
	t.Helper()
	return c.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
}

func TestAccounts(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/passwd", debianPasswd, 0o644, 0, 0).
		AddFile("/etc/group", debianGroup, 0o644, 0, 0)
	f, err := collect(t, accountsCollector{}, m)
	if err != nil {
		t.Fatal(err)
	}
	a := f.Value.(*Accounts)
	if !f.Complete || len(a.Users) != 6 || len(a.Groups) != 4 {
		t.Fatalf("complete %v, %d users, %d groups", f.Complete, len(a.Users), len(a.Groups))
	}
	byName := map[string]User{}
	for _, u := range a.Users {
		byName[u.Name] = u
	}
	tests := []struct {
		name       string
		password   string
		loginShell bool
	}{
		{"root", "shadowed", true},
		{"daemon", "shadowed", false},
		{"sync", "shadowed", false},
		{"legacy", "hash", true}, // empty shell means /bin/sh
	}
	for _, tt := range tests {
		u := byName[tt.name]
		if u.Password != tt.password || u.LoginShell != tt.loginShell {
			t.Errorf("%s: password %q login %v, want %q %v", tt.name, u.Password, u.LoginShell, tt.password, tt.loginShell)
		}
	}
	if u := byName["alice"]; u.UID != 1000 || u.Source != "/etc/passwd:5" || u.Home != "/home/alice" {
		t.Errorf("alice = %+v", u)
	}
	if g := a.Groups[3]; g.Name != "wheel" || !reflect.DeepEqual(g.Members, []string{"alice", "bob"}) {
		t.Errorf("wheel = %+v", g)
	}
	data, _ := json.Marshal(a)
	if strings.Contains(string(data), "$1$") {
		t.Error("a password hash from /etc/passwd leaked into the facts")
	}
}

func TestAccountsMalformedLinesMakeFactsIncomplete(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nbroken:x:notanumber:0::/:/bin/sh\nshort:x\n", 0o644, 0, 0).
		AddFile("/etc/group", "root:x:0:\n", 0o644, 0, 0)
	f, err := collect(t, accountsCollector{}, m)
	if err != nil {
		t.Fatal(err)
	}
	if f.Complete || len(f.Skipped) != 2 || strings.Contains(strings.Join(f.Skipped, " "), "notanumber") {
		t.Errorf("complete %v, skipped %q", f.Complete, f.Skipped)
	}
}

// glibc accepts records without their trailing fields and comments after
// blanks; a hash behind a lock marker is still a readable hash.
func TestAccountsRecords(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root\n  # old:x:0:0::/:/bin/sh\n"+
			"legacy:!$6$salt$abcdefghijklmnopqrstuvwxyz:1000:1000::/home/legacy:/bin/bash\nsvc:NP:999:999::/:/sbin/nologin\n", 0o644, 0, 0).
		AddFile("/etc/group", "root:x:0:\nwheel:x:10\n", 0o644, 0, 0)
	f, err := collect(t, accountsCollector{}, m)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Complete {
		t.Errorf("skipped %v", f.Skipped)
	}
	a := f.Value.(*Accounts)
	var got []string
	for _, u := range a.Users {
		got = append(got, fmt.Sprintf("%s:%d:%s:%v", u.Name, u.UID, u.Password, u.LoginShell))
	}
	if want := "root:0:shadowed:true toor:0:shadowed:true legacy:1000:hash:true svc:999:locked:false"; strings.Join(got, " ") != want {
		t.Errorf("users = %s, want %s", strings.Join(got, " "), want)
	}
	if len(a.Groups) != 2 || a.Groups[1].Name != "wheel" || a.Groups[1].GID != 10 {
		t.Errorf("groups = %+v", a.Groups)
	}
}

func TestAccountsMissingFiles(t *testing.T) {
	_, err := collect(t, accountsCollector{}, hostfs.NewMemFS())
	if err == nil {
		t.Error("missing /etc/passwd must be an error")
	}
}

func TestShadow(t *testing.T) {
	m := hostfs.NewMemFS().AddFile("/etc/shadow", rhelShadow, 0o000, 0, 0)
	f, err := collect(t, shadowCollector{}, m)
	if err != nil {
		t.Fatal(err)
	}
	s := f.Value.(*Shadow)
	if !s.Present || len(s.Entries) != 3 {
		t.Fatalf("shadow = %+v", s)
	}
	if e := s.Entries[0]; e.Name != "root" || e.State != "set" || e.Algorithm != "sha512" || e.MaxDays != 99999 || e.InactiveDays != -1 || e.Source != "/etc/shadow:1" {
		t.Errorf("root = %+v", e)
	}
	if e := s.Entries[2]; e.State != "locked" || e.Algorithm != "" {
		t.Errorf("alice = %+v", e)
	}
	data, _ := json.Marshal(s)
	if strings.Contains(string(data), "$6$") || strings.Contains(string(data), "abcdefgh") {
		t.Error("a hash leaked into the shadow facts")
	}

	f, err = collect(t, shadowCollector{}, hostfs.NewMemFS())
	if err != nil || f.Value.(*Shadow).Present {
		t.Errorf("missing /etc/shadow: %+v, %v; want present=false", f.Value, err)
	}

	_, err = collect(t, shadowCollector{}, hostfs.NewMemFS().AddFile("/etc/shadow", rhelShadow, 0o000, 0, 0).SetError("/etc/shadow", fs.ErrPermission))
	if err == nil || !strings.Contains(err.Error(), "run hostlint as root") {
		t.Errorf("unreadable shadow: %v", err)
	}
}

func TestFactTypes(t *testing.T) {
	for _, c := range All() {
		if err := facts.CheckType(c.Type()); err != nil {
			t.Errorf("%s: %v", c.Name(), err)
		}
	}
}

// Accounts that share a UID are grouped by the collector, so a check does not
// compare every account with every other.
func TestAccountsDuplicateUIDs(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/passwd", "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\nrob:x:0:0::/root:/bin/bash\n", 0o644, 0, 0).
		AddFile("/etc/group", "root:x:0:\n", 0o644, 0, 0)
	f, err := accountsCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	got := f.Value.(*Accounts).DuplicateUIDs
	if len(got) != 1 || got[0].UID != 0 || strings.Join(got[0].Users, ",") != "root,toor,rob" || strings.Join(got[0].Sources, ",") != "/etc/passwd:1,/etc/passwd:2,/etc/passwd:5" {
		t.Errorf("duplicate UIDs = %+v", got)
	}
}

// Thousands of accounts: the grouping stays cheap and finds the one pair.
func TestAccountsDuplicateUIDsLargeHost(t *testing.T) {
	var b strings.Builder
	for i := range 5000 {
		fmt.Fprintf(&b, "u%d:x:%d:%d::/home/u%d:/bin/bash\n", i, 2000+i, 2000+i, i)
	}
	b.WriteString("clone:x:2000:2000::/home/clone:/bin/bash\n")
	m := hostfs.NewMemFS().AddFile("/etc/passwd", b.String(), 0o644, 0, 0).AddFile("/etc/group", "root:x:0:\n", 0o644, 0, 0)
	f, err := accountsCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Value.(*Accounts).DuplicateUIDs; len(got) != 1 || got[0].UID != 2000 || len(got[0].Users) != 2 {
		t.Errorf("duplicate UIDs = %+v", got)
	}
}
