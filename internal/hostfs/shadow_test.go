package hostfs

import (
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

const shadowFixture = `root:$y$j9T$abcdefghijklmnop$QRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456:19700:0:99999:7:::
daemon:*:19700:0:99999:7:::
alice:$6$saltsalt$0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmn:19701:1:90:7:30:20000:
bob::19702::::::
carol:!$5$salt$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR:19703:0:99999:7:::
dave:abCDefGHijKLm:19704:0:99999:7:::
erin:!!:19705:0:99999:7:::
frank:!locked:19706:0:99999:7:::
grace:NP:19707:0:99999:7:::
`

func TestReadShadow(t *testing.T) {
	m := NewMemFS().AddFile("/etc/shadow", shadowFixture, 0o640, 0, 42)
	entries, err := ReadShadow(m)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, fmt.Sprintf("%s %s %s %d %d %d %d %d %d", e.Name, e.State, e.Algorithm,
			e.LastChange, e.MinDays, e.MaxDays, e.WarnDays, e.InactiveDays, e.Expire))
	}
	want := []string{
		"root set yescrypt 19700 0 99999 7 -1 -1",
		"daemon locked  19700 0 99999 7 -1 -1",
		"alice set sha512 19701 1 90 7 30 20000",
		"bob empty  19702 -1 -1 -1 -1 -1",
		"carol locked sha256 19703 0 99999 7 -1 -1",
		"dave set des 19704 0 99999 7 -1 -1",
		"erin locked  19705 0 99999 7 -1 -1",
		"frank locked  19706 0 99999 7 -1 -1",
		"grace locked  19707 0 99999 7 -1 -1",
	}
	if !equal(got, want) {
		t.Errorf("entries:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Nothing hash-like survives parsing.
	if s := fmt.Sprintf("%+v", entries); strings.Contains(s, "$") || strings.Contains(s, "abCDef") {
		t.Errorf("a hash leaked into the entries: %s", s)
	}
	// The generic read path still refuses the file.
	if _, err := m.ReadFile("/etc/shadow"); !isDenied(err) {
		t.Errorf("ReadFile(/etc/shadow) = %v, want ErrDenied", err)
	}
}

func TestReadShadowErrors(t *testing.T) {
	malformed := NewMemFS().AddFile("/etc/shadow", "root:$6$secrethash\n", 0o640, 0, 0)
	_, err := ReadShadow(malformed)
	if err == nil || strings.Contains(err.Error(), "secrethash") {
		t.Errorf("malformed shadow: err %v must not echo the line", err)
	}
	_, err = ReadShadow(NewMemFS())
	checkErr(t, err, fs.ErrNotExist)
	unreadable := NewMemFS().AddFile("/etc/shadow", shadowFixture, 0o640, 0, 0).SetError("/etc/shadow", fs.ErrPermission)
	_, err = ReadShadow(unreadable)
	checkErr(t, err, fs.ErrPermission)
}

func isDenied(err error) bool { return err != nil && strings.Contains(err.Error(), ErrDenied.Error()) }
