package collect

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/hostfs"
)

// netFixture is a live host with the socket tables captured from a Debian 12
// container running sshd, netcat listeners and one established connection.
func netFixture(t *testing.T, selfNS, initNS string) *hostfs.MemFS {
	t.Helper()
	m := fixtureFS(t, "debian-12-net")
	if selfNS != "" {
		m.AddSymlink("/proc/self/ns/net", selfNS)
	}
	if initNS != "" {
		m.AddSymlink("/proc/1/ns/net", initNS)
	}
	return m
}

func socketsCollect(t *testing.T, m *hostfs.MemFS) (engine.Facts, error) {
	t.Helper()
	return socketsCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, true))
}

func TestSockets(t *testing.T) {
	f, err := socketsCollect(t, netFixture(t, "net:[4026531840]", "net:[4026531840]"))
	if err != nil {
		t.Fatal(err)
	}
	if !f.Complete {
		t.Errorf("incomplete: %v", f.Skipped)
	}
	var got []string
	for _, s := range f.Value.(*Sockets).Listening {
		got = append(got, fmt.Sprintf("%s %s %d loopback=%v uid=%d %s", s.Protocol, s.Address, s.Port, s.Loopback, s.UID, s.Source))
	}
	want := []string{
		"tcp 0.0.0.0 22 loopback=false uid=0 /proc/net/tcp:2",
		"tcp 127.0.0.1 25 loopback=true uid=0 /proc/net/tcp:3",
		"tcp :: 22 loopback=false uid=0 /proc/net/tcp6:2",
		"udp 0.0.0.0 69 loopback=false uid=0 /proc/net/udp:2",
		"udp :: 161 loopback=false uid=0 /proc/net/udp6:2",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("listening:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestSocketsNamespace(t *testing.T) {
	// In another network namespace, the host's sockets are not visible.
	if _, err := socketsCollect(t, netFixture(t, "net:[4026532201]", "net:[4026531840]")); err == nil || !strings.Contains(err.Error(), "network namespace") {
		t.Errorf("err = %v, want a namespace mismatch", err)
	}
	// Without root, process 1's namespace cannot be read: not a PASS basis.
	f, err := socketsCollect(t, netFixture(t, "net:[4026531840]", ""))
	if err != nil || f.Complete {
		t.Errorf("complete %v, err %v; want incomplete facts", f.Complete, err)
	}
}

func TestSocketsTables(t *testing.T) {
	// No IPv6 tables when IPv6 is disabled at boot.
	m := hostfs.NewMemFS().
		AddFile("/proc/net/tcp", "  sl  local_address rem_address   st\n   0: 00000000:0017 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1\n", 0o444, 0, 0).
		AddFile("/proc/net/udp", "  sl  local_address rem_address   st\n", 0o444, 0, 0)
	f, err := socketsCollect(t, m)
	if err != nil || len(f.Value.(*Sockets).Listening) != 1 {
		t.Fatalf("facts %+v, err %v", f.Value, err)
	}
	// With IPv6 up, a missing IPv6 table means sockets went unseen.
	f, err = socketsCollect(t, m.AddFile("/proc/net/if_inet6", "", 0o444, 0, 0))
	if err != nil || f.Complete {
		t.Errorf("complete %v, err %v; want incomplete with IPv6 enabled", f.Complete, err)
	}
	if _, err := socketsCollect(t, hostfs.NewMemFS()); err == nil {
		t.Error("missing /proc/net/tcp was accepted")
	}
	bad := hostfs.NewMemFS().
		AddFile("/proc/net/tcp", "header\n   0: 0000:0017 00000000:0000 0A 0 0 0 0 1 1\n", 0o444, 0, 0).
		AddFile("/proc/net/udp", "header\n", 0o444, 0, 0)
	if _, err := socketsCollect(t, bad); err == nil || !strings.Contains(err.Error(), "bad address") {
		t.Errorf("err = %v, want a bad address", err)
	}
}

// Under --root the host's sockets are not the target's.
func TestSocketsAreLive(t *testing.T) {
	if (socketsCollector{}).Access() != engine.AccessLive {
		t.Error("the sockets collector must be live-only")
	}
}
