package collect

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/with-developer/hostlint/internal/hostfs"
)

func sysctlOf(t *testing.T, m *hostfs.MemFS, live bool) (*Sysctl, bool, []string) {
	t.Helper()
	h := hostfs.NewTestHost(m, nil, live)
	got, err := sysctlCollector{}.Collect(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	return got.Value.(*Sysctl), got.Complete, got.Skipped
}

func param(t *testing.T, s *Sysctl, key, want string) {
	t.Helper()
	got, ok := s.Params[key]
	if want == "" {
		if ok {
			t.Errorf("%s = %q, want it absent", key, got.Value)
		}
		return
	}
	if !ok || got.Value != want {
		t.Errorf("%s = %+v, want %q", key, got, want)
	}
}

// The files of real distributions: what systemd-sysctl would set at boot.
func TestSysctlFromRealDistributions(t *testing.T) {
	s, complete, _ := sysctlOf(t, fixtureFS(t, "sysctl-ubuntu-24.04"), false)
	if !complete || s.Live {
		t.Fatalf("complete %v live %v", complete, s.Live)
	}
	param(t, s, "kernel.kptr_restrict", "1")
	param(t, s, "kernel.yama.ptrace_scope", "1")
	param(t, s, "net.ipv4.conf.all.rp_filter", "2")
	param(t, s, "net.ipv4.tcp_syncookies", "")            // only a comment in /etc/sysctl.conf: the kernel's default is not known
	param(t, s, "net.ipv4.conf.all.accept_redirects", "") // commented out
	param(t, s, "fs.protected_hardlinks", "1")            // from /usr/lib/sysctl.d, the file of a vendor
	if set := s.Params["kernel.kptr_restrict"]; !set.Explicit || set.Source != "/etc/sysctl.d/10-kernel-hardening.conf:15" {
		t.Errorf("kptr_restrict = %+v", set)
	}

	// Rocky 9 sets rp_filter for every interface with a wildcard and then takes "all" out again with
	// "-net.ipv4.conf.all.rp_filter": not set, so unknown here (and a wildcard is never read as setting one).
	s, _, _ = sysctlOf(t, fixtureFS(t, "sysctl-rocky-9"), false)
	param(t, s, "kernel.kptr_restrict", "1")
	param(t, s, "net.ipv4.conf.all.rp_filter", "")
	param(t, s, "kernel.yama.ptrace_scope", "0")

	s, _, _ = sysctlOf(t, fixtureFS(t, "sysctl-centos-7"), false)
	param(t, s, "net.ipv4.conf.all.rp_filter", "1")
	param(t, s, "net.ipv4.conf.all.accept_source_route", "0")
	param(t, s, "fs.protected_symlinks", "1")
	param(t, s, "kernel.kptr_restrict", "1")

	s, _, _ = sysctlOf(t, fixtureFS(t, "sysctl-amazonlinux-2023"), false)
	param(t, s, "kernel.yama.ptrace_scope", "0")
	param(t, s, "kernel.kptr_restrict", "")
}

func TestSysctlOrderOfFiles(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/usr/lib/sysctl.d/50-a.conf", "kernel.kptr_restrict = 0\nfs.suid_dumpable = 2\n", 0o644, 0, 0).
		AddFile("/etc/sysctl.d/50-a.conf", "kernel.kptr_restrict = 1\n", 0o644, 0, 0). // hides the vendor's file of that name
		AddFile("/usr/lib/sysctl.d/10-b.conf", "kernel.dmesg_restrict = 0\n", 0o644, 0, 0).
		AddFile("/run/sysctl.d/60-c.conf", "kernel.dmesg_restrict = 1\n", 0o644, 0, 0). // later name wins
		AddFile("/usr/lib/sysctl.d/70-masked.conf", "kernel.randomize_va_space = 0\n", 0o644, 0, 0).
		AddSymlink("/etc/sysctl.d/70-masked.conf", "/dev/null"). // a link to /dev/null masks it
		AddFile("/etc/sysctl.conf", "net.ipv4.tcp_syncookies = 1\nnet.ipv4.tcp_syncookies = 0\n", 0o644, 0, 0)
	s, complete, _ := sysctlOf(t, m, false)
	if !complete {
		t.Fatal("incomplete")
	}
	param(t, s, "kernel.kptr_restrict", "1")
	param(t, s, "fs.suid_dumpable", "") // only in the file that was hidden
	param(t, s, "kernel.dmesg_restrict", "1")
	param(t, s, "kernel.randomize_va_space", "")
	param(t, s, "net.ipv4.tcp_syncookies", "0") // the last line of the last file
	if got := s.Params["net.ipv4.tcp_syncookies"].Source; got != "/etc/sysctl.conf:2" {
		t.Errorf("source = %q", got)
	}
}

func TestParseSysctl(t *testing.T) {
	got := parseSysctl("/f", []byte(`
# a comment
; another
kernel.kptr_restrict=2
  net/ipv4/tcp_syncookies   =   1
-kernel.dmesg_restrict = 1
fs.suid_dumpable
net.ipv4.conf.*.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0 # not a comment of its own
not.a.wanted.key = 5
kernel.randomize_va_space = 2
kernel.randomize_va_space = 1
`))
	want := map[string]string{
		"kernel.kptr_restrict":               "2",
		"net.ipv4.tcp_syncookies":            "1",
		"kernel.dmesg_restrict":              "1",
		"net.ipv4.conf.all.accept_redirects": "0 # not a comment of its own",
		"kernel.randomize_va_space":          "1",
	}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for k, v := range want {
		if got[k].Value != v || !got[k].Explicit {
			t.Errorf("%s = %+v, want %q", k, got[k], v)
		}
	}
	if got["kernel.randomize_va_space"].Source != "/f:12" {
		t.Errorf("source = %q", got["kernel.randomize_va_space"].Source)
	}
}

func TestSysctlLive(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/proc/sys/kernel/kptr_restrict", "1\n", 0o644, 0, 0).
		AddFile("/proc/sys/net/ipv4/tcp_syncookies", "1\n", 0o644, 0, 0).
		AddFile("/proc/sys/net/ipv4/conf/all/rp_filter", "2\n", 0o644, 0, 0)
	s, complete, _ := sysctlOf(t, m, true)
	if !complete || !s.Live {
		t.Fatalf("complete %v live %v", complete, s.Live)
	}
	param(t, s, "kernel.kptr_restrict", "1")
	param(t, s, "net.ipv4.conf.all.rp_filter", "2")
	param(t, s, "kernel.yama.ptrace_scope", "") // no Yama in this kernel: absent
	if got := s.Params["kernel.kptr_restrict"]; got.Explicit || got.Source != "/proc/sys/kernel/kptr_restrict" {
		t.Errorf("a value of the running kernel is not explicit: %+v", got)
	}
	// A parameter that cannot be read leaves the facts incomplete, never silently absent.
	m.SetError("/proc/sys/kernel/dmesg_restrict", fs.ErrPermission)
	_, complete, skipped := sysctlOf(t, m, true)
	if complete || len(skipped) == 0 {
		t.Errorf("complete %v skipped %v", complete, skipped)
	}
	// /etc is not read on a live host: the kernel is the truth.
	m.AddFile("/etc/sysctl.d/10-x.conf", "kernel.kptr_restrict = 0\n", 0o644, 0, 0)
	if s, _, _ = sysctlOf(t, m, true); s.Params["kernel.kptr_restrict"].Value != "1" {
		t.Errorf("a live host follows its files: %+v", s.Params["kernel.kptr_restrict"])
	}
}

func TestSysctlOfAnImageHasNothing(t *testing.T) {
	m := hostfs.NewMemFS().AddFile("/etc/sysctl.d/10-x.conf", "kernel.kptr_restrict = 1\n", 0o644, 0, 0)
	h := hostfs.NewImageHost(&hostfs.ImageFS{}, "x")
	h.FS = m
	got, err := sysctlCollector{}.Collect(context.Background(), h)
	if err != nil || !got.Complete || len(got.Value.(*Sysctl).Params) != 0 {
		t.Errorf("%+v %v", got, err)
	}
	_ = errors.New
}
