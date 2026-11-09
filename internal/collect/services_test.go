package collect

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/hostfs"
)

func servicesFacts(t *testing.T, fsys hostfs.FS) (*Services, bool, []string) {
	t.Helper()
	f := servicesCollect(t, hostfs.NewTestHost(fsys, nil, false))
	return f.Value.(*Services), f.Complete, f.Skipped
}

func servicesCollect(t *testing.T, h *hostfs.Host) engine.Facts {
	t.Helper()
	f, err := servicesCollector{}.Collect(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestServicesDebian(t *testing.T) {
	s, complete, skipped := servicesFacts(t, fixtureFS(t, "debian-12"))
	if !complete || !s.Systemd {
		t.Fatalf("complete %v (%v), systemd %v", complete, skipped, s.Systemd)
	}
	ssh := s.Units["ssh.service"]
	if !ssh.Enabled || ssh.File != "/lib/systemd/system/ssh.service" || ssh.Source != "/etc/systemd/system/multi-user.target.wants/ssh.service" || ssh.Exec != "/usr/sbin/sshd" {
		t.Errorf("ssh.service = %+v", ssh)
	}
	if len(s.Active) != 0 {
		t.Errorf("active = %v under --root", s.Active)
	}
	if a := s.Units["sshd.service"]; a.AliasOf != "ssh.service" {
		t.Errorf("sshd.service = %+v, want an alias of ssh.service", a)
	}
	if u := s.Units["ssh.socket"]; u.Enabled || u.File == "" {
		t.Errorf("ssh.socket = %+v, want a file that is not enabled", u)
	}
	if u := s.Units["rpcbind.socket"]; !u.Enabled {
		t.Errorf("rpcbind.socket = %+v", u)
	}
	// tftpd-hpa has only an init script, started from rc2.d.
	if sv := s.SysV["tftpd-hpa"]; !sv.Enabled || sv.Source != "/etc/rc2.d/S01tftpd-hpa" {
		t.Errorf("sysv tftpd-hpa = %+v", sv)
	}
	if _, ok := s.Units["tftpd-hpa.service"]; ok {
		t.Error("tftpd-hpa has no unit file on Debian 12")
	}
	var names []string
	for _, svc := range s.Inetd {
		names = append(names, svc.Name+"/"+svc.Protocol)
	}
	if got := strings.Join(names, " "); got != "telnet/tcp shell/tcp login/tcp exec/tcp finger/tcp" {
		t.Errorf("inetd = %s", got)
	}
	if tel := s.Inetd[0]; tel.Server != "/usr/sbin/tcpd" || tel.Args != "/usr/sbin/telnetd" || tel.User != "root" || !strings.HasPrefix(tel.Source, "/etc/inetd.conf:") {
		t.Errorf("telnet = %+v", tel)
	}
	if len(s.Xinetd) != 0 {
		t.Errorf("xinetd = %+v", s.Xinetd)
	}
}

func TestServicesRocky9(t *testing.T) {
	s, complete, _ := servicesFacts(t, fixtureFS(t, "rocky-9"))
	if !complete || !s.Systemd {
		t.Fatalf("complete %v, systemd %v", complete, s.Systemd)
	}
	for _, name := range []string{"telnet.socket", "tftp.socket", "vsftpd.service", "snmpd.service", "nfs-server.service"} {
		if u := s.Units[name]; !u.Enabled || u.File == "" {
			t.Errorf("%s = %+v, want enabled with a file", name, u)
		}
	}
	if u := s.Units["telnet@.service"]; u.Enabled || u.File == "" {
		t.Errorf("telnet@.service = %+v, want a template that is not enabled", u)
	}
	if u := s.Units["getty@tty1.service"]; !u.Enabled {
		t.Errorf("getty@tty1.service = %+v", u)
	}
	if len(s.SysV) != 0 || len(s.Inetd) != 0 {
		t.Errorf("sysv %v, inetd %v", s.SysV, s.Inetd)
	}
}

func TestServicesXinetd(t *testing.T) {
	m := fixtureFS(t, "rocky-8")
	s, complete, _ := servicesFacts(t, m)
	if !complete || s.Systemd {
		t.Fatalf("complete %v, systemd %v", complete, s.Systemd)
	}
	byID := map[string]XinetdService{}
	for _, x := range s.Xinetd {
		byID[x.Settings["id"]] = x
	}
	if len(byID) != 11 {
		t.Fatalf("%d services: %+v", len(byID), s.Xinetd)
	}
	if e := byID["echo-stream"]; e.Disabled || e.Name != "echo" || e.Settings["socket_type"] != "stream" || !strings.HasPrefix(e.Source, "/etc/xinetd.d/echo-stream:") {
		t.Errorf("echo-stream = %+v, want enabled", e)
	}
	if d := byID["daytime-stream"]; !d.Disabled {
		t.Errorf("daytime-stream = %+v, want disabled", d)
	}

	// The defaults section can disable services, or enable only some.
	conf := "defaults\n{\n\tdisabled = echo-stream\n}\nincludedir /etc/xinetd.d\n"
	s, _, _ = servicesFacts(t, fixtureFS(t, "rocky-8").AddFile("/etc/xinetd.conf", conf, 0o644, 0, 0))
	for _, x := range s.Xinetd {
		if x.Settings["id"] == "echo-stream" && !x.Disabled {
			t.Error("echo-stream is enabled although defaults disables it")
		}
	}
	conf = "defaults {\n\tenabled = time-stream\n}\nservice telnet {\n\tserver = /usr/sbin/in.telnetd\n\tonly_from = 10.0.0.0/8\n\tonly_from += 192.168.0.0/16\n}\n"
	s, _, _ = servicesFacts(t, hostfs.NewMemFS().AddFile("/etc/xinetd.conf", conf, 0o644, 0, 0))
	if len(s.Xinetd) != 1 || !s.Xinetd[0].Disabled || s.Xinetd[0].Settings["only_from"] != "10.0.0.0/8 192.168.0.0/16" {
		t.Errorf("xinetd = %+v", s.Xinetd)
	}
}

func TestServicesMasked(t *testing.T) {
	m := fixtureFS(t, "rocky-9").
		AddSymlink("/etc/systemd/system/telnet.socket", "/dev/null").
		AddFile("/etc/systemd/system/tftp.socket", "", 0o644, 0, 0)
	s, _, _ := servicesFacts(t, m)
	for _, name := range []string{"telnet.socket", "tftp.socket"} {
		if u := s.Units[name]; !u.Masked || !u.Enabled {
			t.Errorf("%s = %+v, want masked (and still linked)", name, u)
		}
	}
}

// CentOS 7 links dracut's units with targets relative to the link's
// directory (captured from centos:7).
func TestServicesRelativeLink(t *testing.T) {
	m := fixtureFS(t, "rocky-9").
		AddFile("/usr/lib/dracut/modules.d/98systemd/dracut-cmdline.service", "[Unit]\nDescription=dracut cmdline hook\n\n[Service]\nType=oneshot\nExecStart=-/bin/dracut-cmdline\n", 0o644, 0, 0).
		AddSymlink("/usr/lib/systemd/system/dracut-cmdline.service", "../../dracut/modules.d/98systemd/dracut-cmdline.service").
		AddSymlink("/usr/lib/systemd/system/dbus-org.freedesktop.hostname1.service", "systemd-hostnamed.service")
	s, complete, skipped := servicesFacts(t, m)
	if !complete {
		t.Fatalf("incomplete: %v", skipped)
	}
	if u := s.Units["dracut-cmdline.service"]; u.File != "/usr/lib/dracut/modules.d/98systemd/dracut-cmdline.service" || u.Exec != "/bin/dracut-cmdline" {
		t.Errorf("dracut-cmdline.service = %+v", u)
	}
	if u := s.Units["dbus-org.freedesktop.hostname1.service"]; u.AliasOf != "systemd-hostnamed.service" || u.File != "" {
		t.Errorf("alias = %+v", u)
	}
}

// What cannot be read makes the facts incomplete, never silently empty.
func TestServicesUnreadable(t *testing.T) {
	m := fixtureFS(t, "rocky-9").SetError("/etc/systemd/system/multi-user.target.wants", fs.ErrPermission)
	_, complete, skipped := servicesFacts(t, m)
	if complete || len(skipped) == 0 {
		t.Errorf("complete %v, skipped %v", complete, skipped)
	}
}

// On a live target, systemd says which units are active.
func TestServicesActive(t *testing.T) {
	out, err := os.ReadFile("testdata/rocky-9-systemctl-list-units.txt")
	if err != nil {
		t.Fatal(err)
	}
	running := fixtureFS(t, "rocky-9").AddDir("/run/systemd/system", 0o755, 0, 0)
	f := servicesCollect(t, hostfs.NewTestHost(running, hostfs.RecordedRunner{"systemctl list-units": {Stdout: string(out)}}, true))
	s := f.Value.(*Services)
	if s.Active["telnet.socket"] != "listening" || s.Active["dbus-broker.service"] != "running" || s.Active["ldconfig.service"] != "exited" {
		t.Errorf("active = %v", s.Active)
	}
	for _, name := range []string{"getty@tty1.service", "home.mount", "dev-hugepages.mount"} {
		if _, ok := s.Active[name]; ok {
			t.Errorf("%s is listed as active", name)
		}
	}
	if len(f.Unknown) != 0 {
		t.Errorf("unknown = %v", f.Unknown)
	}

	// Without systemd running, no unit is active: that is known.
	f = servicesCollect(t, hostfs.NewTestHost(fixtureFS(t, "rocky-9"), nil, true))
	if s := f.Value.(*Services); len(s.Active) != 0 || len(f.Unknown) != 0 {
		t.Errorf("no systemd: active %v, unknown %v", s.Active, f.Unknown)
	}

	// systemd runs but cannot be asked: the active units are unknown.
	for name, rec := range map[string]hostfs.Recorded{
		"fails":   {Err: errors.New("timed out")},
		"exits":   {ExitCode: 1, Stderr: "Failed to connect to bus"},
		"garbled": {Stdout: "something else\n"},
	} {
		f = servicesCollect(t, hostfs.NewTestHost(running, hostfs.RecordedRunner{"systemctl list-units": rec}, true))
		if len(f.Unknown) != 1 || f.Unknown[0] != "active" || !f.Complete {
			t.Errorf("%s: unknown %v, complete %v", name, f.Unknown, f.Complete)
		}
	}
}

func TestServicesInetdDir(t *testing.T) {
	m := hostfs.NewMemFS().AddFile("/etc/inetd.d/telnet", "telnet stream tcp nowait root /usr/sbin/tcpd /usr/sbin/in.telnetd\n", 0o644, 0, 0)
	s, _, _ := servicesFacts(t, m)
	if len(s.Inetd) != 1 || s.Inetd[0].Name != "telnet" || s.Inetd[0].Source != "/etc/inetd.d/telnet:1" {
		t.Errorf("inetd = %+v", s.Inetd)
	}
}

func startedNames(s *Services) string {
	var out []string
	for _, st := range s.Started {
		out = append(out, st.Kind+":"+st.Service+":"+st.Program)
	}
	return strings.Join(out, " ")
}

// Started gathers every way a service starts, with its program, so a check
// can find a service under any name.
func TestServicesStarted(t *testing.T) {
	s, _, _ := servicesFacts(t, fixtureFS(t, "debian-12"))
	got := startedNames(s)
	for _, want := range []string{
		"unit:ssh:/usr/sbin/sshd",
		"sysv:tftpd-hpa:",
		"inetd:telnet:/usr/sbin/telnetd",
		"inetd:shell:/usr/sbin/in.rshd",
		"inetd:finger:/usr/sbin/in.fingerd",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("started lacks %s:\n%s", want, got)
		}
	}
	// ssh has a unit, so its init script does not count on its own.
	if strings.Contains(got, "sysv:ssh:") {
		t.Errorf("an init script shadowed by a unit is listed:\n%s", got)
	}

	out, err := os.ReadFile("testdata/rocky-9-systemctl-list-units.txt")
	if err != nil {
		t.Fatal(err)
	}
	running := fixtureFS(t, "rocky-9").AddDir("/run/systemd/system", 0o755, 0, 0)
	f := servicesCollect(t, hostfs.NewTestHost(running, hostfs.RecordedRunner{"systemctl list-units": {Stdout: string(out)}}, true))
	got = startedNames(f.Value.(*Services))
	for _, want := range []string{"unit:telnet:/usr/sbin/in.telnetd", "active:telnet:/usr/sbin/in.telnetd", "unit:tftp:/usr/sbin/in.tftpd"} {
		if !strings.Contains(got, want) {
			t.Errorf("started lacks %s:\n%s", want, got)
		}
	}
	if len(f.Partial) != 0 {
		t.Errorf("partial %v", f.Partial)
	}

	// Without the active units, the list is partial.
	f = servicesCollect(t, hostfs.NewTestHost(running, hostfs.RecordedRunner{"systemctl list-units": {ExitCode: 1}}, true))
	if strings.Join(f.Partial, " ") != "started" {
		t.Errorf("partial %v", f.Partial)
	}
}

// systemd splits ExecStart on any white space, joins continued lines, and an
// empty assignment resets the earlier ones.
func TestExecStartForms(t *testing.T) {
	for name, unit := range map[string]string{
		"tab":          "[Service]\nExecStart=/usr/sbin/in.telnetd\t-h\n",
		"continuation": "[Service]\nExecStart=\\\n  /usr/sbin/in.telnetd -h\n",
		"reset":        "[Service]\nExecStart=/bin/false\nExecStart=\nExecStart=/usr/sbin/in.telnetd -h\n",
		"prefix":       "[Service]\nExecStart=-@/usr/sbin/in.telnetd telnetd\n",
	} {
		if got := execStart([]byte(unit)); got != "/usr/sbin/in.telnetd" {
			t.Errorf("%s: execStart = %q", name, got)
		}
	}
}

// An inetd entry may be continued on the next line or end in a comment.
func TestServicesInetdContinuation(t *testing.T) {
	conf := "telnet stream tcp nowait root \\\n  /usr/sbin/tcpd in.telnetd # old\n# shell stream tcp nowait root /usr/sbin/in.rshd in.rshd\nlogin stream tcp nowait root /usr/sbin/in.rlogind in.rlogind\n"
	s, _, _ := servicesFacts(t, hostfs.NewMemFS().AddFile(inetdConf, conf, 0o644, 0, 0))
	if len(s.Inetd) != 2 || s.Inetd[0].Name != "telnet" || s.Inetd[0].Server != "/usr/sbin/tcpd" || s.Inetd[0].Args != "in.telnetd" || s.Inetd[0].Source != inetdConf+":1" || s.Inetd[1].Name != "login" {
		t.Errorf("inetd = %+v", s.Inetd)
	}
}

// A section written on one line is read as a section.
func TestServicesXinetdOneLine(t *testing.T) {
	conf := "service telnet { disable = yes }\nservice shell { server = /usr/sbin/in.rshd\n disable = no }\nservice login\n{\n server = /usr/sbin/in.rlogind }\n"
	s, _, _ := servicesFacts(t, hostfs.NewMemFS().AddFile("/etc/xinetd.conf", conf, 0o644, 0, 0))
	got := map[string]XinetdService{}
	for _, x := range s.Xinetd {
		got[x.Name] = x
	}
	if len(got) != 3 || !got["telnet"].Disabled || got["shell"].Disabled || got["shell"].Settings["server"] != "/usr/sbin/in.rshd" || got["login"].Settings["server"] != "/usr/sbin/in.rlogind" {
		t.Errorf("xinetd = %+v", s.Xinetd)
	}
}

// A .wants link to a unit file of another name, or to nothing, is read as
// the link says.
func TestServicesWantsLinks(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/usr/lib/systemd/system/telnet-real.service", "[Service]\nExecStart=/usr/sbin/in.telnetd\n", 0o644, 0, 0).
		AddDir("/etc/systemd/system/multi-user.target.wants", 0o755, 0, 0).
		AddSymlink("/etc/systemd/system/multi-user.target.wants/telnet.service", "/usr/lib/systemd/system/telnet-real.service").
		AddSymlink("/etc/systemd/system/multi-user.target.wants/ghost.service", "/usr/lib/systemd/system/ghost.service")
	s, _, _ := servicesFacts(t, m)
	if u := s.Units["telnet.service"]; !u.Enabled || u.AliasOf != "telnet-real.service" {
		t.Errorf("telnet.service = %+v, want an enabled alias of telnet-real.service", u)
	}
	if u := s.Units["ghost.service"]; !u.Enabled {
		t.Errorf("ghost.service = %+v", u)
	}
}

// A line longer than the scanner's default limit is read, and one too long to read is reported.
func TestServicesLongLines(t *testing.T) {
	long := strings.Repeat("x", 100<<10)
	conf := "# " + long + "\ntelnet stream tcp nowait root /usr/sbin/in.telnetd in.telnetd\n"
	if s, complete, skipped := servicesFacts(t, hostfs.NewMemFS().AddFile(inetdConf, conf, 0o644, 0, 0)); len(s.Inetd) != 1 || !complete {
		t.Errorf("inetd = %+v, skipped %v", s.Inetd, skipped)
	}
	huge := "# " + strings.Repeat("x", 2<<20) + "\ntelnet stream tcp nowait root /usr/sbin/in.telnetd in.telnetd\n"
	if _, complete, _ := servicesFacts(t, hostfs.NewMemFS().AddFile(inetdConf, huge, 0o644, 0, 0)); complete {
		t.Error("an unreadable rest of inetd.conf left the facts complete")
	}
	huge = "# " + strings.Repeat("x", 2<<20) + "\nservice telnet { disable = no }\n"
	if _, complete, _ := servicesFacts(t, hostfs.NewMemFS().AddFile("/etc/xinetd.conf", huge, 0o644, 0, 0)); complete {
		t.Error("an unreadable rest of xinetd.conf left the facts complete")
	}
}

// include and includedir lines of an included file are followed.
func TestServicesXinetdNestedIncludes(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/xinetd.conf", "includedir /etc/xinetd.d\ninclude /etc/xinetd.extra\n", 0o644, 0, 0).
		AddDir("/etc/xinetd.d", 0o755, 0, 0).
		AddFile("/etc/xinetd.d/more", "includedir /etc/xinetd.more\n", 0o644, 0, 0).
		AddFile("/etc/xinetd.extra", "service shell { server = /usr/sbin/in.rshd\n disable = no }\n", 0o644, 0, 0).
		AddDir("/etc/xinetd.more", 0o755, 0, 0).
		AddFile("/etc/xinetd.more/telnet", "service telnet { disable = no }\n", 0o644, 0, 0)
	s, complete, skipped := servicesFacts(t, m)
	got := map[string]bool{}
	for _, x := range s.Xinetd {
		got[x.Name] = x.Disabled
	}
	if len(got) != 2 || got["shell"] || got["telnet"] || !complete {
		t.Errorf("xinetd = %+v, skipped %v", s.Xinetd, skipped)
	}
}
