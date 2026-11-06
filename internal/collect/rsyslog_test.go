package collect

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/hostfs"
)

func collectRsyslog(t *testing.T, m *hostfs.MemFS) (*Rsyslog, bool) {
	t.Helper()
	f, err := rsyslogCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	return f.Value.(*Rsyslog), f.Complete
}

func rules(r *Rsyslog) string {
	var out []string
	for _, x := range r.Rules {
		out = append(out, x.Selector+" -> "+x.Target)
	}
	return strings.Join(out, "; ")
}

// The packaged configurations of Ubuntu 24.04 (legacy selectors in an included file) and Rocky Linux 9
// (selectors with RainerScript actions).
func TestRsyslogPackagedConfigurations(t *testing.T) {
	r, complete := collectRsyslog(t, fixtureFS(t, "ubuntu-24.04"))
	want := "auth,authpriv.* -> /var/log/auth.log; *.*;auth,authpriv.none -> /var/log/syslog; kern.* -> /var/log/kern.log; mail.* -> /var/log/mail.log; mail.err -> /var/log/mail.err; *.emerg -> :omusrmsg:"
	if !r.Present || !complete || rules(r) != want {
		t.Errorf("ubuntu: %s (complete %v)", rules(r), complete)
	}
	r, complete = collectRsyslog(t, fixtureFS(t, "rocky-9"))
	want = "*.info;mail.none;authpriv.none;cron.none -> /var/log/messages; authpriv.* -> /var/log/secure; mail.* -> /var/log/maillog; cron.* -> /var/log/cron; *.emerg -> action omusrmsg; uucp,news.crit -> /var/log/spooler; local7.* -> /var/log/boot.log"
	if !r.Present || !complete || rules(r) != want {
		t.Errorf("rocky: %s (complete %v)", rules(r), complete)
	}
}

func TestRsyslogForms(t *testing.T) {
	r, complete := collectRsyslog(t, hostfs.NewMemFS().AddFile(rsyslogConf, `# comment
$ModLoad imuxsock
module(load="imuxsock")
global(workDirectory="/var/lib/rsyslog")
auth.*   -/var/log/auth.log
authpriv.*;kern.none	@@loghost.example.org:514
*.* action(type="omfwd" target="loghost" port="514")
if $syslogseverity <= 3 then /var/log/errors.log
input(type="imudp" port="514")
`, 0o644, 0, 0))
	want := "auth.* -> /var/log/auth.log; authpriv.*;kern.none -> @@loghost.example.org:514; *.* -> action omfwd"
	if !complete || rules(r) != want {
		t.Errorf("%s (complete %v)", rules(r), complete)
	}
}

func TestRsyslogIncludes(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile(rsyslogConf, "$IncludeConfig /etc/rsyslog.d/*.conf\ninclude(file=\"/etc/extra.conf\" mode=\"optional\")\ninclude(file=\"/etc/rsyslog.conf\")\n", 0o644, 0, 0).
		AddDir("/etc/rsyslog.d", 0o755, 0, 0).
		AddFile("/etc/rsyslog.d/10.conf", "kern.* /var/log/kern.log\n", 0o644, 0, 0).
		AddFile("/etc/extra.conf", "mail.* /var/log/mail.log\n", 0o644, 0, 0)
	r, complete := collectRsyslog(t, m)
	if !complete || rules(r) != "kern.* -> /var/log/kern.log; mail.* -> /var/log/mail.log" {
		t.Errorf("%s (complete %v)", rules(r), complete)
	}
	// A glob that matches nothing is fine; an unreadable included file is not.
	bad := hostfs.NewMemFS().AddFile(rsyslogConf, "$IncludeConfig /etc/rsyslog.d/*.conf\n", 0o644, 0, 0).
		AddDir("/etc/rsyslog.d", 0o755, 0, 0).
		AddFile("/etc/rsyslog.d/a.conf", "kern.* /x\n", 0o644, 0, 0).SetError("/etc/rsyslog.d/a.conf", fsErrPermission)
	if _, complete := collectRsyslog(t, bad); complete {
		t.Error("an unreadable included file must make the facts incomplete")
	}
	if r, complete := collectRsyslog(t, hostfs.NewMemFS()); r.Present || !complete {
		t.Errorf("%+v complete %v", r, complete)
	}
}

func FuzzRsyslogConfig(f *testing.F) {
	f.Add([]byte(loadTree(f, "ubuntu-24.04")["/etc/rsyslog.conf"]))
	f.Add([]byte("auth.* action(type=\"omfile\" file=\"/x\")\n$IncludeConfig /etc/*.conf\ninclude(file=\"\n"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = rsyslogCollector{}.Collect(context.Background(), hostfs.NewTestHost(hostfs.NewMemFS().AddFile(rsyslogConf, string(data), 0o644, 0, 0), nil, false))
	})
}

// A legacy module action can carry a password in its arguments: only the module is kept.
func TestRsyslogKeepsNoActionArguments(t *testing.T) {
	r, _ := collectRsyslog(t, hostfs.NewMemFS().AddFile(rsyslogConf, "*.* :ommysql:dbhost,Syslog,rsyslog,Sup3r-Secret-Pw\n*.emerg :omusrmsg:*\nauth.* action(type=\"omelasticsearch\" uid=\"u\" pwd=\"Sup3r-Secret-Pw\")\n", 0o644, 0, 0))
	if rules(r) != "*.* -> :ommysql:; *.emerg -> :omusrmsg:; auth.* -> action omelasticsearch" {
		t.Errorf("rules %s", rules(r))
	}
	data, _ := json.Marshal(r)
	if strings.Contains(string(data), "Sup3r-Secret-Pw") {
		t.Errorf("a password is in the facts: %s", data)
	}
}
