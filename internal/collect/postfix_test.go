package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/hostfs"
)

func collectPostfix(t *testing.T, m *hostfs.MemFS) *Postfix {
	t.Helper()
	f, err := postfixCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	if !f.Complete {
		t.Errorf("incomplete: %v", f.Skipped)
	}
	return f.Value.(*Postfix)
}

func postfixConf(text string) *hostfs.MemFS {
	return hostfs.NewMemFS().AddFile(postfixMainCF, text, 0o644, 0, 0)
}

// The packaged main.cf of Ubuntu 24.04 (Postfix 3.8) and Rocky Linux 9 (3.5).
func TestPostfixDistributionDefaults(t *testing.T) {
	for _, name := range []string{"ubuntu-24.04", "rocky-9"} {
		t.Run(name, func(t *testing.T) {
			p := collectPostfix(t, fixtureFS(t, name))
			if !p.Present || len(p.RelayProblems) != 0 {
				t.Fatalf("present %v, problems %v", p.Present, p.RelayProblems)
			}
			if v := p.Settings["disable_vrfy_command"]; v.Value != "no" || v.Explicit {
				t.Errorf("disable_vrfy_command = %+v, want the default no", v)
			}
		})
	}
	p := collectPostfix(t, fixtureFS(t, "ubuntu-24.04"))
	if v := p.Settings["smtpd_relay_restrictions"]; !strings.HasPrefix(v.Value, "permit_mynetworks") || !strings.HasSuffix(v.Source, "main.cf:36") || !v.Explicit {
		t.Errorf("smtpd_relay_restrictions = %+v", v)
	}
}

func TestPostfixParsing(t *testing.T) {
	p := collectPostfix(t, postfixConf(`# comment
disable_vrfy_command = yes
mynetworks = 127.0.0.0/8
	[::1]/128
debugger_command =
	 PATH=/bin
	 ddd $daemon_directory/$process_name
not a setting line
disable_vrfy_command = no
  # an indented comment line is a comment too
`))
	if v := p.Settings["disable_vrfy_command"]; v.Value != "no" || !v.Explicit || !strings.HasSuffix(v.Source, "main.cf:9") {
		t.Errorf("the last assignment wins: %+v", v)
	}
	if v := p.Settings["mynetworks"]; v.Value != "127.0.0.0/8 [::1]/128" {
		t.Errorf("a continuation line is part of the value: %q", v.Value)
	}
	if _, ok := p.Settings["debugger_command"]; ok {
		t.Error("only the parameters the checks read are kept")
	}
}

// A line that is not an assignment ends the logical line before it, so indented
// text after it is not glued to the last setting.
func TestPostfixStrayLineEndsContinuation(t *testing.T) {
	p := collectPostfix(t, postfixConf("disable_vrfy_command = yes\nnot an assignment\n   indented junk\n"))
	if v := p.Settings["disable_vrfy_command"]; v.Value != "yes" {
		t.Errorf("disable_vrfy_command = %q", v.Value)
	}
}

// main.cf may hold credentials: nothing but the parameters read is kept.
func TestPostfixKeepsNoCredentials(t *testing.T) {
	p := collectPostfix(t, postfixConf("smtp_sasl_password_maps = static:user:Sup3r-Secret-Pw\nrelayhost = [smtp.example.org]:587\n"))
	for name, v := range p.Settings {
		if strings.Contains(v.Value, "Sup3r-Secret-Pw") {
			t.Errorf("%s holds a credential", name)
		}
	}
	if _, ok := p.Settings["smtp_sasl_password_maps"]; ok {
		t.Error("smtp_sasl_password_maps was kept")
	}
}

func TestPostfixVRFYValues(t *testing.T) {
	for in, want := range map[string]string{"yes": "yes", "YES": "yes", "Yes": "yes", "on": "yes", "true": "yes", "1": "yes", "no": "no", "off": "no", "0": "no", "$other": "$other"} {
		p := collectPostfix(t, postfixConf("disable_vrfy_command = "+in+"\n"))
		if got := p.Settings["disable_vrfy_command"].Value; got != want {
			t.Errorf("disable_vrfy_command = %s gives %q, want %q", in, got, want)
		}
	}
	p := collectPostfix(t, postfixConf("vrfy = yes\ndisable_vrfy_command = $vrfy\n"))
	if got := p.Settings["disable_vrfy_command"].Value; got != "yes" {
		t.Errorf("a macro gives %q", got)
	}
}

// A value that refers to itself many times does not grow without bound.
func TestPostfixMacroExpansionIsBounded(t *testing.T) {
	refs := strings.Repeat("$a ", 300)
	conf := "a = " + refs + "\nsmtpd_relay_restrictions = " + refs + "\n"
	f, err := postfixCollector{}.Collect(context.Background(), hostfs.NewTestHost(postfixConf(conf), nil, false))
	if err != nil || f.Value.(*Postfix) == nil {
		t.Fatal(err)
	}
}

// master.cf can override main.cf for one service: the checks cannot see that, so
// the facts say they are incomplete.
func TestPostfixMasterOverrides(t *testing.T) {
	m := postfixConf("mynetworks = 127.0.0.0/8\n").AddFile(postfixMasterCF, `# service type private unpriv chroot wakeup maxproc command
smtp      inet  n       -       y       -       -       smtpd
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_relay_restrictions=permit
pickup    unix  n       -       y       60      1       pickup
`, 0o644, 0, 0)
	f, err := postfixCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	if f.Complete || len(f.Skipped) != 1 || !strings.Contains(f.Skipped[0], "submission service overrides smtpd_relay_restrictions") {
		t.Errorf("complete %v, skipped %v", f.Complete, f.Skipped)
	}
	// Overrides of other parameters change nothing the checks read.
	m = postfixConf("mynetworks = 127.0.0.0/8\n").AddFile(postfixMasterCF, "submission inet n - y - - smtpd\n  -o syslog_name=postfix/submission\n", 0o644, 0, 0)
	f, err = postfixCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil || !f.Complete {
		t.Errorf("skipped %v, err %v", f.Skipped, err)
	}
}

func TestPostfixRelayProblems(t *testing.T) {
	tests := []struct {
		name, conf string
		want       int
	}{
		{"defaults", "myhostname = x\n", 0},
		{"the usual relay restrictions", "smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination\n", 0},
		{"every address is trusted", "mynetworks = 0.0.0.0/0\n", 1},
		{"every address, other spellings", "mynetworks = 127.0.0.0/8, 0/0\n", 1},
		{"the prefix of an address with no network bits", "mynetworks = 10.0.0.0/0 [::]/0\n", 1},
		{"a narrow network", "mynetworks = 10.0.0.0/8\n", 0},
		{"an excluded entry", "mynetworks = !0.0.0.0/0 127.0.0.0/8\n", 0},
		{"a bare permit as the relay restrictions", "smtpd_relay_restrictions = permit\n", 1},
		{"a list with no guard ends in a permit", "smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated\n", 1},
		{"a recipient list with no guard does not open the default relay restrictions", "smtpd_recipient_restrictions = permit_mynetworks\n", 0},
		{"a permit after the guard", "smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination, permit\n", 0},
		{"a permit before the guard", "smtpd_relay_restrictions = permit_mynetworks, permit, reject_unauth_destination\n", 1},
		{"a bare reject makes a later permit unreachable", "smtpd_relay_restrictions = permit_mynetworks, reject, permit\n", 0},
		{"a bare defer", "smtpd_relay_restrictions = permit_sasl_authenticated, defer\n", 0},
		{"the guard in the recipient list closes an open relay list", "smtpd_relay_restrictions = permit\nsmtpd_recipient_restrictions = reject_unauth_destination\n", 0},
		{"open in both lists", "smtpd_relay_restrictions = permit\nsmtpd_recipient_restrictions = permit\n", 1},
		{"an open relay list, a recipient list that does not decide", "smtpd_relay_restrictions = permit\nsmtpd_recipient_restrictions = reject_non_fqdn_recipient\n", 1},
		{"permit_mynetworks is not a bare permit", "smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination\n", 0},
		{"a macro", "relay_list = permit\nsmtpd_relay_restrictions = $relay_list\n", 1},
		{"a macro in braces", "relay_list = permit_mynetworks reject_unauth_destination\nsmtpd_relay_restrictions = ${relay_list}, permit\n", 0},
		{"both problems", "mynetworks = 0.0.0.0/0\nsmtpd_relay_restrictions = permit\n", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := collectPostfix(t, postfixConf(tt.conf)).RelayProblems; len(got) != tt.want {
				t.Errorf("problems %q, want %d", got, tt.want)
			}
		})
	}
}

func TestPostfixAbsent(t *testing.T) {
	if p := collectPostfix(t, hostfs.NewMemFS()); p.Present || len(p.RelayProblems) != 0 {
		t.Errorf("%+v", p)
	}
}

func FuzzPostfixConfig(f *testing.F) {
	f.Add([]byte(loadTree(f, "ubuntu-24.04")["/etc/postfix/main.cf"]))
	f.Add([]byte("a = $a\nb = ${b}\n  x\n"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = postfixCollector{}.Collect(context.Background(), hostfs.NewTestHost(postfixConf(string(data)), nil, false))
	})
}
