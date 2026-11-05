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
	if v := p.Settings["smtpd_relay_restrictions"]; !strings.HasPrefix(v.Value, "permit_mynetworks") || !strings.HasSuffix(v.Source, "main.cf:15") && !v.Explicit {
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
	if v := p.Settings["debugger_command"]; v.Value != "PATH=/bin ddd $daemon_directory/$process_name" {
		t.Errorf("debugger_command = %q", v.Value)
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
		{"a narrow network", "mynetworks = 10.0.0.0/8\n", 0},
		{"a bare permit as the relay restrictions", "smtpd_relay_restrictions = permit\n", 1},
		{"a permit after the guard", "smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination, permit\n", 0},
		{"a permit before the guard", "smtpd_relay_restrictions = permit_mynetworks, permit, reject_unauth_destination\n", 1},
		{"permit in the relay list, guard in the recipient list", "smtpd_relay_restrictions = permit\nsmtpd_recipient_restrictions = reject_unauth_destination\n", 0},
		{"permit in both lists", "smtpd_relay_restrictions = permit\nsmtpd_recipient_restrictions = permit\n", 1},
		{"a bare permit in the recipient restrictions", "smtpd_recipient_restrictions = check_recipient_access hash:/etc/postfix/access, permit\n", 1},
		{"permit_mynetworks is not a bare permit", "smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination\n", 0},
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
