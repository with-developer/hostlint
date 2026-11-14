package collect

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/with-developer/vmsctl/internal/hostfs"
)

func auditOf(t *testing.T, m *hostfs.MemFS) (*Audit, bool, []string) {
	t.Helper()
	got, err := auditCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	return got.Value.(*Audit), got.Complete, got.Skipped
}

func rulesFS(files map[string]string) *hostfs.MemFS {
	m := hostfs.NewMemFS().AddDir("/etc", 0o755, 0, 0).AddDir("/etc/audit", 0o750, 0, 0).AddDir("/etc/audit/rules.d", 0o750, 0, 0)
	for name, content := range files {
		m.AddFile(name, content, 0o640, 0, 0)
	}
	return m
}

// The rules file that the auditd package of Ubuntu 22.04 installs sets how the audit system runs and audits nothing.
func TestAuditDefaultRulesOfUbuntu(t *testing.T) {
	a, complete, skipped := auditOf(t, fixtureFS(t, "audit/ubuntu-22.04"))
	if !complete || !a.Present || len(a.Rules) != 0 || len(a.Paths) != 0 {
		t.Errorf("complete %v %v, %+v", complete, skipped, a)
	}
}

// What the fix text of the STIG asks for is read as the STIG's check reads it: the commands as rules for logged-in users, the files
// and the modules as watches.
func TestAuditStigRules(t *testing.T) {
	a, complete, skipped := auditOf(t, fixtureFS(t, "audit/stig-ubuntu-22.04"))
	if !complete {
		t.Fatalf("incomplete: %v", skipped)
	}
	for _, p := range []string{"/usr/bin/chage", "/usr/bin/sudo", "/bin/su", "/sbin/unix_update", "/usr/lib/openssh/ssh-keysign", "/usr/sbin/usermod"} {
		if got := a.UserPaths[p]; got.Perms != "x" || !strings.HasPrefix(got.Source, "/etc/audit/rules.d/stig.rules:") {
			t.Errorf("%s as a command rule: %+v", p, got)
		}
	}
	for p, want := range map[string]string{"/etc/passwd": "wa", "/etc/shadow": "wa", "/etc/sudoers.d": "wa", "/var/log/journal": "wa", "/var/run/utmp": "wa", "/usr/sbin/fdisk": "x", "/sbin/modprobe": "x", "/bin/kmod": "x", "/usr/bin/chage": "x"} {
		if got := a.Paths[p].Perms; got != want {
			t.Errorf("%s audits %q, want %q", p, got, want)
		}
	}
	if _, ok := a.UserPaths["/etc/passwd"]; ok || a.UserPaths["/usr/sbin/fdisk"].Perms != "" {
		t.Error("a watch counted as a rule for logged-in users")
	}
}

func TestAuditRuleForms(t *testing.T) {
	for _, tc := range []struct {
		name, rules string
		path        string
		perms       string // in Paths
		user        bool   // in UserPaths
	}{
		{"a watch without -p audits everything", "-w /etc/x\n", "/etc/x", "rwax", false},
		{"a watch with -p", "-w /etc/x -p wa -k k\n", "/etc/x", "wa", false},
		{"a trailing slash does not matter", "-w /etc/sudoers.d/ -p wa\n", "/etc/sudoers.d", "wa", false},
		{"permissions of several rules add up", "-w /etc/x -p w\n-w /etc/x -p x\n", "/etc/x", "wx", false},
		{"dir= is a path", "-a always,exit -F dir=/etc/y -F perm=wa -k k\n", "/etc/y", "wa", false},
		{"the order of action and list does not matter", "-a exit,always -F path=/usr/bin/z -F perm=x -F auid>=1000 -F auid!=-1\n", "/usr/bin/z", "x", true},
		{"auid!=4294967295 is auid!=unset", "-a always,exit -F path=/usr/bin/z -F perm=x -F auid>=1000 -F auid!=4294967295\n", "/usr/bin/z", "x", true},
		{"without the auid filters it is not for logged-in users", "-a always,exit -F path=/usr/bin/z -F perm=x\n", "/usr/bin/z", "x", false},
		{"auid>=1000 alone is not enough", "-a always,exit -F path=/usr/bin/z -F perm=x -F auid>=1000\n", "/usr/bin/z", "x", false},
		{"a never rule audits nothing", "-a never,exit -F path=/usr/bin/z -F perm=x\n", "/usr/bin/z", "", false},
		{"a rule on another list audits nothing here", "-a always,user -F path=/usr/bin/z -F perm=x\n", "/usr/bin/z", "", false},
		{"a comment is not a rule", "# -w /etc/x -p wa\n", "/etc/x", "", false},
		{"-D deletes what came before", "-w /etc/x -p wa\n-D\n", "/etc/x", "", false},
		{"what follows -D counts", "-D\n-w /etc/x -p wa\n", "/etc/x", "wa", false},
	} {
		a, complete, skipped := auditOf(t, rulesFS(map[string]string{"/etc/audit/rules.d/a.rules": tc.rules}))
		if !complete {
			t.Errorf("%s: incomplete: %v", tc.name, skipped)
		}
		if got := a.Paths[tc.path].Perms; got != tc.perms {
			t.Errorf("%s: Paths = %q, want %q", tc.name, got, tc.perms)
		}
		if _, ok := a.UserPaths[tc.path]; ok != tc.user {
			t.Errorf("%s: in UserPaths = %v, want %v", tc.name, ok, tc.user)
		}
	}
}

// Rules files are read in name order, and audit.rules only when there is no .rules file in rules.d; -D of a later file deletes
// the rules of an earlier one, as the loader does.
func TestAuditFilesAndOrder(t *testing.T) {
	a, _, _ := auditOf(t, rulesFS(map[string]string{
		"/etc/audit/rules.d/10-a.rules": "-w /etc/a -p wa\n",
		"/etc/audit/rules.d/99-b.rules": "-D\n-w /etc/b -p wa\n",
		"/etc/audit/rules.d/notes.txt":  "-w /etc/c -p wa\n",
		"/etc/audit/audit.rules":        "-w /etc/d -p wa\n",
	}))
	if _, ok := a.Paths["/etc/a"]; ok || a.Paths["/etc/b"].Perms != "wa" || len(a.Paths) != 1 {
		t.Errorf("paths = %+v", a.Paths)
	}
	a, _, _ = auditOf(t, rulesFS(map[string]string{"/etc/audit/audit.rules": "-w /etc/d -p wa\n"}))
	if a.Paths["/etc/d"].Perms != "wa" || !a.Present {
		t.Errorf("audit.rules alone: %+v", a)
	}
	a, complete, _ := auditOf(t, hostfs.NewMemFS().AddDir("/etc", 0o755, 0, 0))
	if a.Present || len(a.Paths) != 0 || !complete {
		t.Errorf("no audit: %+v, complete %v", a, complete)
	}
}

// A line that cannot be read may be the rule a check looks for, or a "-d" that removes it: the facts are incomplete, never a pass.
func TestAuditUnreadableLinesMakeTheFactsIncomplete(t *testing.T) {
	for name, rules := range map[string]string{
		"a delete rule":         "-w /etc/x -p wa\n-d always,exit -F path=/etc/x\n",
		"an include":            "-R /etc/other.rules\n",
		"an unknown word":       "-w /etc/x -p wa -Z\n",
		"a missing value":       "-w\n",
		"a bad list":            "-a always,bogus -F path=/x\n",
		"an unknown line":       "something odd\n",
		"spaces inside a field": "-a always,exit -F path=/usr/bin/z -F perm=x -F auid >= 1000\n",
	} {
		a, complete, skipped := auditOf(t, rulesFS(map[string]string{"/etc/audit/rules.d/a.rules": rules}))
		if complete || len(skipped) == 0 {
			t.Errorf("%s: complete %v, skipped %v, %+v", name, complete, skipped, a)
		}
	}
}

func TestAuditLimits(t *testing.T) {
	var b strings.Builder
	for i := 0; i < auditMaxRules+10; i++ {
		fmt.Fprintf(&b, "-w /etc/f%d -p wa\n", i)
	}
	a, complete, skipped := auditOf(t, rulesFS(map[string]string{"/etc/audit/rules.d/a.rules": b.String()}))
	if complete || len(a.Rules) != auditMaxRules || len(skipped) == 0 {
		t.Errorf("complete %v, %d rules, %v", complete, len(a.Rules), skipped)
	}
	_, complete, _ = auditOf(t, rulesFS(map[string]string{"/etc/audit/rules.d/a.rules": "-w /etc/" + strings.Repeat("x", auditMaxLine) + " -p wa\n"}))
	if complete {
		t.Error("a line over the limit was read")
	}
}
