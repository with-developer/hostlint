package collect

import (
	"testing"

	"github.com/with-developer/hostlint/internal/hostfs"
)

func shellEnv(t *testing.T, m *hostfs.MemFS) *ShellEnv {
	t.Helper()
	f, err := collect(t, shellEnvCollector{}, m)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Complete {
		t.Fatalf("incomplete: %v", f.Skipped)
	}
	return f.Value.(*ShellEnv)
}

func TestShellEnvStockRocky9(t *testing.T) {
	env := shellEnv(t, fixtureFS(t, "rocky-9"))
	if len(env.TMOUT) != 0 {
		t.Errorf("stock Rocky 9 sets no TMOUT, got %+v", env.TMOUT)
	}
	// bashrc: [ `umask` -eq 0 ] && umask 022
	if len(env.Umask) != 1 || env.Umask[0].Value != "022" || env.Umask[0].Source != "/etc/bashrc:69" {
		t.Errorf("umask = %+v", env.Umask)
	}
	// pathmunge() assigns PATH inside if blocks.
	for _, p := range env.Path {
		if !p.Conditional {
			t.Errorf("PATH assignment %+v should be marked conditional", p)
		}
	}
}

func TestShellEnvStockDebian12(t *testing.T) {
	env := shellEnv(t, fixtureFS(t, "debian-12"))
	if len(env.TMOUT) != 0 || len(env.Path) == 0 {
		t.Errorf("tmout %+v path %+v", env.TMOUT, env.Path)
	}
}

// profileLoop is how stock /etc/profile files source /etc/profile.d.
const profileLoop = "if [ -d /etc/profile.d ]; then\n  for i in /etc/profile.d/*.sh; do\n    if [ -r $i ]; then\n      . $i\n    fi\n  done\nfi\n"

func TestShellEnvHardened(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/profile", "umask 027\nif [ \"$(id -u)\" -ne 0 ]; then\n  umask 002\nfi\nexport PATH=.:/usr/bin\n"+profileLoop, 0o644, 0, 0).
		AddFile("/etc/profile.d/autologout.sh", "TMOUT=600\nreadonly TMOUT\nexport TMOUT\n", 0o644, 0, 0).
		AddFile("/root/.bash_profile", "if [ -f ~/.bashrc ]; then . ~/.bashrc; fi\n", 0o644, 0, 0).
		AddFile("/root/.bashrc", "declare -r TMOUT=300\nPATH=$PATH:/root/bin\n", 0o644, 0, 0)
	env := shellEnv(t, m)
	if len(env.Umask) != 2 || env.Umask[0].Conditional || !env.Umask[1].Conditional || env.Umask[1].Value != "002" {
		t.Errorf("umask = %+v", env.Umask)
	}
	if len(env.TMOUT) != 2 || env.TMOUT[0].Value != "600" ||
		env.TMOUT[1].Value != "300" || !env.TMOUT[1].Readonly || env.TMOUT[1].Source != "/root/.bashrc:1" {
		t.Errorf("tmout = %+v", env.TMOUT)
	}
	// readonly TMOUT makes the later declare -r fail.
	if e := env.Effective["TMOUT"]; e.Value != "600" {
		t.Errorf("effective = %+v", e)
	}
	if len(env.Path) != 2 || env.Path[0].Value != ".:/usr/bin" || env.Path[1].Value != "$PATH:/root/bin" {
		t.Errorf("path = %+v", env.Path)
	}
}

// Only the system-wide files set TMOUT for every user; root's own files
// set it for root alone.
func TestShellEnvSystemEffective(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/profile", "umask 022\n", 0o644, 0, 0).
		AddFile("/root/.bashrc", "TMOUT=600\nreadonly TMOUT\nexport TMOUT\n", 0o644, 0, 0).
		AddFile("/root/.bash_profile", ". ~/.bashrc\n", 0o644, 0, 0)
	env := shellEnv(t, m)
	if env.Effective["TMOUT"].Value != "600" {
		t.Errorf("root's effective = %+v", env.Effective)
	}
	if _, ok := env.SystemEffective["TMOUT"]; ok {
		t.Errorf("system-wide effective = %+v, want none", env.SystemEffective)
	}
	m.AddFile("/etc/profile.d/autologout.sh", "TMOUT=300\n", 0o644, 0, 0).AddFile("/etc/profile", "umask 022\n"+profileLoop, 0o644, 0, 0)
	if env := shellEnv(t, m); env.SystemEffective["TMOUT"].Value != "300" || env.Effective["TMOUT"].Value != "600" {
		t.Errorf("system %+v, root %+v", env.SystemEffective, env.Effective)
	}
}

// A non-root scan that cannot look into /root does not know which login
// file bash reads: the facts are incomplete, not empty.
func TestShellEnvRootUnreadable(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/profile", "TMOUT=600\nexport TMOUT\n", 0o644, 0, 0).
		AddFile("/root/.profile", "unset TMOUT\n", 0o644, 0, 0).
		SetError("/root", fsErrPermission)
	f, err := collect(t, shellEnvCollector{}, m)
	if err != nil || f.Complete {
		t.Errorf("complete %v, %v; want incomplete", f.Complete, err)
	}
}

func TestShellEnvUnreadable(t *testing.T) {
	m := hostfs.NewMemFS().AddFile("/etc/profile", "umask 022\n"+profileLoop, 0o644, 0, 0).AddDir("/etc/profile.d", 0o755, 0, 0).SetError("/etc/profile.d", fsErrPermission)
	f, err := collect(t, shellEnvCollector{}, m)
	if err != nil || f.Complete {
		t.Errorf("an unreadable profile.d must make the facts incomplete: %v, complete %v", err, f.Complete)
	}
}

func TestShellEnvBlocksAndUnset(t *testing.T) {
	m := hostfs.NewMemFS().AddFile("/etc/profile", profileLoop, 0o644, 0, 0).AddFile("/etc/profile.d/tmout.sh",
		"[ -n \"$SSH_TTY\" ] && echo ssh # TMOUT=1 in a comment\n"+
			"if [ \"$USER\" = root ]; then TMOUT=300;fi\n"+
			"TMOUT=600\n"+
			"case $- in *i*) umask 077;; esac\n"+
			"umask 027\n"+
			"unset TMOUT\n", 0o644, 0, 0)
	env := shellEnv(t, m)
	if len(env.TMOUT) != 3 {
		t.Fatalf("tmout = %+v", env.TMOUT)
	}
	if v := env.TMOUT[0]; v.Value != "300" || !v.Conditional {
		t.Errorf("one-line if: %+v, want conditional", v)
	}
	if v := env.TMOUT[1]; v.Value != "600" || v.Conditional {
		t.Errorf("after the block: %+v, want unconditional", v)
	}
	if v := env.TMOUT[2]; !v.Unset || v.Value != "" || v.Source != "/etc/profile.d/tmout.sh:6" {
		t.Errorf("unset: %+v", v)
	}
	if len(env.Umask) != 2 || !env.Umask[0].Conditional || env.Umask[1].Conditional {
		t.Errorf("umask = %+v", env.Umask)
	}
}

func TestShellEnvEffectiveTMOUT(t *testing.T) {
	tests := []struct {
		name, profile string
		want          string // "" when unset
	}{
		{"none", "umask 022\n", ""},
		{"set", "TMOUT=600\nexport TMOUT\n", "600"},
		{"conditional only", "if [ \"$USER\" = root ]; then\n  TMOUT=300\nfi\n", ""},
		{"later conditional positive keeps it", "TMOUT=600\n[ -n \"$X\" ] && TMOUT=300\n", "600"},
		{"later conditional zero breaks it", "TMOUT=600\n[ -n \"$X\" ] && if true; then TMOUT=0; fi\n", ""},
		{"later conditional unset breaks it", "TMOUT=600\nif [ -n \"$X\" ]; then unset TMOUT; fi\n", ""},
		{"only after &&", "[ -n \"$SSH_TTY\" ] && TMOUT=600\n", ""},
		{"set then unset on one line", "TMOUT=600; unset TMOUT\n", ""},
		{"quoted hash is not a comment", "PS1='\\h # '; TMOUT=0\n", "0"},
		{"unset afterwards", "TMOUT=600\nunset TMOUT\n", ""},
		{"read-only survives unset", "readonly TMOUT=600\nunset TMOUT\nTMOUT=0\n", "600"},
		{"last wins", "TMOUT=600\nTMOUT=1800\n", "1800"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := shellEnv(t, hostfs.NewMemFS().AddFile("/etc/profile", tt.profile, 0o644, 0, 0))
			if got, ok := env.Effective["TMOUT"]; got.Value != tt.want || ok != (tt.want != "") {
				t.Errorf("effective = %+v (present %v), want %q", got, ok, tt.want)
			}
		})
	}
}

// The files are read in bash's order, following what they source.
func TestShellEnvReadingOrder(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		// RHEL sources sh.local after profile.d/*.sh.
		{"sh.local", map[string]string{
			"/etc/profile":            "for i in /etc/profile.d/*.sh /etc/profile.d/sh.local ; do\n  . \"$i\"\ndone\n",
			"/etc/profile.d/tmout.sh": "TMOUT=600\n",
			"/etc/profile.d/sh.local": "unset TMOUT\n",
		}, ""},
		// Debian's /etc/profile sources bash.bashrc before profile.d.
		{"bash.bashrc first", map[string]string{
			"/etc/profile":         "if [ \"${PS1-}\" ]; then\n  if [ -f /etc/bash.bashrc ]; then\n    . /etc/bash.bashrc\n  fi\nfi\n" + profileLoop,
			"/etc/bash.bashrc":     "TMOUT=600\n",
			"/etc/profile.d/zz.sh": "unset TMOUT\n",
		}, ""},
		// bash reads only the first of .bash_profile, .bash_login, .profile.
		{"first login file", map[string]string{
			"/etc/profile":        "",
			"/root/.bash_profile": "# nothing\n",
			"/root/.profile":      "TMOUT=600\n",
		}, ""},
		// Hidden files in profile.d are not sourced.
		{"hidden profile.d file", map[string]string{
			"/etc/profile":             profileLoop,
			"/etc/profile.d/.tmout.sh": "TMOUT=600\nreadonly TMOUT\n",
		}, ""},
		{"sourced from bashrc", map[string]string{
			"/etc/profile":        "",
			"/root/.bash_profile": "if [ -f ~/.bashrc ]; then\n  . ~/.bashrc\nfi\n",
			"/root/.bashrc":       "if [ -f /etc/bashrc ]; then . /etc/bashrc; fi\n",
			"/etc/bashrc":         "TMOUT=900\n",
		}, "900"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := hostfs.NewMemFS()
			for name, content := range tt.files {
				m.AddFile(name, content, 0o644, 0, 0)
			}
			env := shellEnv(t, m)
			if got, ok := env.Effective["TMOUT"]; got.Value != tt.want || ok != (tt.want != "") {
				t.Errorf("effective = %+v (present %v), want %q; tmout %+v", got, ok, tt.want, env.TMOUT)
			}
		})
	}
}

// A conditional readonly may block a later change: the result is unknown.
func TestShellEnvUncertainReadonly(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/profile", "TMOUT=600\nif [ \"$(id -u)\" -ne 0 ]; then readonly TMOUT; fi\n", 0o644, 0, 0).
		AddFile("/root/.profile", "TMOUT=0\n", 0o644, 0, 0)
	f, err := collect(t, shellEnvCollector{}, m)
	if err != nil || len(f.Unknown) != 1 || f.Unknown[0] != "effective" {
		t.Errorf("unknown %v, err %v", f.Unknown, err)
	}
}
