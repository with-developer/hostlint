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

func TestShellEnvHardened(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/profile", "umask 027\nif [ \"$(id -u)\" -ne 0 ]; then\n  umask 002\nfi\nexport PATH=.:/usr/bin\n", 0o644, 0, 0).
		AddFile("/etc/profile.d/autologout.sh", "TMOUT=600\nreadonly TMOUT\nexport TMOUT\n", 0o644, 0, 0).
		AddFile("/root/.bashrc", "declare -r TMOUT=300\nPATH=$PATH:/root/bin\n", 0o644, 0, 0)
	env := shellEnv(t, m)
	if len(env.Umask) != 2 || env.Umask[0].Conditional || !env.Umask[1].Conditional || env.Umask[1].Value != "002" {
		t.Errorf("umask = %+v", env.Umask)
	}
	if len(env.TMOUT) != 2 || env.TMOUT[0].Value != "600" || !env.TMOUT[0].Readonly ||
		env.TMOUT[1].Value != "300" || !env.TMOUT[1].Readonly || env.TMOUT[1].Source != "/root/.bashrc:1" {
		t.Errorf("tmout = %+v", env.TMOUT)
	}
	if len(env.Path) != 2 || env.Path[0].Value != ".:/usr/bin" || env.Path[1].Value != "$PATH:/root/bin" {
		t.Errorf("path = %+v", env.Path)
	}
}

func TestShellEnvUnreadable(t *testing.T) {
	m := hostfs.NewMemFS().AddFile("/etc/profile", "umask 022\n", 0o644, 0, 0).SetError("/etc/profile.d", fsErrPermission)
	f, err := collect(t, shellEnvCollector{}, m)
	if err != nil || f.Complete {
		t.Errorf("an unreadable profile.d must make the facts incomplete: %v, complete %v", err, f.Complete)
	}
}

func TestShellEnvBlocksAndUnset(t *testing.T) {
	m := hostfs.NewMemFS().AddFile("/etc/profile.d/tmout.sh",
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
		t.Errorf("after ;fi: %+v, want unconditional", v)
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
		{"later conditional does not count", "TMOUT=600\n[ -n \"$X\" ] && if true; then TMOUT=0; fi\n", "600"},
		{"unset afterwards", "TMOUT=600\nunset TMOUT\n", ""},
		{"read-only survives unset", "readonly TMOUT=600\nunset TMOUT\nTMOUT=0\n", "600"},
		{"last wins", "TMOUT=600\nTMOUT=1800\n", "1800"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := shellEnv(t, hostfs.NewMemFS().AddFile("/etc/profile", tt.profile, 0o644, 0, 0))
			if got := env.EffectiveTMOUT; got.Value != tt.want || got.Explicit != (tt.want != "") {
				t.Errorf("effective = %+v, want %q", got, tt.want)
			}
		})
	}
}
