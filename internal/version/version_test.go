package version

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestWithBuildInfo(t *testing.T) {
	settings := []debug.BuildSetting{
		{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"},
		{Key: "vcs.time", Value: "2026-11-02T10:00:00Z"},
	}
	tests := []struct {
		name string
		in   Info
		main string
		want Info
	}{
		{
			name: "link-time values win",
			in:   Info{Version: "v0.1.0", Commit: "abc", Date: "2026-01-01T00:00:00Z"},
			main: "v9.9.9",
			want: Info{Version: "v0.1.0", Commit: "abc", Date: "2026-01-01T00:00:00Z"},
		},
		{
			name: "falls back to module version and vcs settings",
			main: "v0.2.0",
			want: Info{Version: "v0.2.0", Commit: "0123456789abcdef0123456789abcdef01234567", Date: "2026-11-02T10:00:00Z"},
		},
		{
			name: "devel module version is ignored",
			main: "(devel)",
			want: Info{Commit: "0123456789abcdef0123456789abcdef01234567", Date: "2026-11-02T10:00:00Z"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bi := &debug.BuildInfo{Main: debug.Module{Version: tt.main}, Settings: settings}
			if got := withBuildInfo(tt.in, bi); got != tt.want {
				t.Errorf("withBuildInfo() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestInfoString(t *testing.T) {
	tests := []struct {
		name string
		in   Info
		want string
	}{
		{
			name: "full",
			in:   Info{Version: "v0.1.0", Commit: "0123456789abcdef", Date: "2026-11-02T10:00:00Z", GoVersion: "go1.26.0", Platform: "linux/amd64"},
			want: "hostlint v0.1.0 (commit 0123456789ab, 2026-11-02T10:00:00Z) go1.26.0 linux/amd64",
		},
		{
			name: "no vcs info",
			in:   Info{Version: "dev", GoVersion: "go1.26.0", Platform: "linux/arm64"},
			want: "hostlint dev go1.26.0 linux/arm64",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGet(t *testing.T) {
	info := Get()
	if info.Version == "" {
		t.Error("Version is empty")
	}
	if !strings.HasPrefix(info.GoVersion, "go") {
		t.Errorf("GoVersion = %q, want go prefix", info.GoVersion)
	}
	if !strings.Contains(info.Platform, "/") {
		t.Errorf("Platform = %q, want os/arch", info.Platform)
	}
}
