// Package version reports build information for the vmsctl binary.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Set at link time, e.g.
// -ldflags "-X github.com/with-developer/vmsctl/internal/version.version=v0.1.0".
// Never modified at run time.
var (
	version string
	commit  string
	date    string
)

// Info describes a vmsctl build.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	Date      string `json:"date,omitempty"`
	GoVersion string `json:"goVersion"`
	Platform  string `json:"platform"`
}

// Get returns the build information. Values injected at link time win;
// otherwise it falls back to what the Go toolchain recorded in the binary.
func Get() Info {
	info := Info{
		Version:   version,
		Commit:    commit,
		Date:      date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		info = withBuildInfo(info, bi)
	}
	if info.Version == "" {
		info.Version = "dev"
	}
	return info
}

// withBuildInfo fills fields that are still empty from the toolchain's build info.
func withBuildInfo(info Info, bi *debug.BuildInfo) Info {
	if info.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		info.Version = bi.Main.Version
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if info.Commit == "" {
				info.Commit = s.Value
			}
		case "vcs.time":
			if info.Date == "" {
				info.Date = s.Value
			}
		}
	}
	return info
}

// String formats the info on one line.
func (i Info) String() string {
	s := "vmsctl " + i.Version
	if i.Commit != "" {
		s += " (commit " + shortCommit(i.Commit)
		if i.Date != "" {
			s += ", " + i.Date
		}
		s += ")"
	}
	return fmt.Sprintf("%s %s %s", s, i.GoVersion, i.Platform)
}

func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}
