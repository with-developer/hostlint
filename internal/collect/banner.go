package collect

import (
	"context"
	"errors"
	"io/fs"
	"reflect"
	"regexp"
	"strings"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/hostfs"
)

// Banner is the `banner` facts: the texts shown before and after a login.
type Banner struct {
	Files []BannerFile `json:"files"`
}

// BannerFile is one of the banner files.
type BannerFile struct {
	Path string `json:"path"`
	// Exists is false when the file is missing.
	Exists bool `json:"exists"`
	// Empty is true when the file has no text but white space.
	Empty bool `json:"empty"`
	// First is the first line with text, cut to 100 characters.
	First string `json:"first"`
	// SystemDetails lists the escapes getty expands into system details (\S the
	// system name, \r the kernel release, \v the kernel version, \m the
	// architecture, \s the OS name, \n the host name).
	SystemDetails []string `json:"system_details"`
}

var bannerFiles = []string{"/etc/issue", "/etc/issue.net", "/etc/motd"}

// \S \s \r \v \m \n are getty escapes (/etc/issue); %s %r %v %m %h are the ones of
// login and telnetd (/etc/issue.net).
var bannerEscape = regexp.MustCompile(`\\[SsrvmnNo]|%[srvmh]`)

const bannerMaxRead = 16 << 10

type bannerCollector struct{}

func (bannerCollector) Name() string          { return "banner" }
func (bannerCollector) Version() int          { return 1 }
func (bannerCollector) Access() engine.Access { return engine.AccessFilesystem }
func (bannerCollector) Type() reflect.Type    { return reflect.TypeFor[Banner]() }

func (bannerCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	b := &Banner{Files: []BannerFile{}}
	for _, name := range bannerFiles {
		f := BannerFile{Path: name, SystemDetails: []string{}}
		data, err := h.FS.ReadFile(name)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			b.Files = append(b.Files, f)
			continue
		case err != nil:
			return engine.Facts{}, err
		}
		f.Exists = true
		text := string(data[:min(len(data), bannerMaxRead)])
		f.Empty = strings.TrimSpace(text) == ""
		for _, line := range strings.Split(text, "\n") {
			if t := strings.TrimSpace(line); t != "" {
				f.First = truncateRunes(t, 100)
				break
			}
		}
		seen := map[string]bool{}
		for _, esc := range bannerEscape.FindAllString(text, -1) {
			if !seen[esc] {
				seen[esc] = true
				f.SystemDetails = append(f.SystemDetails, esc)
			}
		}
		b.Files = append(b.Files, f)
	}
	return engine.Facts{Value: b, Complete: true}, nil
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
