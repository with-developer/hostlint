package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/with-developer/hostlint/internal/hostfs"
)

func collectBanner(t *testing.T, m *hostfs.MemFS) map[string]BannerFile {
	t.Helper()
	f, err := bannerCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil || !f.Complete {
		t.Fatalf("err %v complete %v", err, f.Complete)
	}
	out := map[string]BannerFile{}
	for _, bf := range f.Value.(*Banner).Files {
		out[bf.Path] = bf
	}
	return out
}

// The packaged /etc/issue of Ubuntu 24.04 names the release and uses the escape for the host name.
func TestBannerPackagedFiles(t *testing.T) {
	ubuntu := collectBanner(t, fixtureFS(t, "ubuntu-24.04"))["/etc/issue"]
	if !ubuntu.Exists || ubuntu.Empty || ubuntu.First != `Ubuntu 24.04.5 LTS \n \l` || len(ubuntu.SystemDetails) != 1 || ubuntu.SystemDetails[0] != `\n` {
		t.Errorf("%+v", ubuntu)
	}
	debian := collectBanner(t, fixtureFS(t, "debian-12"))["/etc/issue.net"]
	if !debian.Exists || debian.First != "Debian GNU/Linux 12" {
		t.Errorf("%+v", debian)
	}
	if motd := collectBanner(t, fixtureFS(t, "debian-12"))["/etc/motd"]; motd.Path == "" {
		t.Errorf("a missing file is still listed: %+v", motd)
	}
}

func TestBannerFiles(t *testing.T) {
	m := hostfs.NewMemFS().
		AddFile("/etc/issue", "\n\n  Authorized use only. \\S on \\r (\\m) and \\S again\nsecond line\n", 0o644, 0, 0).
		AddFile("/etc/issue.net", "   \n\t\n", 0o644, 0, 0).
		AddFile("/etc/motd", strings.Repeat("x", 300)+"\n", 0o644, 0, 0)
	files := collectBanner(t, m)
	if f := files["/etc/issue"]; f.First != `Authorized use only. \S on \r (\m) and \S again` || strings.Join(f.SystemDetails, " ") != `\S \r \m` {
		t.Errorf("issue: %+v", f)
	}
	if f := files["/etc/issue.net"]; !f.Exists || !f.Empty || f.First != "" {
		t.Errorf("issue.net: %+v", f)
	}
	if f := files["/etc/motd"]; len([]rune(f.First)) != 101 || !strings.HasSuffix(f.First, "…") {
		t.Errorf("motd: %q", f.First)
	}
}

func TestBannerPercentEscapes(t *testing.T) {
	m := hostfs.NewMemFS().AddFile("/etc/issue.net", "%s %r on %h. 100%% sure\n", 0o644, 0, 0)
	if f := collectBanner(t, m)["/etc/issue.net"]; strings.Join(f.SystemDetails, " ") != "%s %r %h" {
		t.Errorf("%+v", f)
	}
}

func TestBannerUnreadable(t *testing.T) {
	m := hostfs.NewMemFS().AddFile("/etc/issue", "x", 0o644, 0, 0).SetError("/etc/issue", fsErrPermission)
	if _, err := (bannerCollector{}).Collect(context.Background(), hostfs.NewTestHost(m, nil, false)); err == nil {
		t.Error("an unreadable banner file must fail the collector")
	}
}
