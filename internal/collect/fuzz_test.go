package collect

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// The files a collector reads come from the scanned host, so any content must
// give facts or an error: no panic, and no long hang. Each fuzz target puts the
// fuzzed bytes in one file of an otherwise real tree and runs a collector.

// loadTree reads testdata/<name> into a map from host path to content.
func loadTree(tb testing.TB, name string) map[string]string {
	tb.Helper()
	root := filepath.Join("testdata", name)
	files := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files["/"+filepath.ToSlash(strings.TrimPrefix(p, root+string(filepath.Separator)))] = string(data)
		return nil
	})
	if err != nil {
		tb.Fatal(err)
	}
	return files
}

// fuzzCollector runs c on a tree where hostPath holds the fuzzed bytes. The
// seeds are the real files of the trees that have one.
func fuzzCollector(f *testing.F, c engine.Collector, hostPath string, trees ...string) {
	f.Helper()
	var base map[string]string
	for _, name := range trees {
		tree := loadTree(f, name)
		if data, ok := tree[hostPath]; ok {
			f.Add([]byte(data))
		}
		if base == nil {
			base = tree
		}
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		m := hostfs.NewMemFS()
		for p, content := range base {
			m.AddFile(p, content, 0o644, 0, 0)
		}
		m.AddFile(hostPath, string(data), 0o644, 0, 0)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		start := time.Now()
		_, _ = c.Collect(ctx, hostfs.NewTestHost(m, nil, false)) // facts or an error, never a panic
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s took %v on %d bytes", c.Name(), d, len(data))
		}
	})
}

func FuzzShellEnvProfile(f *testing.F) {
	fuzzCollector(f, shellEnvCollector{}, "/etc/profile", "debian-12", "rocky-9")
}

func FuzzShellEnvProfileD(f *testing.F) {
	fuzzCollector(f, shellEnvCollector{}, "/etc/profile.d/hostlint-fuzz.sh", "rocky-9")
}

func FuzzPAMCommonAuth(f *testing.F) {
	fuzzCollector(f, pamCollector{}, "/etc/pam.d/common-auth", "debian-12")
}

func FuzzPAMSSHD(f *testing.F) {
	fuzzCollector(f, pamCollector{}, "/etc/pam.d/sshd", "debian-12")
}

func FuzzPAMPwquality(f *testing.F) {
	fuzzCollector(f, pamCollector{}, "/etc/security/pwquality.conf", "debian-12")
}

func FuzzPAMFaillock(f *testing.F) {
	fuzzCollector(f, pamCollector{}, "/etc/security/faillock.conf", "debian-12")
}

func FuzzSSHDConfig(f *testing.F) {
	fuzzCollector(f, sshdCollector{}, "/etc/ssh/sshd_config", "rocky-9", "rocky-8")
}

func FuzzLoginDefs(f *testing.F) {
	fuzzCollector(f, loginDefsCollector{}, "/etc/login.defs", "debian-12", "rocky-9")
}

func FuzzPasswd(f *testing.F) {
	fuzzCollector(f, accountsCollector{}, "/etc/passwd", "debian-12")
}

func FuzzInetdConf(f *testing.F) {
	fuzzCollector(f, servicesCollector{}, "/etc/inetd.conf", "debian-12")
}

func FuzzGroup(f *testing.F) {
	fuzzCollector(f, accountsCollector{}, "/etc/group", "debian-12", "rocky-9")
}

func FuzzHomesPasswd(f *testing.F) {
	fuzzCollector(f, homesCollector{}, "/etc/passwd", "debian-12", "rocky-9")
}

func FuzzXinetdConf(f *testing.F) {
	f.Add([]byte("defaults\n{\n\tdisabled = telnet\n}\nincludedir /etc/xinetd.d\ninclude /etc/xinetd.extra\nservice telnet\n{\n\tdisable = no\n\tserver = /usr/sbin/in.telnetd\n}\n"))
	fuzzCollector(f, servicesCollector{}, "/etc/xinetd.conf", "debian-12")
}

func FuzzDpkgStatus(f *testing.F) {
	f.Add([]byte("Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.2\n\nPackage: x\nStatus: deinstall ok config-files\n"))
	f.Add([]byte("Package: \nStatus:\n\n\n\nPackage"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = parseDpkg("/var/lib/dpkg/status", data)
	})
}

func FuzzProcNet(f *testing.F) {
	f.Add([]byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"))
	f.Add([]byte("header\n0: 0100007F:1F90 00000000:0000 07 x x x x 0 0 1\n"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = parseProcNet("/proc/net/tcp", "tcp", data)
		_, _ = parseProcNet("/proc/net/udp6", "udp", data)
	})
}

func FuzzMountinfo(f *testing.F) {
	f.Add([]byte(mountinfoSeed))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = hostfs.ParseMountinfo(data, "/")
		_, _ = hostfs.ParseMountinfo(data, "/scan")
	})
}

const mountinfoSeed = `596 433 0:69 / / rw,relatime master:179 - overlay overlay rw,lowerdir=/a:/b
605 596 254:1 /docker/volumes/data /srv/my\040data rw,relatime - ext4 /dev/vda1 rw
606 596 0:80 / /mnt/share rw,relatime - nfs4 server:/export rw,vers=4.2
`

func FuzzSysctl(f *testing.F) {
	fuzzCollector(f, sysctlCollector{}, "/etc/sysctl.d/10-kernel-hardening.conf", "sysctl-ubuntu-24.04", "sysctl-rocky-9")
}
