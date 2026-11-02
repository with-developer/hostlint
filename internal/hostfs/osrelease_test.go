package hostfs

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

func TestDetectOS(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  OS
	}{
		{
			name: "Ubuntu 24.04",
			files: map[string]string{"/etc/os-release": `PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
`},
			want: OS{ID: "ubuntu", IDLike: []string{"debian"}, VersionID: "24.04", VersionMajor: 24,
				Name: "Ubuntu 24.04.1 LTS", Family: FamilyDebian, Supported: true},
		},
		{
			name:  "Ubuntu interim release is best-effort",
			files: map[string]string{"/etc/os-release": "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"25.10\"\n"},
			want:  OS{ID: "ubuntu", IDLike: []string{"debian"}, VersionID: "25.10", VersionMajor: 25, Family: FamilyDebian},
		},
		{
			name:  "Debian 13",
			files: map[string]string{"/etc/os-release": "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\nVERSION_ID=\"13\"\n"},
			want:  OS{ID: "debian", VersionID: "13", VersionMajor: 13, Name: "Debian GNU/Linux 13 (trixie)", Family: FamilyDebian, Supported: true},
		},
		{
			name:  "Rocky Linux 9.4",
			files: map[string]string{"/etc/os-release": "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\n"},
			want:  OS{ID: "rocky", IDLike: []string{"rhel", "centos", "fedora"}, VersionID: "9.4", VersionMajor: 9, Family: FamilyRHEL, Supported: true},
		},
		{
			name:  "AlmaLinux 10",
			files: map[string]string{"/etc/os-release": "ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"10.0\"\n"},
			want:  OS{ID: "almalinux", IDLike: []string{"rhel", "centos", "fedora"}, VersionID: "10.0", VersionMajor: 10, Family: FamilyRHEL, Supported: true},
		},
		{
			name:  "CentOS 7",
			files: map[string]string{"/etc/os-release": "NAME=\"CentOS Linux\"\nVERSION=\"7 (Core)\"\nID=\"centos\"\nID_LIKE=\"rhel fedora\"\nVERSION_ID=\"7\"\n"},
			want:  OS{ID: "centos", IDLike: []string{"rhel", "fedora"}, VersionID: "7", VersionMajor: 7, Name: "CentOS Linux 7 (Core)", Family: FamilyRHEL, Supported: true},
		},
		{
			name:  "RHEL 8 is best-effort",
			files: map[string]string{"/etc/os-release": "ID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"8.10\"\n"},
			want:  OS{ID: "rhel", IDLike: []string{"fedora"}, VersionID: "8.10", VersionMajor: 8, Family: FamilyRHEL},
		},
		{
			name:  "Amazon Linux 2 belongs to the RHEL family",
			files: map[string]string{"/etc/os-release": "ID=\"amzn\"\nID_LIKE=\"centos rhel fedora\"\nVERSION_ID=\"2\"\n"},
			want:  OS{ID: "amzn", IDLike: []string{"centos", "rhel", "fedora"}, VersionID: "2", VersionMajor: 2, Family: FamilyRHEL},
		},
		{
			name:  "unknown distribution",
			files: map[string]string{"/etc/os-release": "ID=arch\nPRETTY_NAME=\"Arch Linux\"\n"},
			want:  OS{ID: "arch", Name: "Arch Linux", Family: FamilyUnknown},
		},
		{
			name:  "quoting and escapes",
			files: map[string]string{"/usr/lib/os-release": "ID='debian'\nVERSION_ID=12\nPRETTY_NAME=\"Debian \\\"bookworm\\\" \\$HOME\"\n# comment\nbroken line\n"},
			want:  OS{ID: "debian", VersionID: "12", VersionMajor: 12, Name: `Debian "bookworm" $HOME`, Family: FamilyDebian, Supported: true},
		},
		{
			name:  "CentOS 7 from redhat-release",
			files: map[string]string{"/etc/redhat-release": "CentOS Linux release 7.9.2009 (Core)\n"},
			want:  OS{ID: "centos", VersionID: "7", VersionMajor: 7, Name: "CentOS Linux release 7.9.2009 (Core)", Family: FamilyRHEL, Supported: true},
		},
		{
			name:  "Debian from debian_version",
			files: map[string]string{"/etc/debian_version": "12.5\n"},
			want:  OS{ID: "debian", VersionID: "12", VersionMajor: 12, Name: "Debian 12.5", Family: FamilyDebian, Supported: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMemFS()
			for p, c := range tt.files {
				m.AddFile(p, c, 0o644, 0, 0)
			}
			got, err := DetectOS(m)
			if err != nil {
				t.Fatal(err)
			}
			if !sameOS(got, tt.want) {
				t.Errorf("DetectOS() = %+v\nwant          %+v", got, tt.want)
			}
		})
	}
}

func TestDetectOSDoesNotGuess(t *testing.T) {
	garbage := NewMemFS().AddFile("/etc/redhat-release", "Something Else entirely\n", 0o644, 0, 0)
	if got, err := DetectOS(garbage); err != nil || got.Family != FamilyUnknown {
		t.Errorf("unrecognized redhat-release: %+v, %v; want family unknown", got, err)
	}
	testing := NewMemFS().AddFile("/etc/os-release", "ID=debian\nPRETTY_NAME=\"Debian GNU/Linux forky/sid\"\n", 0o644, 0, 0)
	if got, err := DetectOS(testing); err != nil || got.VersionKnown || got.Family != FamilyDebian {
		t.Errorf("no VERSION_ID: %+v, %v; want a known family with an unknown version", got, err)
	}
	long := NewMemFS().AddFile("/etc/os-release", "X="+strings.Repeat("a", 2<<20)+"\nID=ubuntu\n", 0o644, 0, 0)
	if _, err := DetectOS(long); err == nil {
		t.Error("an unparseable os-release must be an error, not a partial guess")
	}
}

func TestDetectOSErrors(t *testing.T) {
	got, err := DetectOS(NewMemFS())
	if !errors.Is(err, ErrUnknownOS) || got.Family != FamilyUnknown {
		t.Errorf("empty host: %+v, %v", got, err)
	}
	unreadable := NewMemFS().AddFile("/etc/os-release", "ID=ubuntu\n", 0o600, 0, 0).SetError("/etc/os-release", fs.ErrPermission)
	if _, err := DetectOS(unreadable); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("unreadable os-release: %v, want a permission error", err)
	}
}

func sameOS(a, b OS) bool {
	return a.ID == b.ID && equal(a.IDLike, b.IDLike) && a.VersionID == b.VersionID &&
		a.VersionMajor == b.VersionMajor && a.Name == b.Name && a.Family == b.Family && a.Supported == b.Supported
}
