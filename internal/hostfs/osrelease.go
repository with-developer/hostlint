package hostfs

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// OS families. A check's `platforms` lists families (ADR 0006).
const (
	FamilyDebian  = "debian" // Debian, Ubuntu
	FamilyRHEL    = "rhel"   // RHEL, CentOS, Rocky Linux, AlmaLinux, Oracle Linux
	FamilyUnknown = "unknown"
)

// OS describes the scan target's operating system.
type OS struct {
	ID           string // os-release ID, e.g. "ubuntu", "rocky"
	IDLike       []string
	VersionID    string // e.g. "24.04", "9.4", "7"
	VersionMajor int
	// VersionKnown is false when VERSION_ID is missing or not numeric; then
	// VersionMajor is 0 and must not be relied on.
	VersionKnown bool
	Name         string // human-readable name, e.g. "Ubuntu 24.04.1 LTS"
	Family       string // FamilyDebian, FamilyRHEL or FamilyUnknown
	// Supported is true for versions in the tested matrix (ROADMAP v0.1
	// scope); other versions of a known family are scanned best-effort.
	Supported bool
}

// ErrUnknownOS is returned when no release file identifies the OS.
var ErrUnknownOS = errors.New("cannot identify the operating system: no os-release or vendor release file")

// supported lists the tested versions: exact VERSION_IDs for Ubuntu (interim
// releases are not supported), major versions for the others.
var supported = map[string][]string{
	"ubuntu":    {"22.04", "24.04", "26.04"},
	"debian":    {"12", "13"},
	"rhel":      {"7", "9", "10"},
	"rocky":     {"9", "10"},
	"almalinux": {"9", "10"},
	"centos":    {"7"},
	"amzn":      {"2023"},
}

// DetectOS identifies the target's operating system from /etc/os-release,
// /usr/lib/os-release, or the older vendor release files.
func DetectOS(fsys FS) (OS, error) {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		data, err := fsys.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return OS{Family: FamilyUnknown}, err
		}
		kv, err := parseOSRelease(data)
		if err != nil {
			return OS{Family: FamilyUnknown}, fmt.Errorf("%s: %w", p, err)
		}
		return fromOSRelease(kv), nil
	}
	for _, p := range []string{"/etc/centos-release", "/etc/redhat-release"} {
		data, err := fsys.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return OS{Family: FamilyUnknown}, err
		}
		return fromRedHatRelease(string(data)), nil
	}
	data, err := fsys.ReadFile("/etc/debian_version")
	if err == nil {
		version, _, _ := strings.Cut(strings.TrimSpace(string(data)), ".")
		return finish(OS{ID: "debian", VersionID: version, Name: "Debian " + strings.TrimSpace(string(data))}), nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return OS{Family: FamilyUnknown}, err
	}
	return OS{ID: FamilyUnknown, Family: FamilyUnknown}, ErrUnknownOS
}

// parseOSRelease parses os-release(5): KEY=value lines with optional shell
// quoting.
func parseOSRelease(data []byte) (map[string]string, error) {
	kv := make(map[string]string)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		kv[strings.TrimSpace(key)] = unquote(strings.TrimSpace(value))
	}
	return kv, sc.Err()
}

func unquote(v string) string {
	if len(v) >= 2 {
		switch q := v[0]; {
		case q == '\'' && v[len(v)-1] == '\'':
			return v[1 : len(v)-1]
		case q == '"' && v[len(v)-1] == '"':
			v = v[1 : len(v)-1]
			var b strings.Builder
			for i := 0; i < len(v); i++ {
				if v[i] == '\\' && i+1 < len(v) && strings.IndexByte("\"\\$`", v[i+1]) >= 0 {
					i++
				}
				b.WriteByte(v[i])
			}
			return b.String()
		}
	}
	return v
}

func fromOSRelease(kv map[string]string) OS {
	o := OS{
		ID:        strings.ToLower(kv["ID"]),
		IDLike:    strings.Fields(strings.ToLower(kv["ID_LIKE"])),
		VersionID: kv["VERSION_ID"],
		Name:      kv["PRETTY_NAME"],
	}
	if o.Name == "" {
		o.Name = strings.TrimSpace(kv["NAME"] + " " + kv["VERSION"])
	}
	return finish(o)
}

var redHatRelease = regexp.MustCompile(`^(.*?) release (\d+)(\.\d+)*`)

// fromRedHatRelease parses e.g. "CentOS Linux release 7.9.2009 (Core)".
func fromRedHatRelease(s string) OS {
	s = strings.TrimSpace(s)
	o := OS{Name: s}
	if m := redHatRelease.FindStringSubmatch(s); m != nil {
		o.VersionID = m[2]
		switch {
		case strings.HasPrefix(m[1], "CentOS"):
			o.ID = "centos"
		case strings.HasPrefix(m[1], "Red Hat"):
			o.ID = "rhel"
		case strings.HasPrefix(m[1], "Rocky"):
			o.ID = "rocky"
		case strings.HasPrefix(m[1], "AlmaLinux"):
			o.ID = "almalinux"
		}
	}
	if o.ID == "" {
		// Unrecognized text: say so instead of guessing a family.
		o.ID = FamilyUnknown
	}
	return finish(o)
}

// finish derives the major version, family and support status.
func finish(o OS) OS {
	major, _, _ := strings.Cut(o.VersionID, ".")
	if n, err := strconv.Atoi(major); err == nil {
		o.VersionMajor, o.VersionKnown = n, true
	}
	o.Family = family(o.ID, o.IDLike)
	if versions, ok := supported[o.ID]; ok {
		v := major
		if o.ID == "ubuntu" {
			v = o.VersionID
		}
		o.Supported = slices.Contains(versions, v)
	}
	return o
}

func family(id string, like []string) string {
	for _, name := range append([]string{id}, like...) {
		switch name {
		case "debian", "ubuntu":
			return FamilyDebian
		case "rhel", "centos", "rocky", "almalinux", "ol", "amzn", "fedora":
			return FamilyRHEL
		}
	}
	return FamilyUnknown
}
