package collect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"reflect"
	"regexp"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// FTP is the `ftp` facts: how vsftpd is configured. Other FTP servers are not
// read.
type FTP struct {
	// Present is false when there is no vsftpd.conf.
	Present bool `json:"present"`
	// Settings are the options the checks read: set in vsftpd.conf, or their
	// built-in defaults (vsftpd.conf(5)). Booleans are YES or NO.
	Settings map[string]facts.Setting `json:"settings"`
	// Banner says what a client is told when it connects: "default" (the
	// vsftpd banner, which names the version), "custom" or "version" (a custom
	// banner, or banner_file, that still shows a version or the name vsftpd).
	Banner string `json:"banner"`
	// RootDenied is true when root cannot log in: the PAM stack of the FTP
	// service refuses the users of a file that lists root (pam_listfile,
	// /etc/ftpusers), or userlist_enable and userlist_deny make a listed root
	// refused.
	RootDenied bool `json:"root_denied"`
	// RootDeniedBy is the file that lists root when RootDenied.
	RootDeniedBy string `json:"root_denied_by"`
}

var vsftpdConfigs = []string{"/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf"}

// vsftpdDefaults are the built-in defaults of the options the checks read.
var vsftpdDefaults = map[string]string{
	"anonymous_enable": "YES", "ssl_enable": "NO", "userlist_enable": "NO", "userlist_deny": "YES",
	"pam_service_name": "ftp", "force_local_logins_ssl": "YES", "force_local_data_ssl": "YES",
}

var vsftpdBools = []string{"anonymous_enable", "ssl_enable", "userlist_enable", "userlist_deny", "force_local_logins_ssl", "force_local_data_ssl"}

var (
	ftpName   = regexp.MustCompile(`(?i)vsftpd|version`)
	ftpDotted = regexp.MustCompile(`\d+\.\d+\.\d+(\.\d+)?`)
)

// ftpShowsVersion reports whether a banner names the software or a version
// number (x.y.z; a four-part number is an address, not a version).
func ftpShowsVersion(text string) bool {
	if ftpName.MatchString(text) {
		return true
	}
	for _, m := range ftpDotted.FindAllStringSubmatch(text, -1) {
		if m[1] == "" {
			return true
		}
	}
	return false
}

type ftpCollector struct{}

func (ftpCollector) Name() string          { return "ftp" }
func (ftpCollector) Version() int          { return 1 }
func (ftpCollector) Access() engine.Access { return engine.AccessFilesystem }
func (ftpCollector) Type() reflect.Type    { return reflect.TypeFor[FTP]() }

func (ftpCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	f := &FTP{Settings: map[string]facts.Setting{}, Banner: "default"}
	var data []byte
	var conf string
	var skipped []string
	for _, c := range vsftpdConfigs {
		d, err := h.FS.ReadFile(c)
		switch {
		case err == nil && conf == "":
			data, conf = d, c
		case err == nil:
			skipped = append(skipped, fmt.Sprintf("both %s and %s exist; the first is read", conf, c))
		case errors.Is(err, fs.ErrNotExist):
		case errors.Is(err, fs.ErrPermission):
			return engine.Facts{}, errors.New("vsftpd.conf cannot be read (run hostlint as root)")
		default:
			return engine.Facts{}, err
		}
	}
	if conf == "" {
		return engine.Facts{Value: f, Complete: true}, nil
	}
	f.Present = true
	// vsftpd can be started with another file (an instance unit, a path argument):
	// other configurations next to the default one may be the ones in use.
	if entries, err := h.FS.ReadDir("/etc/vsftpd"); err == nil {
		for _, e := range entries {
			if e.IsRegular() && strings.HasSuffix(path.Base(e.Path), ".conf") && path.Base(e.Path) != "vsftpd.conf" {
				skipped = append(skipped, fmt.Sprintf("%s: another vsftpd configuration exists; which one is in use is not seen", e.Path))
			}
		}
	}
	raw := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		name, value, ok := strings.Cut(text, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		raw[name] = value // the last assignment wins
		f.Settings[name] = facts.Setting{Value: value, Explicit: true, Source: fmt.Sprintf("%s:%d", conf, line)}
	}
	for name, def := range vsftpdDefaults {
		if _, ok := f.Settings[name]; !ok {
			f.Settings[name] = facts.Setting{Value: def, Source: "default (vsftpd.conf(5))"}
		}
	}
	for _, name := range vsftpdBools {
		s := f.Settings[name]
		s.Value = ftpBool(s.Value)
		f.Settings[name] = s
	}
	// Keep only what the checks read.
	for name := range f.Settings {
		if _, ok := vsftpdDefaults[name]; !ok && name != "ftpd_banner" && name != "banner_file" {
			delete(f.Settings, name)
		}
	}
	f.Banner = ftpBanner(h.FS, raw, &skipped)
	f.RootDenied, f.RootDeniedBy = ftpRootDenied(h.FS, f.Settings, raw, &skipped)
	return engine.Facts{Value: f, Complete: len(skipped) == 0, Skipped: skipped}, nil
}

// ftpBool normalizes a vsftpd boolean (YES, NO, TRUE, FALSE, 1, 0, in any
// case) to YES or NO; anything else is left as it is.
func ftpBool(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true", "1":
		return "YES"
	case "no", "false", "0":
		return "NO"
	}
	return v
}

// ftpBanner classifies the connection banner: banner_file (which overrides
// ftpd_banner), else ftpd_banner, else the default (which shows the version).
func ftpBanner(fsys hostfs.FS, raw map[string]string, skipped *[]string) string {
	var text string
	if file, ok := raw["banner_file"]; ok {
		data, err := fsys.ReadFile(file)
		if err != nil {
			*skipped = append(*skipped, fmt.Sprintf("banner_file %s: %v", file, err))
			return "default"
		}
		text = string(data[:min(len(data), 4096)])
	} else if t, ok := raw["ftpd_banner"]; ok {
		text = t
	} else {
		return "default"
	}
	if ftpShowsVersion(text) {
		return "version"
	}
	return "custom"
}

// ftpRootDenied decides whether root is refused: by the users file of a
// pam_listfile line in the FTP service's PAM stack, or by vsftpd's own user
// list (a deny list that holds root, or an allow list that does not).
func ftpRootDenied(fsys hostfs.FS, settings map[string]facts.Setting, raw map[string]string, skipped *[]string) (bool, string) {
	// lists reports whether the file has a line "root"; ok is false when it
	// cannot be read completely.
	lists := func(file string) (listed, ok bool) {
		data, err := fsys.ReadFile(file)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				*skipped = append(*skipped, fmt.Sprintf("%s: %v", file, err))
			}
			return false, false
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) == "root" {
				return true, true
			}
		}
		if err := sc.Err(); err != nil {
			*skipped = append(*skipped, fmt.Sprintf("%s: the rest of the file was not read (%v)", file, err))
			return false, false
		}
		return false, true
	}
	pamName := settings["pam_service_name"].Value
	if pam, err := fsys.ReadFile(path.Join("/etc/pam.d", path.Base(pamName))); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(pam))
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		maySkip := "" // an earlier rule that may let root past a later one
		for sc.Scan() {
			text := strings.TrimSpace(sc.Text())
			if text == "" || strings.HasPrefix(text, "#") {
				continue
			}
			typ, control, module, args := pamLine(text)
			switch {
			case strings.HasPrefix(typ, "@include") || (typ == "auth" && (control == "include" || control == "substack")):
				if maySkip == "" {
					maySkip = "an included PAM file"
				}
				continue
			case typ != "auth" && typ != "-auth":
				continue
			case !strings.Contains(module, "pam_listfile"):
				if control == "sufficient" || (strings.HasPrefix(control, "[") && strings.Contains(control, "success=")) {
					if maySkip == "" {
						maySkip = module
					}
				}
				continue
			}
			refuses := control == "required" || control == "requisite" ||
				(strings.HasPrefix(control, "[") && (strings.Contains(control, "default=die") || strings.Contains(control, "default=bad")))
			if !refuses || args["item"] != "user" || args["sense"] != "deny" || args["file"] == "" {
				continue
			}
			if listed, ok := lists(args["file"]); ok && listed {
				if maySkip != "" {
					// What comes first may let root through without this rule.
					*skipped = append(*skipped, fmt.Sprintf("/etc/pam.d/%s: %s before pam_listfile may let root skip it", path.Base(pamName), maySkip))
					return false, ""
				}
				return true, args["file"]
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		*skipped = append(*skipped, fmt.Sprintf("/etc/pam.d/%s: %v", pamName, err))
	}
	if settings["userlist_enable"].Value == "YES" {
		files := []string{"/etc/vsftpd.user_list", "/etc/vsftpd/user_list"}
		if f, ok := raw["userlist_file"]; ok {
			files = []string{f}
		}
		deny := settings["userlist_deny"].Value
		for _, f := range files {
			listed, ok := lists(f)
			switch {
			case !ok:
			case deny == "YES" && listed, deny == "NO" && !listed:
				return true, f // a deny list with root, or an allow list without it
			}
		}
	}
	return false, ""
}

// pamLine splits a PAM rule: type, control (a word, or a [..] group), module, and
// the module's key=value arguments. Fields are separated by spaces or tabs.
func pamLine(text string) (typ, control, module string, args map[string]string) {
	args = map[string]string{}
	f := strings.Fields(text)
	if len(f) < 2 {
		return text, "", "", args
	}
	typ, f = f[0], f[1:]
	if strings.HasPrefix(f[0], "[") {
		i := 0
		for i < len(f) && !strings.HasSuffix(f[i], "]") {
			i++
		}
		if i == len(f) {
			return typ, strings.Join(f, " "), "", args
		}
		control, f = strings.Join(f[:i+1], " "), f[i+1:]
	} else {
		control, f = f[0], f[1:]
	}
	if len(f) == 0 {
		return typ, control, "", args
	}
	module = f[0]
	for _, a := range f[1:] {
		k, v, _ := strings.Cut(a, "=")
		args[k] = v
	}
	return typ, control, module, args
}
