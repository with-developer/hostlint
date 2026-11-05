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
	"pam_service_name": "ftp",
}

var vsftpdBools = []string{"anonymous_enable", "ssl_enable", "userlist_enable", "userlist_deny"}

var ftpVersionText = regexp.MustCompile(`(?i)vsftpd|\d+\.\d+`)

type ftpCollector struct{}

func (ftpCollector) Name() string          { return "ftp" }
func (ftpCollector) Version() int          { return 1 }
func (ftpCollector) Access() engine.Access { return engine.AccessFilesystem }
func (ftpCollector) Type() reflect.Type    { return reflect.TypeFor[FTP]() }

func (ftpCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	f := &FTP{Settings: map[string]facts.Setting{}, Banner: "default"}
	var data []byte
	var conf string
	for _, c := range vsftpdConfigs {
		d, err := h.FS.ReadFile(c)
		switch {
		case err == nil:
			data, conf = d, c
		case errors.Is(err, fs.ErrNotExist):
			continue
		case errors.Is(err, fs.ErrPermission):
			return engine.Facts{}, errors.New("vsftpd.conf cannot be read (run hostlint as root)")
		default:
			return engine.Facts{}, err
		}
		break
	}
	if conf == "" {
		return engine.Facts{Value: f, Complete: true}, nil
	}
	f.Present = true
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
	var skipped []string
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

// ftpBanner classifies the connection banner: ftpd_banner, else the file
// banner_file names, else the default (which shows the version).
func ftpBanner(fsys hostfs.FS, raw map[string]string, skipped *[]string) string {
	text, ok := raw["ftpd_banner"]
	if !ok {
		file, hasFile := raw["banner_file"]
		if !hasFile {
			return "default"
		}
		data, err := fsys.ReadFile(file)
		if err != nil {
			*skipped = append(*skipped, fmt.Sprintf("banner_file %s: %v", file, err))
			return "default"
		}
		text = string(data[:min(len(data), 4096)])
	}
	if ftpVersionText.MatchString(text) {
		return "version"
	}
	return "custom"
}

// ftpRootDenied decides whether root is refused: by the users file of a
// pam_listfile line in the FTP service's PAM stack, or by vsftpd's own user list.
func ftpRootDenied(fsys hostfs.FS, settings map[string]facts.Setting, raw map[string]string, skipped *[]string) (bool, string) {
	lists := func(file string) bool {
		data, err := fsys.ReadFile(file)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				*skipped = append(*skipped, fmt.Sprintf("%s: %v", file, err))
			}
			return false
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) == "root" {
				return true
			}
		}
		return false
	}
	pamName := settings["pam_service_name"].Value
	if pam, err := fsys.ReadFile(path.Join("/etc/pam.d", path.Base(pamName))); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(pam))
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 3 || fields[0] != "auth" || !strings.Contains(fields[2], "pam_listfile") ||
				(fields[1] != "required" && fields[1] != "requisite") {
				continue
			}
			args := map[string]string{}
			for _, a := range fields[3:] {
				k, v, _ := strings.Cut(a, "=")
				args[k] = v
			}
			if args["item"] == "user" && args["sense"] == "deny" && args["file"] != "" && lists(args["file"]) {
				return true, args["file"]
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		*skipped = append(*skipped, fmt.Sprintf("/etc/pam.d/%s: %v", pamName, err))
	}
	if settings["userlist_enable"].Value == "YES" && settings["userlist_deny"].Value == "YES" {
		files := []string{"/etc/vsftpd.user_list", "/etc/vsftpd/user_list"}
		if f, ok := raw["userlist_file"]; ok {
			files = []string{f}
		}
		for _, f := range files {
			if lists(f) {
				return true, f
			}
		}
	}
	return false, ""
}
