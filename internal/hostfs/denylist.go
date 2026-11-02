package hostfs

import (
	"path"
	"strings"
)

// Contents of these files are never read through FS.ReadFile: they hold
// password hashes, private keys, credentials or other secrets (ADR 0004).
// Their metadata (owner, mode) can still be checked. Collectors that need a
// non-secret fact from one of them (e.g. password aging from /etc/shadow) use
// a dedicated parser in this package that never returns the secret fields.
var (
	// Absolute path patterns (path.Match syntax).
	deniedPaths = []string{
		"/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-",
		"/etc/security/opasswd", "/etc/tcb/*/shadow*",
		"/etc/ssh/ssh_host_*_key",
		"/etc/ssl/private/*", "/etc/pki/*/private/*",
		"/etc/krb5.keytab", "/etc/sssd/sssd.conf", "/etc/*.secret",
		"/etc/NetworkManager/system-connections/*", "/etc/wpa_supplicant/*.conf",
		"/proc/*/environ", "/proc/*/cmdline", "/proc/*/mem", "/proc/kcore",
		"/var/lib/sss/secrets/*",
	}
	// File names denied in any directory.
	deniedNames = []string{
		".*_history", ".my.cnf", ".pgpass", ".netrc", ".git-credentials", "*.keytab",
	}
	// Directory names whose files are denied, wherever the directory is.
	deniedDirs = []string{".ssh", ".gnupg"}
	// "<dir>/<file>" pairs denied wherever they appear.
	deniedPairs = []string{".docker/config.json", ".aws/credentials", ".kube/config"}
)

// identityPaths are stat'ed when a host is opened; ReadFile refuses any file
// with the same device and inode, so a symlink or hard link elsewhere cannot
// be used to read them.
var identityPaths = []string{
	"/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-", "/etc/security/opasswd",
}

// denied reports whether the contents of the file at name must not be read.
func denied(name string) bool {
	for _, p := range deniedPaths {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	base := path.Base(name)
	for _, p := range deniedNames {
		if ok, _ := path.Match(p, base); ok {
			return true
		}
	}
	dirs := strings.Split(strings.Trim(path.Dir(name), "/"), "/")
	for _, d := range dirs {
		for _, p := range deniedDirs {
			if d == p {
				return true
			}
		}
	}
	pair := path.Base(path.Dir(name)) + "/" + base
	for _, p := range deniedPairs {
		if pair == p {
			return true
		}
	}
	return false
}
