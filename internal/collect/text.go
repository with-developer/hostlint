package collect

import (
	"errors"
	"strings"

	"github.com/with-developer/hostlint/internal/hostfs"
)

// The C programs whose files the collectors read (libpam, shadow-utils,
// libpwquality, pam_faillock) split and trim with isspace() in the C locale:
// ASCII whitespace only. A non-breaking space pasted from a web page is part
// of a token to them, so it must be to us too; Go's strings.TrimSpace and
// strings.Fields would drop it and report a value the program never sees.

const asciiSpace = " \t\n\v\f\r"

// isASCIISpaceRune reports whether r is ASCII whitespace.
func isASCIISpaceRune(r rune) bool { return r < 0x80 && strings.ContainsRune(asciiSpace, r) }

// trimASCII removes leading and trailing ASCII whitespace.
func trimASCII(s string) string { return strings.Trim(s, asciiSpace) }

// fieldsASCII splits s around runs of ASCII whitespace.
func fieldsASCII(s string) []string {
	return strings.FieldsFunc(s, isASCIISpaceRune)
}

// splitKeyValue splits a configuration line the way pam_faillock,
// libpwquality and pam_modutil_search_key do: the key ends at whitespace or
// "=", then whitespace and one "=" are skipped.
func splitKeyValue(line string) (key, value string) {
	i := strings.IndexFunc(line, func(r rune) bool { return r == '=' || isASCIISpaceRune(r) })
	if i < 0 {
		return line, ""
	}
	key, rest := line[:i], line[i:]
	rest = strings.TrimLeft(rest, asciiSpace)
	rest = strings.TrimPrefix(rest, "=")
	return key, strings.TrimLeft(rest, asciiSpace)
}

// maxBigFile is the most readBig reads.
const maxBigFile = 256 << 20

// readBig reads a file that is usually small but may pass hostfs.MaxReadSize (the dpkg
// status file of a big install, /proc/net/tcp on a host with very many connections).
func readBig(fsys hostfs.FS, name string) ([]byte, error) {
	data, err := fsys.ReadFile(name)
	if errors.Is(err, hostfs.ErrTooLarge) {
		return hostfs.ReadLargeFile(fsys, name, maxBigFile)
	}
	return data, err
}
