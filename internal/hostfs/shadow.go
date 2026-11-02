package hostfs

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
)

// ShadowEntry is the non-secret part of one /etc/shadow line. The password
// hash itself never leaves this package: only its state and algorithm do.
type ShadowEntry struct {
	Name string
	// State is "set" (a usable password), "locked" (a "!" or "*" prefix, or
	// no hash at all) or "empty" (no password: anyone can log in).
	State string
	// Algorithm of the hash: "yescrypt", "gost-yescrypt", "scrypt",
	// "sha512", "sha256", "bcrypt", "md5", "des", or "" when there is no hash.
	Algorithm string
	// Aging fields in days; -1 when the field is empty.
	LastChange, MinDays, MaxDays, WarnDays, InactiveDays, Expire int64
	// Line is the 1-based line number in /etc/shadow.
	Line int
}

// sensitiveReader is implemented by this package's filesystems; it reads a
// denylisted file for one of the parsers in this package.
type sensitiveReader interface {
	readSensitive(name string) ([]byte, error)
}

// ReadShadow parses /etc/shadow and returns only non-secret fields. The file
// is otherwise on the denylist, so no other code can read it.
func ReadShadow(fsys FS) ([]ShadowEntry, error) {
	sr, ok := fsys.(sensitiveReader)
	if !ok {
		return nil, &fs.PathError{Op: "read", Path: "/etc/shadow", Err: errors.ErrUnsupported}
	}
	data, err := sr.readSensitive("/etc/shadow")
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var entries []ShadowEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 8 || f[0] == "" {
			// Never echo the line: it may hold a hash.
			return nil, fmt.Errorf("/etc/shadow:%d: malformed entry", n)
		}
		e := ShadowEntry{Name: f[0], Line: n}
		e.State, e.Algorithm = classifyHash(f[1])
		var aging [6]int64
		for i := range aging {
			v, err := parseDays(f[2+i])
			if err != nil {
				return nil, fmt.Errorf("/etc/shadow:%d: field %d is not a number", n, 3+i)
			}
			aging[i] = v
		}
		e.LastChange, e.MinDays, e.MaxDays, e.WarnDays, e.InactiveDays, e.Expire =
			aging[0], aging[1], aging[2], aging[3], aging[4], aging[5]
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("/etc/shadow: %w", err)
	}
	return entries, nil
}

func parseDays(s string) (int64, error) {
	if s == "" {
		return -1, nil
	}
	return strconv.ParseInt(s, 10, 64)
}

// classifyHash derives the password state and hash algorithm (crypt(5)).
func classifyHash(field string) (state, algorithm string) {
	switch {
	case field == "":
		return "empty", ""
	case strings.HasPrefix(field, "!") || strings.HasPrefix(field, "*"):
		state = "locked"
		field = strings.TrimLeft(field, "!*")
	default:
		state = "set"
	}
	switch {
	case field == "":
		algorithm = ""
	case strings.HasPrefix(field, "$y$"):
		algorithm = "yescrypt"
	case strings.HasPrefix(field, "$gy$"):
		algorithm = "gost-yescrypt"
	case strings.HasPrefix(field, "$7$"):
		algorithm = "scrypt"
	case strings.HasPrefix(field, "$6$"):
		algorithm = "sha512"
	case strings.HasPrefix(field, "$5$"):
		algorithm = "sha256"
	case strings.HasPrefix(field, "$2a$"), strings.HasPrefix(field, "$2b$"), strings.HasPrefix(field, "$2y$"):
		algorithm = "bcrypt"
	case strings.HasPrefix(field, "$1$"):
		algorithm = "md5"
	case len(field) == 13 && !strings.HasPrefix(field, "$"):
		algorithm = "des"
	default:
		algorithm = "unknown"
	}
	if state == "set" && algorithm == "unknown" && len(field) < 13 {
		// Not a hash any crypt(3) produces, e.g. "x" or "NP": no usable password.
		state, algorithm = "locked", ""
	}
	return state, algorithm
}
