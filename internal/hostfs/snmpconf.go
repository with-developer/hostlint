package hostfs

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"path"
	"slices"
	"strings"
)

// SNMPConfig is what the net-snmp agent's configuration files say about who can
// reach it, without any secret. The files hold community strings and SNMPv3
// passphrases, so they are on the denylist (ADR 0004) and only this parser reads
// them: a community string is classified here (well-known, short) and dropped.
type SNMPConfig struct {
	// Present is true when at least one of the configuration files exists.
	Present bool
	// Communities are the SNMPv1 and v2c access entries.
	Communities []SNMPCommunity
	// Listen are the agentAddress addresses, as written.
	Listen []string
	// LoopbackOnly is true when agentAddress is set and every address is loopback.
	LoopbackOnly bool
	// Skipped lists what could not be read or understood: the config is then
	// incomplete.
	Skipped []string
}

// SNMPCommunity is one v1 or v2c access entry, without its string.
type SNMPCommunity struct {
	Directive string // rocommunity, rwcommunity, authcommunity, com2sec, ...
	// Weak says why the string is easy to guess ("a well-known name" or
	// "shorter than 8 characters"), "" when it is not.
	Weak string
	// Unrestricted is true when the entry answers every source address.
	Unrestricted bool
	// Source is the address the entry is limited to, "" for none.
	Source string
	// Where is file:line.
	Where string
}

// snmpConfigFiles are read when they exist, in this order: snmpd looks for
// snmpd.conf and snmpd.local.conf in its configuration directories.
var snmpConfigFiles = []string{
	"/etc/snmp/snmpd.conf", "/etc/snmp/snmpd.local.conf",
	"/usr/share/snmp/snmpd.conf", "/usr/share/snmp/snmpd.local.conf",
}

// snmpIncludeDirs resolve a relative includeFile or includeDir.
var snmpIncludeDirs = []string{"/etc/snmp", "/usr/share/snmp"}

// wellKnownCommunities are names scanners and vendors' defaults use.
var wellKnownCommunities = []string{
	"public", "private", "community", "snmp", "snmpd", "admin", "secret", "test", "default", "manager",
	"monitor", "read", "write", "cisco", "ilmi", "all", "mngt", "password", "root", "internal",
}

const (
	snmpMinCommunity = 8
	snmpMaxFiles     = 50
	snmpMaxDepth     = 4
)

// ReadSNMPConfig parses the agent's configuration files. A file that cannot be
// read other than for not existing is an error.
func ReadSNMPConfig(fsys FS) (*SNMPConfig, error) {
	sr, ok := fsys.(sensitiveReader)
	if !ok {
		return nil, &fs.PathError{Op: "read", Path: snmpConfigFiles[0], Err: errors.ErrUnsupported}
	}
	p := &snmpParser{fsys: fsys, read: sr.readSensitive, cfg: &SNMPConfig{Communities: []SNMPCommunity{}, Listen: []string{}}, seen: map[string]bool{}}
	for _, name := range snmpConfigFiles {
		err := p.file(name, 0)
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return nil, err
		default:
			p.cfg.Present = true
		}
	}
	p.cfg.Skipped = p.skipped
	p.cfg.LoopbackOnly = len(p.cfg.Listen) > 0 && !slices.ContainsFunc(p.cfg.Listen, func(a string) bool { return !snmpLoopback(a) })
	return p.cfg, nil
}

type snmpParser struct {
	fsys    FS
	read    func(string) ([]byte, error)
	cfg     *SNMPConfig
	seen    map[string]bool
	skipped []string
}

func (p *snmpParser) file(name string, depth int) error {
	switch {
	case depth > snmpMaxDepth:
		p.skipped = append(p.skipped, name+": included too deeply")
		return nil
	case p.seen[name]:
		return nil // an include cycle, or a file included twice
	case len(p.seen) >= snmpMaxFiles:
		if !slices.Contains(p.skipped, "too many included files") {
			p.skipped = append(p.skipped, "too many included files")
		}
		return nil
	}
	p.seen[name] = true
	// Only the agent's own files are read past the denylist: a path a configuration names
	// is read as any other file is, so it cannot be used to reach a secret elsewhere.
	read := p.read
	if !snmpOwnFile(name) {
		read = p.fsys.ReadFile
	}
	data, err := read(name)
	if err != nil {
		return err
	}
	defer clear(data)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		fields, ok := snmpFields(sc.Text())
		if !ok {
			// Never echo the line: it may hold a secret.
			p.skipped = append(p.skipped, fmt.Sprintf("%s:%d: unbalanced quote", name, line))
			continue
		}
		if len(fields) > 0 {
			p.directive(strings.ToLower(fields[0]), fields[1:], fmt.Sprintf("%s:%d", name, line), depth)
		}
	}
	if err := sc.Err(); err != nil {
		p.skipped = append(p.skipped, fmt.Sprintf("%s:%d: the rest of the file was not read (%v)", name, line+1, err))
	}
	return nil
}

func (p *snmpParser) directive(key string, args []string, where string, depth int) {
	add := func(community, source string) {
		src := snmpSource(source)
		p.cfg.Communities = append(p.cfg.Communities, SNMPCommunity{
			Directive: key, Weak: weakCommunity(community), Unrestricted: src == "", Source: src, Where: where,
		})
	}
	switch key {
	case "rocommunity", "rwcommunity", "rocommunity6", "rwcommunity6":
		// rocommunity COMMUNITY [SOURCE [OID | -V VIEW [CONTEXT]]]
		if len(args) >= 1 {
			add(args[0], argOr(args, 1))
		}
	case "authcommunity":
		// authcommunity TYPES COMMUNITY [SOURCE [OID | -V VIEW [CONTEXT]]]
		if len(args) >= 2 {
			add(args[1], argOr(args, 2))
		}
	case "com2sec", "com2sec6":
		// com2sec [-Cn CONTEXT] SECNAME SOURCE COMMUNITY
		a := args
		if len(a) >= 2 && a[0] == "-Cn" {
			a = a[2:]
		}
		if len(a) >= 3 {
			add(a[2], a[1])
		}
	case "agentaddress":
		for _, a := range strings.Split(strings.Join(args, ""), ",") {
			if a = strings.TrimSpace(a); a != "" {
				p.cfg.Listen = append(p.cfg.Listen, a)
			}
		}
	case "includefile":
		if len(args) == 1 {
			p.include(args[0], depth, false)
		}
	case "includedir":
		if len(args) == 1 {
			p.include(args[0], depth, true)
		}
	}
}

func argOr(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

// candidates are the places a name may refer to: itself when absolute, else
// each of the configuration directories.
func snmpCandidates(name string) []string {
	if path.IsAbs(name) {
		return []string{name}
	}
	out := make([]string, 0, len(snmpIncludeDirs))
	for _, d := range snmpIncludeDirs {
		out = append(out, path.Join(d, name))
	}
	return out
}

// include reads a file named by includeFile, or the .conf files of a directory
// named by includeDir.
func (p *snmpParser) include(name string, depth int, dir bool) {
	found := false
	for _, c := range snmpCandidates(name) {
		if dir {
			entries, err := p.fsys.ReadDir(c)
			switch {
			case errors.Is(err, fs.ErrNotExist):
				continue
			case err != nil:
				p.skipped = append(p.skipped, fmt.Sprintf("%s: %v", c, err))
				found = true
				continue
			}
			found = true
			for _, e := range entries {
				if RegularFile(p.fsys, e) && strings.HasSuffix(path.Base(e.Path), ".conf") {
					p.includeOne(e.Path, depth)
				}
			}
			continue
		}
		if _, err := p.fsys.Stat(c); err == nil {
			found = true
			p.includeOne(c, depth)
		}
	}
	// net-snmp ignores a missing includeDir, but a file named by includeFile
	// that is nowhere could hold anything: the config is incomplete.
	if !found && !dir {
		p.skipped = append(p.skipped, name+": no such file")
	}
}

func (p *snmpParser) includeOne(name string, depth int) {
	if err := p.file(name, depth+1); err != nil {
		p.skipped = append(p.skipped, fmt.Sprintf("%s: %v", name, err))
	}
}

// snmpFields splits a line into words. A quote starts a quoted word only at the
// start of a word, as in net-snmp (an apostrophe inside a word is literal), and
// a word starting with # ends the line. ok is false for an unbalanced quote.
func snmpFields(line string) (fields []string, ok bool) {
	var cur strings.Builder
	inWord, quote := false, byte(0)
	flush := func() {
		if inWord {
			fields = append(fields, cur.String())
			cur.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case (c == '"' || c == '\'') && !inWord:
			quote, inWord = c, true
		case c == '#' && !inWord:
			return fields, true
		case c == ' ' || c == '\t' || c == '\r':
			flush()
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if quote != 0 {
		return nil, false
	}
	flush()
	return fields, true
}

// snmpSource returns the address an entry is limited to, or "" when it answers
// every address: "default", an unspecified address, or any prefix of length 0.
func snmpSource(s string) string {
	switch strings.ToLower(s) {
	case "", "default":
		return ""
	}
	host, mask, hasMask := strings.Cut(s, "/")
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return ""
	}
	if hasMask {
		if mask == "0" {
			return ""
		}
		if m := net.ParseIP(mask); m != nil && m.IsUnspecified() {
			return ""
		}
	}
	return s
}

// weakCommunity says why a community string is easy to guess, without
// returning the string.
func weakCommunity(c string) string {
	if slices.Contains(wellKnownCommunities, strings.ToLower(c)) {
		return "a well-known name"
	}
	if len(c) < snmpMinCommunity {
		return "shorter than 8 characters"
	}
	return ""
}

// snmpLoopback reports whether an agentAddress entry ([proto:]address[:port])
// is a loopback address. A bare port or a wildcard is not.
func snmpLoopback(addr string) bool {
	a := addr
	if i := strings.Index(a, ":"); i > 0 {
		switch strings.ToLower(a[:i]) {
		case "udp", "tcp", "udp6", "tcp6", "udp4", "tcp4", "dtlsudp", "tlstcp", "ssh", "unix":
			if strings.EqualFold(a[:i], "unix") {
				return true
			}
			a = a[i+1:]
		}
	}
	host := a
	if strings.HasPrefix(a, "[") {
		if j := strings.Index(a, "]"); j > 0 {
			host = a[1:j]
		}
	} else if strings.Count(a, ":") == 1 {
		host, _, _ = strings.Cut(a, ":")
	}
	if host == "" {
		return false // a bare port: every interface
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// snmpOwnFile reports whether name is one of the agent's own configuration files
// (the ones on the denylist because they hold community strings).
func snmpOwnFile(name string) bool {
	for _, pattern := range []string{"/etc/snmp/*.conf", "/etc/snmp/*/*.conf", "/usr/share/snmp/snmpd*.conf", "/var/lib/net-snmp/*", "/var/lib/snmp/*"} {
		if ok, _ := path.Match(pattern, name); ok {
			return true
		}
	}
	return false
}
