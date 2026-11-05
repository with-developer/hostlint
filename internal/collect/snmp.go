package collect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"path"
	"reflect"
	"slices"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// SNMP is the `snmp` facts: how the net-snmp agent is configured to be reached.
// A community string is a password: it never leaves the collector. Only what
// can be said about it without the string is kept (whether it is a well-known
// name, whether it is short, which source it is limited to).
type SNMP struct {
	// Present is false when there is no /etc/snmp/snmpd.conf.
	Present bool `json:"present"`
	// Communities are the SNMPv1 and v2c access entries: rocommunity,
	// rwcommunity, authcommunity and com2sec lines.
	Communities []SNMPCommunity `json:"communities"`
	// V3Users is the number of SNMPv3 users (rouser, rwuser, authuser,
	// createUser).
	V3Users int64 `json:"v3_users"`
	// Listen are the agentAddress addresses, as written; empty when the file
	// does not set them (the agent then listens on every interface, unless a
	// command-line option says otherwise, which is not seen).
	Listen []string `json:"listen"`
	// LoopbackOnly is true when agentAddress is set and every address is a
	// loopback address.
	LoopbackOnly bool `json:"loopback_only"`
}

// SNMPCommunity is one v1 or v2c access entry, without its string.
type SNMPCommunity struct {
	// Directive is the configuration keyword (rocommunity, com2sec, ...).
	Directive string `json:"directive"`
	// Weak says why the string is easy to guess: "a well-known name" or "shorter
	// than 8 characters"; "" when it is neither.
	Weak string `json:"weak"`
	// Unrestricted is true when the entry answers every source address.
	Unrestricted bool `json:"unrestricted"`
	// Source is the address the entry is limited to, "" for none.
	Source string `json:"source"`
	// Where is file:line.
	Where string `json:"where"`
}

const snmpdConfig = "/etc/snmp/snmpd.conf"

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

type snmpCollector struct{}

func (snmpCollector) Name() string          { return "snmp" }
func (snmpCollector) Version() int          { return 1 }
func (snmpCollector) Access() engine.Access { return engine.AccessFilesystem }
func (snmpCollector) Type() reflect.Type    { return reflect.TypeFor[SNMP]() }

func (snmpCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	s := &SNMP{Communities: []SNMPCommunity{}, Listen: []string{}}
	p := &snmpParser{fsys: h.FS, facts: s}
	if err := p.file(snmpdConfig, 0); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return engine.Facts{Value: s, Complete: true}, nil
		}
		return engine.Facts{}, err
	}
	s.Present = true
	s.LoopbackOnly = len(s.Listen) > 0 && !slices.ContainsFunc(s.Listen, func(a string) bool { return !snmpLoopback(a) })
	return engine.Facts{Value: s, Complete: len(p.skipped) == 0, Skipped: p.skipped}, nil
}

type snmpParser struct {
	fsys    hostfs.FS
	facts   *SNMP
	files   int
	skipped []string
}

func (p *snmpParser) file(name string, depth int) error {
	switch {
	case depth > snmpMaxDepth:
		p.skipped = append(p.skipped, name+": included too deeply")
		return nil
	case p.files >= snmpMaxFiles:
		if !slices.Contains(p.skipped, "too many included files") {
			p.skipped = append(p.skipped, "too many included files")
		}
		return nil
	}
	p.files++
	data, err := p.fsys.ReadFile(name)
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		fields, ok := snmpFields(sc.Text())
		if !ok {
			if strings.TrimSpace(sc.Text()) != "" && !strings.HasPrefix(strings.TrimSpace(sc.Text()), "#") {
				p.skipped = append(p.skipped, fmt.Sprintf("%s:%d: unbalanced quote", name, line))
			}
			continue
		}
		if len(fields) == 0 {
			continue
		}
		p.directive(strings.ToLower(fields[0]), fields[1:], fmt.Sprintf("%s:%d", name, line), depth)
	}
	return nil
}

func (p *snmpParser) directive(key string, args []string, where string, depth int) {
	add := func(community, source string) {
		src := snmpSource(source)
		p.facts.Communities = append(p.facts.Communities, SNMPCommunity{
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
	case "rouser", "rwuser", "authuser", "createuser":
		p.facts.V3Users++
	case "agentaddress":
		for _, a := range strings.Split(strings.Join(args, ""), ",") {
			if a = strings.TrimSpace(a); a != "" {
				p.facts.Listen = append(p.facts.Listen, a)
			}
		}
	case "includefile":
		if len(args) == 1 {
			p.include(args[0], depth)
		}
	case "includedir":
		if len(args) == 1 {
			p.includeDir(args[0], depth)
		}
	}
}

func argOr(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

// include reads a file named by includeFile, relative to /etc/snmp.
func (p *snmpParser) include(name string, depth int) {
	if !path.IsAbs(name) {
		name = path.Join("/etc/snmp", name)
	}
	if err := p.file(name, depth+1); err != nil {
		p.skipped = append(p.skipped, fmt.Sprintf("%s: %v", name, err))
	}
}

// includeDir reads the .conf files of a directory, in name order.
func (p *snmpParser) includeDir(dir string, depth int) {
	if !path.IsAbs(dir) {
		dir = path.Join("/etc/snmp", dir)
	}
	entries, err := p.fsys.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			p.skipped = append(p.skipped, fmt.Sprintf("%s: %v", dir, err))
		}
		return
	}
	for _, e := range entries {
		if e.IsRegular() && strings.HasSuffix(path.Base(e.Path), ".conf") {
			p.include(e.Path, depth)
		}
	}
}

// snmpFields splits a line into words; single and double quotes group, and a
// word starting with # ends the line. ok is false for an unbalanced quote.
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
		case c == '"' || c == '\'':
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
// every address.
func snmpSource(s string) string {
	switch strings.ToLower(s) {
	case "", "default", "0.0.0.0/0", "0.0.0.0", "::/0", "::", "0::0/0", "0.0.0.0/0.0.0.0":
		return ""
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
