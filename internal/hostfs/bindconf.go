package hostfs

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"path"
	"slices"
	"strings"
)

// BindConfig is what BIND's configuration says about who may transfer and
// update its zones, without any secret. named.conf can hold TSIG keys
// (key "k" { secret "..."; };), so its files are on the denylist (ADR 0004)
// and only this parser reads them; it never keeps a string.
type BindConfig struct {
	// Present is true when a named.conf exists.
	Present bool
	// Zones are the zones the server is primary or secondary for, with the
	// settings that apply to them (zone, then view, then options, then the
	// default).
	Zones []BindZone
	// Skipped lists what could not be read or understood.
	Skipped []string
}

// BindZone is one zone and who may transfer or update it.
type BindZone struct {
	Name string
	Type string // primary, master, secondary or slave
	View string // "" outside a view
	// Transfer is "any" (everyone may transfer the zone), "restricted" (some
	// addresses or keys) or "none".
	Transfer string
	// Update is "any", "restricted" or "none" (the default); update-policy counts as restricted.
	Update string
	// Local is true for a zone every installation defines for the host itself
	// (localhost, 127.in-addr.arpa, ...) with the file the packages ship for it:
	// it holds nothing worth protecting.
	Local bool
	Where string // file:line
}

var bindConfigFiles = []string{"/etc/bind/named.conf", "/etc/named.conf"}

const (
	bindMaxFiles  = 100
	bindMaxDepth  = 16
	bindMaxTokens = 1 << 20
)

// bindLocalZones are the zones installations define for the host itself, and
// bindLocalFiles the zone files the packages ship for them (Debian, Ubuntu, RHEL).
var (
	bindLocalZones = []string{
		"localhost", "localhost.localdomain", "127.in-addr.arpa", "0.in-addr.arpa", "255.in-addr.arpa",
		"1.0.0.127.in-addr.arpa", "0.0.127.in-addr.arpa",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", "0.ip6.arpa",
	}
	bindLocalFiles = []string{
		"db.local", "db.127", "db.0", "db.255", "db.empty",
		"named.localhost", "named.loopback", "named.empty", "named.ca",
	}
)

// bindStmt is a statement of named.conf: its words, and the statements of its
// block when it has one.
type bindStmt struct {
	words []string
	block []bindStmt
	hasB  bool
	where string
}

// ReadBindConfig parses named.conf and the files it includes.
func ReadBindConfig(fsys FS) (*BindConfig, error) {
	sr, ok := fsys.(sensitiveReader)
	if !ok {
		return nil, &fs.PathError{Op: "read", Path: bindConfigFiles[0], Err: errors.ErrUnsupported}
	}
	p := &bindParser{read: sr.readSensitive, stack: map[string]bool{}}
	cfg := &BindConfig{}
	found := 0
	for _, name := range bindConfigFiles {
		stmts, err := p.file(name, 0)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			return nil, err
		}
		found++
		if found == 1 {
			cfg.Present = true
			p.top = stmts
		}
	}
	if found > 1 {
		// named loads one of them, and which depends on how it was started.
		p.skipped = append(p.skipped, fmt.Sprintf("both %s and %s exist; the first is read", bindConfigFiles[0], bindConfigFiles[1]))
	}
	var problems []string
	cfg.Zones, problems = interpretBind(p.top)
	cfg.Skipped = slices.Concat(p.skipped, problems)
	return cfg, nil
}

type bindParser struct {
	read    func(string) ([]byte, error)
	stack   map[string]bool // the files being read: an include of one of them is a cycle
	reads   int
	top     []bindStmt
	tokens  int
	skipped []string
}

// file parses one file, with its includes spliced in where they appear.
func (p *bindParser) file(name string, depth int) ([]bindStmt, error) {
	switch {
	case depth > bindMaxDepth:
		p.skipped = append(p.skipped, name+": included too deeply")
		return nil, nil
	case p.stack[name]:
		return nil, nil // an include cycle
	case p.reads >= bindMaxFiles:
		if !slices.Contains(p.skipped, "too many included files") {
			p.skipped = append(p.skipped, "too many included files")
		}
		return nil, nil
	}
	p.reads++
	p.stack[name] = true
	defer delete(p.stack, name)
	data, err := p.read(name)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	toks, err := bindTokens(name, data, &p.tokens)
	if err != nil {
		p.skipped = append(p.skipped, err.Error())
		return nil, nil
	}
	stmts, rest, err := bindParse(toks, 0)
	if err != nil || len(rest) > 0 {
		if err == nil {
			err = fmt.Errorf("%s: unbalanced braces", name)
		}
		p.skipped = append(p.skipped, err.Error())
	}
	return p.splice(name, stmts, depth), nil
}

// splice replaces include statements by the statements of the file, at any
// depth of blocks.
func (p *bindParser) splice(from string, stmts []bindStmt, depth int) []bindStmt {
	var out []bindStmt
	for _, s := range stmts {
		if len(s.words) == 2 && s.words[0] == "include" && !s.hasB {
			target := s.words[1]
			if !path.IsAbs(target) {
				target = path.Join(path.Dir(from), target)
			}
			inc, err := p.file(target, depth+1)
			switch {
			case errors.Is(err, fs.ErrNotExist):
				p.skipped = append(p.skipped, s.words[1]+": no such file")
			case err != nil:
				p.skipped = append(p.skipped, fmt.Sprintf("%s: %v", s.words[1], err))
			}
			out = append(out, inc...)
			continue
		}
		if s.hasB {
			s.block = p.splice(from, s.block, depth)
		}
		out = append(out, s)
	}
	return out
}

type bindTok struct {
	text string
	file string
	line int
	str  bool // a quoted string
}

func (t bindTok) where() string { return fmt.Sprintf("%s:%d", t.file, t.line) }

// bindTokens splits named.conf into words, quoted strings and the punctuation
// { } ;. Comments are // , # and /* */. A quoted string's content is kept (a
// file name) but never reported: secret values are dropped by the interpreter.
func bindTokens(name string, data []byte, count *int) ([]bindTok, error) {
	var toks []bindTok
	line := 1
	for i := 0; i < len(data); {
		c := data[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#' || (c == '/' && i+1 < len(data) && data[i+1] == '/'):
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			end := bytes.Index(data[i+2:], []byte("*/"))
			if end < 0 {
				return nil, fmt.Errorf("%s:%d: unterminated comment", name, line)
			}
			line += bytes.Count(data[i:i+2+end], []byte("\n"))
			i += end + 4
		case c == '{' || c == '}' || c == ';':
			toks = append(toks, bindTok{text: string(c), file: name, line: line})
			i++
		case c == '"':
			j := i + 1
			for j < len(data) && data[j] != '"' && data[j] != '\n' {
				if data[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(data) || data[j] != '"' {
				return nil, fmt.Errorf("%s:%d: unterminated string", name, line)
			}
			toks = append(toks, bindTok{text: string(data[i+1 : j]), file: name, line: line, str: true})
			i = j + 1
		default:
			j := i
			for j < len(data) && !strings.ContainsRune(" \t\r\n{};\"", rune(data[j])) {
				j++
			}
			toks = append(toks, bindTok{text: string(data[i:j]), file: name, line: line})
			i = j
		}
		*count++
		if *count > bindMaxTokens {
			return nil, fmt.Errorf("%s: too large", name)
		}
	}
	return toks, nil
}

// bindParse parses statements until a closing brace or the end; it returns the
// tokens left, starting with the closing brace.
func bindParse(toks []bindTok, depth int) ([]bindStmt, []bindTok, error) {
	if depth > bindMaxDepth {
		return nil, nil, errors.New("blocks nested too deeply")
	}
	var out []bindStmt
	for len(toks) > 0 {
		if toks[0].text == "}" && !toks[0].str {
			return out, toks, nil
		}
		var s bindStmt
		s.where = toks[0].where()
		for len(toks) > 0 {
			t := toks[0]
			if !t.str && t.text == ";" {
				toks = toks[1:]
				break
			}
			if !t.str && t.text == "}" {
				break // the statement ends at the block's end without a ;
			}
			if !t.str && t.text == "{" {
				block, rest, err := bindParse(toks[1:], depth+1)
				if err != nil {
					return nil, nil, err
				}
				if len(rest) == 0 {
					return nil, nil, fmt.Errorf("%s: block is not closed", t.where())
				}
				s.block, s.hasB, toks = block, true, rest[1:]
				if len(toks) > 0 && !toks[0].str && toks[0].text == ";" {
					toks = toks[1:]
				}
				break
			}
			s.words = append(s.words, t.text)
			toks = toks[1:]
		}
		if len(s.words) > 0 || s.hasB {
			out = append(out, s)
		}
	}
	return out, nil, nil
}

// interpretBind finds the zones and what applies to each.
func interpretBind(stmts []bindStmt) ([]BindZone, []string) {
	acls := map[string][]bindStmt{}
	var findACLs func([]bindStmt)
	findACLs = func(ss []bindStmt) {
		for _, s := range ss {
			if len(s.words) == 2 && s.words[0] == "acl" && s.hasB {
				acls[s.words[1]] = s.block
			}
			if s.hasB {
				findACLs(s.block)
			}
		}
	}
	findACLs(stmts)
	var problems []string

	// any, restricted or none for an address match list.
	var classify func(list []bindStmt, depth int) string
	classify = func(list []bindStmt, depth int) string {
		result := "none"
		for _, e := range list {
			words := e.words
			if len(words) > 0 && strings.HasPrefix(words[0], "!") {
				continue // a negated element, or list, grants nothing
			}
			if e.hasB { // a nested list
				if classify(e.block, depth+1) == "any" {
					return "any"
				}
				result = "restricted"
				continue
			}
			if len(words) == 0 {
				continue
			}
			w := words[0]
			switch w {
			case "any", "0.0.0.0/0", "::/0", "0/0":
				return "any"
			case "none":
			case "key", "localhost", "localnets", "geoip":
				result = "restricted"
			default:
				if sub, ok := acls[w]; ok && depth < bindMaxDepth {
					switch classify(sub, depth+1) {
					case "any":
						return "any"
					case "restricted":
						result = "restricted"
					}
					continue
				}
				if !bindAddress(w) {
					// A name that is no address and no acl cannot be judged.
					problems = append(problems, fmt.Sprintf("%s: %q is not a known acl", e.where, w))
				}
				result = "restricted"
			}
		}
		return result
	}

	option := func(block []bindStmt, name string) (string, bool) {
		for i := len(block) - 1; i >= 0; i-- {
			s := block[i]
			if len(s.words) >= 1 && s.words[0] == name && s.hasB { // allow-transfer port 853 transport tls { ... };
				return classify(s.block, 0), true
			}
		}
		return "", false
	}
	updateOf := func(block []bindStmt) (string, bool) {
		if v, ok := option(block, "allow-update"); ok {
			return v, true
		}
		for _, s := range block {
			if len(s.words) >= 1 && s.words[0] == "update-policy" { // with a block, or "local;"
				return "restricted", true
			}
		}
		return "", false
	}

	var globalTransfer = "any" // BIND's default
	for _, s := range stmts {
		if len(s.words) == 1 && s.words[0] == "options" && s.hasB {
			if v, ok := option(s.block, "allow-transfer"); ok {
				globalTransfer = v
			}
		}
	}
	var zones []BindZone
	var collect func(ss []bindStmt, view, viewTransfer string)
	collect = func(ss []bindStmt, view, viewTransfer string) {
		for _, s := range ss {
			switch {
			case len(s.words) >= 2 && s.words[0] == "view" && s.hasB:
				vt := globalTransfer
				if v, ok := option(s.block, "allow-transfer"); ok {
					vt = v
				}
				collect(s.block, s.words[1], vt)
			case len(s.words) >= 2 && s.words[0] == "zone" && s.hasB:
				z := BindZone{Name: strings.ToLower(strings.TrimSuffix(s.words[1], ".")), View: view, Where: s.where, Update: "none"}
				file := ""
				for _, f := range s.block {
					switch {
					case len(f.words) == 2 && f.words[0] == "type":
						z.Type = strings.ToLower(f.words[1])
					case len(f.words) == 2 && f.words[0] == "file":
						file = f.words[1]
					}
				}
				switch z.Type {
				case "master", "primary", "slave", "secondary":
				default:
					continue // hint, forward, stub, static-stub, redirect: nothing to transfer
				}
				z.Transfer = viewTransfer
				if view == "" {
					z.Transfer = globalTransfer
				}
				if v, ok := option(s.block, "allow-transfer"); ok {
					z.Transfer = v
				}
				if v, ok := updateOf(s.block); ok && (z.Type == "master" || z.Type == "primary") {
					z.Update = v
				}
				z.Local = slices.Contains(bindLocalZones, z.Name) && slices.Contains(bindLocalFiles, path.Base(file))
				zones = append(zones, z)
			}
		}
	}
	collect(stmts, "", globalTransfer)
	return zones, problems
}

// bindAddress reports whether w is an IP address or a network in CIDR notation.
func bindAddress(w string) bool {
	if net.ParseIP(w) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(w)
	return err == nil
}
