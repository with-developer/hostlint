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
	"slices"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// ShellEnv are the `shell_env` facts: what root's bash login shell sets,
// following the files it reads in order: /etc/environment (pam_env), then
// /etc/profile and the first of ~/.bash_profile, ~/.bash_login and
// ~/.profile, and the files they source (/etc/profile.d/*.sh, sh.local,
// bashrc files). Shell scripts cannot be evaluated statically, so every
// occurrence is listed in reading order, marked conditional when it may not
// run (inside if, case, loops, functions or subshells, or after && or ||);
// rules decide what to accept.
type ShellEnv struct {
	TMOUT []ShellValue `json:"tmout"` // TMOUT assignments and unsets
	Umask []ShellValue `json:"umask"` // umask commands
	Path  []ShellValue `json:"path"`  // PATH assignments
	// Effective maps a variable to what its unconditional assignments and
	// unsets leave, in reading order (once it is read-only, later changes
	// fail). A variable is absent when no value survives. The map is unknown
	// when a conditional change could alter the result. Only TMOUT is
	// tracked.
	Effective map[string]facts.Setting `json:"effective"`
	// SystemEffective is the same for the system-wide files only
	// (/etc/environment, /etc/profile and what it sources): what every
	// user's login shell gets, before their own startup files.
	SystemEffective map[string]facts.Setting `json:"system_effective"`
}

// ShellValue is one occurrence in a startup file.
type ShellValue struct {
	Value       string `json:"value"`
	Readonly    bool   `json:"readonly"`    // readonly or declare -r on the same command
	Conditional bool   `json:"conditional"` // may not run; see ShellEnv
	Unset       bool   `json:"unset"`       // an unset command (TMOUT only); Value is ""
	Source      string `json:"source"`
}

var (
	tmoutRe      = regexp.MustCompile(`(?:^|[;&|\s(])(readonly\s+|export\s+|declare\s+-[a-zA-Z]+\s+|typeset\s+-[a-zA-Z]+\s+)?TMOUT=["']?(\d*)["']?`)
	unsetTMOUTRe = regexp.MustCompile(`(?:^|[;&|\s(])unset\s+(?:-v\s+)?(?:\w+\s+)*TMOUT\b`)
	// A read-only declaration without an assignment.
	readonlyTMOUTRe = regexp.MustCompile(`(?:^|[;&|\s(])(?:readonly|declare\s+-[a-zA-Z]*r[a-zA-Z]*|typeset\s+-[a-zA-Z]*r[a-zA-Z]*)\s+(?:\w+\s+)*TMOUT\b(?:[^=]|$)`)
	umaskRe         = regexp.MustCompile(`(?:^|[;&|\s(])umask\s+([0-7]{3,4}|[ugoa=+,rwx-]+)\b`)
	pathRe          = regexp.MustCompile(`(?:^|[;&|\s(])(?:export\s+)?PATH=("[^"]*"|'[^']*'|\S*)`)
	sourceRe        = regexp.MustCompile(`(?:^|[;&|{(]\s*|\b(?:then|do|else)\s+)(?:\.|source)\s+("[^"]+"|'[^']+'|[^\s;&|)]+)`)
	shellWordRe     = regexp.MustCompile(`[^\s;&|()]+`)
)

// Bash reads these, in order, for root's login shell.
const envFile = "/etc/environment"

var loginFiles = []string{"/root/.bash_profile", "/root/.bash_login", "/root/.profile"}

// standardSources are files the stock startup files source behind guards
// that hold in an interactive login shell (the file exists, $PS1 is set,
// the shell is bash), so what they set counts as unconditional.
var standardSources = []string{"/etc/bash.bashrc", "/etc/bashrc", "/root/.bashrc", "/etc/profile.d/sh.local"}

const (
	maxShellFiles = 100
	maxShellDepth = 8
)

type shellEnvCollector struct{}

func (shellEnvCollector) Name() string          { return "shell_env" }
func (shellEnvCollector) Version() int          { return 1 }
func (shellEnvCollector) Access() engine.Access { return engine.AccessFilesystem }
func (shellEnvCollector) Type() reflect.Type    { return reflect.TypeFor[ShellEnv]() }

func (shellEnvCollector) Collect(ctx context.Context, h *hostfs.Host) (engine.Facts, error) {
	s := &shellScanner{ctx: ctx, fsys: h.FS, env: &ShellEnv{TMOUT: []ShellValue{}, Umask: []ShellValue{}, Path: []ShellValue{}}, read: map[string]bool{}}
	s.file(envFile, false, 0)
	s.file("/etc/profile", false, 0)
	system := len(s.events)
	// bash reads the first of these that exists; one that cannot be looked
	// at leaves unknown which it reads.
	for _, f := range loginFiles {
		_, err := s.fsys.Stat(f)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			s.skip(err.Error())
		} else {
			s.file(f, false, 0)
		}
		break
	}
	if err := ctx.Err(); err != nil {
		return engine.Facts{}, err
	}
	f := engine.Facts{Value: s.env, Complete: len(s.skipped) == 0, Skipped: s.skipped}
	s.env.Effective, s.env.SystemEffective = map[string]facts.Setting{}, map[string]facts.Setting{}
	uncertain := false
	for _, part := range []struct {
		field  string
		events []shellEvent
		into   map[string]facts.Setting
	}{
		{"effective", s.events, s.env.Effective},
		{"system_effective", s.events[:system], s.env.SystemEffective},
	} {
		effective, certain := effectiveTMOUT(part.events)
		switch {
		case !certain:
			f.Unknown = append(f.Unknown, part.field)
			uncertain = true
		case effective.Explicit:
			part.into["TMOUT"] = effective
		}
	}
	if uncertain {
		f.Skipped = append(f.Skipped, "a conditional readonly TMOUT may block a later change, so the effective value is unknown")
	}
	return f, nil
}

// shellEvent is one change to TMOUT, in reading order.
type shellEvent struct {
	kind     string // set, unset or readonly
	value    string
	readonly bool // a set that also makes TMOUT read-only
	cond     bool
	source   string
}

type shellScanner struct {
	ctx     context.Context
	fsys    hostfs.FS
	env     *ShellEnv
	events  []shellEvent
	read    map[string]bool
	files   int
	skipped []string
}

// file scans one file; cond is true when the line that sourced it may not
// run.
func (s *shellScanner) file(name string, cond bool, depth int) {
	switch {
	case s.ctx.Err() != nil:
		return
	case depth > maxShellDepth || s.files >= maxShellFiles:
		s.skip(name + ": sourced files nest too deeply")
		return
	case s.read[name]:
		return // read already (the stock bashrc files guard against a second time)
	}
	data, err := s.fsys.ReadFile(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return
	case err != nil:
		s.skip(err.Error())
		return
	}
	s.files++
	s.read[name] = true

	depthBlocks := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		code := trimASCII(stripShellComment(sc.Text()))
		if code == "" {
			continue
		}
		opens, closes := blockWords(code)
		src := fmt.Sprintf("%s:%d", name, line)
		// A command may not run inside a block, on a line that opens one,
		// after && or ||, or in a subshell.
		lineCond := cond || depthBlocks > 0 || opens > 0 || hasControlOperator(code)
		s.scanLine(code, src, lineCond)
		s.follow(code, lineCond, depth)
		depthBlocks = max(depthBlocks+opens-closes, 0)
	}
	if err := sc.Err(); err != nil {
		s.skip(fmt.Sprintf("%s: %v", name, err))
	}
}

// scanLine records every TMOUT, umask and PATH occurrence on a line, in
// order.
func (s *shellScanner) scanLine(code, src string, cond bool) {
	type hit struct {
		pos int
		ev  shellEvent
	}
	var hits []hit
	for _, m := range tmoutRe.FindAllStringSubmatchIndex(code, -1) {
		prefix := ""
		if m[2] >= 0 {
			prefix = code[m[2]:m[3]]
		}
		hits = append(hits, hit{m[0], shellEvent{kind: "set", value: code[m[4]:m[5]], readonly: readonlyPrefix(prefix), cond: cond, source: src}})
	}
	for _, m := range unsetTMOUTRe.FindAllStringIndex(code, -1) {
		hits = append(hits, hit{m[0], shellEvent{kind: "unset", cond: cond, source: src}})
	}
	for _, m := range readonlyTMOUTRe.FindAllStringIndex(code, -1) {
		hits = append(hits, hit{m[0], shellEvent{kind: "readonly", cond: cond, source: src}})
	}
	slices.SortStableFunc(hits, func(a, b hit) int { return a.pos - b.pos })
	for _, h := range hits {
		s.events = append(s.events, h.ev)
		switch h.ev.kind {
		case "set":
			s.env.TMOUT = append(s.env.TMOUT, ShellValue{Value: h.ev.value, Readonly: h.ev.readonly, Conditional: cond, Source: src})
		case "unset":
			s.env.TMOUT = append(s.env.TMOUT, ShellValue{Unset: true, Conditional: cond, Source: src})
		}
	}
	for _, m := range umaskRe.FindAllStringSubmatch(code, -1) {
		s.env.Umask = append(s.env.Umask, ShellValue{Value: m[1], Conditional: cond, Source: src})
	}
	for _, m := range pathRe.FindAllStringSubmatch(code, -1) {
		s.env.Path = append(s.env.Path, ShellValue{Value: strings.Trim(m[1], `"'`), Conditional: cond, Source: src})
	}
}

// follow scans the files a line sources: ". file" and "source file", and
// the /etc/profile.d loop of /etc/profile.
func (s *shellScanner) follow(code string, cond bool, depth int) {
	if strings.Contains(code, "/etc/profile.d/") && regexp.MustCompile(`^\s*for\s`).MatchString(code) {
		for _, word := range shellWordRe.FindAllString(code, -1) {
			word = strings.Trim(word, `"'`)
			if !strings.HasPrefix(word, "/etc/profile.d/") {
				continue
			}
			files := []string{word}
			if hostfs.HasMeta(word) {
				matches, problems, err := hostfs.Glob(s.fsys, word)
				if err != nil {
					s.skip(err.Error())
					continue
				}
				for _, p := range problems {
					s.skip(p)
				}
				// bash's globs skip hidden files.
				files = slices.DeleteFunc(matches, func(m string) bool { return strings.HasPrefix(path.Base(m), ".") })
			}
			for _, f := range files {
				s.file(f, false, depth+1) // the stock loop sources every readable file
			}
		}
		return
	}
	for _, m := range sourceRe.FindAllStringSubmatch(code, -1) {
		target := strings.Trim(m[1], `"'`)
		target = strings.Replace(target, "$HOME", "/root", 1)
		if rest, ok := strings.CutPrefix(target, "~/"); ok {
			target = "/root/" + rest
		}
		if !path.IsAbs(target) || strings.ContainsAny(target, "$`") {
			continue // a variable, such as the profile.d loop's $i
		}
		target = path.Clean(target)
		s.file(target, cond && !slices.Contains(standardSources, target), depth+1)
	}
}

func (s *shellScanner) skip(msg string) {
	if !slices.Contains(s.skipped, msg) {
		s.skipped = append(s.skipped, msg)
	}
}

// effectiveTMOUT replays the TMOUT events and returns the value every login
// shell is left with: unconditional events decide it, and a conditional
// unset or non-positive value after them means some shells have none, so
// there is no such value. It is uncertain (false) when a conditional
// read-only declaration may block a later change.
func effectiveTMOUT(events []shellEvent) (facts.Setting, bool) {
	var cur facts.Setting
	frozen, maybeFrozen, broken, uncertain := false, false, false, false
	for _, e := range events {
		if frozen {
			continue // read-only: later changes fail
		}
		if e.cond {
			if e.kind == "readonly" || e.readonly {
				maybeFrozen = true
			}
			if e.kind == "unset" || e.kind == "set" && !positiveTMOUT.MatchString(e.value) {
				broken = true
			}
			continue
		}
		if maybeFrozen {
			uncertain = true // whether this change applies is unknown
		}
		switch e.kind {
		case "readonly":
			frozen = true
		case "unset":
			cur, broken = facts.Setting{}, false
		case "set":
			cur, broken = facts.Setting{Value: e.value, Explicit: true, Source: e.source}, false
			frozen = e.readonly
		}
	}
	switch {
	case uncertain:
		return facts.Setting{}, false
	case broken:
		return facts.Setting{}, true
	}
	return cur, true
}

var positiveTMOUT = regexp.MustCompile(`^0*[1-9][0-9]*$`)

// blockWords counts the words that open (if, case, for, while, until,
// select, a function's or a group's "{") and close (fi, esac, done, "}")
// shell blocks on a line.
func blockWords(code string) (opens, closes int) {
	for _, w := range strings.FieldsFunc(code, func(r rune) bool { return strings.ContainsRune(" \t;&|()", r) }) {
		switch w {
		case "if", "case", "for", "while", "until", "select", "{":
			opens++
		case "fi", "esac", "done", "}":
			closes++
		}
	}
	if regexp.MustCompile(`^\s*(function\s+)?[\w.-]+\s*\(\s*\)`).MatchString(code) && !strings.Contains(code, "{") {
		opens++ // "name()" with its brace on the next line
	}
	return opens, closes
}

// hasControlOperator reports whether a line has && or || or a subshell
// outside quotes.
func hasControlOperator(code string) bool {
	quote := byte(0)
	for i := 0; i < len(code); i++ {
		c := code[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '\\':
			i++
		case (c == '&' || c == '|') && i+1 < len(code) && code[i+1] == c:
			return true
		case c == '(' && (i == 0 || code[i-1] != '$'):
			return true
		}
	}
	return false
}

// stripShellComment removes a comment: "#" at the start of a word, outside
// quotes.
func stripShellComment(text string) string {
	quote := byte(0)
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '\\':
			i++
		case c == '#' && (i == 0 || text[i-1] == ' ' || text[i-1] == '\t'):
			return text[:i]
		}
	}
	return text
}

// readonlyPrefix reports whether an assignment's prefix makes TMOUT
// read-only: readonly, or declare/typeset with -r.
func readonlyPrefix(prefix string) bool {
	prefix = trimASCII(prefix)
	if prefix == "readonly" {
		return true
	}
	if word, flags, ok := strings.Cut(prefix, " -"); ok && (word == "declare" || word == "typeset") {
		return strings.Contains(flags, "r")
	}
	return false
}
