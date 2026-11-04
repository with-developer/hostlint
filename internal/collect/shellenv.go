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
	forRe           = regexp.MustCompile(`^\s*for\s`)
	// A for keyword anywhere a command can start: loops that do not begin
	// the line are not followed.
	forAnywhereRe = regexp.MustCompile(`(?:^|[;&|{(]\s*|\b(?:then|do|else)\s+)for\s`)
	// What may follow a loop list: the "do", then maybe more commands.
	loopRestRe = regexp.MustCompile(`^\s*;?\s*(?:do\b(.*))?$`)
	// The profile.d loop of /etc/profile on Debian 13 and Ubuntu 26.04:
	// for i in $(run-parts --list --regex '<names>' /etc/profile.d); do
	runPartsLoopRe = regexp.MustCompile(`^\s*for\s+\w+\s+in\s+\$\(\s*run-parts\s+--list(?:\s+--regex(?:\s+|=)(?:'([^']*)'|"([^"]*)"))?\s+/etc/profile\.d/?\s*\)`)
	// The names run-parts accepts when no --regex is given.
	runPartsNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
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
	for _, f := range loginFiles {
		if s.exists(f) {
			s.file(f, false, 0)
			break
		}
	}
	if err := ctx.Err(); err != nil {
		return engine.Facts{}, err
	}
	f := engine.Facts{Value: s.env, Complete: len(s.skipped) == 0, Skipped: s.skipped}
	effective, certain := effectiveTMOUT(s.events)
	s.env.Effective = map[string]facts.Setting{}
	switch {
	case !certain:
		f.Unknown = []string{"effective"}
		f.Skipped = append(f.Skipped, "a conditional readonly TMOUT may block a later change, so the effective value is unknown")
	case effective.Explicit:
		s.env.Effective["TMOUT"] = effective
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

func (s *shellScanner) exists(file string) bool {
	_, err := s.fsys.Stat(file)
	return err == nil
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
		s.follow(code, src, lineCond, depth)
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
func (s *shellScanner) follow(code, src string, cond bool, depth int) {
	rest := code
	switch m := runPartsLoopRe.FindStringSubmatch(code); {
	case m != nil:
		after := code[len(m[0]):]
		hasRegex := strings.Contains(m[0], "--regex")
		s.runParts(m[1]+m[2], hasRegex, m[2] != "", src, depth)
		rest = s.afterLoop(src, after)
	case forRe.MatchString(code) && strings.HasSuffix(code, `\`):
		// The list may continue on the next line, which is not parsed.
		s.unknownLoop(src)
	case forRe.MatchString(code) && mentionsProfileD(code):
		rest = s.profileLoop(code, src, depth)
	case forAnywhereRe.MatchString(code) && mentionsProfileD(code):
		// A loop behind a condition or another command.
		s.unknownLoop(src)
	}
	for _, m := range sourceRe.FindAllStringSubmatch(rest, -1) {
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

func mentionsProfileD(code string) bool {
	return strings.Contains(code, "/etc/profile.d") || strings.Contains(code, "run-parts")
}

// unknownLoop notes a loop whose files are not known. The note names the
// line only: its text may hold secrets.
func (s *shellScanner) unknownLoop(src string) {
	s.skip(src + ": cannot tell which files this loop sources")
}

// afterLoop returns the commands that follow a loop's list on its line. It
// notes the loop as incomplete when the list continues past what was parsed.
func (s *shellScanner) afterLoop(src, after string) string {
	m := loopRestRe.FindStringSubmatch(after)
	if m == nil {
		s.unknownLoop(src)
		return ""
	}
	return m[1]
}

// profileLoop scans the files of a for loop over /etc/profile.d, such as
// "for i in /etc/profile.d/*.sh /etc/profile.d/sh.local; do". The stock loops
// source every readable file they list. A loop whose list is not literal
// paths and globs leaves the facts incomplete: what it sources is unknown,
// not absent.
func (s *shellScanner) profileLoop(code, src string, depth int) string {
	list, rest, ok := loopList(code)
	var files []string
	listed := ok // the loop lists literal paths or globs
	for _, word := range strings.Fields(list) {
		word = strings.Trim(word, `"'`)
		if !strings.HasPrefix(word, "/etc/profile.d/") || strings.ContainsAny(word, "$`()~{") {
			listed = false
			break
		}
		if !hostfs.HasMeta(word) {
			files = append(files, word)
			continue
		}
		matches, problems, err := hostfs.Glob(s.fsys, word)
		if err != nil {
			s.skip(err.Error())
			continue
		}
		for _, p := range problems {
			s.skip(p)
		}
		// bash's globs skip hidden files.
		files = append(files, slices.DeleteFunc(matches, func(m string) bool { return strings.HasPrefix(path.Base(m), ".") })...)
	}
	if !listed || list == "" {
		s.unknownLoop(src)
		return rest
	}
	for _, f := range files {
		s.file(f, false, depth+1)
	}
	return rest
}

// loopList splits "for i in LIST; do REST" into LIST and REST. It reports
// false when the line has no "in" list or the list is not closed on the line.
func loopList(code string) (list, rest string, ok bool) {
	i := strings.Index(code, " in ")
	if i < 0 {
		return "", "", false
	}
	body := code[i+4:]
	parens := 0
	for j := 0; j < len(body); j++ {
		switch c := body[j]; {
		case c == '(':
			parens++
		case c == ')':
			parens--
		case parens == 0 && c == ';':
			return body[:j], loopRest(body[j+1:]), true
		case parens == 0 && c == ' ' && (strings.HasPrefix(body[j:], " do ") || body[j:] == " do"):
			return body[:j], loopRest(body[j+1:]), true
		}
	}
	return body, "", false
}

// loopRest returns what follows the "do" of a loop line.
func loopRest(s string) string {
	s = strings.TrimSpace(s)
	if r, ok := strings.CutPrefix(s, "do"); ok {
		return r
	}
	return s
}

// runParts scans what `run-parts --list [--regex expr] /etc/profile.d`
// prints, as debianutils' run-parts does: the regular files, or links to
// them, whose names match, in C-locale order. Root's `[ -r $i ]` always
// holds, so each is sourced. hasRegex is true for an option given even when
// its value is empty (that matches every name).
func (s *shellScanner) runParts(expr string, hasRegex, doubleQuoted bool, src string, depth int) {
	re := runPartsNameRe
	if hasRegex {
		if why := notERE(expr, doubleQuoted); why != "" {
			s.skip(fmt.Sprintf("%s: run-parts --regex %s", src, why))
			return
		}
		var err error
		if re, err = regexp.Compile(expr); err != nil {
			s.skip(src + ": run-parts --regex is not a valid expression")
			return
		}
	}
	entries, err := s.fsys.ReadDir("/etc/profile.d")
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return
	case err != nil:
		s.skip(err.Error())
		return
	}
	var names []string
	modes := map[string]fs.FileMode{}
	for _, e := range entries {
		if name := path.Base(e.Path); re.MatchString(name) {
			names = append(names, name)
			modes[name] = e.Mode
		}
	}
	slices.Sort(names)
	for _, name := range names {
		if s.ctx.Err() != nil {
			return
		}
		if s.files >= maxShellFiles {
			s.skip("/etc/profile.d: more files than hostlint reads")
			return
		}
		p := path.Join("/etc/profile.d", name)
		mode := modes[name]
		if mode&fs.ModeSymlink != 0 {
			fi, err := s.fsys.Stat(p) // a link counts when it points to a regular file
			switch {
			case errors.Is(err, fs.ErrNotExist):
				continue // a dangling link is not listed
			case err != nil:
				s.skip(err.Error())
				continue
			}
			mode = fi.Mode
		}
		if mode.IsRegular() {
			s.file(p, false, depth+1)
		}
	}
}

// notERE explains why expr, read by run-parts as a POSIX extended regular
// expression, may not mean the same to Go's RE2; "" when it does. A shell
// double-quoted string is also changed by bash before run-parts sees it.
func notERE(expr string, doubleQuoted bool) string {
	if strings.Contains(expr, "(?") {
		return "uses a construct POSIX does not have"
	}
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case c == '[':
			// A bracket expression: "]" first is a member, "[:class:]" nests,
			// and a backslash is an ordinary character in POSIX.
			j := i + 1
			if j < len(expr) && expr[j] == '^' {
				j++
			}
			if j < len(expr) && expr[j] == ']' {
				j++
			}
			for ; j < len(expr) && expr[j] != ']'; j++ {
				switch {
				case expr[j] == '\\':
					return "has a backslash in a bracket expression"
				case expr[j] == '[' && j+1 < len(expr) && expr[j+1] == ':':
					end := strings.Index(expr[j:], ":]")
					if end < 0 {
						return "has an unclosed character class"
					}
					switch class := expr[j+2 : j+end]; class {
					case "alpha", "digit", "alnum", "upper", "lower", "space", "blank", "punct", "print", "graph", "cntrl", "xdigit":
					default:
						return "uses a class POSIX does not have"
					}
					j += end + 1
				}
			}
			if j >= len(expr) {
				return "has an unclosed bracket expression"
			}
			i = j
		case c == '\\':
			// Only these escapes mean the same in POSIX and RE2; \< \> \` \'
			// and \w and the like are GNU extensions.
			if i+1 >= len(expr) || strings.IndexByte(`.-/^$*+?()[]{}|\\`, expr[i+1]) < 0 {
				return "has a backslash escape that POSIX does not define"
			}
			if doubleQuoted && strings.IndexByte("$\\", expr[i+1]) >= 0 {
				return "has an escape that the shell rewrites inside double quotes"
			}
			i++
		case doubleQuoted && (c == '`' || c == '$' && i+1 < len(expr) && (isASCIIAlnum(expr[i+1]) || strings.IndexByte("_{(", expr[i+1]) >= 0)):
			return "has an expansion inside double quotes"
		}
	}
	return ""
}

func isASCIIAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
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
