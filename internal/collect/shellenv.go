package collect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"regexp"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// ShellEnv are the `shell_env` facts: what the system-wide and root's shell
// startup files set. Shell scripts cannot be evaluated statically, so every
// occurrence is listed, in the order the files are read, with a flag for
// occurrences inside if/case blocks; rules decide what to accept.
type ShellEnv struct {
	TMOUT []ShellValue `json:"tmout"` // TMOUT assignments and unsets
	Umask []ShellValue `json:"umask"` // umask commands
	Path  []ShellValue `json:"path"`  // PATH assignments
	// EffectiveTMOUT is what the unconditional TMOUT assignments and unsets
	// leave, in reading order; once TMOUT is read-only, later changes fail.
	// It is unset when none survives. Conditional occurrences are only in
	// TMOUT, for rules to judge.
	EffectiveTMOUT facts.Setting `json:"effective_tmout"`
}

// ShellValue is one occurrence in a startup file.
type ShellValue struct {
	Value       string `json:"value"`
	Readonly    bool   `json:"readonly"`    // readonly or declare -r on the same line
	Conditional bool   `json:"conditional"` // inside an if or case block, or a one-line one
	Unset       bool   `json:"unset"`       // an unset command (TMOUT only); Value is ""
	Source      string `json:"source"`
}

// shellFiles are read in this order; globs are expanded in lexical order.
var shellFiles = []string{
	"/etc/environment",
	"/etc/profile", "/etc/profile.d/*.sh",
	"/etc/bash.bashrc", "/etc/bashrc",
	"/root/.profile", "/root/.bash_profile", "/root/.bashrc",
}

var (
	tmoutRe      = regexp.MustCompile(`(?:^|[;&|\s])(readonly\s+|export\s+|declare\s+-[a-zA-Z]+\s+|typeset\s+-[a-zA-Z]+\s+)?TMOUT=["']?(\d*)["']?`)
	unsetTMOUTRe = regexp.MustCompile(`(?:^|[;&|\s])unset\s+(?:-v\s+)?(?:\w+\s+)*TMOUT\b`)
	umaskRe      = regexp.MustCompile(`(?:^|[;&|\s])umask\s+([0-7]{3,4}|[ugoa=+,rwx-]+)\b`)
	pathRe       = regexp.MustCompile(`(?:^|[;&|\s])(?:export\s+)?PATH=("[^"]*"|'[^']*'|\S*)`)
	shellSepRe   = regexp.MustCompile(`[\s;&|()]+`)
)

type shellEnvCollector struct{}

func (shellEnvCollector) Name() string          { return "shell_env" }
func (shellEnvCollector) Version() int          { return 1 }
func (shellEnvCollector) Access() engine.Access { return engine.AccessFilesystem }
func (shellEnvCollector) Type() reflect.Type    { return reflect.TypeFor[ShellEnv]() }

func (shellEnvCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	env := &ShellEnv{TMOUT: []ShellValue{}, Umask: []ShellValue{}, Path: []ShellValue{}}
	var skipped []string
	for _, pattern := range shellFiles {
		files := []string{pattern}
		if strings.Contains(pattern, "*") {
			matches, problems, err := hostfs.Glob(h.FS, pattern)
			if err != nil {
				return engine.Facts{}, err
			}
			files, skipped = matches, append(skipped, problems...)
		}
		for _, file := range files {
			data, err := h.FS.ReadFile(file)
			switch {
			case errors.Is(err, fs.ErrNotExist):
				continue
			case err != nil:
				skipped = append(skipped, err.Error())
				continue
			}
			scanShellFile(env, file, data)
		}
	}
	env.EffectiveTMOUT = effectiveTMOUT(env.TMOUT)
	return engine.Facts{Value: env, Complete: len(skipped) == 0, Skipped: skipped}, nil
}

// effectiveTMOUT replays the unconditional TMOUT occurrences in order.
func effectiveTMOUT(occurrences []ShellValue) facts.Setting {
	var cur facts.Setting
	readonly := false
	for _, v := range occurrences {
		switch {
		case v.Conditional || readonly:
		case v.Unset:
			cur = facts.Setting{}
		default:
			cur = facts.Setting{Value: v.Value, Explicit: true, Source: v.Source}
			readonly = v.Readonly
		}
	}
	return cur
}

func scanShellFile(env *ShellEnv, file string, data []byte) {
	depth := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		code := stripShellComment(strings.TrimSpace(sc.Text()))
		if code == "" {
			continue
		}
		opens, closes := blockWords(code)
		src := fmt.Sprintf("%s:%d", file, line)
		// Inside a block, or on a line that opens one (a one-line if or
		// case), a command may not run.
		cond := depth > 0 || opens > 0
		switch m := tmoutRe.FindStringSubmatch(code); {
		case m != nil:
			env.TMOUT = append(env.TMOUT, ShellValue{Value: m[2], Readonly: readonlyTMOUT(m[1], code), Conditional: cond, Source: src})
		case unsetTMOUTRe.MatchString(code):
			env.TMOUT = append(env.TMOUT, ShellValue{Unset: true, Conditional: cond, Source: src})
		case strings.Contains(code, "readonly TMOUT") && len(env.TMOUT) > 0:
			env.TMOUT[len(env.TMOUT)-1].Readonly = true
		}
		if m := umaskRe.FindStringSubmatch(code); m != nil {
			env.Umask = append(env.Umask, ShellValue{Value: m[1], Conditional: cond, Source: src})
		}
		if m := pathRe.FindStringSubmatch(code); m != nil {
			env.Path = append(env.Path, ShellValue{Value: strings.Trim(m[1], `"'`), Conditional: cond, Source: src})
		}
		depth = max(depth+opens-closes, 0)
	}
}

// blockWords counts the words that open (if, case) and close (fi, esac)
// shell blocks on a line.
func blockWords(code string) (opens, closes int) {
	for _, w := range shellSepRe.Split(code, -1) {
		switch w {
		case "if", "case":
			opens++
		case "fi", "esac":
			closes++
		}
	}
	return opens, closes
}

// stripShellComment removes a comment: "#" at the start of a word.
func stripShellComment(text string) string {
	for i := 0; i < len(text); i++ {
		if text[i] == '#' && (i == 0 || text[i-1] == ' ' || text[i-1] == '\t') {
			return strings.TrimSpace(text[:i])
		}
	}
	return text
}

// readonlyTMOUT reports whether a TMOUT assignment is made read-only: by
// "readonly TMOUT=...", "declare -r"/"typeset -r", or "readonly TMOUT" on
// the same line.
func readonlyTMOUT(prefix, line string) bool {
	prefix = strings.TrimSpace(prefix)
	if prefix == "readonly" || strings.Contains(line, "readonly TMOUT") {
		return true
	}
	if word, flags, ok := strings.Cut(prefix, " -"); ok && (word == "declare" || word == "typeset") {
		return strings.Contains(flags, "r")
	}
	return false
}
