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
	"github.com/with-developer/hostlint/internal/hostfs"
)

// ShellEnv are the `shell_env` facts: what the system-wide and root's shell
// startup files set. Shell scripts cannot be evaluated statically, so every
// occurrence is listed, in the order the files are read, with a flag for
// occurrences inside if/case blocks; rules decide what to accept.
type ShellEnv struct {
	TMOUT []ShellValue `json:"tmout"` // TMOUT assignments
	Umask []ShellValue `json:"umask"` // umask commands
	Path  []ShellValue `json:"path"`  // PATH assignments
}

// ShellValue is one occurrence in a startup file.
type ShellValue struct {
	Value       string `json:"value"`
	Readonly    bool   `json:"readonly"`    // readonly or declare -r on the same line
	Conditional bool   `json:"conditional"` // inside an if or case block
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
	tmoutRe = regexp.MustCompile(`(?:^|[;\s])(readonly\s+|export\s+|declare\s+-[a-zA-Z]+\s+|typeset\s+-[a-zA-Z]+\s+)?TMOUT=["']?(\d*)["']?`)
	umaskRe = regexp.MustCompile(`(?:^|[;\s])umask\s+([0-7]{3,4}|[ugoa=+,rwx-]+)\b`)
	pathRe  = regexp.MustCompile(`(?:^|[;\s])(?:export\s+)?PATH=("[^"]*"|'[^']*'|\S*)`)
	openRe  = regexp.MustCompile(`^(if|case)\b`)
	closeRe = regexp.MustCompile(`^(fi|esac)\b`)
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
	return engine.Facts{Value: env, Complete: len(skipped) == 0, Skipped: skipped}, nil
}

func scanShellFile(env *ShellEnv, file string, data []byte) {
	depth := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if i := strings.Index(text, "#"); i == 0 {
			continue
		}
		if closeRe.MatchString(text) && depth > 0 {
			depth--
		}
		src := fmt.Sprintf("%s:%d", file, line)
		cond := depth > 0
		if m := tmoutRe.FindStringSubmatch(text); m != nil {
			env.TMOUT = append(env.TMOUT, ShellValue{Value: m[2], Readonly: readonlyTMOUT(m[1], text), Conditional: cond, Source: src})
		} else if strings.Contains(text, "readonly TMOUT") && len(env.TMOUT) > 0 {
			env.TMOUT[len(env.TMOUT)-1].Readonly = true
		}
		if m := umaskRe.FindStringSubmatch(text); m != nil {
			env.Umask = append(env.Umask, ShellValue{Value: m[1], Conditional: cond, Source: src})
		}
		if m := pathRe.FindStringSubmatch(text); m != nil {
			env.Path = append(env.Path, ShellValue{Value: strings.Trim(m[1], `"'`), Conditional: cond, Source: src})
		}
		if openRe.MatchString(text) && !strings.Contains(text, "; fi") && !strings.HasSuffix(text, "esac") {
			depth++
		}
	}
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
