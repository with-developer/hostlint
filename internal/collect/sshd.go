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
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// SSHD are the `sshd` facts: the OpenSSH server configuration.
type SSHD struct {
	// Present is true when an sshd program or its configuration exists.
	Present bool `json:"present"`
	// Config holds the effective global settings, keyed by lowercase keyword.
	// On a live host the values come from `sshd -T`, so defaults of the
	// installed version are included (explicit=false); otherwise only values
	// set in the files are known.
	Config map[string]facts.Setting `json:"config"`
	// Match lists the Match blocks, whose settings override the global ones
	// for matching connections.
	Match []SSHDMatch `json:"match"`
}

// SSHDMatch is one Match block.
type SSHDMatch struct {
	Criteria string                   `json:"criteria"`
	Settings map[string]facts.Setting `json:"settings"`
	Source   string                   `json:"source"`
}

const sshdConfig = "/etc/ssh/sshd_config"

// sshdPrograms are where the server is looked for when deciding presence.
var sshdPrograms = []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd"}

// sshdCumulative keywords accumulate values instead of keeping the first.
var sshdCumulative = map[string]bool{
	"acceptenv": true, "allowgroups": true, "allowusers": true, "denygroups": true,
	"denyusers": true, "hostkey": true, "listenaddress": true, "port": true, "setenv": true,
	"subsystem": true,
}

type sshdCollector struct{}

func (sshdCollector) Name() string          { return "sshd" }
func (sshdCollector) Version() int          { return 1 }
func (sshdCollector) Access() engine.Access { return engine.AccessFilesystem }
func (sshdCollector) Type() reflect.Type    { return reflect.TypeFor[SSHD]() }

func (sshdCollector) Collect(ctx context.Context, h *hostfs.Host) (engine.Facts, error) {
	s := &SSHD{Config: map[string]facts.Setting{}, Match: []SSHDMatch{}}
	for _, p := range append([]string{sshdConfig}, sshdPrograms...) {
		if _, err := h.FS.Stat(p); err == nil {
			s.Present = true
			break
		}
	}
	if !s.Present {
		return engine.Facts{Value: s, Complete: true}, nil
	}

	p := &sshdParser{fsys: h.FS, global: map[string]facts.Setting{}}
	if err := p.parseFile(sshdConfig, 0); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return engine.Facts{}, err
	}
	s.Match = p.matches

	// The running server's view, with defaults and distribution patches, is
	// authoritative; the files only tell where a value was set.
	effective, err := sshdEffective(ctx, h)
	switch {
	case err == nil:
		for key, value := range effective {
			set := facts.Setting{Value: value, Source: "sshd -T (default)"}
			if file, ok := p.global[key]; ok {
				set.Explicit, set.Source = true, file.Source
			}
			s.Config[key] = set
		}
	case errors.Is(err, hostfs.ErrUnavailable) || errors.Is(err, hostfs.ErrNotInstalled):
		// A mounted root, or no server program: only explicit values are known.
		s.Config = p.global
	default:
		return engine.Facts{}, err
	}
	return engine.Facts{Value: s, Complete: len(p.skipped) == 0, Skipped: p.skipped}, nil
}

// sshdEffective runs `sshd -T` and parses its "keyword value" lines.
func sshdEffective(ctx context.Context, h *hostfs.Host) (map[string]string, error) {
	out, err := h.Runner.Run(ctx, hostfs.SSHDConfigTest)
	if err != nil {
		return nil, err
	}
	if out.ExitCode != 0 {
		msg := strings.TrimSpace(string(out.Stderr))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, fmt.Errorf("sshd -T exited with %d: %s", out.ExitCode, msg)
	}
	cfg := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out.Stdout))
	for sc.Scan() {
		key, value, _ := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if key == "" {
			continue
		}
		key = strings.ToLower(key)
		value = normalizeSSHDValue(strings.TrimSpace(value))
		if prev, ok := cfg[key]; ok && sshdCumulative[key] {
			value = prev + " " + value
		}
		cfg[key] = value
	}
	return cfg, sc.Err()
}

// sshdParser reads sshd_config(5) files: Include (globs, relative to
// /etc/ssh), Match blocks, "Keyword value" or "Keyword=value", and the
// first-value-wins rule.
type sshdParser struct {
	fsys    hostfs.FS
	global  map[string]facts.Setting
	matches []SSHDMatch
	current *SSHDMatch // nil outside a Match block
	reads   int
	skipped []string
}

const (
	maxIncludeDepth = 16
	maxSSHDReads    = 200 // included files, counting repeats
)

func (p *sshdParser) parseFile(name string, depth int) error {
	switch {
	case depth > maxIncludeDepth:
		p.skipped = append(p.skipped, name+": Include nested too deeply")
		return nil
	case p.reads >= maxSSHDReads:
		if len(p.skipped) == 0 || p.skipped[len(p.skipped)-1] != "too many included files" {
			p.skipped = append(p.skipped, "too many included files")
		}
		return nil
	}
	p.reads++
	data, err := p.fsys.ReadFile(name)
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		key, value := splitSSHDLine(text)
		key = strings.ToLower(key)
		src := fmt.Sprintf("%s:%d", name, line)
		switch key {
		case "include":
			for _, pattern := range strings.Fields(value) {
				p.include(pattern, depth)
			}
		case "match":
			p.matches = append(p.matches, SSHDMatch{Criteria: value, Settings: map[string]facts.Setting{}, Source: src})
			p.current = &p.matches[len(p.matches)-1]
		default:
			target := p.global
			if p.current != nil {
				target = p.current.Settings
			}
			value = normalizeSSHDValue(value)
			if prev, ok := target[key]; ok {
				if sshdCumulative[key] {
					prev.Value += " " + value
					target[key] = prev
				}
				continue // the first value wins
			}
			target[key] = facts.Setting{Value: value, Explicit: true, Source: src}
		}
	}
	return sc.Err()
}

func (p *sshdParser) include(pattern string, depth int) {
	if !path.IsAbs(pattern) {
		pattern = path.Join("/etc/ssh", pattern)
	}
	matches, problems, err := hostfs.Glob(p.fsys, path.Clean(pattern))
	if err != nil {
		p.skipped = append(p.skipped, fmt.Sprintf("Include %s: %v", pattern, err))
		return
	}
	p.skipped = append(p.skipped, problems...)
	for _, m := range matches {
		if strings.HasPrefix(path.Base(m), ".") {
			continue // sshd's glob(3) skips hidden files
		}
		// sshd restores the Match state after each included file: a Match
		// block opened in a drop-in ends with it.
		saved := p.current
		if err := p.parseFile(m, depth+1); err != nil {
			p.skipped = append(p.skipped, err.Error())
		}
		p.current = saved
	}
}

// splitSSHDLine splits "Keyword value" or "Keyword=value".
func splitSSHDLine(text string) (string, string) {
	i := strings.IndexAny(text, " \t=")
	if i < 0 {
		return text, ""
	}
	key, rest := text[:i], strings.TrimLeft(text[i:], " \t")
	rest = strings.TrimPrefix(rest, "=")
	return key, strings.Trim(strings.TrimSpace(rest), `"`)
}

// normalizeSSHDValue lowercases the yes/no style values sshd compares
// case-insensitively, as `sshd -T` prints them.
func normalizeSSHDValue(v string) string {
	switch l := strings.ToLower(v); l {
	case "yes", "no", "prohibit-password", "without-password", "forced-commands-only",
		"any", "inet", "inet6", "none", "delayed", "sandbox", "local", "remote", "all":
		if l == "without-password" {
			return "prohibit-password" // the deprecated alias
		}
		return l
	}
	return v
}
