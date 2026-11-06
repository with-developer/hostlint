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
	"slices"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// Rsyslog is the `rsyslog` facts: the logging rules of /etc/rsyslog.conf and
// the files it includes.
type Rsyslog struct {
	// Present is false when there is no /etc/rsyslog.conf.
	Present bool `json:"present"`
	// Rules are the selector rules (auth,authpriv.* /var/log/auth.log).
	Rules []RsyslogRule `json:"rules"`
}

// RsyslogRule is one selector rule and where it sends the messages.
type RsyslogRule struct {
	Selector string `json:"selector"`
	// Target is a file, "@host" for a remote server, a legacy module action
	// (":omusrmsg:", ":ommysql:": its arguments are dropped, they can hold a
	// password), or the module of a RainerScript action.
	Target string `json:"target"`
	Where  string `json:"where"`
}

const (
	rsyslogConf     = "/etc/rsyslog.conf"
	rsyslogMaxFiles = 100
)

var (
	// A selector is facility.priority pairs joined by ; with , between facilities.
	rsyslogRule   = regexp.MustCompile(`^([*A-Za-z0-9_,;.!=-]+\.[*A-Za-z0-9_!=-]+(?:;[*A-Za-z0-9_,.!=-]+)*)\s+(\S.*)$`)
	rsyslogAction = regexp.MustCompile(`action\s*\(([^)]*)\)`)
	rsyslogFile   = regexp.MustCompile(`file\s*=\s*"([^"]*)"`)
	rsyslogType   = regexp.MustCompile(`type\s*=\s*"([^"]*)"`)
	rsyslogInc    = regexp.MustCompile(`(?i)^include\s*\(\s*file\s*=\s*"([^"]*)"`)
)

type rsyslogCollector struct{}

func (rsyslogCollector) Name() string          { return "rsyslog" }
func (rsyslogCollector) Version() int          { return 1 }
func (rsyslogCollector) Access() engine.Access { return engine.AccessFilesystem }
func (rsyslogCollector) Type() reflect.Type    { return reflect.TypeFor[Rsyslog]() }

func (rsyslogCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	r := &Rsyslog{Rules: []RsyslogRule{}}
	p := &rsyslogParser{fsys: h.FS, out: r, seen: map[string]bool{}}
	if err := p.file(rsyslogConf, 0); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return engine.Facts{Value: r, Complete: true}, nil
		}
		if errors.Is(err, fs.ErrPermission) {
			return engine.Facts{}, errors.New("rsyslog.conf cannot be read (run hostlint as root)")
		}
		return engine.Facts{}, err
	}
	r.Present = true
	return engine.Facts{Value: r, Complete: len(p.skipped) == 0, Skipped: p.skipped}, nil
}

type rsyslogParser struct {
	fsys    hostfs.FS
	out     *Rsyslog
	seen    map[string]bool
	skipped []string
}

func (p *rsyslogParser) file(name string, depth int) error {
	switch {
	case depth > 8 || p.seen[name]:
		return nil
	case len(p.seen) >= rsyslogMaxFiles:
		if !slices.Contains(p.skipped, "too many included files") {
			p.skipped = append(p.skipped, "too many included files")
		}
		return nil
	}
	p.seen[name] = true
	data, err := p.fsys.ReadFile(name)
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		where := fmt.Sprintf("%s:%d", name, line)
		switch {
		case strings.HasPrefix(strings.ToLower(text), "$includeconfig"):
			p.include(strings.TrimSpace(text[len("$includeconfig"):]), depth)
		case rsyslogInc.MatchString(text):
			p.include(rsyslogInc.FindStringSubmatch(text)[1], depth)
		case strings.HasPrefix(text, "$"):
			// a legacy directive
		default:
			// Anything that is not a selector rule (module(), global(), a continuation line)
			// does not match.
			if m := rsyslogRule.FindStringSubmatch(text); m != nil {
				p.out.Rules = append(p.out.Rules, RsyslogRule{Selector: m[1], Target: rsyslogTarget(m[2]), Where: where})
			}
		}
	}
	if err := sc.Err(); err != nil {
		p.skipped = append(p.skipped, fmt.Sprintf("%s:%d: the rest of the file was not read (%v)", name, line+1, err))
	}
	return nil
}

// include reads the files a glob or path names; a path that matches nothing is
// fine (rsyslog's include is optional for a glob).
func (p *rsyslogParser) include(pattern string, depth int) {
	pattern = strings.Trim(strings.TrimSpace(pattern), `"`)
	if pattern == "" {
		return
	}
	files := []string{pattern}
	if hostfs.HasMeta(pattern) {
		matches, problems, err := hostfs.Glob(p.fsys, pattern)
		if err != nil {
			p.skipped = append(p.skipped, err.Error())
			return
		}
		p.skipped = append(p.skipped, problems...)
		files = matches
	}
	for _, f := range files {
		if err := p.file(f, depth+1); err != nil && !errors.Is(err, fs.ErrNotExist) {
			p.skipped = append(p.skipped, fmt.Sprintf("%s: %v", f, err))
		}
	}
}

// rsyslogTarget says where a rule's action sends messages.
func rsyslogTarget(action string) string {
	action = strings.TrimSpace(action)
	if m := rsyslogAction.FindStringSubmatch(action); m != nil {
		if f := rsyslogFile.FindStringSubmatch(m[1]); f != nil {
			return f[1]
		}
		if t := rsyslogType.FindStringSubmatch(m[1]); t != nil {
			return "action " + t[1]
		}
		return "action"
	}
	// A legacy module action carries its arguments after the module name
	// (:ommysql:host,database,user,password): only the module is kept.
	if strings.HasPrefix(action, ":") {
		if end := strings.Index(action[1:], ":"); end >= 0 {
			return action[:end+2]
		}
		return action
	}
	if i := strings.IndexAny(action, " \t;"); i > 0 {
		action = action[:i]
	}
	return strings.TrimPrefix(action, "-") // "-" means no sync after each write
}
