package collect

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"path"
	"reflect"
	"slices"
	"strings"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/hostfs"
)

// Audit are the `audit` facts: the audit rules that the host loads at boot, read from the files, not from the running kernel
// (a rule added with auditctl since boot is not seen; see the `services` facts for whether auditd starts). The files are
// /etc/audit/rules.d/*.rules in name order, which is what augenrules merges into /etc/audit/audit.rules; /etc/audit/audit.rules
// itself when there is no rules.d file. The keys of the rules (-k) are not kept: they are arbitrary names.
type Audit struct {
	// Present is true when a rules file exists.
	Present bool `json:"present"`
	// Rules are the rules of the files in the order they are loaded, with those that a later "-D" deleted left out.
	Rules []AuditRule `json:"rules"`
	// Paths holds, for every path that a watch (-w) or an always,exit rule with path= and perm= audits, the permissions it
	// audits (the union over the rules, in the order r, w, a, x: "wa", "x"), whoever the user is. A directory has no trailing "/".
	Paths map[string]AuditPath `json:"paths"`
	// UserPaths is the same for the rules written for logged-in users: always,exit rules with path=, perm=, auid>=1000 and
	// auid!=unset (also written -1 or 4294967295), the form that the STIG asks for the commands it names.
	UserPaths map[string]AuditPath `json:"user_paths"`
}

// AuditPath is what is audited about one path.
type AuditPath struct {
	Perms string `json:"perms"`
	// Source is the file and line of the first rule that audits it.
	Source string `json:"source"`
}

// AuditRule is one rule of the files that adds something to audit.
type AuditRule struct {
	// Kind is "watch" (-w) or "syscall" (-a).
	Kind string `json:"kind"`
	// Action and List are those of an -a rule ("always", "exit"); empty for a watch.
	Action string `json:"action"`
	List   string `json:"list"`
	// Path is the path of a watch, or the path= or dir= of an -a rule, without a trailing "/".
	Path string `json:"path"`
	// Perms are the audited permissions in the order r, w, a, x; of a watch without -p, all of them.
	Perms string `json:"perms"`
	// Syscalls are those of -S.
	Syscalls []string `json:"syscalls"`
	// Fields are the other -F filters as written without spaces ("arch=b64", "auid>=1000").
	Fields []string `json:"fields"`
	Source string   `json:"source"`
}

const (
	auditRulesDir     = "/etc/audit/rules.d"
	auditRulesFile    = "/etc/audit/audit.rules"
	auditMaxFiles     = 100
	auditMaxRules     = 5000
	auditMaxLine      = 4096
	auditMaxFileBytes = 1 << 20
)

type auditCollector struct{}

func (auditCollector) Name() string          { return "audit" }
func (auditCollector) Version() int          { return 1 }
func (auditCollector) Access() engine.Access { return engine.AccessFilesystem }
func (auditCollector) Type() reflect.Type    { return reflect.TypeFor[Audit]() }

func (auditCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	a := &Audit{Rules: []AuditRule{}, Paths: map[string]AuditPath{}, UserPaths: map[string]AuditPath{}}
	var skipped []string
	files, err := auditFiles(h)
	if err != nil {
		return engine.Facts{Value: a, Complete: false, Skipped: []string{fmt.Sprintf("%s: %v", auditRulesDir, err)}}, nil
	}
	a.Present = len(files) > 0
	for _, file := range files {
		data, err := h.FS.ReadFile(file)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", file, err))
			continue
		}
		if len(data) > auditMaxFileBytes {
			skipped = append(skipped, file+": too large")
			continue
		}
		skipped = append(skipped, parseAuditRules(file, data, a)...)
	}
	if len(skipped) > 0 {
		return engine.Facts{Value: a, Complete: false, Skipped: skipped}, nil
	}
	return engine.Facts{Value: a, Complete: true}, nil
}

// auditFiles are the rules files in the order they are loaded: rules.d/*.rules by name (the C locale order augenrules uses), or
// audit.rules when rules.d has none. A missing directory is not an error.
func auditFiles(h *hostfs.Host) ([]string, error) {
	entries, err := h.FS.ReadDir(auditRulesDir)
	if err != nil && !hostfs.IsMissing(err) {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if e.Mode.IsRegular() && strings.HasSuffix(e.Path, ".rules") {
			files = append(files, path.Join(auditRulesDir, path.Base(e.Path)))
		}
	}
	slices.Sort(files)
	if len(files) > auditMaxFiles {
		files = files[:auditMaxFiles]
	}
	if len(files) > 0 {
		return files, nil
	}
	if _, err := h.FS.Stat(auditRulesFile); err == nil {
		return []string{auditRulesFile}, nil
	} else if !hostfs.IsMissing(err) {
		return nil, err
	}
	return nil, nil
}

// auditOptions are lines that set how the audit system runs and add no rule.
var auditOptions = map[string]bool{"-b": true, "-f": true, "-r": true, "-e": true, "-c": true, "-i": true, "-s": true, "--backlog_wait_time": true, "--loginuid-immutable": true, "--reset-lost": true}

// parseAuditRules reads the rules of one file into a, and returns what it could not read (a line that it does not understand makes the
// facts incomplete: a rule that it cannot read may be the one that a check looks for, or a "-d" that removes one).
func parseAuditRules(file string, data []byte, a *Audit) []string {
	var skipped []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), auditMaxLine*4)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		source := fmt.Sprintf("%s:%d", file, n)
		if len(line) > auditMaxLine {
			skipped = append(skipped, source+": line too long")
			continue
		}
		words := strings.Fields(line)
		switch {
		case words[0] == "-D":
			a.Rules, a.Paths, a.UserPaths = []AuditRule{}, map[string]AuditPath{}, map[string]AuditPath{} // what comes before it is deleted
			continue
		case auditOptions[words[0]] || strings.HasPrefix(words[0], "--backlog_wait_time=") || strings.HasPrefix(words[0], "--rate="):
			continue
		case words[0] != "-w" && words[0] != "-a" && words[0] != "-A":
			skipped = append(skipped, source+": "+words[0]+" is not read")
			continue
		}
		if len(a.Rules) >= auditMaxRules {
			skipped = append(skipped, file+": more rules than are read")
			return skipped
		}
		r, ok := parseAuditRule(words, source)
		if !ok {
			skipped = append(skipped, source+": the rule is not read")
			continue
		}
		a.Rules = append(a.Rules, r)
		a.add(r)
	}
	if err := sc.Err(); err != nil {
		skipped = append(skipped, fmt.Sprintf("%s: %v", file, err))
	}
	return skipped
}

func parseAuditRule(words []string, source string) (AuditRule, bool) {
	r := AuditRule{Syscalls: []string{}, Fields: []string{}, Source: source}
	perm := ""
	for i := 0; i < len(words); i++ {
		w := words[i]
		next := func() (string, bool) {
			if i+1 >= len(words) {
				return "", false
			}
			i++
			return words[i], true
		}
		switch w {
		case "-w":
			p, ok := next()
			if !ok {
				return r, false
			}
			r.Kind, r.Path = "watch", cleanAuditPath(p)
		case "-a", "-A":
			v, ok := next()
			if !ok {
				return r, false
			}
			r.Kind = "syscall"
			for _, part := range strings.Split(v, ",") {
				switch part {
				case "always", "never":
					r.Action = part
				case "exit", "entry", "task", "user", "exclude", "filesystem":
					r.List = part
				default:
					return r, false
				}
			}
		case "-p":
			p, ok := next()
			if !ok {
				return r, false
			}
			perm = p
		case "-k":
			if _, ok := next(); !ok {
				return r, false
			}
		case "-S":
			v, ok := next()
			if !ok {
				return r, false
			}
			r.Syscalls = append(r.Syscalls, strings.Split(v, ",")...)
		case "-F", "-C":
			v, ok := next()
			if !ok {
				return r, false
			}
			v = strings.ReplaceAll(v, " ", "")
			if w == "-C" {
				r.Fields = append(r.Fields, "C:"+v)
				continue
			}
			switch {
			case strings.HasPrefix(v, "path="), strings.HasPrefix(v, "dir="):
				r.Path = cleanAuditPath(v[strings.Index(v, "=")+1:])
			case strings.HasPrefix(v, "perm="):
				perm = v[len("perm="):]
			default:
				r.Fields = append(r.Fields, v)
			}
		default:
			return r, false // -R, -d, -l or something this does not know: not read
		}
	}
	if r.Kind == "" {
		return r, false
	}
	if r.Kind == "watch" && perm == "" {
		perm = "rwax" // a watch without -p audits every kind of access
	}
	r.Perms = canonicalAuditPerms(perm)
	return r, true
}

// add records what r audits in Paths and UserPaths.
func (a *Audit) add(r AuditRule) {
	if r.Path == "" || r.Perms == "" {
		return
	}
	if r.Kind == "syscall" && (r.Action != "always" || r.List != "exit") {
		return
	}
	merge := func(m map[string]AuditPath) {
		cur := m[r.Path]
		cur.Perms = canonicalAuditPerms(cur.Perms + r.Perms)
		if cur.Source == "" {
			cur.Source = r.Source
		}
		m[r.Path] = cur
	}
	merge(a.Paths)
	if r.Kind == "syscall" && slices.Contains(r.Fields, "auid>=1000") &&
		(slices.Contains(r.Fields, "auid!=unset") || slices.Contains(r.Fields, "auid!=-1") || slices.Contains(r.Fields, "auid!=4294967295")) {
		merge(a.UserPaths)
	}
}

// cleanAuditPath drops the trailing "/" of a directory, so a watch of /etc/sudoers.d/ and of /etc/sudoers.d are the same.
func cleanAuditPath(p string) string {
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
		if p == "" {
			p = "/"
		}
	}
	return p
}

// canonicalAuditPerms keeps the letters r, w, a and x of s, once each, in that order.
func canonicalAuditPerms(s string) string {
	var out []byte
	for _, c := range []byte("rwax") {
		if strings.IndexByte(s, c) >= 0 {
			out = append(out, c)
		}
	}
	return string(out)
}
