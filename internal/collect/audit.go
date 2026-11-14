package collect

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"path"
	"reflect"
	"slices"
	"strings"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/hostfs"
)

// Audit are the `audit` facts: what the audit rules that the host loads at boot audit, read from the files, not from the running
// kernel (a rule added with auditctl since boot is not seen; see the `services` facts for whether auditd starts). The files are
// /etc/audit/rules.d/*.rules in name order, which is what augenrules merges into /etc/audit/audit.rules; /etc/audit/audit.rules
// itself when there is no rules.d file. A rule counts only when it audits every event for its path: a rule narrowed by another
// filter (a user, an exit code, success) is left out, and a "never" rule for a path removes the path. A line that cannot be read
// makes the facts incomplete.
type Audit struct {
	// Present is true when a rules file exists.
	Present bool `json:"present"`
	// Paths holds, for every path that a watch (-w) or an always,exit rule with path= or dir= and perm= audits, the permissions it
	// audits (the union over the rules, in the order r, w, a, x: "wa", "x"), whoever the user is. A directory has no trailing "/".
	// A rule on a directory is stored under the directory, not under the files in it.
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

// auditState is what the rules read so far amount to.
type auditState struct {
	a     *Audit
	rules int
	// never are the paths that a never rule names: the kernel takes the first rule that matches an event, so a never rule before
	// or after an always rule for the path keeps the event out of the audit log.
	never map[string]bool
}

func (auditCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	st := &auditState{a: &Audit{Paths: map[string]AuditPath{}, UserPaths: map[string]AuditPath{}}, never: map[string]bool{}}
	var skipped []string
	files, more, err := auditFiles(h)
	if err != nil {
		return engine.Facts{Value: st.a, Complete: false, Skipped: []string{fmt.Sprintf("%s: %v", auditRulesDir, err)}}, nil
	}
	if more {
		skipped = append(skipped, fmt.Sprintf("%s: more than %d rules files", auditRulesDir, auditMaxFiles))
	}
	st.a.Present = len(files) > 0
	for _, file := range files {
		if fi, err := h.FS.Stat(file); err == nil && fi.Size > auditMaxFileBytes {
			skipped = append(skipped, file+": too large")
			continue
		}
		data, err := h.FS.ReadFile(file)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", file, err))
			continue
		}
		skipped = append(skipped, st.parse(file, data)...)
	}
	for p := range st.never {
		delete(st.a.Paths, p)
		delete(st.a.UserPaths, p)
	}
	if len(skipped) > 0 {
		return engine.Facts{Value: st.a, Complete: false, Skipped: skipped}, nil
	}
	return engine.Facts{Value: st.a, Complete: true}, nil
}

// auditFiles are the rules files in the order they are loaded: rules.d/*.rules by name (the C locale order augenrules uses; a
// symbolic link is followed, as augenrules does), or audit.rules when rules.d has none. A missing directory is not an error. more
// is true when there were more files than are read.
func auditFiles(h *hostfs.Host) (files []string, more bool, err error) {
	entries, err := h.FS.ReadDir(auditRulesDir)
	if err != nil && !hostfs.IsMissing(err) {
		return nil, false, err
	}
	for _, e := range entries {
		if (e.Mode.IsRegular() || e.Mode&fs.ModeSymlink != 0) && strings.HasSuffix(e.Path, ".rules") {
			files = append(files, path.Join(auditRulesDir, path.Base(e.Path)))
		}
	}
	slices.Sort(files)
	if len(files) > auditMaxFiles {
		files, more = files[:auditMaxFiles], true
	}
	if len(files) > 0 {
		return files, more, nil
	}
	if _, err := h.FS.Stat(auditRulesFile); err == nil {
		return []string{auditRulesFile}, false, nil
	} else if !hostfs.IsMissing(err) {
		return nil, false, err
	}
	return nil, false, nil
}

// auditOptions are lines that set how the audit system runs and add no rule: the word, and at most one value.
var auditOptions = map[string]bool{"-b": true, "-f": true, "-r": true, "-e": true, "-c": true, "-i": true, "--backlog_wait_time": true, "--loginuid-immutable": true, "--reset-lost": true}

// parse reads the rules of one file, and returns what it could not read: a line that it does not understand may be the rule that a
// check looks for, or a "-d" that removes one, so the facts are incomplete and a check cannot pass on them.
func (st *auditState) parse(file string, data []byte) []string {
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
		case words[0] == "-D" && len(words) == 1:
			// what comes before it is deleted
			st.a.Paths, st.a.UserPaths, st.never, st.rules = map[string]AuditPath{}, map[string]AuditPath{}, map[string]bool{}, 0
			continue
		case (auditOptions[words[0]] && len(words) <= 2) || (strings.HasPrefix(words[0], "--") && strings.Contains(words[0], "=") && len(words) == 1):
			continue
		case words[0] != "-w" && words[0] != "-a" && words[0] != "-A":
			skipped = append(skipped, source+": "+words[0]+" is not read")
			continue
		}
		if st.rules >= auditMaxRules {
			skipped = append(skipped, file+": more rules than are read")
			return skipped
		}
		r, ok := parseAuditRule(words, source)
		if !ok {
			skipped = append(skipped, source+": the rule is not read")
			continue
		}
		st.rules++
		if why := st.add(r); why != "" {
			skipped = append(skipped, source+": "+why)
		}
	}
	if err := sc.Err(); err != nil {
		skipped = append(skipped, fmt.Sprintf("%s: %v", file, err))
	}
	return skipped
}

// auditRule is one rule of the files that audits (or, with never, spares) something.
type auditRule struct {
	// kind is "watch" (-w) or "syscall" (-a).
	kind string
	// action and list are those of an -a rule ("always", "exit"); empty for a watch.
	action, list string
	// path is the path of a watch, or the path= or dir= of an -a rule, without a trailing "/".
	path string
	// perms are the audited permissions in the order r, w, a, x; of a watch without -p, all of them.
	perms string
	// fields are the other filters ("arch=b64", "auid>=1000"), and "S" when the rule names system calls.
	fields []string
	source string
}

func parseAuditRule(words []string, source string) (auditRule, bool) {
	r := auditRule{source: source}
	perm, hasPerm := "", false
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
			if !ok || r.kind != "" {
				return r, false
			}
			r.kind, r.path = "watch", cleanAuditPath(p)
		case "-a", "-A":
			v, ok := next()
			if !ok || r.kind != "" {
				return r, false
			}
			r.kind = "syscall"
			for _, part := range strings.Split(v, ",") {
				switch part {
				case "always", "never":
					r.action = part
				case "exit", "entry", "task", "user", "exclude", "filesystem":
					r.list = part
				default:
					return r, false
				}
			}
		case "-p":
			p, ok := next()
			if !ok {
				return r, false
			}
			perm, hasPerm = p, true
		case "-k":
			if _, ok := next(); !ok {
				return r, false
			}
		case "-S":
			v, ok := next()
			if !ok {
				return r, false
			}
			if v != "all" {
				r.fields = append(r.fields, "S") // a rule for some system calls only: not a rule for a path
			}
		case "-F", "-C":
			v, ok := next()
			if !ok {
				return r, false
			}
			v = strings.ReplaceAll(v, " ", "")
			if w == "-C" {
				r.fields = append(r.fields, "C:"+v)
				continue
			}
			switch {
			case strings.HasPrefix(v, "path="), strings.HasPrefix(v, "dir="):
				r.path = cleanAuditPath(v[strings.Index(v, "=")+1:])
			case strings.HasPrefix(v, "perm="):
				perm, hasPerm = v[len("perm="):], true
			default:
				r.fields = append(r.fields, v)
			}
		default:
			return r, false // -R, -d, -l or something this does not know: not read
		}
	}
	if r.kind == "" {
		return r, false
	}
	if hasPerm {
		// auditctl refuses anything but r, w, x and a, each once: such a line loads nothing
		for i, c := range []byte(perm) {
			if !strings.ContainsRune("rwxa", rune(c)) || strings.IndexByte(perm[:i], c) >= 0 {
				return r, false
			}
		}
	} else if r.kind == "watch" {
		perm = "rwax" // a watch without -p audits every kind of access
	}
	r.perms = canonicalAuditPerms(perm)
	return r, true
}

// harmlessAuditField is a filter that does not narrow what a rule for a path audits for logged-in users: the architecture, and the two
// auid filters of the STIG (the user ID that logged in is at least 1000, and is not the unset value 4294967295).
func harmlessAuditField(f string) bool {
	return strings.HasPrefix(f, "arch=") || f == "auid>=1000" || f == "auid!=unset" || f == "auid!=-1" || f == "auid!=4294967295"
}

// add records what r audits, and returns why it could not tell (for a rule that may keep events out of the log).
func (st *auditState) add(r auditRule) string {
	a := st.a
	if r.kind == "syscall" && r.action == "never" && r.list == "exit" {
		if r.path == "" {
			// a never rule that is about no path can keep any event out
			return "a never rule that names no path is not judged"
		}
		st.never[r.path] = true
		return ""
	}
	if r.path == "" || r.perms == "" {
		return ""
	}
	if r.kind == "syscall" && (r.action != "always" || r.list != "exit") {
		return ""
	}
	for _, f := range r.fields {
		if !harmlessAuditField(f) {
			return "" // narrowed by another filter: it does not audit every event of the path
		}
	}
	merge := func(m map[string]AuditPath) {
		cur := m[r.path]
		cur.Perms = canonicalAuditPerms(cur.Perms + r.perms)
		if cur.Source == "" {
			cur.Source = r.source
		}
		m[r.path] = cur
	}
	merge(a.Paths)
	if r.kind == "syscall" && slices.Contains(r.fields, "auid>=1000") &&
		(slices.Contains(r.fields, "auid!=unset") || slices.Contains(r.fields, "auid!=-1") || slices.Contains(r.fields, "auid!=4294967295")) {
		merge(a.UserPaths)
	}
	return ""
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
