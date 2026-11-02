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

// PAM are the `pam` facts: the PAM stacks of the services hostlint checks and
// the password-quality and lockout policies they enforce.
type PAM struct {
	// Stacks maps a service (login, sshd, su, passwd) to its rules, with
	// @include, include and substack expanded in place. A service without
	// its own file gets the "other" stack, as PAM does.
	Stacks map[string][]PAMRule `json:"stacks"`
	// Modules maps a service to "type module" entries of its stack, e.g.
	// "auth pam_wheel.so", so rules can test membership with `in`.
	Modules map[string][]string `json:"modules"`
	// PasswordQuality is the policy of the passwd service's password stack.
	PasswordQuality PasswordPolicy `json:"password_quality"`
	// PasswordHistory is the password reuse policy of the passwd service:
	// pam_pwhistory (with pwhistory.conf), or pam_unix's remember option.
	PasswordHistory PasswordPolicy `json:"password_history"`
	// Lockout maps a service to the lockout policy of its auth stack.
	Lockout map[string]PasswordPolicy `json:"lockout"`
}

// PAMRule is one line of a PAM stack.
type PAMRule struct {
	Type    string   `json:"type"`    // auth, account, password or session
	Control string   `json:"control"` // required, requisite, sufficient, optional or [...]
	Module  string   `json:"module"`  // base name, e.g. pam_pwquality.so
	Args    []string `json:"args"`
	Source  string   `json:"source"`
}

// PasswordPolicy is the effective configuration of the module that enforces
// a policy: pam_pwquality or pam_cracklib for password quality, pam_faillock
// or pam_tally2 for lockout. Module is "" when no such module is in the stack.
type PasswordPolicy struct {
	Module   string                   `json:"module"`
	Settings map[string]facts.Setting `json:"settings"`
}

// pamServices are the stacks collected.
var pamServices = []string{"login", "sshd", "su", "passwd"}

// Documented defaults (pwquality.conf(5), faillock.conf(5)); pam_cracklib and
// pam_tally2 defaults vary too much between versions to assume.
var (
	pwqualityDefaults = map[string]string{"minlen": "8", "dcredit": "0", "ucredit": "0", "lcredit": "0", "ocredit": "0", "minclass": "0"}
	faillockDefaults  = map[string]string{"deny": "3", "unlock_time": "600", "fail_interval": "900"}
)

type pamCollector struct{}

func (pamCollector) Name() string          { return "pam" }
func (pamCollector) Version() int          { return 1 }
func (pamCollector) Access() engine.Access { return engine.AccessFilesystem }
func (pamCollector) Type() reflect.Type    { return reflect.TypeFor[PAM]() }

func (pamCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	r := &pamReader{fsys: h.FS}
	p := &PAM{Stacks: map[string][]PAMRule{}, Modules: map[string][]string{}, Lockout: map[string]PasswordPolicy{}}
	for _, svc := range pamServices {
		rules, err := r.stack(svc)
		if err != nil {
			return engine.Facts{}, err
		}
		p.Stacks[svc] = rules
		p.Modules[svc] = []string{}
		for _, rule := range rules {
			p.Modules[svc] = append(p.Modules[svc], rule.Type+" "+rule.Module)
		}
		p.Lockout[svc] = r.lockout(rules)
	}
	p.PasswordQuality = r.quality(p.Stacks["passwd"])
	p.PasswordHistory = r.history(p.Stacks["passwd"])
	return engine.Facts{Value: p, Complete: len(r.skipped) == 0, Skipped: r.skipped}, nil
}

type pamReader struct {
	fsys    hostfs.FS
	skipped []string
}

// skip records something that could not be read, once.
func (r *pamReader) skip(msg string) {
	for _, s := range r.skipped {
		if s == msg {
			return
		}
	}
	r.skipped = append(r.skipped, msg)
}

// stack reads a service's stack; a missing service file means "other".
func (r *pamReader) stack(service string) ([]PAMRule, error) {
	rules, err := r.read("/etc/pam.d/"+service, "", 0)
	if errors.Is(err, fs.ErrNotExist) {
		rules, err = r.read("/etc/pam.d/other", "", 0)
		if errors.Is(err, fs.ErrNotExist) {
			return []PAMRule{}, nil
		}
	}
	return rules, err
}

const maxPAMDepth = 8

// read parses one PAM file. With onlyType set (include/substack), only rules
// of that type are kept.
func (r *pamReader) read(file, onlyType string, depth int) ([]PAMRule, error) {
	if depth > maxPAMDepth {
		r.skip(file + ": includes nested too deeply")
		return nil, nil
	}
	data, err := r.fsys.ReadFile(file)
	if err != nil {
		return nil, err
	}
	rules := []PAMRule{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		for strings.HasSuffix(text, `\`) && sc.Scan() {
			line++
			text = strings.TrimSuffix(text, `\`) + " " + strings.TrimSpace(sc.Text())
		}
		if i := strings.Index(text, "#"); i >= 0 {
			text = strings.TrimSpace(text[:i])
		}
		if text == "" {
			continue
		}
		src := fmt.Sprintf("%s:%d", file, line)
		if inc, ok := strings.CutPrefix(text, "@include"); ok {
			rules = append(rules, r.include(strings.TrimSpace(inc), onlyType, depth)...)
			continue
		}
		f := pamFields(text)
		if len(f) < 3 {
			r.skip(src + ": malformed rule")
			continue
		}
		typ := strings.ToLower(strings.TrimPrefix(f[0], "-"))
		if onlyType != "" && typ != onlyType {
			continue
		}
		control := f[1]
		if control == "include" || control == "substack" {
			rules = append(rules, r.include(f[2], typ, depth)...)
			continue
		}
		rules = append(rules, PAMRule{Type: typ, Control: control, Module: path.Base(f[2]), Args: append([]string{}, f[3:]...), Source: src})
	}
	return rules, sc.Err()
}

func (r *pamReader) include(name, onlyType string, depth int) []PAMRule {
	if !path.IsAbs(name) {
		name = "/etc/pam.d/" + name
	}
	rules, err := r.read(path.Clean(name), onlyType, depth+1)
	if err != nil {
		r.skip(err.Error())
	}
	return rules
}

// pamFields splits a rule, keeping a bracketed control like
// "[success=1 default=ignore]" in one field.
func pamFields(text string) []string {
	var out []string
	for text = strings.TrimSpace(text); text != ""; text = strings.TrimSpace(text) {
		if text[0] == '[' {
			end := strings.IndexByte(text, ']')
			if end < 0 {
				return append(out, text)
			}
			out = append(out, text[:end+1])
			text = text[end+1:]
			continue
		}
		i := strings.IndexAny(text, " \t")
		if i < 0 {
			return append(out, text)
		}
		out = append(out, text[:i])
		text = text[i:]
	}
	return out
}

// quality returns the password-quality policy of a stack.
func (r *pamReader) quality(rules []PAMRule) PasswordPolicy {
	for _, rule := range rules {
		if rule.Type != "password" {
			continue
		}
		switch rule.Module {
		case "pam_pwquality.so":
			s := r.confFile("/etc/security/pwquality.conf", "/etc/security/pwquality.conf.d/*.conf")
			addDefaults(s, pwqualityDefaults, "default (pwquality.conf(5))")
			addArgs(s, rule)
			return PasswordPolicy{Module: rule.Module, Settings: s}
		case "pam_cracklib.so":
			s := map[string]facts.Setting{}
			addArgs(s, rule)
			return PasswordPolicy{Module: rule.Module, Settings: s}
		}
	}
	return PasswordPolicy{Settings: map[string]facts.Setting{}}
}

// history returns the password reuse policy of a stack's password rules.
func (r *pamReader) history(rules []PAMRule) PasswordPolicy {
	for _, rule := range rules {
		if rule.Type != "password" {
			continue
		}
		switch {
		case rule.Module == "pam_pwhistory.so":
			s := r.confFile("/etc/security/pwhistory.conf", "")
			addArgs(s, rule)
			return PasswordPolicy{Module: rule.Module, Settings: s}
		case rule.Module == "pam_unix.so" && hasArg(rule, "remember"):
			s := map[string]facts.Setting{}
			addArgs(s, rule)
			return PasswordPolicy{Module: rule.Module, Settings: s}
		}
	}
	return PasswordPolicy{Settings: map[string]facts.Setting{}}
}

func hasArg(rule PAMRule, key string) bool {
	for _, a := range rule.Args {
		if k, _, _ := strings.Cut(a, "="); k == key {
			return true
		}
	}
	return false
}

// lockout returns the lockout policy of a stack's auth rules.
func (r *pamReader) lockout(rules []PAMRule) PasswordPolicy {
	var found []PAMRule
	module := ""
	for _, rule := range rules {
		if rule.Type == "auth" && (rule.Module == "pam_faillock.so" || rule.Module == "pam_tally2.so") {
			if module == "" {
				module = rule.Module
			}
			if rule.Module == module {
				found = append(found, rule)
			}
		}
	}
	s := map[string]facts.Setting{}
	switch module {
	case "pam_faillock.so":
		s = r.confFile("/etc/security/faillock.conf", "")
		addDefaults(s, faillockDefaults, "default (faillock.conf(5))")
	case "":
		return PasswordPolicy{Settings: s}
	}
	for _, rule := range found {
		addArgs(s, rule)
	}
	return PasswordPolicy{Module: module, Settings: s}
}

// confFile reads "key = value" (or bare flag) lines; files from dropIns are
// read after the main file, and later values replace earlier ones.
func (r *pamReader) confFile(main, dropIns string) map[string]facts.Setting {
	s := map[string]facts.Setting{}
	files := []string{main}
	if dropIns != "" {
		matches, problems, err := hostfs.Glob(r.fsys, dropIns)
		if err == nil {
			files = append(files, matches...)
		}
		for _, p := range problems {
			r.skip(p)
		}
	}
	for _, file := range files {
		data, err := r.fsys.ReadFile(file)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			r.skip(err.Error())
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		for line := 1; sc.Scan(); line++ {
			text := strings.TrimSpace(sc.Text())
			if text == "" || strings.HasPrefix(text, "#") {
				continue
			}
			key, value, hasValue := strings.Cut(text, "=")
			if !hasValue {
				value = "1"
			}
			s[strings.TrimSpace(key)] = facts.Setting{Value: strings.TrimSpace(value), Explicit: true, Source: fmt.Sprintf("%s:%d", file, line)}
		}
	}
	return s
}

// addArgs applies module arguments, which override configuration files.
func addArgs(s map[string]facts.Setting, rule PAMRule) {
	for _, arg := range rule.Args {
		key, value, hasValue := strings.Cut(arg, "=")
		if !hasValue {
			value = "1"
		}
		s[key] = facts.Setting{Value: value, Explicit: true, Source: rule.Source}
	}
}

func addDefaults(s map[string]facts.Setting, defaults map[string]string, source string) {
	for key, value := range defaults {
		if _, ok := s[key]; !ok {
			s[key] = facts.Setting{Value: value, Source: source}
		}
	}
}
