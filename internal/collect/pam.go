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
	"slices"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// PAM are the `pam` facts: the PAM stacks of the services hostlint checks and
// the policies they enforce. Policies are decided here, with PAM's semantics
// (controls, module arguments, which configuration files a module version
// reads), so rules do not have to re-implement them.
type PAM struct {
	// Stacks maps a service (login, sshd, su, passwd) to its rules, with
	// @include, include and substack expanded in place. A service without
	// its own file gets the "other" stack, as PAM does.
	Stacks map[string][]PAMRule `json:"stacks"`
	// PasswordQuality is the policy of the passwd service's password stack.
	PasswordQuality PasswordPolicy `json:"password_quality"`
	// PasswordHistory is the password reuse policy of the passwd service:
	// pam_pwhistory (with pwhistory.conf where it reads it), or pam_unix's
	// remember option.
	PasswordHistory PasswordPolicy `json:"password_history"`
	// Lockout maps a service to the lockout policy of its stack.
	Lockout map[string]LockoutPolicy `json:"lockout"`
	// SuWheel says whether pam_wheel restricts su: "restricted", or
	// "not restricted: <why>" for pam_wheel.so lines that do not (trust,
	// deny, a control that does not deny, an earlier sufficient rule). It
	// is unset when the su stack has no pam_wheel.so line.
	SuWheel facts.Setting `json:"su_wheel"`
	// PasswordHash is the hash that pam_unix in the passwd stack is told
	// to use (md5, sha256, sha512, yescrypt, ...). It is unset when no
	// argument names one and pam_unix follows ENCRYPT_METHOD in login.defs.
	PasswordHash facts.Setting `json:"password_hash"`
}

// pamUnixHashes are pam_unix's hashing options (pam_unix(8)).
var pamUnixHashes = []string{"md5", "bigcrypt", "sha256", "sha512", "blowfish", "gost_yescrypt", "yescrypt"}

// PAMRule is one line of a PAM stack.
type PAMRule struct {
	Type    string   `json:"type"`    // auth, account, password or session
	Control string   `json:"control"` // required, requisite, sufficient, optional or [...]
	Module  string   `json:"module"`  // base name, e.g. pam_pwquality.so
	Args    []string `json:"args"`
	Source  string   `json:"source"`
}

// PasswordPolicy is the effective configuration of the module that enforces
// a password policy: pam_pwquality or pam_cracklib for quality, pam_pwhistory
// or pam_unix for history. Module is "" when no such module is in the stack.
type PasswordPolicy struct {
	Module   string                   `json:"module"`
	Settings map[string]facts.Setting `json:"settings"`
}

// LockoutPolicy is the effective configuration of pam_faillock or pam_tally2.
type LockoutPolicy struct {
	Module   string                   `json:"module"` // "" when neither is in the stack
	Settings map[string]facts.Setting `json:"settings"`
	// Actions are the pam_faillock modes present: preauth, authfail and
	// authsucc on auth lines, and account for an account line.
	Actions []string `json:"actions"`
	// Enforced is true when failures are both counted and acted on:
	// pam_faillock needs authfail plus preauth or an account line;
	// pam_tally2 does both from its auth line.
	Enforced bool `json:"enforced"`
}

// pamServices are the stacks collected.
var pamServices = []string{"login", "sshd", "su", "passwd"}

// Documented defaults (pwquality.conf(5), faillock.conf(5), pam_pwhistory(8),
// pam_tally2(8): without deny it never locks). pam_cracklib's defaults vary
// too much between versions to assume.
var (
	pwqualityDefaults = map[string]string{"minlen": "8", "dcredit": "0", "ucredit": "0", "lcredit": "0", "ocredit": "0", "minclass": "0", "enforcing": "1"}
	faillockDefaults  = map[string]string{"deny": "3", "unlock_time": "600", "fail_interval": "900"}
	pwhistoryDefaults = map[string]string{"remember": "10"}
	tally2Defaults    = map[string]string{"deny": "0"}
)

// pamModuleDirs are where distributions install PAM modules.
var pamModuleDirs = []string{
	"/usr/lib64/security", "/lib64/security",
	"/usr/lib/*-linux-gnu/security", "/lib/*-linux-gnu/security",
	"/usr/lib/security", "/lib/security",
}

type pamCollector struct{}

func (pamCollector) Name() string          { return "pam" }
func (pamCollector) Version() int          { return 1 }
func (pamCollector) Access() engine.Access { return engine.AccessFilesystem }
func (pamCollector) Type() reflect.Type    { return reflect.TypeFor[PAM]() }

func (pamCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	r := &pamReader{fsys: h.FS}
	p := &PAM{Stacks: map[string][]PAMRule{}, Lockout: map[string]LockoutPolicy{}}
	for _, svc := range pamServices {
		rules, err := r.stack(svc)
		if err != nil {
			return engine.Facts{}, err
		}
		p.Stacks[svc] = rules
		p.Lockout[svc] = r.lockout(rules)
	}
	p.PasswordQuality = r.quality(p.Stacks["passwd"])
	p.PasswordHistory = r.history(p.Stacks["passwd"])
	p.SuWheel = suWheel(p.Stacks["su"])
	p.PasswordHash = passwordHash(p.Stacks["passwd"])
	return engine.Facts{Value: p, Complete: len(r.skipped) == 0, Skipped: r.skipped}, nil
}

// passwordHash returns the hashing option of the first pam_unix password
// rule, if it has one.
func passwordHash(rules []PAMRule) facts.Setting {
	for _, rule := range rules {
		if rule.Type != "password" || rule.Module != "pam_unix.so" {
			continue
		}
		for _, a := range rule.Args {
			if slices.Contains(pamUnixHashes, a) {
				return facts.Setting{Value: a, Explicit: true, Source: rule.Source}
			}
		}
		return facts.Setting{}
	}
	return facts.Setting{}
}

type pamReader struct {
	fsys    hostfs.FS
	skipped []string
}

// skip records something that could not be read, once.
func (r *pamReader) skip(msg string) {
	if !slices.Contains(r.skipped, msg) {
		r.skipped = append(r.skipped, msg)
	}
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
			// libpwquality reads pwquality.conf.d/*.conf in lexical order,
			// then pwquality.conf, so the main file wins; option names are
			// case-insensitive, and so are the module's arguments.
			files := r.glob("/etc/security/pwquality.conf.d/*.conf")
			s := r.confFiles(append(files, "/etc/security/pwquality.conf"), true)
			addDefaults(s, pwqualityDefaults, "default (pwquality.conf(5))")
			addArgs(s, rule, true)
			return PasswordPolicy{Module: rule.Module, Settings: s}
		case "pam_cracklib.so":
			s := map[string]facts.Setting{}
			addArgs(s, rule, false)
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
			s := r.moduleConf(rule.Module, "/etc/security/pwhistory.conf")
			addDefaults(s, pwhistoryDefaults, "default (pam_pwhistory(8))")
			addArgs(s, rule, false)
			return PasswordPolicy{Module: rule.Module, Settings: s}
		case rule.Module == "pam_unix.so" && hasArg(rule, "remember"):
			s := map[string]facts.Setting{}
			addArgs(s, rule, false)
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

// lockout returns the lockout policy of a stack: the first of pam_faillock
// and pam_tally2 on an auth line, with every auth line of that module.
func (r *pamReader) lockout(rules []PAMRule) LockoutPolicy {
	var found []PAMRule
	module := ""
	actions := map[string]bool{}
	for _, rule := range rules {
		if rule.Module != "pam_faillock.so" && rule.Module != "pam_tally2.so" {
			continue
		}
		if rule.Type == "account" && rule.Module == "pam_faillock.so" {
			actions["account"] = true
			continue
		}
		if rule.Type != "auth" {
			continue
		}
		if module == "" {
			module = rule.Module
		}
		if rule.Module != module {
			continue
		}
		found = append(found, rule)
		for _, a := range rule.Args {
			if a == "preauth" || a == "authfail" || a == "authsucc" {
				actions[a] = true
			}
		}
	}
	p := LockoutPolicy{Module: module, Settings: map[string]facts.Setting{}, Actions: []string{}}
	switch module {
	case "pam_faillock.so":
		p.Settings = r.moduleConf(module, "/etc/security/faillock.conf")
		addDefaults(p.Settings, faillockDefaults, "default (faillock.conf(5))")
		for _, a := range []string{"preauth", "authfail", "authsucc", "account"} {
			if actions[a] {
				p.Actions = append(p.Actions, a)
			}
		}
		p.Enforced = actions["authfail"] && (actions["preauth"] || actions["account"])
	case "pam_tally2.so":
		addDefaults(p.Settings, tally2Defaults, "default (pam_tally2(8): no lockout)")
		p.Enforced = true
	default:
		return p
	}
	for _, rule := range found {
		addArgs(p.Settings, rule, false)
	}
	return p
}

// suWheel decides whether the su stack's pam_wheel.so lines restrict su to a
// group. A line restricts when its control denies on failure, it has neither
// trust (users outside the group are not denied) nor deny (the check is
// reversed), and no sufficient rule before it can end the stack first.
func suWheel(rules []PAMRule) facts.Setting {
	var first facts.Setting
	bypass := ""
	for _, rule := range rules {
		if rule.Type != "auth" {
			continue
		}
		if rule.Module != "pam_wheel.so" {
			if rule.Control == "sufficient" && rule.Module != "pam_rootok.so" && bypass == "" {
				bypass = rule.Module
			}
			continue
		}
		why := ""
		switch {
		case slices.Contains(rule.Args, "trust"):
			why = "trust (users outside the group are not denied)"
		case slices.Contains(rule.Args, "deny"):
			why = "deny (the check is reversed)"
		case !deniesOnFailure(rule.Control):
			why = "control " + rule.Control + " does not deny"
		case bypass != "":
			why = "sufficient " + bypass + " comes first"
		}
		if why == "" {
			return facts.Setting{Value: "restricted", Explicit: true, Source: rule.Source}
		}
		if first.Value == "" {
			first = facts.Setting{Value: "not restricted: " + why, Explicit: true, Source: rule.Source}
		}
	}
	return first
}

// deniesOnFailure reports whether a control makes a module's failure deny
// access: required, requisite, or a bracketed control whose action for
// perm_denied (or, without one, default) is die or bad.
func deniesOnFailure(control string) bool {
	switch control {
	case "required", "requisite":
		return true
	}
	inner, ok := strings.CutPrefix(control, "[")
	if !ok {
		return false
	}
	actions := map[string]string{}
	for _, kv := range strings.Fields(strings.TrimSuffix(inner, "]")) {
		if k, v, ok := strings.Cut(kv, "="); ok {
			actions[strings.ToLower(k)] = strings.ToLower(v)
		}
	}
	action, ok := actions["perm_denied"]
	if !ok {
		action = actions["default"]
	}
	return action == "die" || action == "bad"
}

// moduleConf reads a module's configuration file, if this version of the
// module reads it at all: the file is only applied when the module binary
// names it. When the module cannot be found the facts are incomplete.
func (r *pamReader) moduleConf(module, conf string) map[string]facts.Setting {
	reads, found := r.moduleReads(module, conf)
	switch {
	case !found:
		r.skip(fmt.Sprintf("%s: module not found, so whether it reads %s is unknown", module, conf))
		return map[string]facts.Setting{}
	case !reads:
		return map[string]facts.Setting{}
	}
	return r.confFiles([]string{conf}, false)
}

// moduleReads reports whether the installed module's binary contains the
// path conf; found is false when no readable module file exists.
func (r *pamReader) moduleReads(module, conf string) (reads, found bool) {
	for _, dir := range pamModuleDirs {
		candidates := []string{dir + "/" + module}
		if strings.Contains(dir, "*") {
			candidates = r.glob(dir + "/" + module)
		}
		for _, p := range candidates {
			data, err := r.fsys.ReadFile(p)
			switch {
			case errors.Is(err, fs.ErrNotExist):
				continue
			case err != nil:
				r.skip(err.Error())
				continue
			}
			return bytes.Contains(data, []byte(conf)), true
		}
	}
	return false, false
}

// glob expands pattern; unreadable directories make the facts incomplete.
func (r *pamReader) glob(pattern string) []string {
	matches, problems, err := hostfs.Glob(r.fsys, pattern)
	if err != nil {
		r.skip(err.Error())
		return nil
	}
	for _, p := range problems {
		r.skip(p)
	}
	return matches
}

// confFiles reads "key = value" (or bare flag) lines from files in order;
// later values replace earlier ones. "#" starts a comment anywhere on a line,
// as in pwquality.conf, faillock.conf and pwhistory.conf. With foldCase,
// keys are lowercased.
func (r *pamReader) confFiles(files []string, foldCase bool) map[string]facts.Setting {
	s := map[string]facts.Setting{}
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
			text, _, _ := strings.Cut(sc.Text(), "#")
			text = strings.TrimSpace(text)
			if text == "" {
				continue
			}
			key, value, hasValue := strings.Cut(text, "=")
			if !hasValue {
				value = "1"
			}
			key = strings.TrimSpace(key)
			if foldCase {
				key = strings.ToLower(key)
			}
			s[key] = facts.Setting{Value: strings.TrimSpace(value), Explicit: true, Source: fmt.Sprintf("%s:%d", file, line)}
		}
	}
	return s
}

// addArgs applies module arguments, which override configuration files.
func addArgs(s map[string]facts.Setting, rule PAMRule, foldCase bool) {
	for _, arg := range rule.Args {
		key, value, hasValue := strings.Cut(arg, "=")
		if !hasValue {
			value = "1"
		}
		if foldCase {
			key = strings.ToLower(key)
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
