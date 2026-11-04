package collect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"path"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// PAM are the `pam` facts: the PAM stacks of the services hostlint checks and
// the policies they enforce. Policies are decided here by evaluating each
// stack the way libpam does (controls, jumps, substacks) for the situation
// that matters, with each module's version-specific configuration, so rules
// do not have to re-implement PAM.
type PAM struct {
	// Stacks maps a service (login, sshd, su, passwd) to its rules, with
	// @include, include and substack expanded in place. A service without
	// its own file gets the "other" stack, as PAM does.
	Stacks map[string][]PAMRule `json:"stacks"`
	// PasswordQuality is the policy that rejects weak new passwords in the
	// passwd service: pam_pwquality or pam_cracklib. Module is "" when no
	// such module can reject a password (absent, ignored or skipped).
	PasswordQuality PasswordPolicy `json:"password_quality"`
	// PasswordHistory is the policy that rejects reused passwords in the
	// passwd service: pam_pwhistory, or pam_unix's remember option.
	PasswordHistory PasswordPolicy `json:"password_history"`
	// Lockout maps a service to the lockout policy of its auth stack.
	Lockout map[string]LockoutPolicy `json:"lockout"`
	// Effective holds what the stacks amount to. A key is absent when the
	// stacks do not decide it:
	//   - su_wheel: "restricted" when the su stack denies a user outside the
	//     pam_wheel group who knows root's password; otherwise "not
	//     restricted: <why>". "restricted" also when every su found is
	//     restricted by its permissions: setuid root, a group of
	//     administrators (wheel, sudo, admin, adm), not executable by others.
	//     Absent when neither the su stack has a pam_wheel.so nor su is so
	//     restricted.
	//   - password_hash: the hash pam_unix in the passwd stack uses (md5,
	//     sha256, sha512, yescrypt, ...): its last hash option, or else the
	//     first ENCRYPT_METHOD of /etc/login.defs, which pam_unix reads.
	Effective map[string]facts.Setting `json:"effective"`
}

// pamUnixHashes are pam_unix's hashing options (pam_unix(8)); the last one
// on a line wins.
var pamUnixHashes = []string{"des", "md5", "bigcrypt", "sha256", "sha512", "blowfish", "gost_yescrypt", "yescrypt"}

// PAMRule is one line of a PAM stack.
type PAMRule struct {
	Type    string `json:"type"`    // auth, account, password or session
	Control string `json:"control"` // required, requisite, sufficient, optional or [...]
	Module  string `json:"module"`  // base name, e.g. pam_pwquality.so
	// Args are the module arguments; values of arguments that carry
	// credentials (secret=, password=, key=, ...) and pam_exec's command
	// are replaced by "<redacted>".
	Args   []string `json:"args"`
	Source string   `json:"source"`
	// Scope names the substack a rule came from ("" for the service's own
	// stack): a sufficient or done result only ends its own scope.
	Scope string `json:"scope"`
}

// PasswordPolicy is the effective configuration of the module that enforces
// a password policy, or Module "" when none does.
type PasswordPolicy struct {
	Module   string                   `json:"module"`
	Settings map[string]facts.Setting `json:"settings"`
	// Ignored lists modules of this kind that are in the stack but cannot
	// reject a password, with why (e.g. a sufficient rule ends the stack
	// first).
	Ignored []string `json:"ignored"`
}

// LockoutPolicy is the effective configuration of pam_faillock or pam_tally2.
type LockoutPolicy struct {
	Module   string                   `json:"module"` // "" when neither is in the stack
	Settings map[string]facts.Setting `json:"settings"`
	// Actions are the pam_faillock modes present: preauth, authfail and
	// authsucc on auth lines, and account for an account line.
	Actions []string `json:"actions"`
	// Enforced is true when the auth stack, evaluated as libpam does, counts
	// a wrong password, denies a locked account even with the right
	// password, and still lets an unlocked account in.
	Enforced bool `json:"enforced"`
	// Why says what is missing when Enforced is false.
	Why string `json:"why"`
}

// pamServices are the stacks collected.
var pamServices = []string{"login", "sshd", "su", "passwd"}

// passwordModules verify the password in an auth stack.
var passwordModules = []string{"pam_unix.so", "pam_unix2.so", "pam_sss.so", "pam_ldap.so", "pam_krb5.so", "pam_winbind.so"}

// Documented defaults (faillock.conf(5), pam_pwhistory(8); pam_tally2(8):
// without deny it never locks). libpwquality's depend on its version; see
// pwqualityLibrary. pam_cracklib's vary too much between versions to assume.
var (
	faillockDefaults  = map[string]string{"deny": "3", "unlock_time": "600", "fail_interval": "900"}
	pwhistoryDefaults = map[string]string{"remember": "10"}
	tally2Defaults    = map[string]string{"deny": "0"}
)

// libDirs are where distributions install shared libraries and PAM modules
// ("*-linux-gnu*" covers arm-linux-gnueabihf).
var libDirs = []string{"/usr/lib64", "/lib64", "/usr/lib/*-linux-gnu*", "/lib/*-linux-gnu*", "/usr/lib", "/lib"}

// Bounds on what one collection reads: includes can repeat files.
const (
	maxPAMDepth = 8
	maxPAMReads = 500
	maxPAMRules = 5000
)

// secretArg matches the names of module arguments whose values are
// credentials (secret=, passwd=, bindpw=, key=, api_key=, token=, ...).
var secretArg = regexp.MustCompile(`(?i)^(.*[_-])?(secret|pass|passwd|password|pwd|bindpw|key|apikey|token|credentials?)$`)

type pamCollector struct{}

func (pamCollector) Name() string          { return "pam" }
func (pamCollector) Version() int          { return 1 }
func (pamCollector) Access() engine.Access { return engine.AccessFilesystem }
func (pamCollector) Type() reflect.Type    { return reflect.TypeFor[PAM]() }

func (pamCollector) Collect(ctx context.Context, h *hostfs.Host) (engine.Facts, error) {
	r := &pamReader{ctx: ctx, fsys: h.FS, unknown: map[string]bool{}}
	p := &PAM{Stacks: map[string][]PAMRule{}, Lockout: map[string]LockoutPolicy{}, Effective: map[string]facts.Setting{}}
	for _, svc := range pamServices {
		rules, err := r.stack(svc)
		if err != nil {
			return engine.Facts{}, err
		}
		p.Stacks[svc] = rules
		p.Lockout[svc] = r.lockout(rules)
	}
	if err := ctx.Err(); err != nil {
		return engine.Facts{}, err
	}
	p.PasswordQuality = r.quality(p.Stacks["passwd"])
	p.PasswordHistory = r.history(p.Stacks["passwd"])
	if s, ok := suWheel(p.Stacks["su"]); ok {
		p.Effective["su_wheel"] = s
	}
	if p.Effective["su_wheel"].Value != "restricted" {
		if s, ok := r.suPermissions(); ok {
			p.Effective["su_wheel"] = s
		}
	}
	switch s, state := r.passwordHash(p.Stacks["passwd"]); state {
	case hashDecided:
		p.Effective["password_hash"] = s
	case hashElsewhere:
		// Passwords are changed by another module (pam_sss, pam_ldap, ...), or
		// pam_unix is not certain to run (a sufficient module before it):
		// ENCRYPT_METHOD says nothing about them.
		r.unknownField("effective.password_hash", "the passwd stack does not certainly reach pam_unix: the hash of new passwords may be set elsewhere")
	}
	f := engine.Facts{Value: p, Complete: len(r.skipped) == 0, Skipped: append(r.skipped, r.notes...)}
	for field := range r.unknown {
		f.Unknown = append(f.Unknown, field)
	}
	slices.Sort(f.Unknown)
	return f, nil
}

// suPaths are where su is found; on a merged /usr they are the same file.
var suPaths = []string{"/usr/bin/su", "/bin/su"}

// adminGroups are the groups whose members administer the host. su restricted
// to another group (users, staff) may still be open to every user, so only
// these count; a site's own group is not recognized (the check then fails
// rather than passes).
var adminGroups = []string{"wheel", "sudo", "admin", "adm"}

// suPermissions reports a restriction of su by its file permissions: owned by
// root, a group of administrators, setuid, and not executable by others, so
// only members of that group can run it. Every su found must be restricted.
func (r *pamReader) suPermissions() (facts.Setting, bool) {
	groups := r.groupNames()
	var source string
	for _, p := range suPaths {
		fi, err := r.fsys.Stat(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			r.unknownField("effective.su_wheel", p+": "+err.Error())
			return facts.Setting{}, false
		}
		perm := fi.Perm()
		if !fi.IsRegular() || fi.UID != 0 || !slices.Contains(adminGroups, groups[fi.GID]) || perm&0o4000 == 0 || perm&0o010 == 0 || perm&0o001 != 0 {
			return facts.Setting{}, false
		}
		if source == "" {
			source = fmt.Sprintf("%s (mode %04o, group %s)", p, perm, groups[fi.GID])
		}
	}
	if source == "" {
		return facts.Setting{}, false
	}
	return facts.Setting{Value: "restricted", Explicit: true, Source: source}, true
}

// groupNames maps group ids to names from /etc/group; empty when it cannot be read.
func (r *pamReader) groupNames() map[int64]string {
	names := map[int64]string{}
	data, err := r.fsys.ReadFile("/etc/group")
	if err != nil {
		return names
	}
	for line := range strings.Lines(string(data)) {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) < 3 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if gid, err := strconv.ParseInt(f[2], 10, 64); err == nil {
			if _, dup := names[gid]; !dup {
				names[gid] = f[0]
			}
		}
	}
	return names
}

type pamReader struct {
	ctx     context.Context
	fsys    hostfs.FS
	reads   int
	scopes  int
	skipped []string // what could not be read: the facts are incomplete
	// unknown are policy fields that could not be decided, while the stacks
	// are complete; notes say why.
	unknown map[string]bool
	notes   []string
}

// skip records something that could not be read, once.
func (r *pamReader) skip(msg string) {
	if !slices.Contains(r.skipped, msg) {
		r.skipped = append(r.skipped, msg)
	}
}

// unknownField marks a policy field undecided, saying why.
func (r *pamReader) unknownField(field, why string) {
	r.unknown[field] = true
	if !slices.Contains(r.notes, why) {
		r.notes = append(r.notes, why)
	}
}

// stack reads a service's stack; a missing service file means "other".
func (r *pamReader) stack(service string) ([]PAMRule, error) {
	rules, err := r.read("/etc/pam.d/"+service, "", "", 0)
	if errors.Is(err, fs.ErrNotExist) {
		rules, err = r.read("/etc/pam.d/other", "", "", 0)
		if errors.Is(err, fs.ErrNotExist) {
			return []PAMRule{}, nil
		}
	}
	return rules, err
}

// read parses one PAM file as libpam does. With onlyType set (include,
// substack), only rules of that type are kept; scope is the substack the
// rules belong to.
func (r *pamReader) read(file, onlyType, scope string, depth int) ([]PAMRule, error) {
	switch {
	case depth > maxPAMDepth:
		r.skip(file + ": includes nested too deeply")
		return nil, nil
	case r.reads >= maxPAMReads:
		r.skip(fmt.Sprintf("more than %d PAM files read: the stacks are incomplete", maxPAMReads))
		return nil, nil
	case r.ctx.Err() != nil:
		return nil, r.ctx.Err()
	}
	r.reads++
	data, err := r.fsys.ReadFile(file)
	if err != nil {
		return nil, err
	}
	rules := []PAMRule{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		// libpam drops a comment before joining continued lines, so a
		// comment ending in a backslash does not swallow the next line.
		text := trimASCII(stripComment(sc.Text()))
		start := line
		for strings.HasSuffix(text, `\`) && sc.Scan() {
			line++
			text = strings.TrimSuffix(text, `\`) + " " + trimASCII(stripComment(sc.Text()))
		}
		if text == "" {
			continue
		}
		src := fmt.Sprintf("%s:%d", file, start)
		if inc, ok := strings.CutPrefix(text, "@include"); ok {
			rules = append(rules, r.include(trimASCII(inc), onlyType, scope, depth)...)
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
		if !strings.HasPrefix(control, "[") {
			control = strings.ToLower(control) // libpam compares keywords with strcasecmp
		}
		switch control {
		case "include":
			rules = append(rules, r.include(f[2], typ, scope, depth)...)
			continue
		case "substack":
			r.scopes++
			sub := strconv.Itoa(r.scopes)
			if scope != "" {
				sub = scope + "/" + sub
			}
			rules = append(rules, r.include(f[2], typ, sub, depth)...)
			continue
		}
		module := path.Base(f[2])
		rules = append(rules, PAMRule{Type: typ, Control: control, Module: module, Args: redactArgs(module, f[3:]), Source: src, Scope: scope})
		if len(rules) > maxPAMRules {
			r.skip(file + ": too many rules")
			return rules, nil
		}
	}
	if err := sc.Err(); err != nil {
		r.skip(fmt.Sprintf("%s: %v", file, err))
	}
	return rules, nil
}

func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

func (r *pamReader) include(name, onlyType, scope string, depth int) []PAMRule {
	if !path.IsAbs(name) {
		name = "/etc/pam.d/" + name
	}
	rules, err := r.read(path.Clean(name), onlyType, scope, depth+1)
	if err != nil {
		r.skip(err.Error())
	}
	return rules
}

// pamFields splits a rule on ASCII whitespace, keeping a bracketed control
// like "[success=1 default=ignore]" in one field.
func pamFields(text string) []string {
	var out []string
	for text = trimASCII(text); text != ""; text = trimASCII(text) {
		if text[0] == '[' {
			end := strings.IndexByte(text, ']')
			if end < 0 {
				return append(out, text)
			}
			out = append(out, text[:end+1])
			text = text[end+1:]
			continue
		}
		i := strings.IndexAny(text, asciiSpace)
		if i < 0 {
			return append(out, text)
		}
		out = append(out, text[:i])
		text = text[i:]
	}
	return out
}

// redactArgs replaces the values of credential arguments, and pam_exec's
// command line, so no secret becomes a fact.
func redactArgs(module string, args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		k, _, hasValue := strings.Cut(a, "=")
		switch {
		case module == "pam_exec.so" && strings.HasPrefix(a, "/"):
			return append(out, "<redacted command>")
		case hasValue && secretArg.MatchString(k):
			out = append(out, k+"=<redacted>")
		default:
			out = append(out, a)
		}
	}
	return out
}

// --- Evaluating a stack ------------------------------------------------------

// evaluate runs the rules of one type as libpam does, giving each module the
// result result returns ("success", or a failure such as "auth_err",
// "perm_denied", "authtok_err", or "ignore"). It reports whether the stack
// succeeds and which rules ran.
func evaluate(rules []PAMRule, typ string, result func(PAMRule) string) (ok bool, ran map[int]bool) {
	var idx []int
	for i, rule := range rules {
		if rule.Type == typ {
			idx = append(idx, i)
		}
	}
	ran = map[int]bool{}
	return evalScope(rules, idx, 0, len(idx), "", result, ran), ran
}

// evalScope evaluates idx[from:to], the rules of one scope; a nested
// substack counts as one module that acts like a required one.
func evalScope(rules []PAMRule, idx []int, from, to int, scope string, result func(PAMRule) string, ran map[int]bool) bool {
	failed, succeeded := false, false
	for k := from; k < to; {
		rule := rules[idx[k]]
		control, res, next := rule.Control, "", k+1
		if rule.Scope != scope {
			child := childScope(scope, rule.Scope)
			next = k
			for next < to && inScope(rules[idx[next]].Scope, child) {
				next++
			}
			control, res = "required", "auth_err"
			if evalScope(rules, idx, k, next, child, result, ran) {
				res = "success"
			}
		} else {
			ran[idx[k]] = true
			res = result(rule)
		}
		switch act := pamAction(control, res); act {
		case "ok", "done":
			if res == "success" {
				succeeded = true
			} else {
				failed = true
			}
			if act == "done" {
				return !failed && succeeded
			}
		case "bad":
			failed = true
		case "die":
			return false
		case "ignore":
		case "reset":
			failed, succeeded = false, false
		default: // a jump: like ok, then skip that many modules of this scope
			if res == "success" {
				succeeded = true
			} else {
				failed = true
			}
			n, _ := strconv.Atoi(act)
			for ; n > 0 && next < to; n-- {
				next = skipUnit(rules, idx, next, to, scope)
			}
		}
		k = next
	}
	return !failed && succeeded
}

// skipUnit returns the index after the module at k: a rule of this scope,
// or a whole nested substack.
func skipUnit(rules []PAMRule, idx []int, k, to int, scope string) int {
	s := rules[idx[k]].Scope
	if s == scope {
		return k + 1
	}
	child := childScope(scope, s)
	for k < to && inScope(rules[idx[k]].Scope, child) {
		k++
	}
	return k
}

// inScope reports whether a rule of scope s belongs to scope (or below it).
func inScope(s, scope string) bool {
	return scope == "" || s == scope || strings.HasPrefix(s, scope+"/")
}

// childScope is the scope directly below parent that contains s.
func childScope(parent, s string) string {
	rest := s
	if parent != "" {
		rest = strings.TrimPrefix(s, parent+"/")
	}
	first, _, _ := strings.Cut(rest, "/")
	if parent == "" {
		return first
	}
	return parent + "/" + first
}

// pamAction is what a control does with a result: ok, done, bad, die,
// ignore, reset, or a number of modules to jump over.
func pamAction(control, res string) string {
	success := res == "success"
	if res == "ignore" && !strings.HasPrefix(control, "[") {
		return "ignore" // PAM_IGNORE never counts for a keyword control
	}
	switch control {
	case "required":
		if success {
			return "ok"
		}
		return "bad"
	case "requisite":
		if success {
			return "ok"
		}
		return "die"
	case "sufficient":
		if success {
			return "done"
		}
		return "ignore"
	case "optional":
		if success {
			return "ok"
		}
		return "ignore"
	}
	actions := bracketActions(control)
	if a, ok := actions[res]; ok {
		return a
	}
	if a, ok := actions["default"]; ok {
		return a
	}
	return "bad"
}

// bracketActions parses "[value=action ...]".
func bracketActions(control string) map[string]string {
	actions := map[string]string{}
	inner := strings.TrimSuffix(strings.TrimPrefix(control, "["), "]")
	for _, kv := range fieldsASCII(inner) {
		if k, v, ok := strings.Cut(kv, "="); ok {
			actions[strings.ToLower(k)] = strings.ToLower(v)
		}
	}
	return actions
}

// --- Policies ------------------------------------------------------------------

// quality returns the policy that rejects weak passwords: the pam_pwquality
// or pam_cracklib rule whose rejection fails the passwd stack.
func (r *pamReader) quality(rules []PAMRule) PasswordPolicy {
	p := PasswordPolicy{Settings: map[string]facts.Setting{}, Ignored: []string{}}
	isQuality := func(rule PAMRule) bool {
		return rule.Type == "password" && (rule.Module == "pam_pwquality.so" || rule.Module == "pam_cracklib.so")
	}
	rule, ok := rejecting(rules, isQuality, &p)
	if !ok {
		return p
	}
	p.Module = rule.Module
	if rule.Module == "pam_cracklib.so" {
		addArgs(p.Settings, rule, false)
		return p
	}
	lib, ok := r.pwqualityLibrary()
	if !ok {
		r.unknownField("password_quality", "libpwquality not found, so its version, defaults and configuration files are unknown")
		return p
	}
	p.Settings = r.pwqualityConf(lib)
	addDefaults(p.Settings, lib.defaults, lib.defaultSource)
	pwqualityArgs(p.Settings, lib, rule)
	return p
}

// history returns the policy that rejects reused passwords: pam_pwhistory,
// or pam_unix with remember, whose rejection fails the passwd stack.
func (r *pamReader) history(rules []PAMRule) PasswordPolicy {
	p := PasswordPolicy{Settings: map[string]facts.Setting{}, Ignored: []string{}}
	isHistory := func(rule PAMRule) bool {
		return rule.Type == "password" && (rule.Module == "pam_pwhistory.so" || rule.Module == "pam_unix.so" && hasArg(rule, "remember"))
	}
	rule, ok := rejecting(rules, isHistory, &p)
	if !ok {
		return p
	}
	p.Module = rule.Module
	if rule.Module == "pam_pwhistory.so" {
		conf := argValue(rule, "conf", "/etc/security/pwhistory.conf")
		switch reads, found := r.moduleReads(rule.Module, "/etc/security/pwhistory.conf"); {
		case !found:
			r.unknownField("password_history", fmt.Sprintf("%s: module not found, so whether it reads %s is unknown", rule.Module, conf))
			return p
		case reads:
			p.Settings = r.searchKeyConf(conf, []string{"remember", "enforce_for_root", "retry", "file", "debug"})
		}
		addDefaults(p.Settings, pwhistoryDefaults, "default (pam_pwhistory(8))")
	}
	addArgs(p.Settings, rule, false)
	return p
}

// rejecting finds the first rule matching is whose rejection fails the
// passwd stack when every other module succeeds; the others are listed in
// p.Ignored.
func rejecting(rules []PAMRule, is func(PAMRule) bool, p *PasswordPolicy) (PAMRule, bool) {
	for i, rule := range rules {
		if !is(rule) {
			continue
		}
		ok, ran := evaluate(rules, "password", func(other PAMRule) string {
			switch {
			case other.Source == rule.Source && other.Module == rule.Module:
				return "authtok_err"
			case other.Module == "pam_deny.so":
				return "auth_err"
			}
			return "success"
		})
		writer, writes := writesAnyway(rules, ran, i)
		switch {
		case !ran[i]:
			p.Ignored = append(p.Ignored, rule.Module+" at "+rule.Source+": not reached when the modules before it succeed")
		case ok:
			p.Ignored = append(p.Ignored, rule.Module+" at "+rule.Source+": its rejection does not fail the stack (control "+rule.Control+")")
		case writes:
			p.Ignored = append(p.Ignored, rule.Module+" at "+rule.Source+": its rejection does not stop "+writer.Module+" at "+writer.Source+" from storing the password")
		default:
			return rule, true
		}
	}
	return PAMRule{}, false
}

// writesAnyway returns a module that stores the new password although the
// rule at i rejected it, which only fails the call afterwards: one that ran
// before it, or one after it that asks for the password again. A rejecting
// pam_pwquality, pam_cracklib or pam_pwhistory clears the password it was
// given, so a module with use_authtok after it has nothing to store.
func writesAnyway(rules []PAMRule, ran map[int]bool, i int) (PAMRule, bool) {
	for j, w := range rules {
		if j == i || !ran[j] || w.Type != "password" || !slices.Contains(passwordModules, w.Module) {
			continue
		}
		if j < i || !hasArg(w, "use_authtok") {
			return w, true
		}
	}
	return PAMRule{}, false
}

// lockout returns the lockout policy of an auth stack: it is enforced when
// a wrong password is counted, a locked account is denied even with the
// right password, and an unlocked one still gets in.
func (r *pamReader) lockout(rules []PAMRule) LockoutPolicy {
	p := LockoutPolicy{Settings: map[string]facts.Setting{}, Actions: []string{}}
	modes := map[string]bool{}
	for _, rule := range rules {
		switch {
		case rule.Module == "pam_faillock.so" && rule.Type == "account":
			modes["account"] = true
		case rule.Module == "pam_faillock.so" && rule.Type == "auth" && (p.Module == "" || p.Module == rule.Module):
			p.Module = rule.Module
			modes[faillockMode(rule)] = true
		case rule.Module == "pam_tally2.so" && rule.Type == "auth" && p.Module == "":
			p.Module = rule.Module
		}
	}
	for _, m := range []string{"preauth", "authfail", "authsucc", "account"} {
		if modes[m] {
			p.Actions = append(p.Actions, m)
		}
	}
	if p.Module == "" {
		return p
	}
	isLock := func(rule PAMRule) bool { return rule.Type == "auth" && rule.Module == p.Module }
	// The situations: a wrong password, and the right password for a locked
	// and an unlocked account.
	sim := func(rightPassword, locked bool) (bool, map[int]bool) {
		return evaluate(rules, "auth", func(rule PAMRule) string {
			switch {
			case slices.Contains(passwordModules, rule.Module):
				if rightPassword {
					return "success"
				}
				return "auth_err"
			case rule.Module == "pam_deny.so":
				return "auth_err"
			case isLock(rule) && rule.Module == "pam_faillock.so" && faillockMode(rule) == "authfail":
				return "auth_err" // it records the failure and fails
			case isLock(rule) && locked:
				return "auth_err"
			}
			return "success"
		})
	}
	_, wrongRan := sim(false, false)
	lockedOK, lockedRan := sim(true, true)
	unlockedOK, _ := sim(true, false)

	counted := false
	var checks []PAMRule
	for i, rule := range rules {
		if !isLock(rule) {
			continue
		}
		mode := faillockMode(rule)
		if wrongRan[i] && (p.Module == "pam_tally2.so" || mode == "authfail") {
			counted = true
		}
		if lockedRan[i] && (p.Module == "pam_tally2.so" || mode == "preauth" || mode == "authsucc") {
			checks = append(checks, rule)
		}
	}
	switch {
	case !counted:
		p.Why = "no " + p.Module + " line counts a failed login (pam_faillock needs authfail, reached when the password check fails)"
	case len(checks) == 0 || lockedOK:
		p.Why = "a locked account still logs in with the right password (pam_faillock needs preauth or authsucc, reached and able to fail the stack)"
	case !unlockedOK:
		p.Why = "the stack denies every login"
	default:
		p.Enforced = true
	}
	// The settings that decide the lock are those of the line that checks it.
	switch p.Module {
	case "pam_faillock.so":
		conf := "/etc/security/faillock.conf"
		if len(checks) > 0 {
			conf = argValue(checks[0], "conf", conf)
		}
		switch reads, found := r.moduleReads(p.Module, "/etc/security/faillock.conf"); {
		case !found:
			r.unknownField("lockout", fmt.Sprintf("%s: module not found, so whether it reads %s is unknown", p.Module, conf))
		case reads:
			p.Settings = r.faillockConf(conf)
		}
		addDefaults(p.Settings, faillockDefaults, "default (faillock.conf(5))")
	case "pam_tally2.so":
		addDefaults(p.Settings, tally2Defaults, "default (pam_tally2(8): no lockout)")
	}
	if len(checks) > 0 {
		addArgs(p.Settings, checks[0], false)
	}
	return p
}

// faillockMode is a pam_faillock line's mode; preauth when none is given,
// as pam_faillock does.
func faillockMode(rule PAMRule) string {
	for _, a := range rule.Args {
		if a == "preauth" || a == "authfail" || a == "authsucc" {
			return a
		}
	}
	return "preauth"
}

// suWheel decides whether su is restricted to the pam_wheel group: the su
// stack is evaluated for a user outside the group who knows root's password.
func suWheel(rules []PAMRule) (facts.Setting, bool) {
	var wheel []PAMRule
	for _, rule := range rules {
		if rule.Type == "auth" && rule.Module == "pam_wheel.so" {
			wheel = append(wheel, rule)
		}
	}
	if len(wheel) == 0 {
		return facts.Setting{}, false
	}
	ok, ran := evaluate(rules, "auth", func(rule PAMRule) string {
		switch rule.Module {
		case "pam_rootok.so", "pam_deny.so":
			return "auth_err" // not root; pam_deny always fails
		case "pam_wheel.so":
			if slices.Contains(rule.Args, "deny") {
				return "ignore" // reversed: it only denies members
			}
			return "perm_denied" // trust only changes what members get
		}
		return "success"
	})
	if !ok {
		return facts.Setting{Value: "restricted", Explicit: true, Source: wheel[0].Source}, true
	}
	why := "pam_wheel.so does not deny users outside the group"
	for i, rule := range rules {
		if rule.Type == "auth" && rule.Module == "pam_wheel.so" && !ran[i] {
			why = "pam_wheel.so is not reached: a rule before it ends the stack"
		}
	}
	return facts.Setting{Value: "not restricted: " + why, Explicit: true, Source: wheel[0].Source}, true
}

// hashState says what is known of the hash of new passwords.
type hashState int

const (
	hashNone      hashState = iota // no password rules to speak of (or none that sets a password)
	hashDecided                    // the hash is known
	hashElsewhere                  // password rules exist but pam_unix does not certainly run
)

// passwordHash returns the hash pam_unix uses in the passwd stack: the last
// hash option of the pam_unix rule that changes the password, or else the
// first ENCRYPT_METHOD of /etc/login.defs (pam_unix reads it with
// pam_modutil_search_key). When password rules exist but no pam_unix runs, the
// hash is set elsewhere (hashElsewhere); rules that only deny or permit say
// nothing.
func (r *pamReader) passwordHash(rules []PAMRule) (facts.Setting, hashState) {
	_, ran := evaluate(rules, "password", func(rule PAMRule) string {
		if rule.Module == "pam_deny.so" {
			return "auth_err"
		}
		return "success"
	})
	setters := false // a password rule that runs, other than pam_deny and pam_permit
	for i, rule := range rules {
		if rule.Type != "password" {
			continue
		}
		if ran[i] && rule.Module != "pam_deny.so" && rule.Module != "pam_permit.so" {
			setters = true
		}
		if rule.Module != "pam_unix.so" || !ran[i] {
			continue
		}
		hash := ""
		for _, a := range rule.Args {
			if slices.Contains(pamUnixHashes, a) {
				hash = a
			}
		}
		if hash != "" {
			return facts.Setting{Value: hash, Explicit: true, Source: rule.Source}, hashDecided
		}
		conf := r.searchKeyConf("/etc/login.defs", []string{"ENCRYPT_METHOD"})
		if s, ok := conf["encrypt_method"]; ok {
			s.Value, s.Explicit = strings.ToLower(s.Value), false
			s.Source += " (ENCRYPT_METHOD, read by pam_unix)"
			return s, hashDecided
		}
		return facts.Setting{}, hashNone
	}
	if setters {
		return facts.Setting{}, hashElsewhere
	}
	return facts.Setting{}, hashNone
}

// --- Configuration files ----------------------------------------------------------

// pwqualityLib describes the installed libpwquality.
type pwqualityLib struct {
	options       map[string]bool // the settings it knows
	readsDropIns  bool            // pwquality.conf.d, since 1.3
	defaults      map[string]string
	defaultSource string
}

// pwqualityOptions are the settings libpwquality has had; which ones the
// installed version knows is read from its binary.
var pwqualityOptions = []string{
	"difok", "minlen", "dcredit", "ucredit", "lcredit", "ocredit", "minclass", "maxrepeat", "maxclassrepeat",
	"maxsequence", "gecoscheck", "dictcheck", "usercheck", "usersubstr", "enforcing", "badwords", "dictpath",
	"retry", "enforce_for_root", "local_users_only",
}

// pwqualityLibrary identifies the installed libpwquality from the names in
// its binary: versions from 1.3 read pwquality.conf.d and have "enforcing";
// 1.2 (EL7) has neither and different defaults.
func (r *pamReader) pwqualityLibrary() (pwqualityLib, bool) {
	data, ok := r.findLibrary("libpwquality.so.1")
	if !ok {
		return pwqualityLib{}, false
	}
	lib := pwqualityLib{options: map[string]bool{}}
	for _, o := range pwqualityOptions {
		if regexp.MustCompile(`\b` + o + `\b`).Match(data) {
			lib.options[o] = true
		}
	}
	lib.readsDropIns = bytes.Contains(data, []byte("%s.d"))
	if lib.options["enforcing"] {
		lib.defaults = map[string]string{"minlen": "8", "dcredit": "0", "ucredit": "0", "lcredit": "0", "ocredit": "0", "minclass": "0", "enforcing": "1"}
		lib.defaultSource = "default (pwquality.conf(5), libpwquality 1.3 and later)"
	} else {
		// libpwquality 1.2: minlen 9, each credit 1, and no enforcing setting
		// (it always enforces).
		lib.defaults = map[string]string{"minlen": "9", "dcredit": "1", "ucredit": "1", "lcredit": "1", "ocredit": "1", "minclass": "0", "enforcing": "1"}
		lib.defaultSource = "default (libpwquality 1.2)"
	}
	return lib, true
}

// pwqualityConf reads pwquality.conf.d/*.conf (when this version does) and
// then pwquality.conf, as libpwquality does: later values replace earlier
// ones, names are case-insensitive, and an unknown or invalid setting stops
// the reading there, leaving the rest of that file and the files after it
// unread.
func (r *pamReader) pwqualityConf(lib pwqualityLib) map[string]facts.Setting {
	s := map[string]facts.Setting{}
	var files []string
	if lib.readsDropIns {
		files = r.pwqualityDropIns()
	}
	files = append(files, "/etc/security/pwquality.conf")
	for _, file := range files {
		data, ok := r.readConf(file)
		if !ok {
			continue
		}
		stopped := false
		r.eachConfLine(file, data, func(line int, key, value string) bool {
			key = strings.ToLower(key)
			v, ok := pwqualityValue(lib, key, value)
			if !ok {
				r.notes = append(r.notes, fmt.Sprintf("%s:%d: libpwquality stops reading its configuration at %q", file, line, key))
				stopped = true
				return false
			}
			s[key] = facts.Setting{Value: v, Explicit: true, Source: fmt.Sprintf("%s:%d", file, line)}
			return true
		})
		if stopped {
			break
		}
	}
	return s
}

// pwqualityValue is the value libpwquality's set_name_value stores for key:
// a flag is set whatever its value, a number is read by strtol in base 10
// (so "00" and "+0" are 0) and must fit an int, a string is kept. It is
// false for what libpwquality rejects.
func pwqualityValue(lib pwqualityLib, key, value string) (string, bool) {
	switch {
	case !lib.options[key]:
		return "", false
	case key == "enforce_for_root" || key == "local_users_only":
		return "1", true
	case key == "badwords" || key == "dictpath":
		return value, true
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n >= math.MaxInt32 || n <= math.MinInt32 {
		return "", false
	}
	return strconv.FormatInt(n, 10), true
}

// pwqualityArgs applies pam_pwquality's arguments as it does: the ones the
// module uses itself are skipped, each other one is set as a configuration
// line would be, and one libpwquality rejects is ignored.
func pwqualityArgs(s map[string]facts.Setting, lib pwqualityLib, rule PAMRule) {
	for _, arg := range rule.Args {
		if arg == "debug" || slices.ContainsFunc([]string{"type=", "difignore=", "reject_username", "authtok_type", "use_authtok", "use_first_pass", "try_first_pass"},
			func(prefix string) bool { return strings.HasPrefix(arg, prefix) }) {
			continue
		}
		key, value, _ := strings.Cut(arg, "=")
		key = strings.ToLower(key)
		// Up to libpwquality 1.4.0 the module itself looks for these two flags
		// with a case-sensitive prefix match (any suffix, such as "=0", is
		// ignored); that library has no such settings. Later versions read
		// them as settings below.
		if flag, ok := moduleFlag(arg); ok && !lib.options[flag] {
			s[flag] = facts.Setting{Value: "1", Explicit: true, Source: rule.Source}
			continue
		}
		if v, ok := pwqualityValue(lib, key, value); ok {
			s[key] = facts.Setting{Value: v, Explicit: true, Source: rule.Source}
		}
	}
}

// moduleFlag is the flag pam_pwquality up to 1.4.0 finds in an argument:
// strncmp against the flag's name, so the case must match and a suffix is
// ignored.
func moduleFlag(arg string) (string, bool) {
	for _, flag := range []string{"enforce_for_root", "local_users_only"} {
		if strings.HasPrefix(arg, flag) {
			return flag, true
		}
	}
	return "", false
}

// pwqualityDropIns lists the files libpwquality reads from
// pwquality.conf.d: every name whose first ".conf" ends it, hidden files
// included, in strcmp order (libpwquality 1.4.5 filter_conf).
func (r *pamReader) pwqualityDropIns() []string {
	const dir = "/etc/security/pwquality.conf.d"
	entries, err := r.fsys.ReadDir(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		r.skip(err.Error())
		return nil
	}
	var files []string
	for _, e := range entries {
		name := path.Base(e.Path)
		if i := strings.Index(name, ".conf"); i < 0 || i+len(".conf") != len(name) || e.IsDir() {
			continue
		}
		files = append(files, path.Join(dir, name))
	}
	slices.Sort(files)
	return files
}

// faillockConf reads faillock.conf as pam_faillock does: later values
// replace earlier ones and names are case-sensitive.
func (r *pamReader) faillockConf(file string) map[string]facts.Setting {
	s := map[string]facts.Setting{}
	data, ok := r.readConf(file)
	if !ok {
		return s
	}
	r.eachConfLine(file, data, func(line int, key, value string) bool {
		if value == "" {
			value = "1"
		}
		s[key] = facts.Setting{Value: value, Explicit: true, Source: fmt.Sprintf("%s:%d", file, line)}
		return true
	})
	return s
}

// searchKeyConf reads keys as pam_modutil_search_key does (pwhistory.conf,
// and login.defs for pam_unix): the first line of each key counts and names
// are case-insensitive. Keys are returned lowercased.
func (r *pamReader) searchKeyConf(file string, keys []string) map[string]facts.Setting {
	s := map[string]facts.Setting{}
	data, ok := r.readConf(file)
	if !ok {
		return s
	}
	r.eachConfLine(file, data, func(line int, key, value string) bool {
		key = strings.ToLower(key)
		if _, seen := s[key]; seen || !slices.ContainsFunc(keys, func(k string) bool { return strings.EqualFold(k, key) }) {
			return true
		}
		if value == "" {
			value = "1"
		}
		s[key] = facts.Setting{Value: value, Explicit: true, Source: fmt.Sprintf("%s:%d", file, line)}
		return true
	})
	return s
}

// readConf reads a configuration file; a missing one is empty.
func (r *pamReader) readConf(file string) ([]byte, bool) {
	data, err := r.fsys.ReadFile(file)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, false
	case err != nil:
		r.skip(err.Error())
		return nil, false
	}
	return data, true
}

// eachConfLine calls fn for each setting line: "#" starts a comment
// anywhere, and the key ends at whitespace or "=". fn returns false to stop.
func (r *pamReader) eachConfLine(file string, data []byte, fn func(line int, key, value string) bool) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		text := trimASCII(stripComment(sc.Text()))
		if text == "" {
			continue
		}
		key, value := splitKeyValue(text)
		if !fn(line, key, value) {
			return
		}
	}
	if err := sc.Err(); err != nil {
		r.skip(fmt.Sprintf("%s: %v", file, err))
	}
}

// moduleReads reports whether the installed module's binary contains the
// path conf, i.e. this version reads that file; found is false when no
// readable module file exists.
func (r *pamReader) moduleReads(module, conf string) (reads, found bool) {
	for _, dir := range libDirs {
		if data, ok := r.readLibrary(dir + "/security/" + module); ok {
			return bytes.Contains(data, []byte(conf)), true
		}
	}
	return false, false
}

// findLibrary reads the first copy of a shared library in libDirs.
func (r *pamReader) findLibrary(name string) ([]byte, bool) {
	for _, dir := range libDirs {
		if data, ok := r.readLibrary(dir + "/" + name); ok {
			return data, true
		}
	}
	return nil, false
}

func (r *pamReader) readLibrary(pattern string) ([]byte, bool) {
	candidates := []string{pattern}
	if hostfs.HasMeta(pattern) {
		candidates = r.glob(pattern)
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
		return data, true
	}
	return nil, false
}

// glob expands pattern without hidden files; unreadable directories make the
// facts incomplete.
func (r *pamReader) glob(pattern string) []string {
	matches, problems, err := hostfs.Glob(r.fsys, pattern)
	if err != nil {
		r.skip(err.Error())
		return nil
	}
	for _, p := range problems {
		r.skip(p)
	}
	return slices.DeleteFunc(matches, func(m string) bool { return strings.HasPrefix(path.Base(m), ".") })
}

func hasArg(rule PAMRule, key string) bool {
	for _, a := range rule.Args {
		if k, _, _ := strings.Cut(a, "="); k == key {
			return true
		}
	}
	return false
}

// argValue returns the value of key=value in a rule's arguments.
func argValue(rule PAMRule, key, def string) string {
	for _, a := range rule.Args {
		if k, v, ok := strings.Cut(a, "="); ok && k == key {
			return v
		}
	}
	return def
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
