package collect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/facts"
	"github.com/with-developer/vmsctl/internal/hostfs"
)

// Postfix is the `postfix` facts: /etc/postfix/main.cf.
type Postfix struct {
	// Present is false when /etc/postfix/main.cf does not exist.
	Present bool `json:"present"`
	// Settings are the parameters set in main.cf (the last assignment wins,
	// as in Postfix) and the defaults of the ones the checks read.
	Settings map[string]facts.Setting `json:"settings"`
	// RelayProblems say why the configuration lets anyone relay mail
	// through the server, one sentence each; empty when it does not.
	RelayProblems []string `json:"relay_problems"`
}

const postfixMainCF = "/etc/postfix/main.cf"

// postfixParams are the only parameters kept: main.cf can hold credentials
// (smtp_sasl_password_maps = static:user:secret), so nothing else leaves the
// parser.
var postfixParams = []string{"disable_vrfy_command", "mynetworks", "smtpd_relay_restrictions", "smtpd_recipient_restrictions"}

// postfixDefaults are the defaults of the parameters the checks read
// (postconf(5)): VRFY is allowed unless disabled.
var postfixDefaults = map[string]string{"disable_vrfy_command": "no"}

const (
	postfixMasterCF  = "/etc/postfix/master.cf"
	postfixMaxExpand = 16 << 10 // bytes of a macro-expanded value
)

type postfixCollector struct{}

func (postfixCollector) Name() string          { return "postfix" }
func (postfixCollector) Version() int          { return 1 }
func (postfixCollector) Access() engine.Access { return engine.AccessFilesystem }
func (postfixCollector) Type() reflect.Type    { return reflect.TypeFor[Postfix]() }

func (postfixCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	p := &Postfix{Settings: map[string]facts.Setting{}, RelayProblems: []string{}}
	data, err := h.FS.ReadFile(postfixMainCF)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return engine.Facts{Value: p, Complete: true}, nil
	case err != nil:
		return engine.Facts{}, err
	}
	p.Present = true
	values := parsePostfix(data, p.Settings)
	for name, def := range postfixDefaults {
		if _, ok := p.Settings[name]; !ok {
			p.Settings[name] = facts.Setting{Value: def, Source: "default (postconf(5))"}
		}
	}
	p.RelayProblems = postfixRelayProblems(values, p.Settings)
	// A "-o name=value" in master.cf overrides main.cf for one service: the
	// checks only read main.cf, so say what they cannot see.
	var skipped []string
	if master, err := h.FS.ReadFile(postfixMasterCF); err == nil {
		skipped = postfixOverrides(master)
	} else if !errors.Is(err, fs.ErrNotExist) {
		skipped = append(skipped, fmt.Sprintf("%s: %v", postfixMasterCF, err))
	}
	return engine.Facts{Value: p, Complete: len(skipped) == 0, Skipped: skipped}, nil
}

// postfixOverrides lists the "-o name=value" options of master.cf that change a
// parameter the checks read.
func postfixOverrides(data []byte) []string {
	var out []string
	var lines []string
	var first []int
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		text := sc.Text()
		trimmed := strings.TrimSpace(text)
		switch {
		case trimmed == "" || strings.HasPrefix(trimmed, "#"):
			continue
		case (text[0] == ' ' || text[0] == '\t') && len(lines) > 0:
			lines[len(lines)-1] += " " + trimmed
		default:
			lines = append(lines, trimmed)
			first = append(first, n)
		}
	}
	for i, l := range lines {
		f := strings.Fields(l)
		for j := 0; j+1 < len(f); j++ {
			if f[j] != "-o" {
				continue
			}
			name, _, _ := strings.Cut(f[j+1], "=")
			if slices.Contains(postfixParams, name) {
				out = append(out, fmt.Sprintf("%s:%d: the %s service overrides %s", postfixMasterCF, first[i], f[0], name))
			}
		}
	}
	return out
}

// parsePostfix reads main.cf: "name = value" lines, a line starting with
// white space continues the one before, a line whose first non-blank character
// is "#" is a comment. It records the parameters the checks read (the last
// assignment wins) and returns the macro-expanded values of the ones that
// decide who may relay.
func parsePostfix(data []byte, settings map[string]facts.Setting) map[string]string {
	raw := map[string]string{}
	type entry struct {
		name, value string
		line        int
	}
	var entries []entry
	continues := false // the line before was an assignment
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		trimmed := strings.TrimSpace(text)
		switch {
		case trimmed == "" || strings.HasPrefix(trimmed, "#"):
			continue // blank, or a comment line
		case (text[0] == ' ' || text[0] == '\t') && continues:
			e := &entries[len(entries)-1]
			e.value = strings.TrimSpace(e.value + " " + trimmed)
			continue
		}
		name, value, ok := strings.Cut(text, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" || strings.ContainsAny(name, " \t") {
			continues = false // a line that is no assignment ends the one before
			continue
		}
		entries = append(entries, entry{name, strings.TrimSpace(value), line})
		continues = true
	}
	for _, e := range entries {
		raw[e.name] = e.value
		if slices.Contains(postfixParams, e.name) {
			settings[e.name] = facts.Setting{Value: e.value, Explicit: true, Source: fmt.Sprintf("%s:%d", postfixMainCF, e.line)}
		}
	}
	if v, ok := settings["disable_vrfy_command"]; ok {
		v.Value = postfixBool(expandPostfix(v.Value, raw))
		settings["disable_vrfy_command"] = v
	}
	out := map[string]string{}
	for _, name := range []string{"mynetworks", "smtpd_relay_restrictions", "smtpd_recipient_restrictions"} {
		if v, ok := raw[name]; ok {
			out[name] = expandPostfix(v, raw)
		}
	}
	return out
}

// postfixBool normalizes a Postfix boolean (yes, no, on, off, true, false, 1, 0,
// in any case) to yes or no; anything else is left as it is.
func postfixBool(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "on", "true", "1":
		return "yes"
	case "no", "off", "false", "0":
		return "no"
	}
	return v
}

var postfixMacro = regexp.MustCompile(`\$(?:\{([a-z_0-9]+)\}|([a-z_0-9]+))`)

// expandPostfix replaces $name and ${name} by the value of a parameter set in
// main.cf; a reference to one that is not set stays as written. The result is
// bounded: a value that refers to itself stops growing at postfixMaxExpand.
func expandPostfix(v string, raw map[string]string) string {
	budget := postfixMaxExpand
	var expand func(string, int) string
	expand = func(v string, depth int) string {
		if depth == 0 || budget <= 0 {
			return v
		}
		return postfixMacro.ReplaceAllStringFunc(v, func(m string) string {
			name := strings.Trim(m, "${}")
			val, ok := raw[name]
			if !ok || budget <= 0 {
				return m
			}
			budget -= len(val)
			return expand(val, depth-1)
		})
	}
	return expand(v, 5)
}

// postfixList splits a restriction or network list at white space and commas.
func postfixList(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' })
}

// postfixTrustsEverything reports whether mynetworks has an entry with a
// prefix length of 0, which matches every address ("!" entries exclude).
func postfixTrustsEverything(v string) bool {
	for _, tok := range postfixList(v) {
		if strings.HasPrefix(tok, "!") {
			continue
		}
		if addr, ok := strings.CutSuffix(strings.NewReplacer("[", "", "]", "").Replace(tok), "/0"); ok && (addr == "0" || net.ParseIP(addr) != nil) {
			return true
		}
	}
	return false
}

// postfixListOpen reports whether a restriction list lets mail for any
// destination through. Restrictions are tried in order; a list that reaches its
// end without a decision permits (the implicit default), so only a refusal of
// unauthorized destinations (reject_unauth_destination, defer_unauth_destination)
// or a bare reject or defer first makes it safe, and a bare permit first opens it.
func postfixListOpen(list string) bool {
	for _, tok := range postfixList(list) {
		switch strings.ToLower(tok) {
		case "reject_unauth_destination", "defer_unauth_destination", "reject", "defer", "reject_all", "defer_all":
			return false
		case "permit":
			return true
		}
	}
	return true
}

// postfixRelayProblems says why mail can be relayed by anyone. The defaults
// are safe (Postfix 2.10 and later: smtpd_relay_restrictions ends with
// defer_unauth_destination, and mynetworks is the host or its subnet), so only
// what main.cf sets can make the server an open relay.
func postfixRelayProblems(values map[string]string, settings map[string]facts.Setting) []string {
	problems := []string{}
	if v, ok := values["mynetworks"]; ok && postfixTrustsEverything(v) {
		problems = append(problems, fmt.Sprintf("mynetworks trusts every address (%s)", settings["mynetworks"].Source))
	}
	// Both lists apply to a recipient, the relay list first: a recipient is
	// relayed for anyone when neither refuses it. Without its own relay list
	// Postfix uses the safe default, which no recipient list can open.
	relay, hasRelay := values["smtpd_relay_restrictions"]
	rcpt, hasRcpt := values["smtpd_recipient_restrictions"]
	if hasRelay && postfixListOpen(relay) && (!hasRcpt || postfixListOpen(rcpt)) {
		problems = append(problems, fmt.Sprintf("smtpd_relay_restrictions lets mail for any destination through (no reject_unauth_destination or defer_unauth_destination before a permit or the end of the list) (%s)", settings["smtpd_relay_restrictions"].Source))
	}
	return problems
}
