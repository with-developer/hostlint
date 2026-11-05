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

// postfixDefaults are the defaults of the parameters the checks read
// (postconf(5)): VRFY is allowed unless disabled.
var postfixDefaults = map[string]string{"disable_vrfy_command": "no"}

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
	return engine.Facts{Value: p, Complete: true}, nil
}

// parsePostfix reads main.cf: "name = value" lines, a line starting with
// white space continues the one before, "#" starts a comment line. It records
// each parameter (the last assignment wins) and returns the macro-expanded
// values of the ones that decide who may relay.
func parsePostfix(data []byte, settings map[string]facts.Setting) map[string]string {
	raw := map[string]string{}
	type entry struct {
		name, value string
		line        int
	}
	var entries []entry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		trimmed := strings.TrimSpace(text)
		switch {
		case trimmed == "" || strings.HasPrefix(trimmed, "#"):
			continue // blank, or a comment line (its first non-blank character is #)
		case (text[0] == ' ' || text[0] == '\t') && len(entries) > 0:
			e := &entries[len(entries)-1]
			e.value = strings.TrimSpace(e.value + " " + trimmed)
			continue
		}
		name, value, ok := strings.Cut(text, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" || strings.ContainsAny(name, " \t") {
			continue
		}
		entries = append(entries, entry{name, strings.TrimSpace(value), line})
	}
	for _, e := range entries {
		raw[e.name] = e.value
		settings[e.name] = facts.Setting{Value: e.value, Explicit: true, Source: fmt.Sprintf("%s:%d", postfixMainCF, e.line)}
	}
	out := map[string]string{}
	for _, name := range []string{"mynetworks", "smtpd_relay_restrictions", "smtpd_recipient_restrictions"} {
		if v, ok := raw[name]; ok {
			out[name] = expandPostfix(v, raw, 5)
		}
	}
	return out
}

var postfixMacro = regexp.MustCompile(`\$(?:\{([a-z_0-9]+)\}|([a-z_0-9]+))`)

// expandPostfix replaces $name and ${name} by the value of a parameter set in
// main.cf; a reference to one that is not set stays as written.
func expandPostfix(v string, raw map[string]string, depth int) string {
	if depth == 0 {
		return v
	}
	return postfixMacro.ReplaceAllStringFunc(v, func(m string) string {
		name := strings.Trim(m, "${}")
		if val, ok := raw[name]; ok {
			return expandPostfix(val, raw, depth-1)
		}
		return m
	})
}

var (
	// mynetworks entries that match every address.
	postfixAnyNetwork = regexp.MustCompile(`(^|[\s,])\[?(0\.0\.0\.0|::|0)\]?/0([\s,]|$)`)
	// A bare "permit" in a restriction list lets everything through at that point.
	postfixPermit = regexp.MustCompile(`(^|[\s,])permit([\s,]|$)`)
	// The restrictions that refuse mail for domains the server is not responsible for.
	postfixGuard = regexp.MustCompile(`(^|[\s,])(reject|defer)_unauth_destination([\s,]|$)`)
)

// postfixRelayProblems says why mail can be relayed by anyone. The defaults
// are safe (Postfix 2.10 and later: smtpd_relay_restrictions ends with
// defer_unauth_destination, and mynetworks is the host or its subnet), so only
// what main.cf sets can make the server an open relay.
func postfixRelayProblems(values map[string]string, settings map[string]facts.Setting) []string {
	problems := []string{}
	if v, ok := values["mynetworks"]; ok && postfixAnyNetwork.MatchString(v) {
		problems = append(problems, fmt.Sprintf("mynetworks trusts every address (%s)", settings["mynetworks"].Source))
	}
	open := func(list string) bool {
		if !postfixPermit.MatchString(list) {
			return false
		}
		// Everything after a guard is only reached by mail for local destinations.
		loc := postfixGuard.FindStringIndex(list)
		perm := postfixPermit.FindStringIndex(list)
		return loc == nil || perm[0] < loc[0]
	}
	relay, hasRelay := values["smtpd_relay_restrictions"]
	rcpt, hasRcpt := values["smtpd_recipient_restrictions"]
	// Both lists apply to a recipient: relaying is open when neither refuses it.
	if (hasRelay && open(relay) && (!hasRcpt || open(rcpt))) || (!hasRelay && hasRcpt && open(rcpt)) {
		which := "smtpd_relay_restrictions"
		if !hasRelay {
			which = "smtpd_recipient_restrictions"
		}
		problems = append(problems, fmt.Sprintf("%s permits mail to any destination (a bare permit with no reject_unauth_destination or defer_unauth_destination before it) (%s)", which, settings[which].Source))
	}
	return problems
}
