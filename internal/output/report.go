package output

import (
	"bytes"
	"crypto/sha256"
	_ "embed" // report assets
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/with-developer/vmsctl/internal/engine"
)

// maxResultSize bounds one result document read by ReadResult.
const maxResultSize = 64 << 20

//go:embed report/report.css
var reportCSS string

//go:embed report/report.js
var reportJS string

var reportPage = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
{{.CSP}}
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="{{.Tool}}">
<link rel="icon" href="data:,">
<title>{{.Title}}</title>
<style>{{.CSS}}</style>
</head>
<body>
<header class="top"><h1>{{.Title}}</h1><div id="toolbar"></div></header>
<main id="app"><noscript>This report shows its results with JavaScript; please allow it for this file.</noscript></main>
<footer id="footer"></footer>
<script id="report-data" type="application/json">{{.Data}}</script>
<script>{{.JS}}</script>
</body>
</html>
`))

// ReportInput is one result document and the file it was read from.
type ReportInput struct {
	Name   string
	Result *engine.Result
}

// ReportOptions control WriteReport.
type ReportOptions struct {
	Title string    // the report's title; "vmsctl report" when empty
	Tool  string    // the vmsctl version writing the report
	Now   time.Time // when the report is written
}

// ReadResult decodes one result document. Result documents come from the
// hosts that were scanned, so they are untrusted input: the size is bounded,
// the schema version must be one this vmsctl reads, every status must be
// known and every reference must resolve.
func ReadResult(r io.Reader) (*engine.Result, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxResultSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResultSize {
		return nil, fmt.Errorf("larger than %d MiB, not a vmsctl result", maxResultSize>>20)
	}
	var head struct {
		SchemaVersion *int `json:"schemaVersion"`
		Scan          struct {
			Privileges *struct {
				EUID *int `json:"euid"`
			} `json:"privileges"`
		} `json:"scan"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, fmt.Errorf("not a vmsctl result: %w", err)
	}
	switch {
	case head.SchemaVersion == nil:
		return nil, errors.New("not a vmsctl result: no schemaVersion")
	case *head.SchemaVersion != engine.SchemaVersion:
		return nil, fmt.Errorf("result schema version %d is not supported; this vmsctl reads version %d", *head.SchemaVersion, engine.SchemaVersion)
	case head.Scan.Privileges == nil || head.Scan.Privileges.EUID == nil:
		// Without it a missing value would read as root.
		return nil, errors.New("not a vmsctl result: no scan.privileges.euid")
	}
	var res engine.Result
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, fmt.Errorf("not a valid vmsctl result: %w", err)
	}
	if err := checkResult(&res); err != nil {
		return nil, fmt.Errorf("not a valid vmsctl result: %w", err)
	}
	return &res, nil
}

func knownStatus(s engine.Status) bool { return slices.Contains(engine.Statuses(), s) }

// knownSeverity: severities become class names in the page, so only the
// known ones are let through.
func knownSeverity(s engine.Severity) bool {
	return s == engine.SeverityLow || s == engine.SeverityMedium || s == engine.SeverityHigh
}

func checkResult(res *engine.Result) error {
	if res.Host.Hostname == "" {
		return errors.New("no host name")
	}
	// The newest scan of a host is picked by this time: it must be one.
	if _, err := time.Parse(time.RFC3339, res.Scan.StartedAt); err != nil {
		return fmt.Errorf("scan.startedAt %q is not a timestamp", res.Scan.StartedAt)
	}
	profiles := map[string]bool{}
	for _, p := range res.Profiles {
		if profiles[p.ID] {
			return fmt.Errorf("profile %q listed twice", p.ID)
		}
		profiles[p.ID] = true
	}
	checks := map[string]bool{}
	for _, c := range res.Checks {
		switch {
		case checks[c.Ref]:
			return fmt.Errorf("check %q listed twice", c.Ref)
		case !knownStatus(c.Status):
			return fmt.Errorf("check %q: unknown status %q", c.Ref, c.Status)
		case c.OriginalStatus != "" && !knownStatus(c.OriginalStatus):
			return fmt.Errorf("check %q: unknown original status %q", c.Ref, c.OriginalStatus)
		case !knownSeverity(c.Severity):
			return fmt.Errorf("check %q: unknown severity %q", c.Ref, c.Severity)
		}
		checks[c.Ref] = true
	}
	controls := map[string]bool{}
	for _, c := range res.Controls {
		key := c.Profile + "\x00" + c.ID
		switch {
		case !profiles[c.Profile]:
			return fmt.Errorf("control %q: unknown profile %q", c.ID, c.Profile)
		case controls[key]:
			return fmt.Errorf("control %q listed twice", c.ID)
		case !knownStatus(c.Status):
			return fmt.Errorf("control %q: unknown status %q", c.ID, c.Status)
		case !knownSeverity(c.Severity):
			return fmt.Errorf("control %q: unknown severity %q", c.ID, c.Severity)
		}
		controls[key] = true
		for _, ref := range c.Checks {
			if !checks[ref] {
				return fmt.Errorf("control %q: unknown check %q", c.ID, ref)
			}
		}
	}
	return nil
}

// reportData is what the report page renders. Texts that repeat across hosts
// (reasons, evidence) are stored once in Strings and referred to by index;
// index 0 is the empty string.
type reportData struct {
	Title     string          `json:"title"`
	Tool      string          `json:"tool"`
	Generated string          `json:"generated"`
	Files     int             `json:"files"`
	Notes     []string        `json:"notes,omitempty"`
	Profiles  []reportProfile `json:"profiles"`
	Checks    []reportCheck   `json:"checks"`
	Hosts     []reportHost    `json:"hosts"`
	Strings   []string        `json:"strings"`
}

type reportProfile struct {
	ID        string          `json:"id"`
	Title     string          `json:"title,omitempty"`
	Revisions []int           `json:"revisions"`
	Controls  []reportControl `json:"controls"`
}

type reportControl struct {
	ID       string          `json:"id"`
	Title    string          `json:"title"`
	TitleKo  string          `json:"titleKo,omitempty"`
	Severity engine.Severity `json:"severity"`
}

type reportCheck struct {
	Ref      string          `json:"ref"`
	ID       string          `json:"id"`
	Version  int             `json:"version"`
	Title    string          `json:"title"`
	TitleKo  string          `json:"titleKo,omitempty"`
	Severity engine.Severity `json:"severity"`
	Params   map[string]any  `json:"params,omitempty"`
	// Remediation is how to fix a failure of the check, when some host failed it.
	Remediation string `json:"remediation,omitempty"`
	// RemediationKo is the same in Korean, where the rule has it.
	RemediationKo string `json:"remediationKo,omitempty"`
}

type reportHost struct {
	Name      string              `json:"name"`
	File      string              `json:"file"`
	OS        string              `json:"os"`
	Supported bool                `json:"supported"`
	Kernel    string              `json:"kernel,omitempty"`
	Arch      string              `json:"arch,omitempty"`
	Labels    map[string]string   `json:"labels,omitempty"`
	Scanned   string              `json:"scanned"`
	Target    string              `json:"target"`
	Root      bool                `json:"root"`
	Tool      string              `json:"tool"`
	Controls  []reportHostControl `json:"controls"`
	Checks    []reportHostCheck   `json:"checks"`
	Waivers   []engine.WaiverNote `json:"waivers,omitempty"`
	// Attestations are the configured attestations that did not apply.
	Attestations []engine.AttestationNote `json:"attestations,omitempty"`
	Collectors   []reportCollector        `json:"collectors,omitempty"`
}

// reportHostControl is a host's result for one control: p and c index the
// profile and its control, k indexes the host's checks.
type reportHostControl struct {
	Profile    int              `json:"p"`
	Control    int              `json:"c"`
	Status     engine.Status    `json:"s"`
	Reason     int              `json:"r,omitempty"`
	Checks     []int            `json:"k"`
	Waiver     *engine.WaiverOf `json:"w,omitempty"`
	Customized bool             `json:"x,omitempty"`
}

// reportHostCheck is a host's result for one check: c indexes the report's
// checks; evidence is [text, source] string indexes.
type reportHostCheck struct {
	Check    int              `json:"c"`
	Status   engine.Status    `json:"s"`
	Original engine.Status    `json:"o,omitempty"`
	Reason   int              `json:"r,omitempty"`
	Evidence [][2]int         `json:"e,omitempty"`
	Omitted  int              `json:"m,omitempty"`
	Coverage *engine.Coverage `json:"v,omitempty"`
	Waiver   *engine.WaiverOf `json:"w,omitempty"`
	// Attestation is the human verdict behind an attested result.
	Attestation *engine.AttestationOf `json:"a,omitempty"`
}

// reportCollector is a collector that failed or saw only part of the host.
type reportCollector struct {
	Name    string   `json:"name"`
	Status  string   `json:"status"`
	Error   string   `json:"error,omitempty"`
	Skipped []string `json:"skipped,omitempty"`
}

// WriteReport merges result documents into one self-contained HTML page:
// no external requests, the data embedded as JSON and shown by an inline
// script, with a Content-Security-Policy that allows nothing else.
func WriteReport(w io.Writer, inputs []ReportInput, opts ReportOptions) error {
	data, err := buildReport(inputs, opts)
	if err != nil {
		return err
	}
	// json.Marshal escapes <, > and & (and U+2028, U+2029), so the data
	// cannot end the script element it is embedded in.
	js, err := json.Marshal(data)
	if err != nil {
		return err
	}
	csp := fmt.Sprintf(`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src '%s'; script-src '%s'; img-src data:; base-uri 'none'; form-action 'none'">`,
		cspHash(reportCSS), cspHash(reportJS))
	var buf bytes.Buffer
	err = reportPage.Execute(&buf, map[string]any{
		"CSP":   template.HTML(csp), //nolint:gosec // G203: built here from two hashes
		"Title": data.Title,
		"Tool":  data.Tool,
		"CSS":   template.CSS(reportCSS), //nolint:gosec // G203: embedded asset
		"JS":    template.JS(reportJS),   //nolint:gosec // G203: embedded asset
		"Data":  template.JS(js),         //nolint:gosec // G203: JSON with <, >, & escaped
	})
	if err != nil {
		return err
	}
	_, err = w.Write(buf.Bytes())
	return err
}

// WriteReportFile writes the report into the file at path, creating or
// replacing it with mode 0644. The report is built first, so a failure leaves
// an existing file alone.
func WriteReportFile(path string, inputs []ReportInput, opts ReportOptions) error {
	return writeFile(path, func(w io.Writer) error { return WriteReport(w, inputs, opts) })
}

// cspHash is the CSP source expression for an inline element's content.
func cspHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

type reportBuilder struct {
	data     reportData
	strs     map[string]int
	checks   map[string]int // ref and digest → index in data.Checks
	profiles map[string]int // profile ID → index in data.Profiles
	controls []map[string]int
}

func (b *reportBuilder) str(s string) int {
	if s == "" {
		return 0
	}
	if i, ok := b.strs[s]; ok {
		return i
	}
	b.data.Strings = append(b.data.Strings, s)
	b.strs[s] = len(b.data.Strings) - 1
	return len(b.data.Strings) - 1
}

func buildReport(inputs []ReportInput, opts ReportOptions) (*reportData, error) {
	if len(inputs) == 0 {
		return nil, errors.New("no results to report")
	}
	title := opts.Title
	if title == "" {
		title = "vmsctl report"
	}
	b := &reportBuilder{
		data: reportData{
			Title: title, Tool: opts.Tool, Generated: opts.Now.UTC().Format(time.RFC3339),
			Files: len(inputs), Strings: []string{""},
			Profiles: []reportProfile{}, Checks: []reportCheck{}, Hosts: []reportHost{},
		},
		strs:     map[string]int{"": 0},
		checks:   map[string]int{},
		profiles: map[string]int{},
	}
	kept, notes := newestPerHost(inputs)
	notes = append(notes, contentNotes(kept)...)
	b.data.Notes = notes
	b.addProfiles(kept)
	names := map[string]int{}
	for _, in := range kept {
		names[in.Result.Host.Hostname]++
	}
	for _, in := range kept {
		b.addHost(in, names[in.Result.Host.Hostname] > 1)
	}
	return &b.data, nil
}

// newestPerHost keeps the newest result of each host; a host is the same
// when its name, ID, scan target, labels and profiles are.
func newestPerHost(inputs []ReportInput) ([]ReportInput, []string) {
	newest := map[string]int{}
	var order []string
	var notes []string
	for i, in := range inputs {
		id := hostIdentity(in.Result)
		j, seen := newest[id]
		if !seen {
			newest[id] = i
			order = append(order, id)
			continue
		}
		older, newer := inputs[j], in
		// The same time (a result exported twice): the file name decides, so the
		// report does not depend on the order of the arguments.
		if scanTime(in.Result).Before(scanTime(inputs[j].Result)) ||
			scanTime(in.Result).Equal(scanTime(inputs[j].Result)) && in.Name > inputs[j].Name {
			older, newer = in, inputs[j]
		} else {
			newest[id] = i
		}
		notes = append(notes, fmt.Sprintf("%s was scanned more than once; showing %s (%s), not %s (%s)",
			in.Result.Host.Hostname, newer.Name, newer.Result.Scan.StartedAt, older.Name, older.Result.Scan.StartedAt))
	}
	kept := make([]ReportInput, 0, len(order))
	for _, id := range order {
		kept = append(kept, inputs[newest[id]])
	}
	slices.SortStableFunc(kept, func(a, b ReportInput) int {
		if c := naturalCompare(a.Result.Host.Hostname, b.Result.Host.Hostname); c != 0 {
			return c
		}
		return naturalCompare(a.Name, b.Name)
	})
	return kept, notes
}

func hostIdentity(r *engine.Result) string {
	parts := []string{r.Host.Hostname, r.Host.HostID, r.Scan.Target.Kind, r.Scan.Target.Root}
	for _, k := range slices.Sorted(maps.Keys(r.Host.Labels)) {
		parts = append(parts, k+"="+r.Host.Labels[k])
	}
	for _, p := range r.Profiles {
		parts = append(parts, "profile="+p.ID)
	}
	return strings.Join(parts, "\x00")
}

func scanTime(r *engine.Result) time.Time {
	t, _ := time.Parse(time.RFC3339, r.Scan.StartedAt)
	return t
}

// addProfiles lists each profile's controls: in the order of the newest
// revision seen, then controls only older revisions had.
func (b *reportBuilder) addProfiles(inputs []ReportInput) {
	type source struct {
		revision int
		controls []engine.ControlResult
	}
	sources := map[string][]source{}
	var ids []string
	titles := map[string]string{}
	for _, in := range inputs {
		for _, p := range in.Result.Profiles {
			if _, ok := sources[p.ID]; !ok {
				ids = append(ids, p.ID)
			}
			var controls []engine.ControlResult
			for _, c := range in.Result.Controls {
				if c.Profile == p.ID {
					controls = append(controls, c)
				}
			}
			sources[p.ID] = append(sources[p.ID], source{p.Revision, controls})
			if p.Title != "" {
				titles[p.ID] = p.Title
			}
		}
	}
	slices.Sort(ids)
	for _, id := range ids {
		srcs := sources[id]
		slices.SortStableFunc(srcs, func(a, b source) int { return b.revision - a.revision })
		p := reportProfile{ID: id, Title: titles[id], Controls: []reportControl{}}
		index := map[string]int{}
		for _, s := range srcs {
			if !slices.Contains(p.Revisions, s.revision) {
				p.Revisions = append(p.Revisions, s.revision)
			}
			for _, c := range s.controls {
				if _, ok := index[c.ID]; ok {
					continue
				}
				index[c.ID] = len(p.Controls)
				p.Controls = append(p.Controls, reportControl{ID: c.ID, Title: c.Title, TitleKo: c.TitleKo, Severity: c.Severity})
			}
		}
		slices.Sort(p.Revisions)
		b.profiles[id] = len(b.data.Profiles)
		b.data.Profiles = append(b.data.Profiles, p)
		b.controls = append(b.controls, index)
	}
}

func (b *reportBuilder) addHost(in ReportInput, ambiguous bool) {
	r := in.Result
	h := reportHost{
		Name: r.Host.Hostname, File: in.Name, OS: osName(r.Host.OS), Supported: r.Host.OS.Supported,
		Kernel: r.Host.Kernel, Arch: r.Host.Arch, Labels: r.Host.Labels, Scanned: r.Scan.StartedAt,
		Root: r.Scan.Privileges.EUID == 0, Tool: r.Scan.Tool.Version,
		Controls: []reportHostControl{}, Checks: []reportHostCheck{}, Waivers: r.Waivers, Attestations: r.Attestations,
	}
	if ambiguous {
		h.Name += " (" + in.Name + ")"
	}
	h.Target = "running host"
	if r.Scan.Target.Kind == "root" {
		h.Target = "filesystem mounted at " + r.Scan.Target.Root
	}
	checkIndex := map[string]int{}
	for _, c := range r.Checks {
		checkIndex[c.Ref] = len(h.Checks)
		hc := reportHostCheck{
			Check: b.check(c), Status: c.Status, Original: c.OriginalStatus, Reason: b.str(c.Reason),
			Omitted: c.EvidenceOmitted, Coverage: c.Coverage, Waiver: c.Waiver, Attestation: c.Attestation,
		}
		for _, e := range c.Evidence {
			hc.Evidence = append(hc.Evidence, [2]int{b.str(e.Text), b.str(e.Source)})
		}
		h.Checks = append(h.Checks, hc)
	}
	for _, c := range r.Controls {
		p := b.profiles[c.Profile]
		hc := reportHostControl{
			Profile: p, Control: b.controls[p][c.ID], Status: c.Status, Reason: b.str(c.Reason),
			Checks: []int{}, Waiver: c.Waiver, Customized: c.Customized,
		}
		for _, ref := range c.Checks {
			hc.Checks = append(hc.Checks, checkIndex[ref])
		}
		h.Controls = append(h.Controls, hc)
	}
	for _, c := range r.Collectors {
		if c.Status != "ok" || !c.Complete {
			h.Collectors = append(h.Collectors, reportCollector{Name: c.Name, Status: c.Status, Error: c.Error, Skipped: c.Skipped})
		}
	}
	b.data.Hosts = append(b.data.Hosts, h)
}

// check returns the index of c's check in the report, adding it when new.
func (b *reportBuilder) check(c engine.CheckResult) int {
	key := c.Ref + "\x00" + c.Digest
	if i, ok := b.checks[key]; ok {
		if b.data.Checks[i].RemediationKo == "" {
			b.data.Checks[i].RemediationKo = c.RemediationKo
		}
		if b.data.Checks[i].Remediation == "" {
			b.data.Checks[i].Remediation = c.Remediation // the first host to scan it may have passed
		}
		return i
	}
	b.checks[key] = len(b.data.Checks)
	b.data.Checks = append(b.data.Checks, reportCheck{
		Ref: c.Ref, ID: c.ID, Version: c.Version, Title: c.Title, TitleKo: c.TitleKo, Severity: c.Severity, Params: c.Params, Remediation: c.Remediation, RemediationKo: c.RemediationKo,
	})
	return len(b.data.Checks) - 1
}

func osName(o engine.OSInfo) string {
	if o.Name != "" {
		return o.Name
	}
	return strings.TrimSpace(o.ID + " " + o.VersionID)
}

// naturalCompare orders strings with runs of digits compared as numbers, so
// web-9 sorts before web-10.
func naturalCompare(a, b string) int {
	for a != "" && b != "" {
		da, db := digits(a), digits(b)
		if da != "" && db != "" {
			na, nb := strings.TrimLeft(da, "0"), strings.TrimLeft(db, "0")
			if c := len(na) - len(nb); c != 0 {
				return c
			}
			if c := strings.Compare(na, nb); c != 0 {
				return c
			}
			a, b = a[len(da):], b[len(db):]
			continue
		}
		ra, sa := utf8.DecodeRuneInString(a)
		rb, sb := utf8.DecodeRuneInString(b)
		if ra != rb {
			return int(ra) - int(rb)
		}
		a, b = a[sa:], b[sb:]
	}
	return len(a) - len(b)
}

func digits(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

// contentNotes warns when the results of one report were produced with different content: a profile that
// differs in its content, or policy packs that differ, so that a control of one host may not mean the
// same as the control of another.
func contentNotes(inputs []ReportInput) []string {
	variants := map[string]map[string]bool{} // profile ID and revision → digests (a revision change is shown as it is)
	packSets := map[string]bool{}
	for _, in := range inputs {
		for _, p := range in.Result.Profiles {
			key := fmt.Sprintf("%s revision %d", p.ID, p.Revision)
			if variants[key] == nil {
				variants[key] = map[string]bool{}
			}
			variants[key][p.Digest] = true
		}
		packSets[packList(in.Result.Scan.Packs)] = true
	}
	var notes []string
	for _, key := range slices.Sorted(maps.Keys(variants)) {
		if n := len(variants[key]); n > 1 {
			notes = append(notes, fmt.Sprintf("profile %s was scanned with %d different contents (the digests differ): the hosts' controls may not mean the same", oneLine(key), n))
		}
	}
	if len(packSets) > 1 {
		notes = append(notes, "the results used different policy packs: checks and controls of a pack are not comparable with those of another version")
	}
	return notes
}
