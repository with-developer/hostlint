package output

import (
	"encoding/json"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
)

// SARIF 2.1.0 (OASIS), the subset hostlint emits: one rule per check, one
// result per failing or erroring check, located at the files its evidence
// cites.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name,omitempty"`
	ShortDescription sarifText `json:"shortDescription"`
	// Help is how to fix a failure; code scanning shows it with the alert.
	Help       *sarifText     `json:"help,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
	// Suppressions say that the finding is accepted: every control it belongs to is waived.
	Suppressions []sarifSuppression `json:"suppressions,omitempty"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification"`
}

// maxSarifLocations is the most locations GitHub code scanning takes for a result.
const maxSarifLocations = 10

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func writeSARIF(w io.Writer, res *engine.Result) error {
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name: "hostlint", Version: res.Scan.Tool.Version,
			InformationURI: "https://github.com/with-developer/hostlint",
			Rules:          []sarifRule{},
		}},
		Results: []sarifResult{},
	}
	controls := controlsByCheck(res)
	accepted := waivedByControls(res)
	for i, c := range res.Checks {
		ctls := controls[c.Ref]
		if ctls == nil {
			ctls = []string{}
		}
		rule := sarifRule{
			ID: c.Ref, Name: c.ID, ShortDescription: sarifText{Text: c.Title},
			Properties: map[string]any{"severity": string(c.Severity), "controls": ctls},
		}
		if c.Remediation != "" {
			rule.Help = &sarifText{Text: c.Remediation}
		}
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
		var level string
		switch c.Status {
		case engine.StatusFail:
			level = map[engine.Severity]string{engine.SeverityHigh: "error", engine.SeverityMedium: "warning", engine.SeverityLow: "note"}[c.Severity]
		case engine.StatusError:
			level = "warning"
		default:
			continue
		}
		msg := c.Title
		if c.Status == engine.StatusError {
			msg = "Could not check: " + c.Reason
		} else if len(c.Evidence) > 0 {
			texts := make([]string, 0, len(c.Evidence))
			for _, ev := range c.Evidence {
				texts = append(texts, ev.Text)
			}
			msg += ": " + strings.Join(texts, "; ")
		}
		result := sarifResult{
			RuleID: c.Ref, RuleIndex: i, Level: level, Message: sarifText{Text: msg}, Locations: sarifLocations(c.Evidence),
		}
		if reason, ok := accepted[c.Ref]; ok {
			result.Suppressions = []sarifSuppression{{Kind: "external", Justification: reason}}
		}
		run.Results = append(run.Results, result)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	})
}

// sarifLocations turns evidence sources like "/etc/ssh/sshd_config:32" into
// file locations; sources that are not files are skipped.
func sarifLocations(evidence []engine.Evidence) []sarifLocation {
	var locs []sarifLocation
	seen := map[string]bool{}
	for _, ev := range evidence {
		src := ev.Source
		if !strings.HasPrefix(src, "/") || seen[src] {
			continue
		}
		if len(locs) >= maxSarifLocations {
			break
		}
		seen[src] = true
		file, line := src, 0
		if i := strings.LastIndex(src, ":"); i > 0 {
			if n, err := strconv.Atoi(src[i+1:]); err == nil {
				file, line = src[:i], n
			}
		}
		// A path with a space, "#", "%" or "?" must be escaped to be a URI.
		loc := sarifLocation{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: (&url.URL{Scheme: "file", Path: file}).String()}}}
		if line > 0 {
			loc.PhysicalLocation.Region = &sarifRegion{StartLine: line}
		}
		locs = append(locs, loc)
	}
	return locs
}

// controlsByCheck maps a check ref to "profile:control" IDs that include it.
func controlsByCheck(res *engine.Result) map[string][]string {
	m := map[string][]string{}
	for _, ctl := range res.Controls {
		for _, ref := range ctl.Checks {
			m[ref] = append(m[ref], ctl.Profile+":"+ctl.ID)
		}
	}
	return m
}

// waivedByControls maps a check to the reason of its waiver when every control
// that holds it is waived (a control waiver leaves its checks FAIL).
func waivedByControls(res *engine.Result) map[string]string {
	total, waived := map[string]int{}, map[string]int{}
	reasons := map[string][]string{}
	for _, ctl := range res.Controls {
		for _, ref := range ctl.Checks {
			total[ref]++
			if ctl.Status == engine.StatusWaived && ctl.Waiver != nil {
				waived[ref]++
				if !slices.Contains(reasons[ref], ctl.Waiver.Reason) {
					reasons[ref] = append(reasons[ref], ctl.Waiver.Reason)
				}
			}
		}
	}
	out := map[string]string{}
	for ref, n := range total {
		if n > 0 && waived[ref] == n {
			out[ref] = strings.Join(reasons[ref], "; ")
		}
	}
	return out
}
