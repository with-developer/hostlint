package output

import (
	"encoding/json"
	"io"
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
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifText      `json:"shortDescription"`
	Properties       map[string]any `json:"properties,omitempty"`
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
}

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
	for i, c := range res.Checks {
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
			ID: c.Ref, Name: c.ID, ShortDescription: sarifText{Text: c.Title},
			Properties: map[string]any{"severity": string(c.Severity), "controls": controls[c.Ref]},
		})
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
		run.Results = append(run.Results, sarifResult{
			RuleID: c.Ref, RuleIndex: i, Level: level, Message: sarifText{Text: msg}, Locations: sarifLocations(c.Evidence),
		})
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
		seen[src] = true
		loc := sarifLocation{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: "file://" + src}}}
		if i := strings.LastIndex(src, ":"); i > 0 {
			if line, err := strconv.Atoi(src[i+1:]); err == nil {
				loc.PhysicalLocation.ArtifactLocation.URI = "file://" + src[:i]
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: line}
			}
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
