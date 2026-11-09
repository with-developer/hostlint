package output

import (
	"encoding/xml"
	"io"
	"strings"

	"github.com/with-developer/vmsctl/internal/engine"
)

// JUnit XML: one test suite per profile, one test case per control.
type junitSuites struct {
	XMLName xml.Name     `xml:"testsuites"`
	Name    string       `xml:"name,attr"`
	Suites  []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Errors   int         `xml:"errors,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	ClassName string        `xml:"classname,attr"`
	Name      string        `xml:"name,attr"`
	Failure   *junitMessage `xml:"failure,omitempty"`
	Error     *junitMessage `xml:"error,omitempty"`
	Skipped   *junitMessage `xml:"skipped,omitempty"`
}

type junitMessage struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

func writeJUnit(w io.Writer, res *engine.Result) error {
	checks := map[string]engine.CheckResult{}
	for _, c := range res.Checks {
		checks[c.Ref] = c
	}
	suites := junitSuites{Name: "vmsctl " + res.Host.Hostname}
	for _, pr := range res.Profiles {
		suite := junitSuite{Name: pr.ID}
		for _, ctl := range res.Controls {
			if ctl.Profile != pr.ID {
				continue
			}
			tc := junitCase{ClassName: pr.ID + "." + res.Host.Hostname, Name: ctl.ID + " " + ctl.Title}
			details := controlDetails(ctl, checks)
			switch ctl.Status {
			case engine.StatusFail:
				tc.Failure = &junitMessage{Message: "FAIL [" + string(ctl.Severity) + "]", Body: details}
				suite.Failures++
			case engine.StatusError:
				tc.Error = &junitMessage{Message: "ERROR: could not check", Body: details}
				suite.Errors++
			case engine.StatusManual, engine.StatusNotApplicable, engine.StatusWaived:
				tc.Skipped = &junitMessage{Message: string(ctl.Status), Body: details}
				suite.Skipped++
			case engine.StatusPass:
			}
			suite.Cases = append(suite.Cases, tc)
			suite.Tests++
		}
		suites.Suites = append(suites.Suites, suite)
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(suites); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// controlDetails lists the non-passing checks of a control with their
// reasons and evidence.
func controlDetails(ctl engine.ControlResult, checks map[string]engine.CheckResult) string {
	var b strings.Builder
	if ctl.Reason != "" {
		b.WriteString(ctl.Reason + "\n")
	}
	for _, ref := range ctl.Checks {
		c := checks[ref]
		if c.Status == engine.StatusPass {
			continue
		}
		b.WriteString(string(c.Status) + " " + c.ID + ": " + c.Title + "\n")
		if c.Reason != "" && c.Status != engine.StatusFail {
			b.WriteString("  " + c.Reason + "\n")
		}
		for _, ev := range c.Evidence {
			b.WriteString("  " + ev.Text)
			if ev.Source != "" {
				b.WriteString(" (" + ev.Source + ")")
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}
