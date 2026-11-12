package engine

// Status of a check or control. The set is closed for result schema v1.
type Status string

// Statuses.
const (
	StatusPass          Status = "PASS"
	StatusFail          Status = "FAIL"
	StatusManual        Status = "MANUAL"
	StatusNotApplicable Status = "NOT_APPLICABLE"
	StatusError         Status = "ERROR"
	StatusWaived        Status = "WAIVED"
)

// Statuses lists every status, in aggregation precedence (highest first).
func Statuses() []Status {
	return []Status{StatusFail, StatusError, StatusManual, StatusWaived, StatusPass, StatusNotApplicable}
}

func (s Status) valid() bool { return s.precedence() > 0 }

// precedence ranks statuses for control aggregation (ADR 0006 §7): FAIL >
// ERROR > MANUAL > WAIVED > PASS > NOT_APPLICABLE; 0 for anything else.
func (s Status) precedence() int {
	switch s {
	case StatusFail:
		return 6
	case StatusError:
		return 5
	case StatusManual:
		return 4
	case StatusWaived:
		return 3
	case StatusPass:
		return 2
	case StatusNotApplicable:
		return 1
	}
	return 0
}

// SchemaVersion is the version of the result document.
const SchemaVersion = 1

// Result is the result document (schema/result-v1.schema.json).
type Result struct {
	SchemaVersion int                       `json:"schemaVersion"`
	Scan          ScanInfo                  `json:"scan"`
	Host          HostInfo                  `json:"host"`
	Profiles      []ProfileInfo             `json:"profiles"`
	Summary       map[string]ProfileSummary `json:"summary"`
	Controls      []ControlResult           `json:"controls"`
	Checks        []CheckResult             `json:"checks"`
	Collectors    []CollectorRun            `json:"collectors"`
	// Waivers lists the configured waivers that did not apply (expired,
	// stale, or blocked by an ERROR), so they are not silently ignored.
	Waivers []WaiverNote `json:"waivers,omitempty"`
	// Attestations lists the configured attestations that did not apply
	// (expired, stale, or for a check that is not MANUAL).
	Attestations []AttestationNote `json:"attestations,omitempty"`
}

// ScanInfo describes the scan itself.
type ScanInfo struct {
	ID         string     `json:"id"`
	StartedAt  string     `json:"startedAt"`
	FinishedAt string     `json:"finishedAt"`
	Tool       ToolInfo   `json:"tool"`
	Target     TargetInfo `json:"target"`
	Privileges Privileges `json:"privileges"`
	// Packs are the policy packs the scan used (ADR 0012); absent for a scan of the built-in content.
	Packs []PackInfo `json:"packs,omitempty"`
}

// PackInfo identifies a policy pack in a result: its name and version, and the digest of its files.
type PackInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

// ToolInfo identifies the vmsctl build.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

// TargetInfo says what was scanned.
type TargetInfo struct {
	Kind string `json:"kind"` // host or root
	Root string `json:"root"`
	// Image says which container image a scan of an archive was of (kind stays root, ADR 0011).
	Image *ImageInfo `json:"image,omitempty"`
}

// ImageInfo identifies the image of a scan: the reference it was named with (repository and tag, when the archive names one)
// and its image ID.
type ImageInfo struct {
	Ref    string `json:"ref,omitempty"`
	Digest string `json:"digest"`
}

// Privileges the scan ran with.
type Privileges struct {
	EUID         int64    `json:"euid"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// HostInfo identifies the scanned host.
type HostInfo struct {
	Hostname string            `json:"hostname"`
	HostID   string            `json:"hostId,omitempty"`
	OS       OSInfo            `json:"os"`
	Kernel   string            `json:"kernel,omitempty"`
	Arch     string            `json:"arch,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// OSInfo describes the scanned OS.
type OSInfo struct {
	ID        string `json:"id"`
	VersionID string `json:"versionId,omitempty"`
	Family    string `json:"family"`
	Name      string `json:"name,omitempty"`
	Supported bool   `json:"supported"`
}

// ProfileInfo identifies a profile used by the scan.
type ProfileInfo struct {
	ID       string `json:"id"`
	Revision int    `json:"revision"`
	Digest   string `json:"digest"`
	Title    string `json:"title,omitempty"`
}

// ProfileSummary counts results for one profile.
type ProfileSummary struct {
	Controls   map[Status]int `json:"controls"`
	Checks     map[Status]int `json:"checks,omitempty"`
	Customized int            `json:"customized"`
}

// ControlResult is one control's aggregated result.
type ControlResult struct {
	Profile    string    `json:"profile"`
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	TitleKo    string    `json:"titleKo,omitempty"`
	Severity   Severity  `json:"severity"`
	Status     Status    `json:"status"`
	Reason     string    `json:"reason,omitempty"`
	Customized bool      `json:"customized,omitempty"`
	Checks     []string  `json:"checks"`
	Waiver     *WaiverOf `json:"waiver,omitempty"`
}

// CheckResult is one check's result.
type CheckResult struct {
	Ref            string   `json:"ref"`
	ID             string   `json:"id"`
	Version        int      `json:"version"`
	Digest         string   `json:"digest"`
	Title          string   `json:"title"`
	TitleKo        string   `json:"titleKo,omitempty"`
	Severity       Severity `json:"severity"`
	Status         Status   `json:"status"`
	OriginalStatus Status   `json:"originalStatus,omitempty"`
	StatusSource   string   `json:"statusSource"` // observed or attested
	Reason         string   `json:"reason,omitempty"`
	// ReasonKo is the reason in Korean, for a MANUAL check whose rule has Korean guidance.
	ReasonKo string `json:"reasonKo,omitempty"`
	// Remediation is the check's guidance on fixing a failure: static text of the rule, set for a check that
	// failed (not one that could not be decided: there is nothing to fix yet), so a result says what to do about
	// what it found.
	Remediation     string         `json:"remediation,omitempty"`
	RemediationKo   string         `json:"remediationKo,omitempty"` // the same in Korean, where the rule has it
	Params          map[string]any `json:"params,omitempty"`
	Customized      bool           `json:"customized,omitempty"`
	Evidence        []Evidence     `json:"evidence"`
	EvidenceOmitted int            `json:"evidenceOmitted,omitempty"`
	Coverage        *Coverage      `json:"coverage,omitempty"`
	// EvidenceDigest is the digest of the full value a MANUAL check shows. An
	// attestation is bound to it, so it stops applying when the value changes.
	EvidenceDigest string         `json:"evidenceDigest,omitempty"`
	Waiver         *WaiverOf      `json:"waiver,omitempty"`
	Attestation    *AttestationOf `json:"attestation,omitempty"`
	DurationMs     int64          `json:"durationMs"`

	// shows is true for a MANUAL check with a value to show (not serialized).
	shows bool
}

// Evidence is one observation supporting a result.
type Evidence struct {
	Key    string `json:"key"`
	Text   string `json:"text"`
	Source string `json:"source,omitempty"`
}

// Coverage is the population a violations check looked at.
type Coverage struct {
	Population string `json:"population"`
	Count      int    `json:"count"`
}

// WaiverOf records the waiver applied to a result.
type WaiverOf struct {
	Reason  string `json:"reason"`
	Expires string `json:"expires"`
	Scope   string `json:"scope"` // check or control
	Errors  bool   `json:"errors,omitempty"`
}

// CollectorRun records how one collector ran.
type CollectorRun struct {
	Name       string   `json:"name"`
	Version    int      `json:"version"`
	Access     Access   `json:"access"`
	Status     string   `json:"status"` // ok, error or unavailable
	Complete   bool     `json:"complete"`
	Skipped    []string `json:"skipped,omitempty"`
	Error      string   `json:"error,omitempty"`
	DurationMs int64    `json:"durationMs"`
}
