package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"path"
	"slices"
	"time"

	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
)

// Attestation is a human verdict for a MANUAL check (ADR 0006 §6): PASS or
// FAIL, by whom and when. It is bound to the check's logic digest and to the
// digest of the full value the check shows, so it stops applying when either
// changes, and it never applies to a result that is not MANUAL.
type Attestation struct {
	Check  string
	Status Status // PASS or FAIL
	// Digest is the check's logic digest (CheckResult.Digest).
	Digest string
	// EvidenceDigest is the digest of the full value the check shows
	// (CheckResult.EvidenceDigest); empty for a check with nothing to show,
	// which can be attested only until the attestation expires.
	EvidenceDigest string
	By             string
	At             time.Time
	// Expires is the last day the attestation applies (a date, UTC).
	Expires time.Time
	Note    string
	// Hosts are hostname globs; empty means every host.
	Hosts []string
}

// AttestationNote is an attestation that did not apply, with why.
type AttestationNote struct {
	Check   string `json:"check"`
	By      string `json:"by"`
	Expires string `json:"expires"`
	Problem string `json:"problem"`
}

// AttestationOf records the attestation applied to a result.
type AttestationOf struct {
	Status  Status `json:"status"`
	By      string `json:"by"`
	At      string `json:"at"`
	Expires string `json:"expires"`
	Note    string `json:"note,omitempty"`
}

func (a Attestation) appliesTo(hostname string) bool {
	if len(a.Hosts) == 0 {
		return true
	}
	return slices.ContainsFunc(a.Hosts, func(glob string) bool {
		ok, _ := path.Match(glob, hostname)
		return ok
	})
}

func (a Attestation) note(problem string) AttestationNote {
	return AttestationNote{Check: a.Check, By: a.By, Expires: a.Expires.Format(dateLayout), Problem: problem}
}

// attestChecks applies attestations to the MANUAL check results, before
// waivers. It returns the attestations that did not apply.
func attestChecks(atts []Attestation, checks map[string]*CheckResult, shows func(id string) bool, hostname string, today time.Time) []AttestationNote {
	var notes []AttestationNote
	for _, a := range atts {
		if !a.appliesTo(hostname) {
			continue
		}
		if a.Expires.Before(today) {
			notes = append(notes, a.note("expired"))
			continue
		}
		applied, problem := false, ""
		for _, ref := range slices.Sorted(maps.Keys(checks)) {
			cr := checks[ref]
			if cr.ID != a.Check {
				continue
			}
			switch {
			case cr.StatusSource == "attested":
				problem = "not applied: another attestation already applies"
			case cr.Status != StatusManual:
				problem = fmt.Sprintf("not applied: the check is %s, and only a MANUAL result can be attested", cr.Status)
			case cr.Digest != a.Digest:
				problem = fmt.Sprintf("stale: the check's logic changed (digest is now %s)", cr.Digest)
			case shows(cr.ID) && cr.EvidenceDigest == "":
				problem = "not applied: the evidence the check shows is incomplete on this host"
			case shows(cr.ID) && cr.EvidenceDigest != a.EvidenceDigest:
				problem = fmt.Sprintf("stale: the observed value changed (evidence digest is now %s)", cr.EvidenceDigest)
			default:
				cr.OriginalStatus, cr.Status, cr.StatusSource = StatusManual, a.Status, "attested"
				cr.Attestation = &AttestationOf{Status: a.Status, By: a.By, At: a.At.Format(dateLayout), Expires: a.Expires.Format(dateLayout), Note: a.Note}
				cr.Reason = truncate(fmt.Sprintf("attested %s by %s on %s: %s", a.Status, a.By, a.At.Format(dateLayout), a.Note), maxReasonLen)
				applied = true
			}
		}
		if !applied {
			if problem == "" {
				problem = "not applied: the check is not in the scanned profile"
			}
			notes = append(notes, a.note(problem))
		}
	}
	return notes
}

// showDigest is the digest of the full value a manual check shows: its
// elements as text, in order, not the truncated evidence.
func showDigest(v ref.Val) string {
	var items []string
	if l, ok := v.(traits.Lister); ok {
		n := int(l.Size().(types.Int))
		items = make([]string, 0, n)
		for i := range n {
			item := l.Get(types.Int(i))
			text, ok := item.Value().(string)
			if !ok {
				text = render(item)
			}
			items = append(items, text)
		}
	} else {
		items = []string{render(v)}
	}
	data, err := json.Marshal(items)
	if err != nil {
		panic(fmt.Sprintf("digest: %v", err))
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
