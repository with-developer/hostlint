package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
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

func (a Attestation) appliesTo(hostname string) bool { return hostMatches(a.Hosts, hostname) }

func (a Attestation) note(problem string) AttestationNote {
	return AttestationNote{Check: a.Check, By: a.By, Expires: a.Expires.Format(dateLayout), Problem: problem}
}

// attestChecks applies attestations to the MANUAL check results, before
// waivers. It returns the attestations that did not apply, or that did not
// cover every instance of their check.
func attestChecks(atts []Attestation, checks map[string]*CheckResult, hostname string, today time.Time) []AttestationNote {
	var notes []AttestationNote
	for _, a := range atts {
		if !a.appliesTo(hostname) {
			continue
		}
		switch {
		case a.Expires.Before(today):
			notes = append(notes, a.note("expired"))
			continue
		case a.At.After(today):
			notes = append(notes, a.note("not applied: dated "+a.At.Format(dateLayout)+", which is in the future"))
			continue
		}
		var problems []string
		matched := false
		for _, ref := range slices.Sorted(maps.Keys(checks)) {
			cr := checks[ref]
			if cr.ID != a.Check {
				continue
			}
			matched = true
			switch {
			case cr.StatusSource == "attested":
				problems = append(problems, "not applied to "+ref+": another attestation already applies")
			case cr.Status != StatusManual:
				problems = append(problems, fmt.Sprintf("not applied to %s: the check is %s, and only a MANUAL result can be attested", ref, cr.Status))
			case cr.Digest != a.Digest:
				problems = append(problems, fmt.Sprintf("stale: the check's logic changed (digest is now %s)", cr.Digest))
			case cr.shows && cr.EvidenceDigest == "":
				problems = append(problems, "not applied to "+ref+": the evidence the check shows is incomplete on this host")
			case cr.shows && a.EvidenceDigest == "":
				problems = append(problems, "stale: the check now shows a value, so the attestation needs its evidence_digest ("+cr.EvidenceDigest+")")
			case !cr.shows && a.EvidenceDigest != "":
				problems = append(problems, "stale: the check no longer shows a value, so the attestation has no evidence to be bound to")
			case cr.shows && cr.EvidenceDigest != a.EvidenceDigest:
				problems = append(problems, fmt.Sprintf("stale: the observed value changed (evidence digest is now %s)", cr.EvidenceDigest))
			default:
				cr.OriginalStatus, cr.Status, cr.StatusSource = StatusManual, a.Status, "attested"
				cr.Attestation = &AttestationOf{Status: a.Status, By: a.By, At: a.At.Format(dateLayout), Expires: a.Expires.Format(dateLayout), Note: a.Note}
				cr.Reason = truncate(fmt.Sprintf("attested %s by %s on %s: %s", a.Status, a.By, a.At.Format(dateLayout), a.Note), maxReasonLen)
				cr.ReasonKo = "" // the Korean guidance of the review is not the reason any more
			}
		}
		switch {
		case !matched:
			notes = append(notes, a.note("not applied: the check is not in the scanned profile"))
		case len(problems) > 0:
			notes = append(notes, a.note(strings.Join(slices.Compact(problems), "; ")))
		}
	}
	return notes
}

// showDigest is the digest of the full value a manual check shows, not the
// truncated evidence: the canonical form of every element, with the source and
// state of a setting. It is false when part of the value is unknown or in error
// (a collector saw only part of the host), so the evidence cannot be attested.
func showDigest(v ref.Val) (string, bool) {
	c, ok := canonical(v)
	if !ok {
		return "", false
	}
	data, err := json.Marshal(c)
	if err != nil {
		panic(fmt.Sprintf("digest: %v", err))
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), true
}

// canonical turns a CEL value into plain data that encodes the same way every
// time: lists in order, maps with sorted keys (encoding/json), settings with
// their value, state and source.
func canonical(v ref.Val) (any, bool) {
	if types.IsUnknown(v) || types.IsError(v) {
		return nil, false
	}
	if s, ok := asSetting(v); ok {
		return map[string]any{"setting": s.Value, "explicit": s.Explicit, "source": s.Source}, true
	}
	if l, ok := v.(traits.Lister); ok {
		n := int(l.Size().(types.Int))
		out := make([]any, 0, n)
		for i := range n {
			item, ok := canonical(l.Get(types.Int(i)))
			if !ok {
				return nil, false
			}
			out = append(out, item)
		}
		return out, true
	}
	if m, ok := v.(traits.Mapper); ok {
		out := map[string]any{}
		for it := m.Iterator(); it.HasNext() == types.True; {
			k := it.Next()
			item, ok := canonical(m.Get(k))
			if !ok {
				return nil, false
			}
			out[fmt.Sprint(k.Value())] = item
		}
		return out, true
	}
	switch x := v.Value().(type) {
	case string, bool, int64, uint64, float64:
		return x, true
	}
	return fmt.Sprintf("%T:%v", v.Value(), v.Value()), true
}
