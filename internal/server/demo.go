package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"slices"
	"strings"
	"time"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/output"
	"github.com/with-developer/vmsctl/internal/signing"
)

// demoHost is a made-up host and how its configuration behaves over the two weeks of demo data.
type demoHost struct {
	name, os, family string
	// base is the share of checks that fail at the start, and drift how it changes by the last day
	// (negative: the host gets hardened, positive: it gets worse).
	base, drift float64
	every       int  // a scan every n days
	silent      int  // the last scan was this many days ago
	noRoot      bool // ran without root: some checks cannot read their files (ERROR)
	signs       bool // signs its results with a key
}

var demoFleet = []demoHost{
	{"web-01", "Ubuntu 24.04", "debian", 0.30, -0.20, 1, 0, false, false},
	{"web-02", "Ubuntu 24.04", "debian", 0.30, -0.18, 1, 0, false, false},
	{"web-03", "Ubuntu 22.04", "debian", 0.38, 0.0, 1, 0, false, false},
	{"web-04", "Debian 12", "debian", 0.12, 0.10, 1, 0, false, false}, // was hardened, then drifted
	{"api-01", "Debian 12", "debian", 0.02, 0.0, 1, 0, false, true},
	{"api-02", "Debian 12", "debian", 0.10, 0.0, 2, 0, false, false},
	{"api-03", "Rocky Linux 9", "rhel", 0.22, -0.08, 1, 0, false, false},
	{"db-01", "Rocky Linux 9", "rhel", 0.0, 0.0, 1, 0, false, true}, // nothing fails
	{"db-02", "AlmaLinux 9", "rhel", 0.08, 0.04, 1, 0, false, true},
	{"cache-01", "Amazon Linux 2023", "rhel", 0.35, 0.0, 2, 0, false, false},
	{"batch-01", "CentOS 7", "rhel", 0.55, 0.0, 3, 9, false, false}, // stopped reporting
	{"bastion-01", "Ubuntu 24.04", "debian", 0.15, 0.0, 1, 0, true, false},
}

// SeedDemo fills the store with generated scans of a made-up fleet: fourteen days of history
// for twelve hosts, built from the real controls and checks of the profile. Nothing is scanned.
// It returns how many results it stored.
func SeedDemo(ctx context.Context, store *Store, content *engine.Content, profileID string, now time.Time) (int, error) {
	profile := content.Profiles[profileID]
	if profile == nil {
		return 0, fmt.Errorf("no profile %q", profileID)
	}
	token, id, err := store.CreateCredential(ctx, ScopeIngest, "demo", "", 0)
	if err != nil {
		return 0, err
	}
	_ = token // the demo has no host that sends
	cred := &Credential{ID: id, Scope: ScopeIngest, Name: "demo"}
	realNow := store.now
	defer func() { store.now = realNow }()

	const days = 14
	n := 0
	for _, h := range demoFleet {
		for d := days; d >= 0; d-- {
			if d < h.silent || (days-d)%h.every != 0 {
				continue
			}
			at := now.Add(-time.Duration(d)*24*time.Hour - time.Duration(len(h.name))*7*time.Minute)
			store.now = func() time.Time { return at.Add(3 * time.Minute) }
			res := demoResult(content, profile, h, d, days, at)
			raw, err := json.Marshal(res)
			if err != nil {
				return n, err
			}
			parsed, err := output.ReadResult(bytes.NewReader(raw))
			if err != nil {
				return n, fmt.Errorf("demo result of %s: %w", h.name, err)
			}
			var opts []IngestOption
			if h.signs {
				sig, pub := signing.Sign(ed25519.NewKeyFromSeed(demoSeed(h.name)), raw)
				opts = append(opts, WithSignature(pub, sig))
			}
			if _, err := store.IngestScan(ctx, cred, parsed, raw, "demo", opts...); err != nil {
				return n, fmt.Errorf("demo result of %s: %w", h.name, err)
			}
			n++
		}
	}
	// The images CI built over the same two weeks: one asset each, a tag for every build.
	for _, img := range demoImages {
		for build := range img.builds {
			daysAgo := days - 1 - build*(days-2)/max(1, img.builds-1)
			at := now.Add(-time.Duration(daysAgo)*24*time.Hour - time.Duration(len(img.name))*3*time.Minute)
			store.now = func() time.Time { return at.Add(2 * time.Minute) }
			tag := fmt.Sprintf("%s:1.%d", img.name, build)
			res := demoResult(content, profile, demoHost{name: img.name, os: img.os, family: img.family, base: img.base, drift: img.drift, every: 1}, daysAgo, days, at)
			res.Host.HostID, res.Host.Labels = "", nil
			res.Scan.Target = engine.TargetInfo{Kind: "root", Root: "image:" + tag, Image: &engine.ImageInfo{Ref: tag, Digest: demoImageDigest(tag)}}
			raw, err := json.Marshal(res)
			if err != nil {
				return n, err
			}
			parsed, err := output.ReadResult(bytes.NewReader(raw))
			if err != nil {
				return n, fmt.Errorf("demo result of %s: %w", tag, err)
			}
			if _, err := store.IngestScan(ctx, cred, parsed, raw, "demo"); err != nil {
				return n, fmt.Errorf("demo result of %s: %w", tag, err)
			}
			n++
		}
	}
	return n, nil
}

// demoImage is a made-up image and how its builds behave: each new tag is a bit better (negative drift) or worse.
type demoImage struct {
	name, os, family string
	base, drift      float64
	builds           int
}

var demoImages = []demoImage{
	{"ghcr.io/acme/web", "Debian 12", "debian", 0.34, -0.22, 6},
	{"ghcr.io/acme/api", "Debian 12", "debian", 0.18, -0.10, 5},
	{"ghcr.io/acme/worker", "Alpine Linux 3.20", "alpine", 0.28, 0.0, 4},
}

// demoRand is a number in [0,1) that is the same for the same inputs.
func demoRand(parts ...string) float64 {
	h := fnv.New64a()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return rand.New(rand.NewPCG(h.Sum64(), 0x9e3779b97f4a7c15)).Float64() //nolint:gosec // generated demo data, not a secret
}

func demoResult(content *engine.Content, profile *engine.Profile, h demoHost, daysAgo, days int, at time.Time) *engine.Result {
	progress := float64(days-daysAgo) / float64(days) // 0 at the first scan, 1 at the last
	failRate := h.base + h.drift*progress
	if h.drift > 0 && daysAgo == 0 {
		failRate += 0.12 // a change that made the host worse, in the last scan
	}
	failRate = min(max(failRate, 0), 0.9)
	digest := "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32))
	res := &engine.Result{
		SchemaVersion: engine.SchemaVersion,
		Scan: engine.ScanInfo{
			ID:        fmt.Sprintf("demo-%s-%d", h.name, daysAgo),
			StartedAt: at.UTC().Format(time.RFC3339), FinishedAt: at.Add(4 * time.Second).UTC().Format(time.RFC3339),
			Tool:       engine.ToolInfo{Name: "vmsctl", Version: "demo"},
			Target:     engine.TargetInfo{Kind: "host", Root: "/"},
			Privileges: engine.Privileges{EUID: map[bool]int64{true: 1000, false: 0}[h.noRoot]},
		},
		Host: engine.HostInfo{
			Hostname: h.name, HostID: hex.EncodeToString(fnvSum(h.name)),
			OS:   engine.OSInfo{ID: h.family, Family: h.family, Name: h.os, Supported: true},
			Arch: "amd64", Labels: demoLabels(h.name),
		},
		Profiles: []engine.ProfileInfo{{ID: profile.ID, Revision: profile.Revision, Digest: digest, Title: profile.Title}},
		Summary:  map[string]engine.ProfileSummary{},
	}
	counts := map[engine.Status]int{}
	for _, ctl := range profile.Controls {
		cr := engine.ControlResult{Profile: profile.ID, ID: ctl.ID, Title: ctl.Title, TitleKo: ctl.TitleKo, Severity: ctl.Severity, Checks: []string{}}
		worst := engine.StatusNotApplicable
		mixed := false // some checks are automated, some ask for a person
		for _, id := range ctl.Checks {
			if c := content.Checks[id]; c != nil && c.Manual != nil {
				continue
			}
			mixed = len(ctl.Checks) > 1
		}
		for _, id := range ctl.Checks {
			check := content.Checks[id]
			if check == nil {
				continue
			}
			st := demoCheckStatus(check, ctl.ID, mixed, h, failRate)
			cr.Checks = append(cr.Checks, id)
			cres := engine.CheckResult{
				Ref: id, ID: id, Version: check.Version, Digest: digest, Title: check.Title, TitleKo: check.TitleKo, Severity: check.Severity,
				Status: st, StatusSource: "observed", Reason: demoReason(st),
				Evidence: demoEvidence(st, id), DurationMs: 3,
			}
			if st == engine.StatusFail { // as a real scan does: the rule's own guidance on a failed check
				cres.Remediation = truncate(strings.TrimSpace(check.Remediation), maxRemediation)
			}
			res.Checks = append(res.Checks, cres)
			if rank(st) > rank(worst) {
				worst = st
			}
		}
		cr.Status = worst
		if worst == engine.StatusManual {
			cr.Reason = "Review the listed facts."
		}
		counts[worst]++
		res.Controls = append(res.Controls, cr)
	}
	res.Summary[profile.ID] = engine.ProfileSummary{Controls: counts}
	res.Collectors = []engine.CollectorRun{{Name: "demo", Version: 1, Access: engine.AccessFilesystem, Status: "ok", Complete: true}}
	// Checks a control lists twice (shared) must appear once.
	seen := map[string]bool{}
	res.Checks = slices.DeleteFunc(res.Checks, func(c engine.CheckResult) bool {
		dup := seen[c.Ref]
		seen[c.Ref] = true
		return dup
	})
	return res
}

// demoSeed is a fixed 32-byte seed for a demo host's key, so the demo is the same every time.
func demoSeed(name string) []byte {
	sum := sha256.Sum256([]byte("vmsctl demo key " + name))
	return sum[:]
}

func fnvSum(s string) []byte {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum(nil)
}

// rank orders statuses by how bad they are.
func rank(s engine.Status) int {
	switch s {
	case engine.StatusFail:
		return 5
	case engine.StatusError:
		return 4
	case engine.StatusManual:
		return 3
	case engine.StatusPass:
		return 2
	case engine.StatusNotApplicable, engine.StatusWaived:
		return 1
	}
	return 1
}

// demoCheckStatus picks the status of one check of one host on one day. The draw does not depend on
// the day, only the threshold does, so a check that gets fixed stays fixed.
func demoCheckStatus(check *engine.Check, controlID string, mixed bool, h demoHost, failRate float64) engine.Status {
	if check.Manual != nil {
		// A control that also has automated checks asks for a person only where its `applies`
		// says so: mostly not.
		if mixed && demoRand(h.name, check.ID, "manual") < 0.85 {
			return engine.StatusNotApplicable
		}
		return engine.StatusManual
	}
	draw := demoRand(h.name, controlID, check.ID)
	if h.noRoot && demoRand(h.name, check.ID, "root") < 0.35 {
		return engine.StatusError
	}
	// Service checks do not apply to hosts that do not run the service.
	if len(check.ID) > 9 && check.ID[:9] == "services." && demoRand(h.name, check.ID, "na") < 0.7 {
		return engine.StatusNotApplicable
	}
	if draw < failRate {
		return engine.StatusFail
	}
	return engine.StatusPass
}

func demoReason(st engine.Status) string {
	switch st {
	case engine.StatusError:
		return "not running as root: the file cannot be read (demo data)"
	case engine.StatusManual:
		return "Review the listed facts."
	case engine.StatusPass, engine.StatusFail, engine.StatusNotApplicable, engine.StatusWaived:
		return ""
	}
	return ""
}

func demoEvidence(st engine.Status, id string) []engine.Evidence {
	switch st {
	case engine.StatusFail:
		return []engine.Evidence{{Key: id, Text: "the value does not meet the requirement (demo data)", Source: "/etc/demo.conf:12"}}
	case engine.StatusPass:
		return []engine.Evidence{{Key: id, Text: "the value meets the requirement (demo data)"}}
	case engine.StatusManual, engine.StatusNotApplicable, engine.StatusError, engine.StatusWaived:
		return []engine.Evidence{}
	}
	return []engine.Evidence{}
}

// demoLabels are the labels of a made-up host: its role, from its name, and where it runs.
func demoLabels(name string) map[string]string {
	role, _, _ := strings.Cut(name, "-")
	env := "prod"
	if name == "web-03" || name == "cache-01" {
		env = "staging"
	}
	return map[string]string{"role": role, "env": env}
}

// demoImageDigest is a made-up image ID: the sha256 of the tag, so it is the same on every run.
func demoImageDigest(tag string) string {
	sum := sha256.Sum256([]byte(tag))
	return "sha256:" + hex.EncodeToString(sum[:])
}
