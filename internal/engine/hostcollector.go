package engine

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"regexp"
	"runtime"
	"strings"

	"github.com/with-developer/vmsctl/internal/hostfs"
)

// hostCollector reads what identifies the target in the report: its
// hostname and an ID derived from its machine ID. It is bounded like any
// other collector. Rules cannot reference it.
type hostCollector struct{}

// hostFacts is what the host collector observed.
type hostFacts struct {
	Hostname string
	HostID   string
	Arch     string
}

const hostCollectorName = "host"

// hostIDKey derives host IDs; the raw machine ID never leaves the host.
var hostIDKey = []byte("hostlint host id v1")

func (hostCollector) Name() string       { return hostCollectorName }
func (hostCollector) Version() int       { return 1 }
func (hostCollector) Access() Access     { return AccessFilesystem }
func (hostCollector) Type() reflect.Type { return reflect.TypeFor[hostFacts]() }

// machineIDRe is a valid machine ID (machine-id(5)); anything else, such
// as "uninitialized" in an image, identifies nothing.
var machineIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (hostCollector) Collect(_ context.Context, h *hostfs.Host) (Facts, error) {
	hf := &hostFacts{Hostname: h.Hostname()}
	if h.Live {
		hf.Arch = runtime.GOARCH
	}
	if h.Image {
		// Every container of an image shares what is baked into it: that is no host identity (ADR 0011).
		return Facts{Value: hf, Complete: true}, nil
	}
	if data, err := h.FS.ReadFile("/etc/machine-id"); err == nil {
		if id := strings.TrimSpace(string(data)); machineIDRe.MatchString(id) {
			mac := hmac.New(sha256.New, hostIDKey)
			mac.Write([]byte(id))
			hf.HostID = hex.EncodeToString(mac.Sum(nil))[:32]
		}
	}
	return Facts{Value: hf, Complete: true}, nil
}

// hostInfo builds the report's host section; identity fields stay empty
// when the host collector failed.
func hostInfo(c *collected, o hostfs.OS, labels map[string]string) HostInfo {
	hi := HostInfo{
		OS:     OSInfo{ID: o.ID, VersionID: o.VersionID, Family: o.Family, Name: o.Name, Supported: o.Supported},
		Labels: labels,
	}
	if hf, ok := c.facts.Value.(*hostFacts); ok && c.ok() {
		hi.Hostname, hi.HostID, hi.Arch = hf.Hostname, hf.HostID, hf.Arch
	}
	return hi
}
