package collect

import (
	"context"
	"errors"
	"io/fs"
	"reflect"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// Bind is the `bind` facts: who may transfer and update the zones BIND serves.
// named.conf can hold TSIG keys, so its files are on the denylist and
// hostfs.ReadBindConfig keeps no string from them.
type Bind struct {
	// Present is false when there is no named.conf.
	Present bool `json:"present"`
	// Zones are the primary and secondary zones, with what applies to each.
	Zones []BindZone `json:"zones"`
}

// BindZone is one zone and who may transfer or update it.
type BindZone struct {
	Name string `json:"name"`
	Type string `json:"type"` // primary, master, secondary or slave
	View string `json:"view"` // "" outside a view
	// Transfer is any (everyone may transfer the zone; BIND's default),
	// restricted or none.
	Transfer string `json:"transfer"`
	// Update is any, restricted (addresses, keys or an update-policy) or none
	// (the default).
	Update string `json:"update"`
	// Local is true for the zones every installation defines for the host
	// itself (localhost, 127.in-addr.arpa, ...).
	Local bool   `json:"local"`
	Where string `json:"where"`
}

type bindCollector struct{}

func (bindCollector) Name() string          { return "bind" }
func (bindCollector) Version() int          { return 1 }
func (bindCollector) Access() engine.Access { return engine.AccessFilesystem }
func (bindCollector) Type() reflect.Type    { return reflect.TypeFor[Bind]() }

func (bindCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	cfg, err := hostfs.ReadBindConfig(h.FS)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return engine.Facts{}, errors.New("BIND's configuration cannot be read (run hostlint as root)")
		}
		return engine.Facts{}, err
	}
	b := &Bind{Present: cfg.Present, Zones: []BindZone{}}
	for _, z := range cfg.Zones {
		b.Zones = append(b.Zones, BindZone(z))
	}
	return engine.Facts{Value: b, Complete: len(cfg.Skipped) == 0, Skipped: cfg.Skipped}, nil
}
