package engine

import (
	"context"
	"reflect"

	"github.com/with-developer/hostlint/internal/facts"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// osCollector is the built-in `os` collector; the engine also uses it for
// `platforms`.
type osCollector struct{}

func (osCollector) Name() string       { return "os" }
func (osCollector) Version() int       { return 1 }
func (osCollector) Access() Access     { return AccessFilesystem }
func (osCollector) Type() reflect.Type { return reflect.TypeFor[facts.OS]() }

func (osCollector) Collect(_ context.Context, h *hostfs.Host) (Facts, error) {
	o, err := hostfs.DetectOS(h.FS)
	if err != nil {
		return Facts{}, err
	}
	f := Facts{Value: &facts.OS{
		ID: o.ID, IDLike: o.IDLike, VersionID: o.VersionID, VersionMajor: int64(o.VersionMajor),
		Name: o.Name, Family: o.Family, Supported: o.Supported,
	}, Complete: true}
	if !o.VersionKnown {
		// version_major is 0 here; a check that depends on it must not decide.
		f.Complete = false
		f.Skipped = []string{"the OS version is missing or not numeric (VERSION_ID)"}
	}
	return f, nil
}

func osFromFacts(v any) hostfs.OS {
	f, ok := v.(*facts.OS)
	if !ok {
		return hostfs.OS{ID: hostfs.FamilyUnknown, Family: hostfs.FamilyUnknown}
	}
	return hostfs.OS{
		ID: f.ID, IDLike: f.IDLike, VersionID: f.VersionID, VersionMajor: int(f.VersionMajor),
		Name: f.Name, Family: f.Family, Supported: f.Supported,
	}
}
