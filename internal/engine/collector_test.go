package engine

import (
	"reflect"
	"testing"
)

type fieldProbe struct {
	Config    map[string]int    `json:"config"`
	Lockout   map[string]string `json:"lockout"`
	Name      string            `json:"name"`
	Nested    struct{ N int }   `json:"nested"`
	Anything  []string          `json:"anything"`
	unexposed int               //nolint:unused // not exported: not a field
}

// A key of a map field is a field path: collectors mark pam.effective.su_wheel
// unknown without losing the rest of the map.
func TestHasFieldThroughMapKeys(t *testing.T) {
	typ := reflect.TypeFor[fieldProbe]()
	for path, want := range map[string]bool{
		"config":          true,
		"config.su_wheel": true,
		"lockout.login":   true,
		"name":            true,
		"name.x":          false,
		"nope":            false,
		"nope.x":          false,
		"nested":          true,
		"anything.x":      false,
	} {
		if got := hasField(typ, path); got != want {
			t.Errorf("hasField(%q) = %v, want %v", path, got, want)
		}
	}
}
