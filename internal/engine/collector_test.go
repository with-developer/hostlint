package engine

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/with-developer/vmsctl/internal/hostfs"
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

// A collector that returns complete facts after its time ran out may have stopped early.
func TestFactsOfACollectorThatRanOutOfTimeAreIncomplete(t *testing.T) {
	slow := &fakeCollector{name: "svc", access: AccessFilesystem, complete: true, facts: &svcFacts{Present: true}, delay: 80 * time.Millisecond}
	c := runCollector(context.Background(), slow, hostfs.NewTestHost(demoHost(), nil, false), 20*time.Millisecond)
	if c.err != nil {
		t.Skipf("the collector was cut off with an error: %v", c.err)
	}
	if c.facts.Complete || c.run.Complete {
		t.Errorf("complete %v (run %v), want incomplete: %+v", c.facts.Complete, c.run.Complete, c.facts.Skipped)
	}
}
