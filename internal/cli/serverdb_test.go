package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPickDefaultDB(t *testing.T) {
	dir := t.TempDir()
	cur, old := filepath.Join(dir, "vmsctl-server.db"), filepath.Join(dir, "hostlint-server.db")
	touch := func(p string) {
		t.Helper()
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got, note, err := pickDefaultDB(cur, old); err != nil || got != cur || note != "" {
		t.Errorf("neither exists: %q %q %v", got, note, err)
	}
	touch(old)
	if got, note, err := pickDefaultDB(cur, old); err != nil || got != old || !strings.Contains(note, "old name") {
		t.Errorf("only the old one: %q %q %v", got, note, err)
	}
	touch(cur)
	if _, _, err := pickDefaultDB(cur, old); err == nil || !strings.Contains(err.Error(), "choose one with --db") {
		t.Errorf("both exist: %v", err)
	}
	if err := os.Remove(old); err != nil {
		t.Fatal(err)
	}
	if got, note, err := pickDefaultDB(cur, old); err != nil || got != cur || note != "" {
		t.Errorf("only the new one: %q %q %v", got, note, err)
	}
}
