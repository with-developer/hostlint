package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// The default database file, and the name it had before the project was renamed (ADR 0017).
const (
	defaultDBPath = "vmsctl-server.db"
	legacyDBPath  = "hostlint-server.db"
)

// pickDefaultDB chooses the database when --db was not given: the default file, unless only the old default
// exists, which is then kept (with a note) rather than replaced by a new empty database. Both existing is an
// error: serving the wrong one would show an empty fleet or old results.
func pickDefaultDB(current, legacy string) (picked, note string, err error) {
	has := func(p string) (bool, error) {
		switch _, err := os.Lstat(p); { //nolint:forbidigo // the server's own database files, not the scanned host
		case err == nil:
			return true, nil
		case errors.Is(err, fs.ErrNotExist):
			return false, nil
		default:
			return false, err
		}
	}
	cur, err := has(current)
	if err != nil {
		return "", "", err
	}
	old, err := has(legacy)
	if err != nil {
		return "", "", err
	}
	switch {
	case cur && old:
		return "", "", fmt.Errorf("both %s and %s exist: choose one with --db", current, legacy)
	case old:
		return legacy, fmt.Sprintf("vmsctl: using %s, the database under its old name: rename it to %s to silence this note", legacy, current), nil
	}
	return current, "", nil
}
