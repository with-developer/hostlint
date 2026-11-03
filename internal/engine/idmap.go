package engine

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/with-developer/hostlint/internal/hostfs"
)

// idMap resolves user and group names from the target's /etc/passwd and
// /etc/group (only names and IDs are read). The file collector loads it, so
// evaluating file checks does no I/O.
type idMap struct {
	err    error // set when either file could not be read
	users  map[string]int64
	groups map[string]int64
	uids   map[int64]string
	gids   map[int64]string
}

func loadIDMap(fsys hostfs.FS) *idMap {
	m := &idMap{}
	m.users, m.uids, m.err = parseIDs(fsys, "/etc/passwd")
	if m.err == nil {
		m.groups, m.gids, m.err = parseIDs(fsys, "/etc/group")
	}
	return m
}

// parseIDs reads name:x:id lines; only the first and third fields are kept.
func parseIDs(fsys hostfs.FS, path string) (map[string]int64, map[int64]string, error) {
	byName, byID := map[string]int64{}, map[int64]string{}
	data, err := fsys.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return byName, byID, nil
	}
	if err != nil {
		return nil, nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.SplitN(sc.Text(), ":", 4)
		if len(f) < 3 || f[0] == "" || strings.HasPrefix(f[0], "#") {
			continue
		}
		id, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			continue
		}
		if _, dup := byName[f[0]]; !dup {
			byName[f[0]] = id
		}
		if _, dup := byID[id]; !dup {
			byID[id] = f[0]
		}
	}
	return byName, byID, sc.Err()
}

// matches reports whether id is one of the names or numeric IDs in want.
// "root" (and 0) always resolve, even without /etc/passwd.
func (m *idMap) matches(want []string, id int64, group bool) (bool, error) {
	for _, w := range want {
		if n, err := strconv.ParseInt(w, 10, 64); err == nil {
			if n == id {
				return true, nil
			}
			continue
		}
		if w == "root" {
			if id == 0 {
				return true, nil
			}
			continue
		}
		if m.err != nil {
			return false, fmt.Errorf("cannot resolve %q: %w", w, m.err)
		}
		table := m.users
		if group {
			table = m.groups
		}
		if want, ok := table[w]; ok && want == id {
			return true, nil
		}
	}
	return false, nil
}

func (m *idMap) userName(id int64) string  { return m.name(id, false) }
func (m *idMap) groupName(id int64) string { return m.name(id, true) }

func (m *idMap) name(id int64, group bool) string {
	table := m.uids
	if group {
		table = m.gids
	}
	if n, ok := table[id]; ok {
		return n
	}
	if id == 0 {
		return "root"
	}
	return strconv.FormatInt(id, 10)
}
