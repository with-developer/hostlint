package engine

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/with-developer/vmsctl/internal/hostfs"
)

// idMap resolves user and group names from the target's /etc/passwd and
// /etc/group (only names and IDs are read). The file collector loads it, so
// evaluating file checks does no I/O.
type idMap struct {
	users, groups idTable
}

// idTable is one of the two files. When err is set, names cannot be
// resolved: a missing or unreadable file must not make a name look unused.
type idTable struct {
	err    error
	byName map[string]int64
	byID   map[int64]string
}

func loadIDMap(fsys hostfs.FS) *idMap {
	return &idMap{users: parseIDs(fsys, "/etc/passwd"), groups: parseIDs(fsys, "/etc/group")}
}

// parseIDs reads name:x:id lines; only the first and third fields are kept.
func parseIDs(fsys hostfs.FS, path string) idTable {
	t := idTable{byName: map[string]int64{}, byID: map[int64]string{}}
	data, err := fsys.ReadFile(path)
	if err != nil {
		t.err = err
		return t
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20) // group lines list members
	for sc.Scan() {
		f := strings.SplitN(sc.Text(), ":", 4)
		if len(f) < 3 || f[0] == "" || strings.HasPrefix(f[0], "#") {
			continue
		}
		id, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			continue
		}
		if _, dup := t.byName[f[0]]; !dup {
			t.byName[f[0]] = id
		}
		if _, dup := t.byID[id]; !dup {
			t.byID[id] = f[0]
		}
	}
	if err := sc.Err(); err != nil {
		t.err = fmt.Errorf("%s: %w", path, err)
	}
	return t
}

// problems lists the files that could not be read.
func (m *idMap) problems() []string {
	var out []string
	for _, t := range []idTable{m.users, m.groups} {
		if t.err != nil {
			out = append(out, t.err.Error())
		}
	}
	return out
}

// matches reports whether id is one of the names or numeric IDs in want.
// "root" (and 0) always resolve, even without /etc/passwd.
func (m *idMap) matches(want []string, id int64, group bool) (bool, error) {
	t := m.users
	if group {
		t = m.groups
	}
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
		if t.err != nil {
			return false, fmt.Errorf("cannot resolve %q: %w", w, t.err)
		}
		if v, ok := t.byName[w]; ok && v == id {
			return true, nil
		}
	}
	return false, nil
}

func (m *idMap) userName(id int64) string  { return m.users.name(id) }
func (m *idMap) groupName(id int64) string { return m.groups.name(id) }

func (t idTable) name(id int64) string {
	if n, ok := t.byID[id]; ok {
		return n
	}
	if id == 0 {
		return "root"
	}
	return strconv.FormatInt(id, 10)
}
