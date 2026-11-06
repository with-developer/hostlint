// Package collect holds hostlint's fact collectors (ADR 0006 §2). Every
// collector reads the host only through internal/hostfs.
package collect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// All returns every collector, for engine.New.
func All() []engine.Collector {
	return []engine.Collector{accountsCollector{}, shadowCollector{}, loginDefsCollector{}, sshdCollector{}, snmpCollector{}, postfixCollector{}, bindCollector{}, nfsCollector{}, ftpCollector{}, sambaCollector{}, bannerCollector{}, pamCollector{}, shellEnvCollector{}, packagesCollector{}, servicesCollector{}, socketsCollector{}, filesystemCollector{}, homesCollector{}}
}

// Accounts are the `accounts` facts: /etc/passwd and /etc/group.
type Accounts struct {
	Users  []User  `json:"users"`
	Groups []Group `json:"groups"`
	// DuplicateUIDs are the UIDs shared by more than one account, so a check
	// does not compare every account with every other (it would run out of
	// its evaluation budget on a host with thousands of accounts).
	DuplicateUIDs []SharedUID `json:"duplicate_uids"`
	// EmptyGroups are the groups with no members that are no account's
	// primary group (computed here for the same reason as DuplicateUIDs).
	EmptyGroups []Group `json:"empty_groups"`
}

// SharedUID is a UID that more than one account has.
type SharedUID struct {
	UID   int64    `json:"uid"`
	Users []string `json:"users"` // in /etc/passwd order
	// Sources are the /etc/passwd lines of Users, in the same order.
	Sources []string `json:"sources"`
}

// User is one /etc/passwd entry.
type User struct {
	Name  string `json:"name"`
	UID   int64  `json:"uid"`
	GID   int64  `json:"gid"`
	Home  string `json:"home"`
	Shell string `json:"shell"`
	// LoginShell is false for nologin, false and similar shells. An empty
	// shell field means /bin/sh, so it is a login shell.
	LoginShell bool `json:"login_shell"`
	// Password describes the password field of /etc/passwd itself:
	// "shadowed" ("x"), "empty", "locked" ("*" or "!") or "hash" (a hash
	// stored in the world-readable /etc/passwd). The value is never exposed.
	Password string `json:"password"`
	Source   string `json:"source"`
}

// Group is one /etc/group entry.
type Group struct {
	Name    string   `json:"name"`
	GID     int64    `json:"gid"`
	Members []string `json:"members"`
	Source  string   `json:"source"`
}

// noLoginShells cannot be used to log in interactively.
var noLoginShells = map[string]bool{
	"/sbin/nologin": true, "/usr/sbin/nologin": true, "/bin/false": true, "/usr/bin/false": true,
	"/sbin/shutdown": true, "/sbin/halt": true, "/bin/sync": true, "/usr/bin/sync": true,
}

type accountsCollector struct{}

func (accountsCollector) Name() string          { return "accounts" }
func (accountsCollector) Version() int          { return 1 }
func (accountsCollector) Access() engine.Access { return engine.AccessFilesystem }
func (accountsCollector) Type() reflect.Type    { return reflect.TypeFor[Accounts]() }

func (accountsCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	var skipped []string
	a := &Accounts{Users: []User{}, Groups: []Group{}, DuplicateUIDs: []SharedUID{}, EmptyGroups: []Group{}}
	err := eachRecord(h.FS, "/etc/passwd", 7, func(f []string, src string) error {
		uid, err1 := strconv.ParseInt(f[2], 10, 64)
		gid, err2 := strconv.ParseInt(f[3], 10, 64)
		if err1 != nil || err2 != nil {
			return errMalformed
		}
		a.Users = append(a.Users, User{
			Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6],
			LoginShell: !noLoginShells[f[6]], Password: passwdField(f[1]), Source: src,
		})
		return nil
	}, &skipped)
	if err != nil {
		return engine.Facts{}, err
	}
	err = eachRecord(h.FS, "/etc/group", 4, func(f []string, src string) error {
		gid, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			return errMalformed
		}
		members := []string{}
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				members = append(members, m)
			}
		}
		a.Groups = append(a.Groups, Group{Name: f[0], GID: gid, Members: members, Source: src})
		return nil
	}, &skipped)
	if err != nil {
		return engine.Facts{}, err
	}
	a.DuplicateUIDs = sharedUIDs(a.Users)
	a.EmptyGroups = emptyGroups(a.Users, a.Groups)
	return engine.Facts{Value: a, Complete: len(skipped) == 0, Skipped: skipped}, nil
}

// emptyGroups lists the groups without members that no account has as its
// primary group, in /etc/group order.
func emptyGroups(users []User, groups []Group) []Group {
	primary := map[int64]bool{}
	for _, u := range users {
		primary[u.GID] = true
	}
	out := []Group{}
	for _, g := range groups {
		if len(g.Members) == 0 && !primary[g.GID] {
			out = append(out, g)
		}
	}
	return out
}

// sharedUIDs groups the accounts that share a UID, in order of UID.
func sharedUIDs(users []User) []SharedUID {
	byUID := map[int64][]User{}
	for _, u := range users {
		byUID[u.UID] = append(byUID[u.UID], u)
	}
	out := []SharedUID{}
	for _, uid := range slices.Sorted(maps.Keys(byUID)) {
		group := byUID[uid]
		if len(group) < 2 {
			continue
		}
		s := SharedUID{UID: uid}
		for _, u := range group {
			s.Users = append(s.Users, u.Name)
			s.Sources = append(s.Sources, u.Source)
		}
		out = append(out, s)
	}
	return out
}

// passwdField classifies the password field of /etc/passwd. A hash behind
// a lock marker ("!$6$...") is still a hash anyone can read; short markers
// such as "*", "!!", "NP" or "LK" are not hashes.
func passwdField(s string) string {
	switch s {
	case "x":
		return "shadowed"
	case "":
		return "empty"
	}
	rest := strings.TrimLeft(s, "!*")
	if strings.HasPrefix(rest, "$") && len(rest) > 3 || len(rest) >= 13 {
		return "hash"
	}
	return "locked"
}

var errMalformed = errors.New("malformed entry")

// eachRecord calls fn for every colon-separated record of path, padded with
// empty fields to n, as glibc accepts records without their trailing fields.
// Lines starting with "#" after blanks are comments. Records with fewer
// than three fields are recorded in skipped (never echoed: they may contain
// secrets) so the facts are marked incomplete.
func eachRecord(fsys hostfs.FS, path string, n int, fn func(fields []string, source string) error, skipped *[]string) error {
	data, err := fsys.ReadFile(path)
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimLeft(sc.Text(), " \t")
		if trimASCII(text) == "" || strings.HasPrefix(text, "#") {
			continue
		}
		src := fmt.Sprintf("%s:%d", path, line)
		f := strings.Split(text, ":")
		if len(f) < 3 || f[0] == "" {
			*skipped = append(*skipped, src+": malformed entry")
			continue
		}
		for len(f) < n {
			f = append(f, "")
		}
		if err := fn(f, src); err != nil {
			*skipped = append(*skipped, src+": "+err.Error())
		}
	}
	return sc.Err()
}

// Shadow are the `shadow` facts: the non-secret part of /etc/shadow.
type Shadow struct {
	// Present is false when /etc/shadow does not exist.
	Present bool          `json:"present"`
	Entries []ShadowEntry `json:"entries"`
}

// ShadowEntry is one /etc/shadow line without its hash.
type ShadowEntry struct {
	Name string `json:"name"`
	// State is "set", "locked" or "empty" (no password).
	State string `json:"state"`
	// Algorithm is the hash algorithm (yescrypt, sha512, sha256, bcrypt,
	// md5, des, ...), or "" without a hash.
	Algorithm string `json:"algorithm"`
	// Aging fields in days; -1 when empty.
	LastChange   int64  `json:"last_change"`
	MinDays      int64  `json:"min_days"`
	MaxDays      int64  `json:"max_days"`
	WarnDays     int64  `json:"warn_days"`
	InactiveDays int64  `json:"inactive_days"`
	Expire       int64  `json:"expire"`
	Source       string `json:"source"`
}

type shadowCollector struct{}

func (shadowCollector) Name() string          { return "shadow" }
func (shadowCollector) Version() int          { return 1 }
func (shadowCollector) Access() engine.Access { return engine.AccessFilesystem }
func (shadowCollector) Type() reflect.Type    { return reflect.TypeFor[Shadow]() }

func (shadowCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	entries, err := hostfs.ReadShadow(h.FS)
	if errors.Is(err, fs.ErrNotExist) {
		return engine.Facts{Value: &Shadow{Entries: []ShadowEntry{}}, Complete: true}, nil
	}
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return engine.Facts{}, fmt.Errorf("%w (run hostlint as root)", err)
		}
		return engine.Facts{}, err
	}
	s := &Shadow{Present: true, Entries: make([]ShadowEntry, 0, len(entries))}
	for _, e := range entries {
		s.Entries = append(s.Entries, ShadowEntry{
			Name: e.Name, State: e.State, Algorithm: e.Algorithm,
			LastChange: e.LastChange, MinDays: e.MinDays, MaxDays: e.MaxDays, WarnDays: e.WarnDays,
			InactiveDays: e.InactiveDays, Expire: e.Expire,
			Source: fmt.Sprintf("/etc/shadow:%d", e.Line),
		})
	}
	return engine.Facts{Value: s, Complete: true}, nil
}
