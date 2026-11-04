package collect

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"reflect"
	"slices"
	"strconv"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// Homes are the `homes` facts: the home directory of every account in
// /etc/passwd and the shell startup files in it. Only metadata is read.
type Homes struct {
	Accounts []Home `json:"accounts"`
}

// Home is one account's home directory.
type Home struct {
	User string `json:"user"`
	UID  int64  `json:"uid"`
	// LoginShell is the account's accounts.login_shell.
	LoginShell bool   `json:"login_shell"`
	Path       string `json:"path"`
	// Exists is false when nothing is at Path (or Path is empty).
	Exists bool `json:"exists"`
	// Owner and Mode describe Path (following a symbolic link) when it exists.
	OwnerUID int64  `json:"owner_uid"`
	Mode     string `json:"mode"` // octal, e.g. "0750"
	// StartupFiles are the shell startup files present in the directory.
	StartupFiles []HomeFile `json:"startup_files"`
}

// HomeFile is one file in a home directory. A symbolic link is described by
// its target.
type HomeFile struct {
	Path string `json:"path"`
	UID  int64  `json:"uid"`
	Mode string `json:"mode"`
	// Dangling is true for a symbolic link whose target does not exist:
	// whoever creates the target controls the file.
	Dangling bool `json:"dangling"`
}

// startupFiles are the per-user shell and session startup files.
var startupFiles = []string{
	".profile", ".bash_profile", ".bash_login", ".bashrc", ".bash_logout",
	".cshrc", ".login", ".logout", ".kshrc", ".zshenv", ".zprofile", ".zshrc", ".zlogin",
	".exrc", ".xinitrc", ".xsession", ".zlogout", ".xprofile", ".tcshrc", ".pam_environment", ".ssh/rc",
}

type homesCollector struct{}

func (homesCollector) Name() string          { return "homes" }
func (homesCollector) Version() int          { return 1 }
func (homesCollector) Access() engine.Access { return engine.AccessFilesystem }
func (homesCollector) Type() reflect.Type    { return reflect.TypeFor[Homes]() }

func (homesCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	var skipped []string
	homes := &Homes{Accounts: []Home{}}
	seen := map[string]Home{} // accounts often share a home (/, /var/empty)
	err := eachRecord(h.FS, "/etc/passwd", 7, func(f []string, _ string) error {
		uid, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			return errMalformed
		}
		home := Home{User: f[0], UID: uid, LoginShell: !noLoginShells[f[6]], Path: f[5], StartupFiles: []HomeFile{}}
		if prev, ok := seen[home.Path]; ok {
			home.Exists, home.OwnerUID, home.Mode, home.StartupFiles = prev.Exists, prev.OwnerUID, prev.Mode, prev.StartupFiles
		} else {
			if err := observeHome(h.FS, &home); err != nil && !slices.Contains(skipped, err.Error()) {
				skipped = append(skipped, err.Error())
			}
			seen[home.Path] = home
		}
		homes.Accounts = append(homes.Accounts, home)
		return nil
	}, &skipped)
	if err != nil {
		return engine.Facts{}, err
	}
	return engine.Facts{Value: homes, Complete: len(skipped) == 0, Skipped: skipped}, nil
}

// observeHome fills in what is at the account's home directory. An error
// means part of it could not be observed.
func observeHome(fsys hostfs.FS, home *Home) error {
	p := path.Clean(home.Path)
	if home.Path == "" || !path.IsAbs(p) {
		return nil // no home directory to look at
	}
	fi, err := fsys.Stat(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if target, ok := hostfs.DanglingLink(fsys, p); ok {
			return fmt.Errorf("%s: symbolic link to %s, which does not exist", p, target)
		}
		return nil
	case err != nil:
		return err
	}
	home.Exists, home.OwnerUID, home.Mode = true, fi.UID, fmt.Sprintf("%04o", fi.Perm())
	if !fi.IsDir() {
		return nil
	}
	for _, name := range startupFiles {
		file := path.Join(p, name)
		if pointsToNull(fsys, file) {
			continue // a blanked file: nothing runs
		}
		f, err := fsys.Stat(file)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if _, ok := hostfs.DanglingLink(fsys, file); ok {
				home.StartupFiles = append(home.StartupFiles, HomeFile{Path: file, Dangling: true})
			}
			continue
		case err != nil:
			return err
		}
		home.StartupFiles = append(home.StartupFiles, HomeFile{Path: file, UID: f.UID, Mode: fmt.Sprintf("%04o", f.Perm())})
	}
	return nil
}

// pointsToNull reports whether file is a symbolic link to /dev/null, the way
// to blank a file that others would otherwise create.
func pointsToNull(fsys hostfs.FS, file string) bool {
	li, err := fsys.Lstat(file)
	if err != nil || !li.IsSymlink() {
		return false
	}
	target, err := fsys.ReadLink(file)
	if err != nil {
		return false
	}
	if !path.IsAbs(target) {
		target = path.Join(path.Dir(file), target)
	}
	return path.Clean(target) == "/dev/null"
}
