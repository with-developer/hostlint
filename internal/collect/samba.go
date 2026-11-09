package collect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"reflect"
	"strings"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/hostfs"
)

// Samba is the `samba` facts: /etc/samba/smb.conf.
type Samba struct {
	// Present is false when there is no smb.conf.
	Present bool `json:"present"`
	// Shares are the shares ([global] and the special sections are not
	// shares) and whether they allow guests.
	Shares []SambaShare `json:"shares"`
}

// SambaShare is one share.
type SambaShare struct {
	Name string `json:"name"`
	// Guest is true when the share is open to guests ("guest ok = yes" or "public
	// = yes", on the share or as the default [global] had when the share began).
	Guest bool `json:"guest"`
	// Where is the line that opens the share to guests, or the share's own line.
	Where string `json:"where"`
}

type sambaCollector struct{}

func (sambaCollector) Name() string          { return "samba" }
func (sambaCollector) Version() int          { return 1 }
func (sambaCollector) Access() engine.Access { return engine.AccessFilesystem }
func (sambaCollector) Type() reflect.Type    { return reflect.TypeFor[Samba]() }

const sambaConfig = "/etc/samba/smb.conf"

func (sambaCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	s := &Samba{Shares: []SambaShare{}}
	data, err := h.FS.ReadFile(sambaConfig)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return engine.Facts{Value: s, Complete: true}, nil
	case errors.Is(err, fs.ErrPermission):
		return engine.Facts{}, errors.New("smb.conf cannot be read (run vmsctl as root)")
	case err != nil:
		return engine.Facts{}, err
	}
	s.Present = true
	skipped, included := parseSamba(h.FS, data, s)
	// smbd can be started with another file (-s): other .conf files next to
	// smb.conf may be the ones in use.
	if entries, err := h.FS.ReadDir("/etc/samba"); err == nil {
		for _, e := range entries {
			if hostfs.RegularFile(h.FS, e) && strings.HasSuffix(e.Path, ".conf") && e.Path != sambaConfig && !included[e.Path] {
				skipped = append(skipped, fmt.Sprintf("%s: another Samba configuration exists; which one is in use is not seen", e.Path))
			}
		}
	}
	return engine.Facts{Value: s, Complete: len(skipped) == 0, Skipped: skipped}, nil
}

// sambaBool reads a Samba boolean (yes, true, 1, on or no, false, 0, off).
func sambaBool(v string) (value, ok bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true", "1", "on":
		return true, true
	case "no", "false", "0", "off":
		return false, true
	}
	return false, false
}

// sambaParser reads smb.conf and the files it includes.
type sambaParser struct {
	fsys    hostfs.FS
	shares  []SambaShare
	section string
	// the default [global] gives the shares that begin after it
	globalGuest bool
	globalWhere string
	seen        map[string]bool // the files being read: an include of one of them is a cycle
	included    map[string]bool // the files that were read
	files       int
	skipped     []string
}

const sambaMaxFiles = 50

// parseSamba reads smb.conf: "[section]" lines and "name = value" lines, with ; and #
// comment lines and a backslash at the end of a line continuing it. An include
// is read in place (it continues the current section); one that does not exist is
// ignored, as Samba does, one whose name has a % macro cannot be followed.
func parseSamba(fsys hostfs.FS, data []byte, s *Samba) (skipped []string, included map[string]bool) {
	p := &sambaParser{fsys: fsys, seen: map[string]bool{sambaConfig: true}, included: map[string]bool{}}
	p.feed(sambaConfig, data, 0)
	s.Shares = append(s.Shares, p.shares...)
	return p.skipped, p.included
}

func (p *sambaParser) feed(name string, data []byte, depth int) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var pending strings.Builder
	start, line := 0, 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if pending.Len() == 0 {
			start = line
		}
		if cont, ok := strings.CutSuffix(strings.TrimRight(text, " \t\r"), "\\"); ok {
			pending.WriteString(cont + " ")
			continue
		}
		pending.WriteString(text)
		p.handle(name, pending.String(), start, depth)
		pending.Reset()
	}
	if pending.Len() > 0 {
		p.handle(name, pending.String(), start, depth)
	}
	if err := sc.Err(); err != nil {
		p.skipped = append(p.skipped, fmt.Sprintf("%s:%d: the rest of the file was not read (%v)", name, line+1, err))
	}
}

func (p *sambaParser) handle(file, text string, line, depth int) {
	text = strings.TrimSpace(text)
	where := fmt.Sprintf("%s:%d", file, line)
	switch {
	case text == "" || text[0] == '#' || text[0] == ';':
		return
	case text[0] == '[':
		end := strings.Index(text, "]")
		if end < 0 {
			p.skipped = append(p.skipped, where+": a section without a closing bracket")
			return
		}
		p.section = strings.TrimSpace(text[1:end])
		low := strings.ToLower(p.section)
		if low == "global" || low == "printers" {
			return
		}
		// A section named twice is one share: Samba merges them.
		for _, sh := range p.shares {
			if strings.EqualFold(sh.Name, p.section) {
				return
			}
		}
		sh := SambaShare{Name: p.section, Guest: p.globalGuest, Where: p.globalWhere}
		if sh.Where == "" {
			sh.Where = where
		}
		p.shares = append(p.shares, sh)
		return
	}
	name, value, ok := strings.Cut(text, "=")
	if !ok {
		return
	}
	// Samba ignores case and spaces in parameter names ("Guest OK", "guestok").
	key := strings.ToLower(strings.Join(strings.Fields(name), ""))
	switch key {
	case "include":
		p.include(strings.TrimSpace(value), where, depth)
	case "configfile":
		p.skipped = append(p.skipped, fmt.Sprintf("%s: config file is not followed", where))
	case "guestok", "public":
		v, ok := sambaBool(value)
		switch {
		case !ok:
			p.skipped = append(p.skipped, fmt.Sprintf("%s: %s is not a yes or no value", where, key))
		case strings.EqualFold(p.section, "global"):
			p.globalGuest, p.globalWhere = v, where
		default:
			for i := range p.shares {
				if strings.EqualFold(p.shares[i].Name, p.section) {
					p.shares[i].Guest, p.shares[i].Where = v, where
				}
			}
		}
	}
}

func (p *sambaParser) include(file, where string, depth int) {
	file = strings.Trim(file, `"`)
	switch {
	case strings.Contains(file, "%"):
		p.skipped = append(p.skipped, fmt.Sprintf("%s: include %s has a macro and is not followed", where, file))
		return
	case file == "registry":
		p.skipped = append(p.skipped, where+": include = registry is not followed")
		return
	}
	relative := !strings.HasPrefix(file, "/")
	if relative {
		file = "/etc/samba/" + file
	}
	file = path.Clean(file)
	switch {
	case p.seen[file]:
		return // a cycle
	case depth >= 8 || p.files >= sambaMaxFiles:
		p.skipped = append(p.skipped, where+": too many included files")
		return
	}
	data, err := p.fsys.ReadFile(file)
	switch {
	case errors.Is(err, fs.ErrNotExist) && !relative:
		return // Samba ignores a file that is not there
	case errors.Is(err, fs.ErrNotExist):
		// Where Samba looks for a relative name is not known here.
		p.skipped = append(p.skipped, fmt.Sprintf("%s: the relative include %s was not found", where, file))
		return
	case err != nil:
		p.skipped = append(p.skipped, fmt.Sprintf("%s: %v", file, err))
		return
	}
	p.files++
	p.seen[file], p.included[file] = true, true
	p.feed(file, data, depth+1)
	delete(p.seen, file)
}
