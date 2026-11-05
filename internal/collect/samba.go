package collect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/hostfs"
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
		return engine.Facts{}, errors.New("smb.conf cannot be read (run hostlint as root)")
	case err != nil:
		return engine.Facts{}, err
	}
	s.Present = true
	skipped := parseSamba(data, s)
	// smbd can be started with another file (-s): other .conf files next to
	// smb.conf may be the ones in use.
	if entries, err := h.FS.ReadDir("/etc/samba"); err == nil {
		for _, e := range entries {
			if e.IsRegular() && strings.HasSuffix(e.Path, ".conf") && e.Path != sambaConfig {
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

// parseSamba reads smb.conf: "[section]" lines and "name = value" lines, with
// ; and # comment lines and a backslash at the end of a line continuing it.
// A guest default in [global] applies to every share that does not say. It
// returns what it could not follow (include files).
func parseSamba(data []byte, s *Samba) (skipped []string) {
	type share struct{ SambaShare }
	var shares []share
	var section string
	globalGuest, globalWhere := false, "" // the default [global] gives the shares that begin after it
	var pending strings.Builder
	start := 0
	handle := func(text string, line int) {
		text = strings.TrimSpace(text)
		switch {
		case text == "" || text[0] == '#' || text[0] == ';':
			return
		case text[0] == '[':
			end := strings.Index(text, "]")
			if end < 0 {
				skipped = append(skipped, fmt.Sprintf("%s:%d: a section without a closing bracket", sambaConfig, line))
				return
			}
			section = strings.TrimSpace(text[1:end])
			low := strings.ToLower(section)
			if low != "global" && low != "printers" {
				// A section named twice is one share: Samba merges them.
				found := false
				for _, sh := range shares {
					found = found || strings.EqualFold(sh.Name, section)
				}
				if !found {
					shares = append(shares, share{
						SambaShare: SambaShare{Name: section, Guest: globalGuest, Where: globalWhere},
					})
					if globalWhere == "" {
						shares[len(shares)-1].Where = fmt.Sprintf("%s:%d", sambaConfig, line)
					}
				}
			}
			return
		}
		name, value, ok := strings.Cut(text, "=")
		if !ok {
			return
		}
		// Samba ignores case and spaces in parameter names ("Guest OK", "guestok").
		key := strings.ToLower(strings.Join(strings.Fields(name), ""))
		switch key {
		case "include", "configfile":
			skipped = append(skipped, fmt.Sprintf("%s:%d: %s is not followed", sambaConfig, line, key))
		case "guestok", "public":
			v, ok := sambaBool(value)
			where := fmt.Sprintf("%s:%d", sambaConfig, line)
			switch {
			case !ok:
				skipped = append(skipped, fmt.Sprintf("%s: %s is not a yes or no value", where, key))
			case strings.EqualFold(section, "global"):
				globalGuest, globalWhere = v, where
			default:
				for i := range shares {
					if strings.EqualFold(shares[i].Name, section) {
						shares[i].Guest, shares[i].Where = v, where
					}
				}
			}
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	line := 0
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
		handle(pending.String(), start)
		pending.Reset()
	}
	if pending.Len() > 0 {
		handle(pending.String(), start)
	}
	if err := sc.Err(); err != nil {
		skipped = append(skipped, fmt.Sprintf("%s:%d: the rest of the file was not read (%v)", sambaConfig, line+1, err))
	}
	for _, sh := range shares {
		s.Shares = append(s.Shares, sh.SambaShare)
	}
	return skipped
}
