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
	"slices"
	"strings"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/hostfs"
)

// NFS is the `nfs` facts: /etc/exports and /etc/exports.d/*.exports. They
// describe the static exports; an export added by a command at run time is not
// in them.
type NFS struct {
	// Present is true when /etc/exports or a file in /etc/exports.d exists.
	Present bool `json:"present"`
	// Exports has one entry per client of each exported directory.
	Exports []NFSExport `json:"exports"`
}

// NFSExport is one client entry of an exported directory.
type NFSExport struct {
	Path string `json:"path"`
	// Client is the host, network, netgroup or wildcard the entry is for; "*"
	// when the line names none (an export with only options is open to everyone).
	Client string `json:"client"`
	// Everyone is true when the entry applies to every host: "*", or a client
	// list that is only options.
	Everyone bool `json:"everyone"`
	// NoRootSquash is true when the entry lets a remote root act as root.
	NoRootSquash bool `json:"no_root_squash"`
	// Writable is true for rw (read-write is also allowed to be the default of
	// no option: exports are read-only unless rw is given, as in exports(5)).
	Writable bool   `json:"writable"`
	Where    string `json:"where"`
}

type nfsCollector struct{}

func (nfsCollector) Name() string          { return "nfs" }
func (nfsCollector) Version() int          { return 1 }
func (nfsCollector) Access() engine.Access { return engine.AccessFilesystem }
func (nfsCollector) Type() reflect.Type    { return reflect.TypeFor[NFS]() }

const (
	nfsExports    = "/etc/exports"
	nfsExportsDir = "/etc/exports.d"
)

func (nfsCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	n := &NFS{Exports: []NFSExport{}}
	var skipped []string
	files := []string{nfsExports}
	entries, err := h.FS.ReadDir(nfsExportsDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		skipped = append(skipped, fmt.Sprintf("%s: %v", nfsExportsDir, err))
	default:
		for _, e := range entries {
			if e.IsRegular() && strings.HasSuffix(path.Base(e.Path), ".exports") {
				files = append(files, e.Path)
			}
		}
	}
	for _, name := range files {
		data, err := h.FS.ReadFile(name)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			if errors.Is(err, fs.ErrPermission) {
				return engine.Facts{}, fmt.Errorf("%s cannot be read (run hostlint as root)", name)
			}
			return engine.Facts{}, err
		}
		n.Present = true
		skipped = append(skipped, parseExports(name, data, n)...)
	}
	return engine.Facts{Value: n, Complete: len(skipped) == 0, Skipped: skipped}, nil
}

// parseExports reads exports(5): a directory, then clients, each with
// "(options)" glued to it; # starts a comment line, and a backslash continues a line.
func parseExports(name string, data []byte, n *NFS) (problems []string) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var pending strings.Builder
	start := 0
	flush := func() {
		text := strings.TrimSpace(pending.String())
		pending.Reset()
		if text == "" {
			return
		}
		where := fmt.Sprintf("%s:%d", name, start)
		dir, rest, ok := nfsWord(text)
		if !ok || !strings.HasPrefix(dir, "/") {
			problems = append(problems, where+": not an export line")
			return
		}
		clients := strings.Fields(rest)
		if len(clients) == 0 {
			clients = []string{"(ro)"} // no client: the default is every host, read-only (exports(5))
		}
		for _, c := range clients {
			host, opts, hasOpts := strings.Cut(c, "(")
			e := NFSExport{Path: dir, Client: host, Everyone: host == "" || host == "*", Where: where}
			if host == "" {
				e.Client = "*"
			}
			if hasOpts {
				list := strings.Split(strings.TrimSuffix(opts, ")"), ",")
				e.NoRootSquash = slices.Contains(list, "no_root_squash")
				e.Writable = slices.Contains(list, "rw")
			}
			n.Exports = append(n.Exports, e)
		}
	}
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if pending.Len() == 0 {
			if strings.HasPrefix(strings.TrimSpace(text), "#") {
				continue
			}
			start = line
		}
		if cont, ok := strings.CutSuffix(text, "\\"); ok {
			pending.WriteString(cont + " ")
			continue
		}
		pending.WriteString(text)
		flush()
	}
	flush()
	return problems
}

// nfsWord returns the first word of s, which may be quoted ("/a b"), and the rest.
func nfsWord(s string) (word, rest string, ok bool) {
	if strings.HasPrefix(s, `"`) {
		end := strings.Index(s[1:], `"`)
		if end < 0 {
			return "", "", false
		}
		return s[1 : 1+end], s[end+2:], true
	}
	word, rest, _ = strings.Cut(s, " ")
	if i := strings.IndexAny(word, "\t"); i >= 0 {
		word, rest = word[:i], word[i+1:]+" "+rest
	}
	return word, rest, true
}
