package collect

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"reflect"
	"slices"
	"strings"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/hostfs"
)

// Services are the `services` facts: which services are set up to start,
// read from the files that decide it (unit files and their links, SysV init
// links, inetd and xinetd configuration), so they are the same under --root;
// and, on a live target, which systemd units are active.
//
// Known gaps: units started only through Wants= or Requires= in other unit
// files or drop-ins, and units that presets enable on a golden image's first
// boot, do not show as enabled. On a live target, Active shows them if they
// run.
type Services struct {
	// Systemd is true when the target has systemd unit directories.
	Systemd bool `json:"systemd"`
	// Active maps each unit systemd reports as active (or activating,
	// reloading, ...) to its sub-state, such as "running", "listening" or
	// "exited", on a live target. It is empty under --root and when systemd
	// is not running; when systemd runs but cannot be asked, it is unknown.
	Active map[string]string `json:"active"`
	// Units maps a systemd unit name (ssh.service, telnet.socket,
	// getty@tty1.service) to how it is set up. Every unit with a file or an
	// enabling link is listed.
	Units map[string]Unit `json:"units"`
	// SysV maps an /etc/init.d script to whether a boot runlevel starts it.
	// systemd runs such scripts too, unless a unit of the same name exists.
	SysV map[string]SysVScript `json:"sysv"`
	// Inetd lists the services /etc/inetd.conf starts (commented-out lines
	// are not services).
	Inetd []InetdService `json:"inetd"`
	// Xinetd lists the services of /etc/xinetd.conf and /etc/xinetd.d,
	// enabled or not.
	Xinetd []XinetdService `json:"xinetd"`
	// Started lists everything above that starts a service: enabled units
	// that are not masked, active units (live), enabled SysV scripts without
	// a unit of the same name, inetd lines and enabled xinetd services.
	// Checks for a service match it by name or program. It is partial when
	// the active units are unknown.
	Started []StartedService `json:"started"`
}

// StartedService is one way a service is started.
type StartedService struct {
	// Service is the service's name without unit type or instance:
	// "telnet" for telnet.socket, telnet@.service or an inetd telnet line.
	Service string `json:"service"`
	// Name is the unit, script or inetd/xinetd service name.
	Name string `json:"name"`
	Kind string `json:"kind"` // unit, active, sysv, inetd or xinetd
	// Program is the path of the program it runs, when known.
	Program string `json:"program"`
	Source  string `json:"source"`
}

// Unit is how one systemd unit is set up.
type Unit struct {
	// Enabled is true when a .wants or .requires directory links to the
	// unit, so it starts with the unit that wants it (at boot, for the
	// usual targets).
	Enabled bool `json:"enabled"`
	// Masked is true when the unit is linked to /dev/null or empty: it
	// cannot start, enabled or not.
	Masked bool `json:"masked"`
	// File is the unit file systemd loads (a template's for an instance),
	// "" when there is none.
	File string `json:"file"`
	// AliasOf names the unit this name is an alias of, if it is one.
	AliasOf string `json:"alias_of"`
	// Exec is the program of a service's first ExecStart= line in its unit
	// file (drop-ins are not read), so a renamed unit is still recognized.
	Exec string `json:"exec"`
	// Source is the link that enables the unit, else its file.
	Source string `json:"source"`
}

// SysVScript is one /etc/init.d script.
type SysVScript struct {
	// Enabled is true when an S link in /etc/rc[2-5S].d (or /etc/rc.d/rc[2-5].d)
	// starts it.
	Enabled bool   `json:"enabled"`
	Source  string `json:"source"`
}

// InetdService is one active line of /etc/inetd.conf or /etc/inetd.d.
type InetdService struct {
	Name       string `json:"name"`
	SocketType string `json:"socket_type"`
	Protocol   string `json:"protocol"`
	User       string `json:"user"`
	Server     string `json:"server"`
	Args       string `json:"args"`
	Source     string `json:"source"`
}

// XinetdService is one service section of the xinetd configuration.
type XinetdService struct {
	Name string `json:"name"`
	// Disabled is true when the service says disable = yes, or the defaults
	// section disables it (its disabled list, or an enabled list without it).
	Disabled bool `json:"disabled"`
	// Settings are the section's other attributes (socket_type, protocol,
	// user, server, only_from, ...), with += values appended.
	Settings map[string]string `json:"settings"`
	Source   string            `json:"source"`
}

// unitDirs are the unit search path, highest precedence first.
var unitDirs = []string{"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}

var unitSuffixes = []string{".service", ".socket", ".target", ".timer", ".path", ".mount", ".automount", ".swap", ".slice", ".scope", ".device"}

// rcDirs hold the SysV start links of the boot runlevels.
var rcDirs = []string{
	"/etc/rcS.d", "/etc/rc2.d", "/etc/rc3.d", "/etc/rc4.d", "/etc/rc5.d",
	"/etc/rc.d/rc2.d", "/etc/rc.d/rc3.d", "/etc/rc.d/rc4.d", "/etc/rc.d/rc5.d",
}

const (
	inetdConf  = "/etc/inetd.conf"
	inetdDir   = "/etc/inetd.d" // read by inetutils-inetd
	xinetdConf = "/etc/xinetd.conf"
)

type servicesCollector struct{}

func (servicesCollector) Name() string          { return "services" }
func (servicesCollector) Version() int          { return 1 }
func (servicesCollector) Access() engine.Access { return engine.AccessFilesystem }
func (servicesCollector) Type() reflect.Type    { return reflect.TypeFor[Services]() }

func (servicesCollector) Collect(ctx context.Context, h *hostfs.Host) (engine.Facts, error) {
	r := &serviceReader{fsys: h.FS}
	s := &Services{Units: r.units(), SysV: r.sysv(), Inetd: r.inetd(), Xinetd: r.xinetd(), Active: map[string]string{}}
	s.Systemd = r.systemd
	f := engine.Facts{Value: s, Complete: len(r.skipped) == 0, Skipped: r.skipped}
	if err := s.readActive(ctx, h); err != nil {
		// Without the active units, a running service can hide.
		f.Unknown, f.Partial, f.Skipped = []string{"active"}, []string{"started"}, append(f.Skipped, err.Error())
	}
	s.Started = s.started()
	return f, nil
}

// readActive fills Active on a live target running systemd (sd_booted(3):
// /run/systemd/system exists).
func (s *Services) readActive(ctx context.Context, h *hostfs.Host) error {
	if !h.Live {
		return nil
	}
	switch _, err := h.FS.Stat("/run/systemd/system"); {
	case errors.Is(err, fs.ErrNotExist):
		return nil // nothing is active as a systemd unit
	case err != nil:
		return err
	}
	active, err := systemdActive(ctx, h)
	if err != nil {
		return err
	}
	s.Active = active
	return nil
}

// started lists how services are started; see Services.Started.
func (s *Services) started() []StartedService {
	out := []StartedService{}
	for _, name := range slices.Sorted(maps.Keys(s.Units)) {
		if u := s.Units[name]; u.Enabled && !u.Masked {
			out = append(out, StartedService{Service: serviceName(name), Name: name, Kind: "unit", Program: s.program(name), Source: u.Source})
		}
	}
	for _, name := range slices.Sorted(maps.Keys(s.Active)) {
		out = append(out, StartedService{Service: serviceName(name), Name: name, Kind: "active", Program: s.program(name), Source: "systemctl list-units"})
	}
	for _, name := range slices.Sorted(maps.Keys(s.SysV)) {
		// systemd ignores a script when a unit of the same name exists.
		if sv := s.SysV[name]; sv.Enabled && s.Units[name+".service"].Source == "" {
			out = append(out, StartedService{Service: name, Name: name, Kind: "sysv", Source: sv.Source})
		}
	}
	for _, svc := range s.Inetd {
		out = append(out, StartedService{Service: svc.Name, Name: svc.Name, Kind: "inetd", Program: inetdProgram(svc.Server, svc.Args), Source: svc.Source})
	}
	for _, svc := range s.Xinetd {
		if !svc.Disabled {
			out = append(out, StartedService{Service: svc.Name, Name: svc.Name, Kind: "xinetd", Program: inetdProgram(svc.Settings["server"], svc.Settings["server_args"]), Source: svc.Source})
		}
	}
	return out
}

// program returns the program a unit runs: its own ExecStart, its alias
// target's, its template's, or for a socket, path or timer unit the service
// it activates.
func (s *Services) program(name string) string {
	if a := s.Units[name].AliasOf; a != "" {
		name = a
	}
	if p := s.Units[name].Exec; p != "" {
		return p
	}
	dot := strings.LastIndex(name, ".")
	if dot < 0 {
		return ""
	}
	base, suffix := name[:dot], name[dot:]
	if at := strings.Index(base, "@"); at >= 0 {
		base = base[:at] // an instance or a template
	}
	candidates := []string{base + "@.service"}
	if suffix != ".service" {
		candidates = append([]string{base + ".service"}, candidates...)
	}
	for _, c := range candidates {
		if p := s.Units[c].Exec; p != "" {
			return p
		}
	}
	return ""
}

// serviceName strips the unit type and instance: telnet@.service → telnet.
func serviceName(unit string) string {
	if dot := strings.LastIndex(unit, "."); dot > 0 {
		unit = unit[:dot]
	}
	if at := strings.Index(unit, "@"); at >= 0 {
		unit = unit[:at]
	}
	return unit
}

// inetdProgram is the program an inetd or xinetd entry runs: the server,
// or the program tcpd wraps.
func inetdProgram(server, args string) string {
	if path.Base(server) == "tcpd" {
		if prog, _, _ := strings.Cut(strings.TrimSpace(args), " "); prog != "" {
			return prog
		}
	}
	return server
}

// systemdActive asks systemd which units are active:
// "UNIT LOAD ACTIVE SUB DESCRIPTION" lines.
func systemdActive(ctx context.Context, h *hostfs.Host) (map[string]string, error) {
	out, err := h.Runner.Run(ctx, hostfs.SystemctlListUnits)
	if err != nil {
		return nil, err
	}
	if out.ExitCode != 0 {
		return nil, fmt.Errorf("systemctl list-units exited with status %d: %s", out.ExitCode, firstLine(out.Stderr))
	}
	active := map[string]string{}
	for line := range strings.Lines(string(out.Stdout)) {
		f := strings.Fields(line)
		if len(f) > 0 && (f[0] == "●" || f[0] == "*") {
			f = f[1:] // a marker for failed or not-found units
		}
		if len(f) < 4 || !isUnitName(f[0]) {
			return nil, fmt.Errorf("systemctl list-units: unexpected line %q", strings.TrimSpace(line))
		}
		if f[2] != "inactive" && f[2] != "failed" {
			active[f[0]] = f[3]
		}
	}
	return active, nil
}

func firstLine(b []byte) string {
	s, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	return s
}

type serviceReader struct {
	fsys    hostfs.FS
	systemd bool
	skipped []string
}

// readDir lists dir; a missing directory is empty, an unreadable one is
// recorded as skipped.
func (r *serviceReader) readDir(dir string) []hostfs.FileInfo {
	entries, err := r.fsys.ReadDir(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		r.skipped = append(r.skipped, err.Error())
		return nil
	}
	return entries
}

func (r *serviceReader) readFile(name string) ([]byte, bool) {
	data, err := r.fsys.ReadFile(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, false
	case err != nil:
		r.skipped = append(r.skipped, err.Error())
		return nil, false
	}
	return data, true
}

func isUnitName(name string) bool {
	return slices.ContainsFunc(unitSuffixes, func(s string) bool { return strings.HasSuffix(name, s) && len(name) > len(s) })
}

// units reads the unit files and the .wants/.requires links of every unit
// directory.
func (r *serviceReader) units() map[string]Unit {
	units := map[string]Unit{}
	var wantDirs []string
	for _, dir := range unitDirs {
		entries, err := r.fsys.ReadDir(dir)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			r.skipped = append(r.skipped, err.Error())
			continue
		}
		r.systemd = true
		for _, e := range entries {
			name := path.Base(e.Path)
			switch {
			case e.IsDir() && (strings.HasSuffix(name, ".wants") || strings.HasSuffix(name, ".requires") || strings.HasSuffix(name, ".upholds")):
				wantDirs = append(wantDirs, e.Path)
			case !isUnitName(name):
			case units[name].Source != "":
				// Shadowed by a directory of higher precedence.
			default:
				units[name] = r.unitFile(e)
			}
		}
	}
	for _, dir := range wantDirs {
		for _, e := range r.readDir(dir) {
			name := path.Base(e.Path)
			if !isUnitName(name) {
				continue
			}
			u, known := units[name]
			if !known && e.IsSymlink() {
				// A link to a unit file of another name, or to nothing: what
				// it points at is what the unit is.
				u = r.unitFile(e)
			}
			if !u.Enabled {
				u.Enabled, u.Source = true, e.Path
			}
			if u.File == "" && u.AliasOf == "" {
				u.File = templateFile(units, name)
			}
			units[name] = u
		}
	}
	return units
}

// unitFile describes the unit whose file (or link) is e.
func (r *serviceReader) unitFile(e hostfs.FileInfo) Unit {
	u := Unit{File: e.Path, Source: e.Path}
	switch {
	case e.IsSymlink():
		target, err := r.fsys.ReadLink(e.Path)
		if err == nil && !path.IsAbs(target) {
			// Relative to the link's directory: EL7 links dracut's units
			// as ../../dracut/modules.d/98systemd/<unit>.
			target = path.Join(path.Dir(e.Path), target)
		}
		switch {
		case err != nil:
			r.skipped = append(r.skipped, err.Error())
		case target == "/dev/null":
			u.Masked, u.File = true, ""
		case path.Base(target) != path.Base(e.Path):
			u.AliasOf, u.File = path.Base(target), ""
		default:
			u.File = target // a linked unit file
		}
	case e.Size == 0 && !e.IsDir():
		u.Masked, u.File = true, ""
	}
	if u.File != "" && strings.HasSuffix(u.File, ".service") {
		// Read through the link itself, so it resolves as the kernel would.
		if data, ok := r.readFile(e.Path); ok {
			u.Exec = execStart(data)
		}
	}
	return u
}

// execStart returns the program of the first ExecStart= line of a service
// unit, without systemd's prefixes (-, @, +, !, :).
func execStart(data []byte) string {
	section, prog := "", ""
	// A line ending in a backslash continues on the next one.
	for line := range strings.Lines(strings.ReplaceAll(string(data), "\\\n", " ")) {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "["):
			section = line
		case section != "[Service]":
		default:
			key, value, ok := strings.Cut(line, "=")
			if !ok || strings.TrimSpace(key) != "ExecStart" {
				continue
			}
			value = strings.TrimLeft(strings.TrimSpace(value), "-@+!:")
			switch f := strings.Fields(value); {
			case len(f) == 0:
				prog = "" // an empty assignment resets the earlier ones
			case prog == "":
				prog = f[0]
			}
		}
	}
	return prog
}

// templateFile returns the file of an instance's template unit
// (getty@tty1.service → getty@.service).
func templateFile(units map[string]Unit, name string) string {
	at := strings.Index(name, "@")
	if at < 0 {
		return ""
	}
	return units[name[:at+1]+name[strings.LastIndex(name, "."):]].File
}

// sysv reads /etc/init.d and the start links of the boot runlevels.
func (r *serviceReader) sysv() map[string]SysVScript {
	scripts := map[string]SysVScript{}
	for _, dir := range []string{"/etc/init.d", "/etc/rc.d/init.d"} {
		for _, e := range r.readDir(dir) {
			if name := path.Base(e.Path); !e.IsDir() && !strings.HasPrefix(name, ".") && name != "README" {
				if _, seen := scripts[name]; !seen {
					scripts[name] = SysVScript{Source: e.Path}
				}
			}
		}
	}
	for _, dir := range rcDirs {
		for _, e := range r.readDir(dir) {
			if !strings.HasPrefix(path.Base(e.Path), "S") || !e.IsSymlink() {
				continue
			}
			target, err := r.fsys.ReadLink(e.Path)
			if err != nil {
				r.skipped = append(r.skipped, err.Error())
				continue
			}
			name := path.Base(target)
			if s, ok := scripts[name]; ok && !s.Enabled {
				scripts[name] = SysVScript{Enabled: true, Source: e.Path}
			}
		}
	}
	return scripts
}

// inetd reads the active lines of /etc/inetd.conf and /etc/inetd.d:
// name socket-type protocol wait/nowait user server [args].
func (r *serviceReader) inetd() []InetdService {
	out := []InetdService{}
	files := []string{inetdConf}
	for _, e := range r.readDir(inetdDir) {
		if !e.IsDir() {
			files = append(files, e.Path)
		}
	}
	for _, file := range files {
		data, ok := r.readFile(file)
		if !ok {
			continue
		}
		// A line ending in a backslash continues on the next one; the entry is
		// reported at the line it starts on.
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for line := 1; sc.Scan(); line++ {
			text, start := sc.Text(), line
			for strings.HasSuffix(text, `\`) && sc.Scan() {
				line++
				text = strings.TrimSuffix(text, `\`) + " " + sc.Text()
			}
			if i := strings.Index(text, " #"); i >= 0 {
				text = text[:i] // a trailing comment
			}
			f := strings.Fields(text)
			if len(f) < 6 || strings.HasPrefix(f[0], "#") {
				continue
			}
			out = append(out, InetdService{
				Name: f[0], SocketType: f[1], Protocol: f[2], User: f[4], Server: f[5],
				Args: strings.Join(f[6:], " "), Source: fmt.Sprintf("%s:%d", file, start),
			})
		}
		if err := sc.Err(); err != nil {
			r.skipped = append(r.skipped, fmt.Sprintf("%s: the rest of the file was not read (%v)", file, err))
		}
	}
	return out
}

// xinetd reads /etc/xinetd.conf and the files of its includedir lines.
func (r *serviceReader) xinetd() []XinetdService {
	out := []XinetdService{}
	data, ok := r.readFile(xinetdConf)
	if !ok {
		return out
	}
	x := &xinetdParser{r: r}
	x.parse(xinetdConf, data)
	// An includedir or include in an included file is followed too.
	for i := 0; i < len(x.includeDirs); i++ {
		if i >= xinetdMaxIncludes {
			r.skipped = append(r.skipped, "xinetd: too many includedir lines; the rest are not read")
			break
		}
		for _, e := range r.readDir(x.includeDirs[i]) {
			// xinetd skips names with a dot or ending in a tilde.
			name := path.Base(e.Path)
			if e.IsDir() || strings.Contains(name, ".") || strings.HasSuffix(name, "~") {
				continue
			}
			if data, ok := r.readFile(e.Path); ok {
				x.parse(e.Path, data)
			}
		}
	}
	for i := range x.services {
		s := &x.services[i]
		id := s.Name
		if v, ok := s.Settings["id"]; ok {
			id = v
		}
		switch {
		case strings.EqualFold(s.Settings["disable"], "yes"):
			s.Disabled = true
		case slices.Contains(x.disabled, id):
			s.Disabled = true
		case x.enabled != nil && !slices.Contains(x.enabled, id):
			s.Disabled = true
		}
		delete(s.Settings, "disable")
	}
	return x.services
}

const xinetdMaxIncludes = 50

type xinetdParser struct {
	r                 *serviceReader
	services          []XinetdService
	includeDirs       []string
	includes          int      // include files read
	disabled, enabled []string // from the defaults section; enabled nil when not set
}

// parse reads "service <name> { attr = value }" and "defaults { ... }"
// sections and includedir lines.
func (x *xinetdParser) parse(file string, data []byte) {
	var state xinetdState
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	defer func() {
		if err := sc.Err(); err != nil {
			x.r.skipped = append(x.r.skipped, fmt.Sprintf("%s: the rest of the file was not read (%v)", file, err))
		}
	}()
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if i := strings.Index(text, "#"); i >= 0 {
			text = strings.TrimSpace(text[:i])
		}
		// A brace is a statement of its own: "service a { disable = yes }"
		// may share one line.
		for _, stmt := range splitBraces(text) {
			x.statement(stmt, file, line, &state)
		}
	}
}

// xinetdState is where the parser is in the file.
type xinetdState struct {
	cur                   *XinetdService
	inDefaults, inSection bool
}

func (x *xinetdParser) statement(text, file string, line int, st *xinetdState) {
	cur, inDefaults, inSection := st.cur, st.inDefaults, st.inSection
	defer func() { st.cur, st.inDefaults, st.inSection = cur, inDefaults, inSection }()
	{
		f := strings.Fields(text)
		switch {
		case len(f) == 0:
		case f[0] == "includedir" && len(f) == 2 && !inSection:
			x.includeDirs = append(x.includeDirs, f[1])
		case f[0] == "include" && len(f) == 2 && !inSection:
			if x.includes >= xinetdMaxIncludes {
				x.r.skipped = append(x.r.skipped, fmt.Sprintf("%s:%d: too many include lines; the rest are not read", file, line))
			} else if data, ok := x.r.readFile(f[1]); ok {
				x.includes++
				x.parse(f[1], data)
			}
		case f[0] == "service" && len(f) >= 2 && !inSection:
			x.services = append(x.services, XinetdService{Name: f[1], Settings: map[string]string{}, Source: fmt.Sprintf("%s:%d", file, line)})
			cur = &x.services[len(x.services)-1]
			inSection = f[len(f)-1] == "{"
		case f[0] == "defaults" && !inSection:
			inDefaults, cur = true, nil
			inSection = f[len(f)-1] == "{"
		case f[0] == "{":
			inSection = true
		case f[0] == "}":
			inSection, inDefaults, cur = false, false, nil
		case !inSection:
		case inDefaults:
			attr, op, values := xinetdAttr(text)
			switch {
			case attr == "disabled" && op != "-=":
				x.disabled = append(x.disabled, values...)
			case attr == "enabled" && op != "-=":
				x.enabled = append(x.enabled, values...)
			}
		case cur != nil:
			attr, op, values := xinetdAttr(text)
			switch {
			case attr == "":
			case op == "+=" && cur.Settings[attr] != "":
				cur.Settings[attr] += " " + strings.Join(values, " ")
			default:
				cur.Settings[attr] = strings.Join(values, " ")
			}
		}
	}
}

// xinetdAttr splits "attr = value ...", "attr += value" or "attr -= value".
func xinetdAttr(text string) (attr, op string, values []string) {
	i := strings.Index(text, "=")
	if i < 1 {
		return "", "", nil
	}
	attr, op = text[:i], "="
	if c := attr[len(attr)-1]; c == '+' || c == '-' {
		attr, op = attr[:len(attr)-1], string(c)+"="
	}
	return strings.TrimSpace(attr), op, strings.Fields(text[i+1:])
}

// splitBraces cuts a line at its braces: "service a { b = c }" becomes
// "service a", "{", "b = c", "}".
func splitBraces(text string) []string {
	var out []string
	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] == '{' || text[i] == '}' {
			if s := strings.TrimSpace(text[start:i]); s != "" {
				out = append(out, s)
			}
			out = append(out, text[i:i+1])
			start = i + 1
		}
	}
	if s := strings.TrimSpace(text[start:]); s != "" {
		out = append(out, s)
	}
	return out
}
