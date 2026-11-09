package collect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"reflect"
	"strconv"
	"strings"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/hostfs"
)

// Sockets are the `sockets` facts: the TCP and UDP sockets of the running
// system that accept traffic, from /proc/net. Which program owns a socket is
// not recorded, and a port alone does not identify a service (RPC services
// get theirs from rpcbind): checks combine sockets with other signals.
type Sockets struct {
	Listening []Socket `json:"listening"`
}

// Socket is one listening TCP socket or one unconnected UDP socket.
type Socket struct {
	Protocol string `json:"protocol"` // tcp or udp
	Address  string `json:"address"`  // local address: 0.0.0.0, ::, 127.0.0.1, ...
	Port     int64  `json:"port"`
	// Loopback is true when only the host itself can reach the socket.
	Loopback bool   `json:"loopback"`
	UID      int64  `json:"uid"`
	Source   string `json:"source"`
}

// procNetTables are read in this order.
var procNetTables = []struct{ file, protocol string }{
	{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp"},
	{"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp"},
}

// Socket states in /proc/net (include/net/tcp_states.h).
const (
	stateListen = "0A" // TCP_LISTEN
	stateClose  = "07" // TCP_CLOSE: an unconnected UDP socket
)

type socketsCollector struct{}

func (socketsCollector) Name() string          { return "sockets" }
func (socketsCollector) Version() int          { return 1 }
func (socketsCollector) Access() engine.Access { return engine.AccessLive }
func (socketsCollector) Type() reflect.Type    { return reflect.TypeFor[Sockets]() }

func (socketsCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	f := engine.Facts{Complete: true}
	// /proc/net shows the network namespace vmsctl runs in. In another
	// one (a container, ip netns exec), the host's sockets are invisible.
	self, err1 := h.FS.ReadLink("/proc/self/ns/net")
	hostNS, err2 := h.FS.ReadLink("/proc/1/ns/net")
	switch {
	case err1 == nil && err2 == nil && self != hostNS:
		return engine.Facts{}, fmt.Errorf("vmsctl runs in network namespace %s, not the host's %s, so it cannot see the host's sockets", self, hostNS)
	case err1 != nil || err2 != nil:
		f.Complete = false
		f.Skipped = append(f.Skipped, "cannot tell whether vmsctl shares the network namespace of process 1 (run vmsctl as root)")
	}
	s := &Sockets{Listening: []Socket{}}
	for _, t := range procNetTables {
		data, err := readBig(h.FS, t.file)
		if err != nil {
			// tcp6 and udp6 are missing when IPv6 is disabled at boot, and
			// so are IPv6 sockets; tcp and udp always exist.
			if errors.Is(err, fs.ErrNotExist) && strings.HasSuffix(t.file, "6") {
				// With IPv6 up the interface table exists: a missing socket
				// table then means the IPv6 sockets could not be seen.
				if _, statErr := h.FS.Stat("/proc/net/if_inet6"); statErr == nil {
					f.Complete = false
					f.Skipped = append(f.Skipped, t.file+": missing although IPv6 is enabled")
				}
				continue
			}
			return engine.Facts{}, err
		}
		sockets, err := parseProcNet(t.file, t.protocol, data)
		if err != nil {
			return engine.Facts{}, err
		}
		s.Listening = append(s.Listening, sockets...)
	}
	f.Value = s
	return f, nil
}

// parseProcNet reads the sockets that accept traffic from one /proc/net
// table: "sl local_address rem_address st ... uid timeout inode ...".
func parseProcNet(file, protocol string, data []byte) ([]Socket, error) {
	var out []Socket
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for line := 1; sc.Scan(); line++ {
		f := strings.Fields(sc.Text())
		if line == 1 || len(f) < 8 {
			continue // header
		}
		local, remote, state := f[1], f[2], f[3]
		listening := state == stateListen && protocol == "tcp" ||
			state == stateClose && protocol == "udp" && strings.Trim(remote, "0:") == ""
		if !listening {
			continue
		}
		addr, port, err := parseProcAddr(local)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", file, line, err)
		}
		uid, err := strconv.ParseInt(f[7], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: uid %q: %w", file, line, f[7], err)
		}
		out = append(out, Socket{
			Protocol: protocol, Address: addr.String(), Port: int64(port),
			Loopback: addr.Unmap().IsLoopback(), UID: uid, Source: fmt.Sprintf("%s:%d", file, line),
		})
	}
	return out, sc.Err()
}

// parseProcAddr decodes "0100007F:0016": the address as 32-bit words in host
// byte order, then the port in hexadecimal.
func parseProcAddr(s string) (netip.Addr, uint16, error) {
	hexAddr, hexPort, ok := strings.Cut(s, ":")
	raw, err := hex.DecodeString(hexAddr)
	if !ok || err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.Addr{}, 0, fmt.Errorf("bad address %q", s)
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("bad port in %q", s)
	}
	// Each word was printed as a host-order integer; turn it back into
	// network-order bytes.
	for i := 0; i < len(raw); i += 4 {
		binary.NativeEndian.PutUint32(raw[i:], binary.BigEndian.Uint32(raw[i:]))
	}
	addr, _ := netip.AddrFromSlice(raw)
	return addr, uint16(port), nil
}
