package collect

import (
	"context"
	"errors"
	"io/fs"
	"reflect"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/hostfs"
)

// SNMP is the `snmp` facts: how the net-snmp agent is configured to be reached.
// A community string is a password: the configuration files are on the denylist
// and hostfs.ReadSNMPConfig keeps only what can be said without the string
// (whether it is a well-known name or short, which source it answers).
type SNMP struct {
	// Present is false when none of the agent's configuration files exists.
	Present bool `json:"present"`
	// Communities are the SNMPv1 and v2c access entries: rocommunity,
	// rwcommunity, authcommunity and com2sec lines.
	Communities []SNMPCommunity `json:"communities"`
	// Listen are the agentAddress addresses, as written; empty when the files
	// do not set them (the agent then listens on every interface). A listen
	// address given on the command line overrides them and is not seen here.
	Listen []string `json:"listen"`
	// LoopbackOnly is true when agentAddress is set and every address is a
	// loopback address.
	LoopbackOnly bool `json:"loopback_only"`
}

// SNMPCommunity is one v1 or v2c access entry, without its string.
type SNMPCommunity struct {
	// Directive is the configuration keyword (rocommunity, com2sec, ...).
	Directive string `json:"directive"`
	// Weak says why the string is easy to guess: "a well-known name" or "shorter
	// than 8 characters"; "" when it is neither.
	Weak string `json:"weak"`
	// Unrestricted is true when the entry answers every source address.
	Unrestricted bool `json:"unrestricted"`
	// Source is the address the entry is limited to, "" for none.
	Source string `json:"source"`
	// Where is file:line.
	Where string `json:"where"`
}

type snmpCollector struct{}

func (snmpCollector) Name() string          { return "snmp" }
func (snmpCollector) Version() int          { return 1 }
func (snmpCollector) Access() engine.Access { return engine.AccessFilesystem }
func (snmpCollector) Type() reflect.Type    { return reflect.TypeFor[SNMP]() }

func (snmpCollector) Collect(_ context.Context, h *hostfs.Host) (engine.Facts, error) {
	cfg, err := hostfs.ReadSNMPConfig(h.FS)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return engine.Facts{}, errors.New("the SNMP agent's configuration cannot be read (run vmsctl as root)")
		}
		return engine.Facts{}, err
	}
	s := &SNMP{Present: cfg.Present, Communities: []SNMPCommunity{}, Listen: cfg.Listen, LoopbackOnly: cfg.LoopbackOnly}
	for _, c := range cfg.Communities {
		s.Communities = append(s.Communities, SNMPCommunity(c))
	}
	return engine.Facts{Value: s, Complete: len(cfg.Skipped) == 0, Skipped: cfg.Skipped}, nil
}
