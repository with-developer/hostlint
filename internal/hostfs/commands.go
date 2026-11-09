package hostfs

// The commands vmsctl may run. Collectors pick from this list; they can
// never supply a program or an argument themselves (ADR 0004).
var (
	// SSHDConfigTest prints the OpenSSH server's effective configuration.
	SSHDConfigTest = newCommand("sshd -T", []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd"}, "-T")
	// SystemctlListUnits lists the units systemd has loaded, with their
	// active and sub-states, one per line.
	SystemctlListUnits = newCommand("systemctl list-units", []string{"/usr/bin/systemctl", "/bin/systemctl"},
		"list-units", "--all", "--plain", "--no-legend", "--no-pager", "--full")
)
