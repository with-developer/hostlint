package hostfs

// The commands hostlint may run. Collectors pick from this list; they can
// never supply a program or an argument themselves (ADR 0004).
var (
	// SSHDConfigTest prints the OpenSSH server's effective configuration.
	SSHDConfigTest = newCommand("sshd -T", []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd"}, "-T")
)
