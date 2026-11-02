package hostfs

import "testing"

func TestDenied(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/etc/shadow", true},
		{"/etc/gshadow-", true},
		{"/etc/security/opasswd", true},
		{"/etc/ssh/ssh_host_ed25519_key", true},
		{"/etc/ssh/ssh_host_ed25519_key.pub", false},
		{"/etc/ssh/sshd_config", false},
		{"/etc/ssl/private/server.key", true},
		{"/etc/pki/tls/private/server.key", true},
		{"/etc/sssd/sssd.conf", true},
		{"/etc/ldap.secret", true},
		{"/proc/1/environ", true},
		{"/proc/self/cmdline", true},
		{"/proc/1/status", false},
		{"/root/.bash_history", true},
		{"/home/u/.zsh_history", true},
		{"/root/.ssh/authorized_keys", true},
		{"/var/lib/svc/.ssh/id_ed25519", true},
		{"/home/u/.my.cnf", true},
		{"/home/u/.docker/config.json", true},
		{"/home/u/.kube/config", true},
		{"/home/u/config", false},
		{"/home/u/.rhosts", false},
		{"/root/.bashrc", false},
		{"/etc/passwd", false},
		{"/etc/login.defs", false},
	}
	for _, tt := range tests {
		if got := denied(tt.path); got != tt.want {
			t.Errorf("denied(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
