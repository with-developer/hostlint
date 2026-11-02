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
		{"/proc/1/task/1/environ", true},
		{"/proc/kmsg", true},
		{"/sys/kernel/debug/tracing/trace_pipe", true},
		{"/sys/kernel/tracing/trace_pipe", true},
		{"/var/lib/lxc/c1/rootfs/etc/shadow", true},
		{"/etc/letsencrypt/live/example.org/privkey.pem", true},
		{"/etc/wireguard/wg0.conf", true},
		{"/etc/kubernetes/admin.conf", true},
		{"/srv/app/server.key", true},
		{"/run/credentials/app.service/token", true},
		{"/etc/ssh/ssh_config", false},
		{"/etc/hosts", false},
	}
	for _, tt := range tests {
		if got := denied(tt.path); got != tt.want {
			t.Errorf("denied(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
