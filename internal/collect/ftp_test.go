package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/with-developer/vmsctl/internal/hostfs"
)

func collectFTP(t *testing.T, m *hostfs.MemFS) (*FTP, bool) {
	t.Helper()
	f, err := ftpCollector{}.Collect(context.Background(), hostfs.NewTestHost(m, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	return f.Value.(*FTP), f.Complete
}

func vsftpd(conf string, extra map[string]string) *hostfs.MemFS {
	m := hostfs.NewMemFS().AddFile("/etc/vsftpd.conf", conf, 0o644, 0, 0)
	for name, text := range extra {
		m.AddFile(name, text, 0o644, 0, 0)
	}
	return m
}

const pamFtpusers = "auth required pam_listfile.so item=user sense=deny file=/etc/ftpusers onerr=succeed\n"

// The packaged vsftpd of Ubuntu 24.04 and Rocky Linux 9.
func TestFTPDistributionDefaults(t *testing.T) {
	for _, name := range []string{"ubuntu-24.04", "rocky-9"} {
		t.Run(name, func(t *testing.T) {
			f, complete := collectFTP(t, fixtureFS(t, name))
			if !f.Present || !complete {
				t.Fatalf("%+v complete %v", f, complete)
			}
			if f.Banner != "default" || !f.RootDenied || f.Settings["anonymous_enable"].Value != "NO" || f.Settings["ssl_enable"].Value != "NO" {
				t.Errorf("%+v", f)
			}
		})
	}
	f, _ := collectFTP(t, fixtureFS(t, "ubuntu-24.04"))
	if f.RootDeniedBy != "/etc/ftpusers" || !f.Settings["ssl_enable"].Explicit {
		t.Errorf("ubuntu: %+v", f)
	}
	f, _ = collectFTP(t, fixtureFS(t, "rocky-9"))
	if f.RootDeniedBy != "/etc/vsftpd/ftpusers" || f.Settings["userlist_enable"].Value != "YES" {
		t.Errorf("rocky: %+v", f)
	}
}

func TestFTPBanner(t *testing.T) {
	tests := []struct {
		name, conf string
		extra      map[string]string
		want       string
	}{
		{"the default shows the version", "anonymous_enable=NO\n", nil, "default"},
		{"a custom text", "ftpd_banner=Authorized users only.\n", nil, "custom"},
		{"a text with a version", "ftpd_banner=Welcome to vsFTPd 3.0.5\n", nil, "version"},
		{"a two-part number is not taken for a version", "ftpd_banner=Server 2.4 ready\n", nil, "custom"},
		{"a banner file", "banner_file=/etc/ftp.banner\n", map[string]string{"/etc/ftp.banner": "Authorized users only.\n"}, "custom"},
		{"a banner file with a version", "banner_file=/etc/ftp.banner\n", map[string]string{"/etc/ftp.banner": "vsftpd 3.0.5\n"}, "version"},
		{"the banner file overrides the text", "ftpd_banner=Authorized users only.\nbanner_file=/etc/ftp.banner\n", map[string]string{"/etc/ftp.banner": "vsftpd 3.0.5\n"}, "version"},
		{"a safe banner file over a text with a version", "ftpd_banner=vsftpd 3.0.5\nbanner_file=/etc/ftp.banner\n", map[string]string{"/etc/ftp.banner": "Authorized users only.\n"}, "custom"},
		{"an address and a policy number are no version", "ftpd_banner=Authorized users only. Contact 10.0.0.5 or see policy 2.1\n", nil, "custom"},
		{"a version number of three parts", "ftpd_banner=Server 3.0.5 ready\n", nil, "version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if f, _ := collectFTP(t, vsftpd(tt.conf, tt.extra)); f.Banner != tt.want {
				t.Errorf("banner = %q, want %q", f.Banner, tt.want)
			}
		})
	}
	// A banner file that cannot be read leaves the facts incomplete.
	if _, complete := collectFTP(t, vsftpd("banner_file=/etc/none\n", nil)); complete {
		t.Error("an unreadable banner_file must make the facts incomplete")
	}
}

func TestFTPRootDenied(t *testing.T) {
	tests := []struct {
		name, conf string
		extra      map[string]string
		want       bool
	}{
		{"pam_listfile with root in the file", "pam_service_name=vsftpd\n", map[string]string{"/etc/pam.d/vsftpd": pamFtpusers, "/etc/ftpusers": "daemon\nroot\n"}, true},
		{"root is not in the file", "pam_service_name=vsftpd\n", map[string]string{"/etc/pam.d/vsftpd": pamFtpusers, "/etc/ftpusers": "daemon\n"}, false},
		{"no pam_listfile line", "pam_service_name=vsftpd\n", map[string]string{"/etc/pam.d/vsftpd": "auth required pam_shells.so\n", "/etc/ftpusers": "root\n"}, false},
		{"allow, not deny", "pam_service_name=vsftpd\n", map[string]string{"/etc/pam.d/vsftpd": "auth required pam_listfile.so item=user sense=allow file=/etc/ftpusers onerr=fail\n", "/etc/ftpusers": "root\n"}, false},
		{"a pam_listfile that is only optional", "pam_service_name=vsftpd\n", map[string]string{"/etc/pam.d/vsftpd": "auth optional pam_listfile.so item=user sense=deny file=/etc/ftpusers\n", "/etc/ftpusers": "root\n"}, false},
		{"the default PAM service is ftp", "", map[string]string{"/etc/pam.d/ftp": pamFtpusers, "/etc/ftpusers": "root\n"}, true},
		{"the user list denies", "userlist_enable=YES\n", map[string]string{"/etc/vsftpd.user_list": "root\nbin\n"}, true},
		{"the user list is not enabled", "userlist_enable=NO\n", map[string]string{"/etc/vsftpd.user_list": "root\n"}, false},
		{"the user list allows", "userlist_enable=YES\nuserlist_deny=NO\n", map[string]string{"/etc/vsftpd.user_list": "root\n"}, false},
		{"a named user list", "userlist_enable=YES\nuserlist_file=/etc/denied\n", map[string]string{"/etc/denied": "root\n"}, true},
		{"nothing refuses root", "anonymous_enable=NO\n", nil, false},
		{"apply limits pam_listfile to some users", "pam_service_name=vsftpd\n", map[string]string{"/etc/pam.d/vsftpd": "auth required pam_listfile.so item=user sense=deny file=/etc/ftpusers apply=@ftpguests onerr=succeed\n", "/etc/ftpusers": "root\n"}, false},
		{"only the default user list of this packaging counts", "userlist_enable=YES\n", map[string]string{"/etc/vsftpd/user_list": "root\n"}, false},
		{"an allow list that does not hold root", "userlist_enable=YES\nuserlist_deny=NO\n", map[string]string{"/etc/vsftpd.user_list": "alice\n"}, true},
		{"an allow list that holds root", "userlist_enable=YES\nuserlist_deny=NO\n", map[string]string{"/etc/vsftpd.user_list": "root\nalice\n"}, false},
		{"a bracketed control that dies", "pam_service_name=vsftpd\n", map[string]string{"/etc/pam.d/vsftpd": "auth [default=die] pam_listfile.so item=user sense=deny file=/etc/ftpusers onerr=succeed\n", "/etc/ftpusers": "root\n"}, true},
		{"a sufficient rule before pam_listfile may let root skip it", "pam_service_name=vsftpd\n", map[string]string{"/etc/pam.d/vsftpd": "auth sufficient pam_succeed_if.so user = root\n" + pamFtpusers, "/etc/ftpusers": "root\n"}, false},
		{"an include before pam_listfile", "pam_service_name=vsftpd\n", map[string]string{"/etc/pam.d/vsftpd": "@include common-auth\n" + pamFtpusers, "/etc/ftpusers": "root\n"}, false},
		{"an include after pam_listfile", "pam_service_name=vsftpd\n", map[string]string{"/etc/pam.d/vsftpd": pamFtpusers + "@include common-auth\n", "/etc/ftpusers": "root\n"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if f, _ := collectFTP(t, vsftpd(tt.conf, tt.extra)); f.RootDenied != tt.want {
				t.Errorf("root_denied = %v, want %v (%+v)", f.RootDenied, tt.want, f)
			}
		})
	}
}

// What the checks cannot see makes the facts incomplete.
func TestFTPIncomplete(t *testing.T) {
	both := vsftpd("anonymous_enable=NO\n", nil).AddFile("/etc/vsftpd/vsftpd.conf", "anonymous_enable=YES\n", 0o644, 0, 0)
	if _, complete := collectFTP(t, both); complete {
		t.Error("two default configurations must make the facts incomplete")
	}
	other := hostfs.NewMemFS().AddFile("/etc/vsftpd/vsftpd.conf", "ssl_enable=YES\n", 0o644, 0, 0).AddFile("/etc/vsftpd/ftp-public.conf", "ssl_enable=NO\n", 0o644, 0, 0)
	if _, complete := collectFTP(t, other); complete {
		t.Error("another vsftpd configuration must make the facts incomplete")
	}
	long := vsftpd("pam_service_name=vsftpd\n", map[string]string{"/etc/pam.d/vsftpd": pamFtpusers, "/etc/ftpusers": strings.Repeat("x", 2<<20) + "\nroot\n"})
	if f, complete := collectFTP(t, long); complete || f.RootDenied {
		t.Errorf("a too long line must make the facts incomplete (denied %v, complete %v)", f.RootDenied, complete)
	}
	forced := collectFTPSettings(t, "ssl_enable=YES\nforce_local_logins_ssl=NO\n")
	if forced["force_local_logins_ssl"] != "NO" || forced["force_local_data_ssl"] != "YES" {
		t.Errorf("%+v", forced)
	}
}

func collectFTPSettings(t *testing.T, conf string) map[string]string {
	t.Helper()
	f, _ := collectFTP(t, vsftpd(conf, nil))
	out := map[string]string{}
	for k, v := range f.Settings {
		out[k] = v.Value
	}
	return out
}

func TestFTPBooleansAndAbsence(t *testing.T) {
	f, _ := collectFTP(t, vsftpd("ssl_enable=yes\nanonymous_enable=0\n", nil))
	if f.Settings["ssl_enable"].Value != "YES" || f.Settings["anonymous_enable"].Value != "NO" || !f.Settings["ssl_enable"].Explicit {
		t.Errorf("%+v", f.Settings)
	}
	if f, complete := collectFTP(t, hostfs.NewMemFS()); f.Present || !complete {
		t.Errorf("%+v complete %v", f, complete)
	}
	m := vsftpd("x=y\n", nil).SetError("/etc/vsftpd.conf", fsErrPermission)
	if _, err := (ftpCollector{}).Collect(context.Background(), hostfs.NewTestHost(m, nil, false)); err == nil || !strings.Contains(err.Error(), "run vmsctl as root") {
		t.Errorf("err = %v", err)
	}
}

func FuzzVsftpdConfig(f *testing.F) {
	f.Add([]byte(loadTree(f, "rocky-9")["/etc/vsftpd/vsftpd.conf"]))
	f.Add([]byte("ftpd_banner=x\nbanner_file=/a\nuserlist_file=/b\n"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ftpCollector{}.Collect(context.Background(), hostfs.NewTestHost(vsftpd(string(data), nil), nil, false))
	})
}
