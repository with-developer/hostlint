#!/bin/sh
# Hardens a container image for the e2e "hardened" variant: the KISA Unix
# controls that hostlint decides automatically, configured the way an
# administrator would on each distribution. It shows that the checks can
# pass on real configuration; it is not a hardening guide for real hosts.
set -eu

# shellcheck source=/dev/null
. /etc/os-release
major=${VERSION_ID%%.*}
case " $ID ${ID_LIKE:-} " in
*" debian "* | *" ubuntu "*) family=debian ;;
*" rhel "* | *" centos "* | *" fedora "*) family=rhel ;;
*)
	echo "harden.sh: unsupported distribution $ID" >&2
	exit 1
	;;
esac

# Packages: password quality, time synchronization, an SSH server, and on
# EL the PAM configuration tool.
case $family in
debian)
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y -qq --no-install-recommends libpam-pwquality chrony openssh-server >/dev/null
	rm -rf /var/lib/apt/lists/*
	;;
rhel)
	if [ "$major" = 7 ]; then
		# CentOS 7 is end of life; its packages are in the vault.
		# shellcheck disable=SC2016 # $releasever is the repository file's
		sed -i -e 's/^mirrorlist=/#mirrorlist=/' \
			-e 's|^#\{0,1\}baseurl=http://mirror.centos.org/\(altarch/\)\{0,1\}$releasever|baseurl=https://vault.centos.org/\17.9.2009|' \
			/etc/yum.repos.d/CentOS-*.repo
		yum -q -y install chrony openssh-server >/dev/null
		yum clean all >/dev/null
	else
		# The minimal images lack passwd (its PAM service) and su.
		dnf -q -y install authselect pam libpwquality passwd util-linux chrony openssh-server >/dev/null
		dnf clean all >/dev/null
	fi
	;;
esac

# U-01: no direct root login over SSH. sshd keeps the first value it reads.
sed -i '1i PermitRootLogin no' /etc/ssh/sshd_config
# On a server sshd has started once: it has host keys and, on Debian, its
# privilege separation directory. `sshd -T` needs both.
ssh-keygen -A >/dev/null
mkdir -p /run/sshd

# U-02: password length, complexity, also for root, and age.
cat >/etc/security/pwquality.conf <<'EOF'
minlen = 8
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
enforce_for_root
EOF
sed -i -e 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' -e 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' /etc/login.defs

# U-02 (history) and U-03 (lockout after 5 failures).
case $family in
debian)
	cat >/etc/pam.d/common-auth <<'EOF'
auth	required			pam_faillock.so preauth
auth	[success=2 default=ignore]	pam_unix.so nullok
auth	[default=die]			pam_faillock.so authfail
auth	requisite			pam_deny.so
auth	required			pam_permit.so
EOF
	sed -i '1i account\trequired\t\t\tpam_faillock.so' /etc/pam.d/common-account
	sed -i '/pam_pwquality.so/a password\trequired\t\t\tpam_pwhistory.so remember=4 use_authtok' /etc/pam.d/common-password
	printf 'deny = 5\nunlock_time = 900\n' >/etc/security/faillock.conf
	;;
rhel)
	if [ "$major" = 7 ]; then
		for f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
			sed -i \
				-e '/^auth.*pam_env.so/a auth        required      pam_faillock.so preauth silent deny=5 unlock_time=900' \
				-e '/^auth.*pam_unix.so/a auth        [default=die] pam_faillock.so authfail deny=5 unlock_time=900' \
				-e '0,/^account/s//account     required      pam_faillock.so\naccount/' \
				-e '/^password.*pam_pwquality.so/s/$/ enforce_for_root/' \
				-e '/^password.*pam_pwquality.so/a password    requisite     pam_pwhistory.so remember=4 use_authtok' \
				"$f"
		done
	else
		profile=minimal
		[ "$major" -ge 10 ] && profile=local
		authselect select "$profile" with-faillock with-pwhistory --force >/dev/null
		printf 'deny = 5\nunlock_time = 900\n' >/etc/security/faillock.conf
		printf 'remember = 4\nenforce_for_root\n' >/etc/security/pwhistory.conf
	fi
	;;
esac

# U-06: only members of the wheel group may su to root.
sed -i 's/^#[[:space:]]*\(auth[[:space:]]\{1,\}required[[:space:]]\{1,\}pam_wheel.so\)/\1/' /etc/pam.d/su

# U-12: idle shells end after 10 minutes.
printf 'TMOUT=600\nreadonly TMOUT\nexport TMOUT\n' >/etc/profile.d/tmout.sh

# U-18, U-21, U-30, U-37: file permissions and the default umask.
chmod 0400 /etc/shadow
chmod 0640 /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/cron.d/* 2>/dev/null || true
sed -i 's/umask 002/umask 022/' /etc/profile /etc/bashrc /etc/bash.bashrc 2>/dev/null || true

# U-65: time synchronization starts at boot.
case $family in
debian) ln -sf /lib/systemd/system/chrony.service /etc/systemd/system/multi-user.target.wants/chrony.service ;;
rhel) ln -sf /usr/lib/systemd/system/chronyd.service /etc/systemd/system/multi-user.target.wants/chronyd.service ;;
esac
