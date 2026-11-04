package hostfs

import (
	"fmt"
	"testing"
)

// From a Debian 12 container, with a network share and a bind mount added.
const mountinfoFixture = `596 433 0:69 / / rw,relatime master:179 - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/X:/var/lib/docker/overlay2/l/Y,upperdir=/var/lib/docker/overlay2/a/diff,workdir=/var/lib/docker/overlay2/a/work
597 596 0:72 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
598 596 0:73 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
599 598 0:74 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
600 596 0:75 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
605 596 254:1 /docker/volumes/data /srv/my\040data rw,relatime - ext4 /dev/vda1 rw
606 596 0:80 / /mnt/share rw,relatime - nfs4 server:/export rw,vers=4.2
607 596 0:81 / /scan/img rw,relatime - ext4 /dev/vdb1 rw
608 607 0:82 / /scan/img/proc rw,relatime - proc proc rw
`

func TestParseMountinfo(t *testing.T) {
	tests := []struct {
		root string
		want string
	}{
		{"/", "[{/ overlay overlay} {/proc proc proc} {/dev tmpfs tmpfs} {/dev/pts devpts devpts} {/sys sysfs sysfs} {/srv/my data ext4 /dev/vda1} {/mnt/share nfs4 server:/export} {/scan/img ext4 /dev/vdb1} {/scan/img/proc proc proc}]"},
		// A mounted root sees what is mounted inside it, as target paths.
		{"/scan/img", "[{/ ext4 /dev/vdb1} {/proc proc proc}]"},
		{"/scan", "[{/img ext4 /dev/vdb1} {/img/proc proc proc}]"},
		{"/nowhere", "[]"},
	}
	for _, tt := range tests {
		m, err := ParseMountinfo([]byte(mountinfoFixture), tt.root)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprint(m); got != tt.want {
			t.Errorf("root %s:\n got %s\nwant %s", tt.root, got, tt.want)
		}
	}
	for _, bad := range []string{"1 2 3\n", "596 433 0:69 / / rw master:179 overlay overlay\n", `1 0 0:1 / /a\04 rw - ext4 x rw` + "\n"} {
		if _, err := ParseMountinfo([]byte(bad), "/"); err == nil {
			t.Errorf("ParseMountinfo(%q) succeeded", bad)
		}
	}
}
