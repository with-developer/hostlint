//go:build lintguard

// Package lintguard holds deliberate violations of the ADR 0004 lint guards.
// It is only compiled with the lintguard build tag; scripts/lint-guards.sh
// checks that every line marked "want <linter>" is reported and nothing else.
package lintguard

import (
	"fmt"
	"net"
	"net/http" // want depguard
	"os"
	"os/exec" // want depguard
	"path/filepath"
	"syscall" // want depguard
)

// ModifyHost violates the read-only guards.
func ModifyHost(r *os.Root, f *os.File, p *os.Process) {
	_ = os.WriteFile("/etc/x", nil, 0o600) // want forbidigo
	_ = os.RemoveAll("/etc/x")             // want forbidigo
	_ = os.Chmod("/etc/shadow", 0o600)     // want forbidigo
	_ = os.CopyFS("/etc/x", nil)           // want forbidigo
	_ = r.WriteFile("etc/x", nil, 0o600)   // want forbidigo
	_ = r.Remove("etc/x")                  // want forbidigo
	_ = f.Chmod(0o600)                     // want forbidigo
	_ = f.Chown(0, 0)                      // want forbidigo
	_ = p.Kill()                           // want forbidigo
	_ = syscall.Unlink("/etc/x")           // want forbidigo
}

// ReadHostDirectly bypasses internal/hostfs.
func ReadHostDirectly() {
	_, _ = os.ReadFile("/etc/hostname")        // want forbidigo
	_, _ = os.Open("/etc/hostname")            // want forbidigo
	_, _ = os.Stat("/etc/hostname")            // want forbidigo
	_ = os.DirFS("/")                          // want forbidigo
	_, _ = os.Hostname()                       // want forbidigo
	_ = filepath.WalkDir("/etc", nil)          // want forbidigo
	_, _ = net.Dial("unix", "/run/x.sock")     // want forbidigo
	_, _ = http.Get("http://example.invalid/") // import already reported
}

// RunCommand runs a command and prints to stdout.
func RunCommand() {
	_ = exec.Command("true").Run() // import already reported
	fmt.Println("stdout")          // want forbidigo
}
