// Command vmsctl checks a Linux host's security configuration against
// hardening baselines.
package main

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/with-developer/vmsctl/internal/cli"
)

func main() {
	// The packages keep a "hostlint" link for a while after the rename (ADR 0017): say so when a person runs it. Cron
	// jobs and units that still use the name get nothing on standard error, which they may mail or treat as a failure.
	if fi, err := os.Stderr.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 && filepath.Base(os.Args[0]) == "hostlint" {
		_, _ = os.Stderr.WriteString("vmsctl: this program is now called vmsctl; the name hostlint will stop working in a later release\n")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ctx.Done()
		stop() // restore default handling: a second signal ends the process at once
	}()
	code := cli.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
