// Command hostlint checks a Linux host's security configuration against
// hardening baselines.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/with-developer/hostlint/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ctx.Done()
		stop() // restore default handling: a second signal ends the process at once
	}()
	code := cli.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
