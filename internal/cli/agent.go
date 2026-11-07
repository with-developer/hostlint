package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/internal/push"
	"github.com/with-developer/hostlint/profiles"
	"github.com/with-developer/hostlint/rules"
)

const (
	agentMinGap       = time.Minute      // the least time between two scans of the agent
	agentScanLimit    = 10 * time.Minute // a scan that takes longer is given up
	agentBackoffFirst = 5 * time.Second
	agentBackoffCap   = 5 * time.Minute
)

var agentProfileRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// agent is the loop of "hostlint agent" with the parts that touch the network or the host passed in, so a test can
// drive it.
type agent struct {
	allow []string
	poll  func(ctx context.Context, allow []string) (*push.Job, error)
	fail  func(ctx context.Context, id int64, reason string) error
	scan  func(ctx context.Context, job *push.Job) error
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) // returns when d has passed or ctx is done
	log   func(format string, args ...any)
}

func newAgentCommand() *cobra.Command {
	var f scanFlags
	var allow []string
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Scan this host when the fleet server asks (docs/fleet.md)",
		Long: `Agent keeps a connection open to a hostlint server, outbound only, and scans this host when someone
asks for it on the dashboard ("scan now"). The only thing the server can ask for is a scan with one of the profiles
you allow here with --allow-profile, at most once a minute: it cannot send waivers, parameters or commands, and
the result goes back through the same token, pin and signature as "hostlint scan --push".

The token is the host's ingest token (HOSTLINT_TOKEN or --token-file); the host has to have sent a result once.
Run it as root, as a service: scheduled scans (a systemd timer) keep working next to it.`,
		Example: `  sudo hostlint agent --server https://hostlint.example.org:8443 --pin sha256/... \
      --token-file /etc/hostlint/token --sign-key /etc/hostlint/sign.key --allow-profile kisa-2026`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAgent(cmd, f, allow)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.pushURL, "server", "", "the server's URL, such as https://hostlint.example.org:8443 (required)")
	fl.StringVar(&f.pin, "pin", "", `trust the server's public key ("sha256/<base64>") instead of the system roots`)
	fl.StringVar(&f.tokenFile, "token-file", "", "read the ingest token from this file (default: the HOSTLINT_TOKEN environment variable)")
	fl.StringVar(&f.signKey, "sign-key", "", "sign results with this key (made with: hostlint key generate)")
	fl.StringVar(&f.config, "config", "", "configuration file (default: ./hostlint.yaml, then /etc/hostlint/hostlint.yaml, if present)")
	fl.StringVar(&f.root, "root", "/", "scan a filesystem mounted at this directory instead of the running system (for tests)")
	_ = fl.MarkHidden("root")
	fl.StringArrayVar(&allow, "allow-profile", nil, "a profile the server may ask this agent to scan with (required; repeatable)")
	return cmd
}

func runAgent(cmd *cobra.Command, f scanFlags, allow []string) error {
	if f.pushURL == "" {
		return errors.New("--server is required")
	}
	if len(allow) == 0 || len(allow) > 8 {
		return errors.New("--allow-profile is required: name one to eight profiles the server may ask for")
	}
	content, err := engine.Load(rules.FS, profiles.FS)
	if err != nil {
		return fmt.Errorf("built-in content: %w", err)
	}
	for _, p := range allow {
		if !agentProfileRe.MatchString(p) || content.Profiles[p] == nil {
			return fmt.Errorf("--allow-profile %q is not a built-in profile", p)
		}
	}
	token, err := readToken(f.tokenFile)
	if err != nil {
		return err
	}
	opts := push.Options{URL: f.pushURL, Token: token, Pin: f.pin}
	logf := func(format string, args ...any) {
		fmt.Fprintf(cmd.ErrOrStderr(), "%s hostlint agent: %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
	}
	a := &agent{
		allow: slices.Clone(allow),
		poll:  func(ctx context.Context, allow []string) (*push.Job, error) { return push.Poll(ctx, opts, allow) },
		fail:  func(ctx context.Context, id int64, reason string) error { return push.FailJob(ctx, opts, id, reason) },
		scan: func(ctx context.Context, job *push.Job) error {
			// The scan is the one of "hostlint scan --push": same flags, the profile of the job, no output.
			sc := f
			sc.profiles, sc.format, sc.failOn, sc.color, sc.jobID = []string{job.Profile}, "json", "none", "never", job.ID
			c := &cobra.Command{}
			c.SetContext(ctx)
			c.SetOut(io.Discard)
			c.SetErr(cmd.ErrOrStderr())
			return runScan(c, sc)
		},
		now: time.Now,
		sleep: func(ctx context.Context, d time.Duration) {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
			case <-ctx.Done():
			}
		},
		log: logf,
	}
	logf("connected to %s, allowing %s", f.pushURL, strings.Join(allow, ", "))
	a.run(cmd.Context())
	return nil
}

// run polls until ctx is done.
func (a *agent) run(ctx context.Context) {
	var lastScan time.Time
	failures := 0
	for ctx.Err() == nil {
		job, err := a.poll(ctx, a.allow)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			failures++
			wait := backoff(failures)
			a.log("poll: %s (trying again in %s)", clean(err.Error()), wait.Round(time.Second))
			a.sleep(ctx, wait)
			continue
		}
		failures = 0
		if job == nil {
			continue
		}
		a.handle(ctx, job, &lastScan)
	}
}

func (a *agent) handle(ctx context.Context, job *push.Job, lastScan *time.Time) {
	// The server is trusted to ask, not to decide: the allowlist and the rate are this host's own.
	switch {
	case !slices.Contains(a.allow, job.Profile):
		a.log("job %d: profile %q is not allowed here", job.ID, job.Profile)
		a.report(ctx, job, "the agent does not allow this profile")
		return
	case !lastScan.IsZero() && a.now().Sub(*lastScan) < agentMinGap:
		a.log("job %d: a scan ran less than a minute ago", job.ID)
		a.report(ctx, job, "the agent scanned a moment ago")
		return
	}
	*lastScan = a.now()
	a.log("job %d: scanning with %s", job.ID, job.Profile)
	sctx, cancel := context.WithTimeout(ctx, agentScanLimit)
	defer cancel()
	if err := a.scan(sctx, job); err != nil {
		if ctx.Err() != nil {
			return
		}
		a.log("job %d: %s", job.ID, clean(err.Error()))
		a.report(ctx, job, "the scan failed: "+clean(err.Error()))
		return
	}
	a.log("job %d: done", job.ID)
}

func (a *agent) report(ctx context.Context, job *push.Job, reason string) {
	if err := a.fail(ctx, job.ID, truncateRunes(reason, 250)); err != nil && ctx.Err() == nil {
		a.log("job %d: could not tell the server: %s", job.ID, clean(err.Error()))
	}
}

// backoff is how long to wait after the n-th failure in a row: doubling from 5 seconds to 5 minutes, spread by up
// to a quarter so a fleet that lost its server does not come back in step.
func backoff(n int) time.Duration {
	d := agentBackoffFirst
	for i := 1; i < n && d < agentBackoffCap; i++ {
		d *= 2
	}
	d = min(d, agentBackoffCap)
	return d + time.Duration(rand.Int64N(int64(d/4)+1)) //nolint:gosec // jitter, not a secret
}

func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
