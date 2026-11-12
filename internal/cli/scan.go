package cli

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/with-developer/vmsctl/internal/collect"
	"github.com/with-developer/vmsctl/internal/config"
	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/hostfs"
	"github.com/with-developer/vmsctl/internal/image"
	"github.com/with-developer/vmsctl/internal/output"
	"github.com/with-developer/vmsctl/internal/signing"
	"github.com/with-developer/vmsctl/internal/version"
	"github.com/with-developer/vmsctl/profiles"
	"github.com/with-developer/vmsctl/rules"
)

// failOnLevels are the accepted --fail-on values, lowest first.
var failOnLevels = []string{"low", "medium", "high", "none"}

// findingsError means the scan ran and found failures at or above the
// --fail-on threshold; Execute turns it into ExitFail.
type findingsError struct {
	controls  int
	threshold string
}

// regressionError means `vmsctl diff --fail-on-regression` found controls that got worse.
type regressionError struct{ controls int }

func (e *regressionError) Error() string {
	return fmt.Sprintf("%d control(s) regressed since the earlier scan", e.controls)
}

func (e *findingsError) Error() string {
	return fmt.Sprintf("%d control(s) failed or could not be checked at severity %s or above", e.controls, e.threshold)
}

// defaultProfile is scanned when neither --profile nor vmsctl.yaml names one.
const defaultProfile = "kisa-2026"

type scanFlags struct {
	format, output, root, failOn, color, config string
	pushURL, pin, tokenFile, signKey, imageTar  string
	lang                                        string // the language of the titles in the table and in Markdown (--lang)
	name                                        string // the asset name of an image in the result (--name)
	labels                                      []string
	profiles, packs                             []string
	verifyPack                                  bool
	verbose                                     bool
	jobID                                       int64 // the agent's job this scan answers (vmsctl agent)
}

func newScanCommand() *cobra.Command {
	var f scanFlags
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Check this host, or a mounted root filesystem, against a profile",
		Long: `Scan checks the host it runs on (or, with --root, a filesystem mounted
elsewhere) against a profile and reports a result per control.

vmsctl only reads: it never changes the host. Run it as root, or checks that
need protected files (such as /etc/shadow) report ERROR.`,
		Example: `  sudo vmsctl scan
  sudo vmsctl scan --format json --output web-01.json
  sudo vmsctl scan --root /mnt/image --fail-on high

  # scan a container image from the archive docker save wrote (nothing is mounted or run)
  docker save app:1.4 -o app.tar && vmsctl scan --image-tar app.tar --fail-on high

  # scan and send the result to a vmsctl server (the token is in VMSCTL_TOKEN)
  sudo vmsctl scan --push https://vmsctl.example.org:8443 --pin sha256/...`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd, f)
		},
	}
	fl := cmd.Flags()
	fl.StringArrayVarP(&f.profiles, "profile", "p", nil, "profile to check against; repeat it to check several (default: kisa-2026, or the one in vmsctl.yaml)")
	fl.StringArrayVar(&f.packs, "pack", nil, "load a policy pack, a directory of your own checks and profiles (docs/packs.md); repeatable, also VMSCTL_PACK (a list of directories); select its profile with --profile")
	fl.BoolVar(&f.verifyPack, "verify-pack", false, "with --pack: run the tests of the pack's checks before the scan, and refuse to scan when one fails")
	fl.StringVarP(&f.format, "format", "f", "table", "output format: "+strings.Join(output.Formats, ", "))
	fl.StringVar(&f.lang, "lang", "", "language of the control and check titles in the table and in Markdown: "+strings.Join(output.Languages, " or ")+" (default: VMSCTL_LANG, else en); the other formats are not translated")
	fl.StringVarP(&f.output, "output", "o", "", "write the report to this file instead of stdout")
	fl.StringVar(&f.root, "root", "/", "scan a filesystem mounted at this directory instead of the running system")
	fl.StringVar(&f.name, "name", "", "with --image-tar: the name the image goes by in the result and on a fleet server, such as ghcr.io/acme/app (default: the reference of the archive without its tag)")
	fl.StringVar(&f.imageTar, "image-tar", "", "scan the filesystem of a container image from this archive (docker save, or an OCI layout) instead of a host (docs/images.md)")
	fl.StringVar(&f.failOn, "fail-on", "low", "exit with status 1 when a control of this severity or higher fails or could not be checked (ERROR): "+strings.Join(failOnLevels, ", "))
	fl.StringArrayVar(&f.labels, "label", nil, "add a key=value label to the host in the report (repeatable)")
	fl.BoolVarP(&f.verbose, "verbose", "v", false, "also list passing and not-applicable controls in the table")
	fl.StringVar(&f.color, "color", "auto", "color the table: auto, always or never")
	fl.StringVar(&f.pushURL, "push", "", "after the scan, send the result to this vmsctl server (docs/fleet.md)")
	fl.StringVar(&f.pin, "pin", "", `with --push: trust the server's public key ("sha256/<base64>") instead of the system roots`)
	fl.StringVar(&f.tokenFile, "token-file", "", "with --push: read the ingest token from this file (default: the VMSCTL_TOKEN environment variable)")
	fl.StringVar(&f.signKey, "sign-key", "", "with --push: sign the result with this key (made with: vmsctl key generate)")
	fl.StringVar(&f.config, "config", "", "configuration file (default: ./vmsctl.yaml, then /etc/vmsctl/vmsctl.yaml, if present)")
	return cmd
}

func runScan(cmd *cobra.Command, f scanFlags) error {
	if !output.ValidFormat(f.format) {
		return fmt.Errorf("unknown --format %q (use %s)", f.format, strings.Join(output.Formats, ", "))
	}
	lang, err := resolveLang(f.lang)
	if err != nil {
		return err
	}
	f.lang = lang
	if !slices.Contains(failOnLevels, f.failOn) {
		return fmt.Errorf("unknown --fail-on %q (use %s)", f.failOn, strings.Join(failOnLevels, ", "))
	}
	if f.color != "auto" && f.color != "always" && f.color != "never" {
		return fmt.Errorf("unknown --color %q (use auto, always or never)", f.color)
	}
	labels, err := parseLabels(f.labels)
	if err != nil {
		return err
	}
	if f.imageTar != "" {
		if f.root != "/" {
			return errors.New("--image-tar and --root exclude each other")
		}
	} else if f.name != "" {
		return errors.New("--name is for --image-tar")
	}
	// A scan that cannot be sent is found out before it runs, not after.
	token := ""
	if f.pushURL != "" {
		if token, err = readToken(f.tokenFile); err != nil {
			return err
		}
	} else if f.pin != "" || f.tokenFile != "" || f.signKey != "" {
		return errors.New("--pin, --token-file and --sign-key are for --push")
	}
	var signer ed25519.PrivateKey
	if f.signKey != "" {
		if signer, err = signing.Load(f.signKey); err != nil {
			return err
		}
	}

	content, err := engine.Load(rules.FS, profiles.FS)
	if err != nil {
		return fmt.Errorf("built-in content: %w", err)
	}
	packDirs := packDirsFrom(f.packs)
	if len(packDirs) == 0 && f.verifyPack {
		return errors.New("--verify-pack is for --pack")
	}
	opts := engine.Options{Labels: labels, Profiles: f.profiles}
	packs, err := addPacks(cmd, content, packDirs)
	if err != nil {
		return err
	}
	opts.Packs = packs.infos
	cfgPath, unusedCfg, err := config.FindNotes(f.config)
	if err != nil {
		return err
	}
	for _, u := range unusedCfg {
		fmt.Fprintf(cmd.ErrOrStderr(), "vmsctl: %s is not used: %s has the new name of the file (the old one is for hosts that still run a release before v0.27.0)\n", u, cfgPath)
	}
	var cfg *config.File
	if cfgPath != "" {
		if config.LegacyName(cfgPath) {
			fmt.Fprintf(cmd.ErrOrStderr(), "vmsctl: %s has the old name of the file: rename it to vmsctl.yaml\n", cfgPath)
		}
		if cfg, err = config.Load(cfgPath); err != nil {
			return err
		}
	}
	// The profiles to scan with: --profile, else the one of vmsctl.yaml, else the default.
	if len(opts.Profiles) == 0 {
		switch {
		case cfg != nil && cfg.Profile != "":
			opts.Profiles = []string{cfg.Profile}
		default:
			opts.Profiles = []string{defaultProfile}
		}
	}
	if cfg != nil {
		if err := cfg.ValidateProfiles(content, opts.Profiles); err != nil {
			return fmt.Errorf("%s:\n%w", cfgPath, err)
		}
		opts.Params, opts.Waivers = cfg.Engine()
		opts.Attestations = cfg.EngineAttestations()
	}
	e, err := engine.New(content, collect.All()...)
	if err != nil {
		return fmt.Errorf("built-in content: %w", err)
	}
	if err := packs.check(cmd, e, opts.Profiles, f.verifyPack); err != nil {
		return err
	}
	var h *hostfs.Host
	var imageInfo *engine.ImageInfo
	name := ""
	if f.imageTar != "" {
		img, err := image.Load(cmd.Context(), f.imageTar)
		if err != nil {
			return fmt.Errorf("--image-tar %s: %s", f.imageTar, printable(err.Error()))
		}
		if !hasOSRelease(img.FS) {
			// A scratch or distroless image has no operating system to judge: absent files would pass.
			return fmt.Errorf("--image-tar %s: no operating system found in the image (no os-release): a scratch or distroless image cannot be checked", f.imageTar)
		}
		// An image goes to a fleet server as an asset of its own (ADR 0016): named by its repository, with no host ID; every
		// scan records the tag and the image ID.
		if f.pushURL != "" || f.name != "" {
			if name, err = assetName(f.name, img.Ref); err != nil {
				return fmt.Errorf("--image-tar %s: %w", f.imageTar, err)
			}
		}
		h = hostfs.NewImageHost(img.FS, img.Label)
		h.Asset = name
		imageInfo = &engine.ImageInfo{Ref: img.Ref, Digest: img.Digest}
	} else if h, err = hostfs.Open(f.root); err != nil {
		return err
	}
	defer h.Close()

	info := version.Get()
	opts.Tool = engine.ToolInfo{Name: "vmsctl", Version: info.Version, Commit: info.Commit}
	res, err := e.Scan(cmd.Context(), h, opts)
	if err != nil {
		return err
	}
	if imageInfo != nil {
		res.Scan.Target.Image = imageInfo
	}
	if f.imageTar != "" && res.Host.OS.ID == "unknown" {
		// A scratch or distroless image has no operating system to judge: absent files would pass.
		return fmt.Errorf("--image-tar %s: no operating system found in the image (no os-release): a scratch or distroless image cannot be checked", f.imageTar)
	}
	if f.root != "/" && res.Host.OS.ID == "unknown" {
		// Without an operating system, absent files would read as passing
		// checks for a root that was never a system.
		return fmt.Errorf("--root %s: no operating system found there (no os-release); is it the root of a mounted system?", f.root)
	}

	outOpts := output.Options{Verbose: f.verbose, Color: useColor(f.color, f.output, cmd.OutOrStdout()), Lang: f.lang}
	if f.output != "" {
		err = output.WriteFile(f.output, res, f.format, outOpts)
	} else {
		err = output.Write(cmd.OutOrStdout(), res, f.format, outOpts)
	}
	if err != nil {
		return err
	}
	if f.pushURL != "" {
		if err := pushScan(cmd, res, f, token, signer); err != nil {
			return err
		}
	}
	if n := failedAtOrAbove(res, f.failOn); n > 0 {
		return &findingsError{controls: n, threshold: f.failOn}
	}
	return nil
}

// printable replaces the control characters of s: names from an image reach the terminal and CI logs.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return '?'
		}
		return r
	}, s)
}

// hasOSRelease reports whether a filesystem has an os-release file, where an operating system names itself.
func hasOSRelease(fsys hostfs.FS) bool {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if _, err := fsys.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func parseLabels(raw []string) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	labels := map[string]string{}
	for _, l := range raw {
		k, v, ok := strings.Cut(l, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--label %q: want key=value", l)
		}
		labels[k] = v
	}
	return labels, nil
}

// failedAtOrAbove counts FAIL and ERROR controls whose severity reaches
// threshold: a control that could not be checked is not a pass.
func failedAtOrAbove(res *engine.Result, threshold string) int {
	if threshold == "none" {
		return 0
	}
	minRank := engine.Severity(threshold).Rank()
	n := 0
	for _, c := range res.Controls {
		if (c.Status == engine.StatusFail || c.Status == engine.StatusError) && c.Severity.Rank() >= minRank {
			n++
		}
	}
	return n
}

// useColor decides whether the table gets ANSI colors: never when writing a
// file or when NO_COLOR is set, otherwise only on a terminal.
func useColor(mode, outputPath string, w io.Writer) bool {
	switch {
	case mode == "always":
		return true
	case mode == "never", outputPath != "", os.Getenv("NO_COLOR") != "", os.Getenv("TERM") == "dumb":
		return false
	}
	return isTerminal(w)
}

// isTerminal reports whether w is a terminal.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

var assetNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$`)

// assetName is the name an image goes by on a fleet server: --name when given, else the repository of the reference the
// archive names it with (no tag, no digest), so the tags of one image are the history of one asset. An archive that names
// no image needs --name.
func assetName(flag, ref string) (string, error) {
	if flag != "" {
		if !assetNameRe.MatchString(flag) {
			return "", errors.New("--name is letters, digits and . _ : / @ + -, at most 200 characters")
		}
		return flag, nil
	}
	if ref == "" {
		return "", errors.New("the archive names no image (it was saved without a tag): give the image a name with --name")
	}
	repo := ref
	if i := strings.Index(repo, "@"); i >= 0 {
		repo = repo[:i]
	}
	if i := strings.LastIndex(repo, ":"); i > strings.LastIndex(repo, "/") {
		repo = repo[:i] // a colon after the last slash is a tag, one before it a registry port
	}
	if !assetNameRe.MatchString(repo) {
		return "", fmt.Errorf("%q is not a name for an image: give one with --name", ref)
	}
	return repo, nil
}

// languageOfEnv is the language of the value of VMSCTL_LANG: "ko" for ko, KO, ko_KR and ko_KR.UTF-8, "" when it is not a language
// vmsctl has titles in.
func languageOfEnv(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if i := strings.IndexAny(v, "_.-@"); i >= 0 {
		v = v[:i]
	}
	if slices.Contains(output.Languages, v) {
		return v
	}
	return ""
}

// resolveLang is the language of a command: the --lang flag, else VMSCTL_LANG, else English. The environment names a locale as often
// as a language (ko_KR.UTF-8, KO): its language is taken, and a value that is none of ours is ignored, so a shell profile never breaks
// a command; a flag that is none of ours is an error.
func resolveLang(flag string) (string, error) {
	lang := flag
	if lang == "" {
		lang = languageOfEnv(os.Getenv("VMSCTL_LANG"))
	}
	if lang == "" {
		lang = "en"
	}
	if !slices.Contains(output.Languages, lang) {
		return "", fmt.Errorf("unknown --lang %q (use %s)", lang, strings.Join(output.Languages, " or "))
	}
	return lang, nil
}
