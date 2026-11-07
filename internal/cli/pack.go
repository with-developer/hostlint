package cli

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/with-developer/hostlint/internal/collect"
	"github.com/with-developer/hostlint/internal/config"
	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/profiles"
	"github.com/with-developer/hostlint/rules"
)

// packTestError means `hostlint pack test` found a problem with a pack that loads: a failing test, or a
// pack nothing can select.
type packTestError struct{ problems int }

func (e *packTestError) Error() string {
	return fmt.Sprintf("%d problem(s) with the pack", e.problems)
}

func newPackCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pack",
		Short: "Test and inspect a policy pack: your own checks and profiles (docs/packs.md)",
		Long: `A policy pack is a directory with pack.yaml, rules/<area>/<name>.yaml (checks) and
profiles/<id>.yaml (profiles), in the format of hostlint's own content. The area of every check and the
ID of every profile start with "x-". A pack can only use what the compiled-in collectors observe: it
adds no collector, command or function. It is trusted like hostlint.yaml, so read it with "pack show"
before you use it.`,
	}
	cmd.AddCommand(newPackTestCommand(), newPackShowCommand(), newPackFactsCommand())
	return cmd
}

type loadedPack struct {
	pack    *config.Pack
	added   *engine.PackContent
	content *engine.Content
	engine  *engine.Engine
}

// openPack loads the pack in dir next to the built-in content and compiles it.
func openPack(dir string) (lp *loadedPack, err error) {
	// What a pack's files are called and say reaches the terminal in these errors.
	defer func() {
		if err != nil {
			err = errors.New(printable(err.Error()))
		}
	}()
	p, err := config.LoadPack(dir)
	if err != nil {
		return nil, err
	}
	content, err := engine.Load(rules.FS, profiles.FS)
	if err != nil {
		return nil, fmt.Errorf("built-in content: %w", err)
	}
	added, err := content.Extend(p.Source)
	if err != nil {
		return nil, fmt.Errorf("pack %s: %w", p.Name, err)
	}
	e, err := engine.New(content, collect.All()...)
	if err != nil {
		return nil, fmt.Errorf("pack %s: %w", p.Name, err)
	}
	return &loadedPack{pack: p, added: added, content: content, engine: e}, nil
}

func newPackTestCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "test DIR",
		Short:   "Load a pack and run the tests of its checks",
		Example: "  hostlint pack test ./acme-pack",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lp, err := openPack(args[0])
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			tests := 0
			for _, id := range lp.added.Checks {
				tests += len(lp.content.Checks[id].Tests)
			}
			fmt.Fprintf(out, "pack %s %s (%s): %d checks, %d profiles, %d tests\n",
				oneLineText(lp.pack.Name), oneLineText(lp.pack.Version), lp.pack.Digest, len(lp.added.Checks), len(lp.added.Profiles), tests)
			problems := 0
			for _, n := range lp.added.Notes {
				fmt.Fprintf(out, "note: %s\n", oneLineText(n))
			}
			if len(lp.added.Profiles) == 0 {
				fmt.Fprintln(out, "problem: the pack has no profile, so nothing can select its checks")
				problems++
			}
			mapped := map[string]bool{}
			for _, pid := range lp.added.Profiles {
				for _, c := range lp.content.Profiles[pid].Controls {
					for _, id := range c.Checks {
						mapped[id] = true
					}
				}
			}
			for _, id := range lp.added.Checks {
				if !mapped[id] {
					fmt.Fprintf(out, "problem: check %s is in no profile of the pack\n", id)
					problems++
				}
			}
			failures := lp.engine.RunRuleTestsOf(cmd.Context(), lp.added.Checks)
			for _, f := range failures {
				fmt.Fprintf(out, "FAIL %s\n", oneLineText(f.Error()))
			}
			problems += len(failures)
			if problems == 0 {
				fmt.Fprintln(out, "ok")
				return nil
			}
			return &packTestError{problems: problems}
		},
	}
}

func newPackShowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "show DIR",
		Short: "Show what a pack does: the collectors, files and evidence its checks use, and how its profiles map them",
		Long: `Show prints what a reviewer needs before a pack is used: its name, version and digest, for every check
the collectors it reads, the file paths it lists, the expressions that decide what is shown as evidence, and
for every profile the controls with their severity and the checks they map. Nothing is scanned.`,
		Example: "  hostlint pack show ./acme-pack",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lp, err := openPack(args[0])
			if err != nil {
				return err
			}
			showPack(cmd.OutOrStdout(), lp)
			return nil
		},
	}
}

func showPack(w io.Writer, lp *loadedPack) {
	t := oneLineText // everything a pack says goes through this on its way to the terminal
	p := lp.pack
	fmt.Fprintf(w, "pack %s %s", t(p.Name), t(p.Version))
	if p.Description != "" {
		fmt.Fprintf(w, " — %s", t(p.Description))
	}
	fmt.Fprintf(w, "\ndigest %s (%d files)\n", p.Digest, len(p.Files))
	if p.RequiresHostlint != "" {
		fmt.Fprintf(w, "requires hostlint %s or later\n", t(p.RequiresHostlint))
	}
	fmt.Fprintf(w, "\nchecks (%d):\n", len(lp.added.Checks))
	for _, id := range lp.added.Checks {
		c := lp.content.Checks[id]
		fmt.Fprintf(w, "  %s  %s  %s\n", t(id), c.Severity, checkKind(c))
		if uses := lp.engine.Uses(id); len(uses) > 0 {
			fmt.Fprintf(w, "      reads the collectors: %s\n", t(strings.Join(uses, ", ")))
		}
		if c.Applies != "" {
			fmt.Fprintf(w, "      applies when: %s\n", t(c.Applies))
		}
		for _, line := range checkLogic(c) {
			fmt.Fprintf(w, "      %s\n", t(line))
		}
	}
	fmt.Fprintf(w, "\nprofiles (%d):\n", len(lp.added.Profiles))
	for _, pid := range lp.added.Profiles {
		pr := lp.content.Profiles[pid]
		fmt.Fprintf(w, "  %s revision %d — %s\n", t(pr.ID), pr.Revision, t(pr.Title))
		for _, c := range pr.Controls {
			what := strings.Join(c.Checks, ", ")
			if c.Manual != "" {
				what = "(a person decides)"
			}
			fmt.Fprintf(w, "      %s  %s  %s: %s\n", t(c.ID), c.Severity, t(c.Title), t(what))
			for _, id := range slices.Sorted(maps.Keys(c.Params)) {
				fmt.Fprintf(w, "          parameters of %s: %s\n", t(id), t(fmt.Sprint(c.Params[id])))
			}
		}
	}
	if len(lp.added.Notes) > 0 {
		fmt.Fprintln(w, "\nnotes:")
		for _, n := range lp.added.Notes {
			fmt.Fprintf(w, "  %s\n", t(n))
		}
	}
}

// checkLogic says what decides PASS or FAIL in a check, and what it shows as evidence: what a reviewer
// reads to see that a check does what its title says.
func checkLogic(c *engine.Check) []string {
	var out []string
	switch {
	case c.Setting != nil:
		s := c.Setting
		switch {
		case len(s.In) > 0:
			out = append(out, fmt.Sprintf("passes when the value is one of %q", s.In))
		case s.Range != nil:
			out = append(out, fmt.Sprintf("passes when the value is a number from %s to %s", bound(s.Range.Min), bound(s.Range.Max)))
		case s.Matches != "":
			out = append(out, fmt.Sprintf("passes when the value matches %q", s.Matches))
		}
		out = append(out, "when it is not set: "+s.Absent)
	case c.File != nil:
		f := c.File
		out = append(out, fmt.Sprintf("lists the files %s: owner one of %v, group one of %v, mode %q or stricter; a missing file: %s", strings.Join(f.Paths, ", "), f.Owner, f.Group, f.Mode, f.Missing))
		if f.NoMatch != "" {
			out = append(out, "a pattern that matches nothing: "+f.NoMatch)
		}
	case c.Violations != nil:
		v := c.Violations
		out = append(out, "fails for each "+v.As+" of "+v.Over+" where: "+v.Where, "evidence, key: "+v.Key, "evidence, text: "+v.Text)
	case c.Expect != "":
		out = append(out, "passes when: "+c.Expect)
	case c.Manual != nil:
		out = append(out, "a person decides: "+c.Manual.Guidance)
		if c.Manual.Show != "" {
			out = append(out, "shows: "+c.Manual.Show)
		}
	}
	return out
}

func bound(b *engine.Bound) string {
	switch {
	case b == nil:
		return "?"
	case b.Param != "":
		return "params." + b.Param
	}
	return fmt.Sprint(b.Value)
}

func checkKind(c *engine.Check) string {
	switch {
	case c.Setting != nil:
		return "setting " + c.Setting.Fact
	case c.File != nil:
		return "file"
	case c.Violations != nil:
		return "violations"
	case c.Expect != "":
		return "expect"
	case c.Manual != nil:
		return "manual"
	}
	return "?"
}

// oneLineText makes text from a pack safe for one terminal line: it is not ours, so control characters
// do not reach the terminal.
func oneLineText(s string) string {
	return printable(strings.Join(strings.Fields(s), " "))
}

// splitPackEnv reads HOSTLINT_PACK: a list of directories separated like PATH.
func splitPackEnv(v string) []string {
	var out []string
	for _, d := range filepath.SplitList(v) {
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

// loadedPacks are the policy packs a scan uses.
type loadedPacks struct {
	infos []engine.PackInfo
	added []*engine.PackContent
	notes []string
}

// addPacks loads the packs in dirs and adds them to the content, in the order given.
func addPacks(cmd *cobra.Command, content *engine.Content, dirs []string) (*loadedPacks, error) {
	lp := &loadedPacks{}
	for _, dir := range dirs {
		p, err := config.LoadPack(dir)
		if err != nil {
			return nil, errors.New(printable(err.Error()))
		}
		added, err := content.Extend(p.Source)
		if err != nil {
			return nil, errors.New(printable(fmt.Sprintf("pack %s: %v", p.Name, err)))
		}
		lp.infos = append(lp.infos, engine.PackInfo{Name: p.Name, Version: p.Version, Digest: p.Digest})
		lp.added = append(lp.added, added)
		for _, n := range added.Notes {
			lp.notes = append(lp.notes, p.Name+": "+n)
			fmt.Fprintf(cmd.ErrOrStderr(), "hostlint: pack %s: note: %s\n", oneLineText(p.Name), oneLineText(n))
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "hostlint: using pack %s %s (%s)\n", oneLineText(p.Name), oneLineText(p.Version), p.Digest)
	}
	return lp, nil
}

// check runs after the engine compiled the content: a pack none of whose profiles is selected is an error
// (a scan that quietly ignores the pack would be a false assurance), and with --verify-pack the tests of
// the pack's checks run first.
func (lp *loadedPacks) check(cmd *cobra.Command, e *engine.Engine, selected []string, verify bool) error {
	for i, added := range lp.added {
		name := lp.infos[i].Name
		if len(added.Profiles) == 0 {
			return fmt.Errorf("pack %s has no profile: nothing can select its checks", name)
		}
		if !slices.ContainsFunc(selected, func(id string) bool { return slices.Contains(added.Profiles, id) }) {
			return errors.New(printable(fmt.Sprintf("pack %s is loaded, but none of its profiles is selected: add --profile %s", name, strings.Join(added.Profiles, " or --profile "))))
		}
		if verify {
			if failures := e.RunRuleTestsOf(cmd.Context(), added.Checks); len(failures) > 0 {
				for _, f := range failures {
					fmt.Fprintf(cmd.ErrOrStderr(), "FAIL %s\n", oneLineText(f.Error()))
				}
				return fmt.Errorf("pack %s fails %d of its own tests: not scanning with it", name, len(failures))
			}
		}
	}
	return nil
}

// uniqueDirs drops a directory named twice (by --pack and HOSTLINT_PACK, say), as the same path.
func uniqueDirs(dirs []string) []string {
	var out, seen []string
	for _, d := range dirs {
		abs, err := filepath.Abs(d)
		if err != nil {
			abs = filepath.Clean(d)
		}
		if !slices.Contains(seen, abs) {
			seen = append(seen, abs)
			out = append(out, d)
		}
	}
	return out
}

func newPackFactsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "facts [COLLECTOR]",
		Short: "List the facts a check or a pack can read (docs/facts.md has them with their descriptions)",
		Long: `Facts lists every fact path the compiled-in collectors produce, with its type: the names a check
writes in its expressions. Give a collector (sshd, login_defs, ...) to see only its facts.`,
		Example: "  hostlint pack facts sshd",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			content, err := engine.Load(rules.FS, profiles.FS)
			if err != nil {
				return fmt.Errorf("built-in content: %w", err)
			}
			e, err := engine.New(content, collect.All()...)
			if err != nil {
				return fmt.Errorf("built-in content: %w", err)
			}
			out := cmd.OutOrStdout()
			shown := 0
			for _, f := range e.FactCatalog() {
				root, _, _ := strings.Cut(f.Path, ".")
				if len(args) == 1 && root != args[0] {
					continue
				}
				shown++
				fmt.Fprintf(out, "%-60s %s\n", f.Path, f.Type)
			}
			if shown == 0 {
				return fmt.Errorf("no collector %q (have: %s)", args[0], strings.Join(e.FactCollectors(), ", "))
			}
			return nil
		},
	}
}
