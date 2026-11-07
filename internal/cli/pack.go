package cli

import (
	"fmt"
	"io"
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
	cmd.AddCommand(newPackTestCommand(), newPackShowCommand())
	return cmd
}

type loadedPack struct {
	pack    *config.Pack
	added   *engine.PackContent
	content *engine.Content
	engine  *engine.Engine
}

// openPack loads the pack in dir next to the built-in content and compiles it.
func openPack(dir string) (*loadedPack, error) {
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
				lp.pack.Name, lp.pack.Version, lp.pack.Digest, len(lp.added.Checks), len(lp.added.Profiles), tests)
			problems := 0
			for _, n := range lp.added.Notes {
				fmt.Fprintf(out, "note: %s\n", n)
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
			failures := lp.engine.RunRuleTestsFor(cmd.Context(), nonNil(lp.added.Checks))
			for _, f := range failures {
				fmt.Fprintf(out, "FAIL %s\n", f.Error())
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

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
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
	p := lp.pack
	fmt.Fprintf(w, "pack %s %s", p.Name, p.Version)
	if p.Description != "" {
		fmt.Fprintf(w, " — %s", oneLineText(p.Description))
	}
	fmt.Fprintf(w, "\ndigest %s (%d files)\n", p.Digest, len(p.Files))
	if p.RequiresHostlint != "" {
		fmt.Fprintf(w, "requires hostlint %s or later\n", p.RequiresHostlint)
	}
	fmt.Fprintf(w, "\nchecks (%d):\n", len(lp.added.Checks))
	for _, id := range lp.added.Checks {
		c := lp.content.Checks[id]
		fmt.Fprintf(w, "  %s  %s  %s\n", id, c.Severity, checkKind(c))
		if uses := lp.engine.Uses(id); len(uses) > 0 {
			fmt.Fprintf(w, "      reads the collectors: %s\n", strings.Join(uses, ", "))
		}
		if c.File != nil {
			fmt.Fprintf(w, "      lists the files: %s\n", strings.Join(c.File.Paths, ", "))
		}
		if c.Violations != nil {
			fmt.Fprintf(w, "      evidence: %s\n", oneLineText(c.Violations.Text))
		}
		if c.Manual != nil && c.Manual.Show != "" {
			fmt.Fprintf(w, "      shows: %s\n", oneLineText(c.Manual.Show))
		}
		if c.Applies != "" {
			fmt.Fprintf(w, "      applies when: %s\n", oneLineText(c.Applies))
		}
	}
	fmt.Fprintf(w, "\nprofiles (%d):\n", len(lp.added.Profiles))
	for _, pid := range lp.added.Profiles {
		pr := lp.content.Profiles[pid]
		fmt.Fprintf(w, "  %s revision %d — %s\n", pr.ID, pr.Revision, oneLineText(pr.Title))
		for _, c := range pr.Controls {
			what := strings.Join(c.Checks, ", ")
			if c.Manual != "" {
				what = "(a person decides)"
			}
			fmt.Fprintf(w, "      %s  %s  %s: %s\n", c.ID, c.Severity, oneLineText(c.Title), what)
			for _, id := range slices.Sorted(mapsKeys(c.Params)) {
				fmt.Fprintf(w, "          parameters of %s: %v\n", id, c.Params[id])
			}
		}
	}
	if len(lp.added.Notes) > 0 {
		fmt.Fprintln(w, "\nnotes:")
		for _, n := range lp.added.Notes {
			fmt.Fprintf(w, "  %s\n", n)
		}
	}
}

func mapsKeys[K comparable, V any](m map[K]V) func(func(K) bool) {
	return func(yield func(K) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func checkKind(c *engine.Check) string {
	switch {
	case c.Setting != nil:
		return "setting " + c.Setting.Fact
	case c.File != nil:
		return "file"
	case c.Violations != nil:
		return "violations over " + c.Violations.Over
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
