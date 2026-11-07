package cli

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/with-developer/hostlint/internal/engine"
	"github.com/with-developer/hostlint/profiles"
	"github.com/with-developer/hostlint/rules"
)

func newExplainCommand() *cobra.Command {
	var packs []string
	cmd := &cobra.Command{
		Use:   "explain ID...",
		Short: "Explain a control or a check: what it looks at, why, and how to fix it",
		Long: `Explain prints what a control or a check is for: its severity, what it looks at, why it matters, and how
to fix a failure. A scan lists what failed; this tells what to do about it. ID is a control of a profile
(U-02, ES-07: every profile that has it is shown) or a check (ssh.permit-root-login).`,
		Example: `  hostlint explain U-02
  hostlint explain ssh.permit-root-login accounts.lockout-threshold`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			content, err := engine.Load(rules.FS, profiles.FS)
			if err != nil {
				return fmt.Errorf("built-in content: %w", err)
			}
			if _, err := addPacks(cmd, content, uniqueDirs(append(packs, splitPackEnv(os.Getenv("HOSTLINT_PACK"))...))); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			missing := 0
			for i, id := range args {
				if i > 0 {
					fmt.Fprintln(out)
				}
				if !explain(out, content, id) {
					fmt.Fprintf(cmd.ErrOrStderr(), "hostlint: nothing is called %s: it is neither a check nor a control of a profile (profiles: %s)\n", oneLineText(id), strings.Join(sortedProfileIDs(content), ", "))
					missing++
				}
			}
			if missing > 0 {
				return fmt.Errorf("%d of %d not found", missing, len(args))
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&packs, "pack", nil, "also know the checks and profiles of this policy pack (docs/packs.md)")
	return cmd
}

func sortedProfileIDs(c *engine.Content) []string {
	ids := make([]string, 0, len(c.Profiles))
	for id := range c.Profiles {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// explain prints a check, or the controls with this ID; it reports whether there was anything.
func explain(w io.Writer, c *engine.Content, id string) bool {
	found := false
	if ch := c.Checks[id]; ch != nil {
		explainCheck(w, ch, "")
		found = true
	}
	for _, pid := range sortedProfileIDs(c) {
		for _, ctl := range c.Profiles[pid].Controls {
			if ctl.ID != id {
				continue
			}
			if found {
				fmt.Fprintln(w)
			}
			found = true
			fmt.Fprintf(w, "%s  %s  [%s]\nprofile %s, %s\n", oneLineText(ctl.ID), oneLineText(ctl.Title), ctl.Severity, oneLineText(pid), oneLineText(c.Profiles[pid].Title))
			if ctl.Manual != "" {
				fmt.Fprintf(w, "\nA person decides this one:\n%s\n", wrap(ctl.Manual, "  "))
			}
			for _, ref := range ctl.Checks {
				if ch := c.Checks[ref]; ch != nil {
					fmt.Fprintln(w)
					explainCheck(w, ch, "  ")
				}
			}
		}
	}
	return found
}

func explainCheck(w io.Writer, c *engine.Check, indent string) {
	fmt.Fprintf(w, "%s%s  %s  [%s]\n", indent, oneLineText(c.ID), oneLineText(c.Title), c.Severity)
	section := func(name, text string) {
		if strings.TrimSpace(text) != "" {
			fmt.Fprintf(w, "%s%s:\n%s\n", indent, name, wrap(text, indent+"  "))
		}
	}
	section("What it looks at", c.Description)
	section("Why it matters", c.Rationale)
	section("How to fix it", c.Remediation)
	if c.Manual != nil {
		section("A person decides", c.Manual.Guidance)
	}
	if len(c.Platforms) > 0 {
		fmt.Fprintf(w, "%sApplies to: %s\n", indent, oneLineText(strings.Join(c.Platforms, ", ")))
	}
	for _, name := range slices.Sorted(mapsKeysOf(c.Params)) {
		p := c.Params[name]
		dir := ""
		if p.Stricter != "" {
			dir = ", stricter is " + p.Stricter
		}
		fmt.Fprintf(w, "%sParameter %s (default %v%s): %s\n", indent, oneLineText(name), p.Default, dir, oneLineText(p.Description))
	}
}

func mapsKeysOf[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// wrap makes text one paragraph, cut into lines of about 100 characters, each starting with indent. The text
// may come from a pack, so control characters do not reach the terminal.
func wrap(text, indent string) string {
	words := strings.Fields(printable(text))
	var lines []string
	line := indent
	for _, w := range words {
		if len(line)+len(w)+1 > 100 && strings.TrimSpace(line) != "" {
			lines = append(lines, line)
			line = indent
		}
		if strings.TrimSpace(line) != "" {
			line += " "
		}
		line += w
	}
	if strings.TrimSpace(line) != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}
