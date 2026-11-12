package cli

import (
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/with-developer/vmsctl/internal/engine"
	"github.com/with-developer/vmsctl/internal/output"
	"github.com/with-developer/vmsctl/profiles"
	"github.com/with-developer/vmsctl/rules"
)

func newExplainCommand() *cobra.Command {
	var packs []string
	var lang string
	cmd := &cobra.Command{
		Use:   "explain ID...",
		Short: "Explain a control or a check: what it looks at, why, and how to fix it",
		Long: `Explain prints what a control or a check is for: its severity, what it looks at, why it matters, and how
to fix a failure. A scan lists what failed; this tells what to do about it. ID is a control of a profile
(U-02, ES-07: every profile that has it is shown) or a check (ssh.permit-root-login).`,
		Example: `  vmsctl explain U-02
  vmsctl explain ssh.permit-root-login accounts.lockout-threshold
  vmsctl explain U-02 --lang ko`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			content, err := engine.Load(rules.FS, profiles.FS)
			if err != nil {
				return fmt.Errorf("built-in content: %w", err)
			}
			if _, err := addPacks(cmd, content, packDirsFrom(packs)); err != nil {
				return err
			}
			if lang == "" {
				lang = languageOfEnv(os.Getenv("VMSCTL_LANG"))
			}
			if lang == "" {
				lang = "en"
			}
			if !slices.Contains(output.Languages, lang) {
				return fmt.Errorf("unknown --lang %q (use %s)", lang, strings.Join(output.Languages, " or "))
			}
			out := cmd.OutOrStdout()
			missing := 0
			for i, id := range args {
				if i > 0 {
					fmt.Fprintln(out)
				}
				found := explain(out, content, id, lang)
				if !found && strings.ToUpper(id) != id {
					found = explain(out, content, strings.ToUpper(id), lang) // control IDs are upper case: u-02
				}
				if !found {
					fmt.Fprintf(cmd.ErrOrStderr(), "vmsctl: nothing is called %s: it is neither a check nor a control of a profile (profiles: %s)\n", oneLineText(id), strings.Join(sortedProfileIDs(content), ", "))
					missing++
				}
			}
			if missing > 0 {
				return fmt.Errorf("%d of %d not found", missing, len(args))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&lang, "lang", "", "language of the text: "+strings.Join(output.Languages, " or ")+", where a rule has Korean text (default: VMSCTL_LANG, else en)")
	cmd.Flags().StringArrayVar(&packs, "pack", nil, "also know the checks and profiles of this policy pack (docs/packs.md)")
	return cmd
}

func sortedProfileIDs(c *engine.Content) []string { return slices.Sorted(maps.Keys(c.Profiles)) }

// explain prints a check, or the controls with this ID; it reports whether there was anything.
func explain(w io.Writer, c *engine.Content, id string, lang string) bool {
	found := false
	if ch := c.Checks[id]; ch != nil {
		explainCheck(w, ch, "", lang)
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
			fmt.Fprintf(w, "%s  %s  [%s]\nprofile %s, %s\n", oneLineText(ctl.ID), oneLineText(pick(lang, ctl.Title, ctl.TitleKo)), ctl.Severity, oneLineText(pid), oneLineText(c.Profiles[pid].Title))
			if ctl.Manual != "" {
				fmt.Fprintf(w, "\n%s\n%s\n", label(lang, "A person decides this one:", "사람이 판단하는 항목입니다:"), wrap(pick(lang, ctl.Manual, ctl.ManualKo), "  "))
			}
			for _, ref := range ctl.Checks {
				if ch := c.Checks[ref]; ch != nil {
					fmt.Fprintln(w)
					explainCheckWith(w, ch, "  ", ctl.Params[ref], lang)
				}
			}
		}
	}
	return found
}

func explainCheck(w io.Writer, c *engine.Check, indent, lang string) {
	explainCheckWith(w, c, indent, nil, lang)
}

// pick is the text in the language asked for: the Korean one where it is asked for and there is one.
func pick(lang, text, ko string) string {
	if lang == "ko" && strings.TrimSpace(ko) != "" {
		return ko
	}
	return text
}

// label is a heading in the language asked for.
func label(lang, en, ko string) string {
	if lang == "ko" {
		return ko
	}
	return en
}

// explainCheckWith is explainCheck for a check as a control maps it: set are the parameters the control gives it.
func explainCheckWith(w io.Writer, c *engine.Check, indent string, set map[string]any, lang string) {
	fmt.Fprintf(w, "%s%s  %s  [%s]\n", indent, oneLineText(c.ID), oneLineText(pick(lang, c.Title, c.TitleKo)), c.Severity)
	section := func(name, text string) {
		if strings.TrimSpace(text) != "" {
			fmt.Fprintf(w, "%s%s:\n%s\n", indent, name, wrap(text, indent+"  "))
		}
	}
	section(label(lang, "What it looks at", "무엇을 점검하나"), pick(lang, c.Description, c.DescriptionKo))
	section(label(lang, "Why it matters", "왜 중요한가"), pick(lang, c.Rationale, c.RationaleKo))
	section(label(lang, "How to fix it", "조치 방법"), pick(lang, c.Remediation, c.RemediationKo))
	if c.Manual != nil {
		section(label(lang, "A person decides", "사람이 판단합니다"), pick(lang, c.Manual.Guidance, c.Manual.GuidanceKo))
	}
	if len(c.Platforms) > 0 {
		fmt.Fprintf(w, "%sApplies to: %s\n", indent, oneLineText(strings.Join(c.Platforms, ", ")))
	}
	if c.Applies != "" {
		fmt.Fprintf(w, "%sApplies when: %s\n", indent, oneLineText(c.Applies))
	}
	for _, name := range slices.Sorted(maps.Keys(c.Params)) {
		p := c.Params[name]
		dir := ""
		if p.Stricter != "" {
			dir = ", stricter is " + p.Stricter
		}
		value := fmt.Sprintf("default %v%s", oneLineText(fmt.Sprint(p.Default)), dir)
		if v, ok := set[name]; ok {
			value = fmt.Sprintf("this control requires %v; the check's default is %v%s", oneLineText(fmt.Sprint(v)), oneLineText(fmt.Sprint(p.Default)), dir)
		}
		fmt.Fprintf(w, "%sParameter %s (%s): %s\n", indent, oneLineText(name), value, oneLineText(p.Description))
	}
}

// wrap makes text one paragraph, cut into lines of about 100 characters, each starting with indent. The text
// may come from a pack, so control characters do not reach the terminal.
func wrap(text, indent string) string {
	words := strings.Fields(oneLineText(text)) // one paragraph, and what a pack wrote does not reach the terminal raw
	var lines []string
	line := indent
	for _, w := range words {
		if utf8.RuneCountInString(line)+utf8.RuneCountInString(w)+1 > 100 && strings.TrimSpace(line) != "" {
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
