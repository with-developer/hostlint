// Package rules embeds hostlint's built-in checks (ADR 0006): one YAML file
// per check, rules/<area>/<name>.yaml.
package rules

import "embed"

// FS holds the checks.
//
//go:embed */*.yaml
var FS embed.FS
