// Package profiles embeds the control mappings of each supported standard
// edition (ADR 0003, ADR 0007).
package profiles

import "embed"

// FS holds the profiles.
//
//go:embed *.yaml
var FS embed.FS
