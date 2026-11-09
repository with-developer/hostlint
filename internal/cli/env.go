package cli

import "os"

// env reads the environment variable VMSCTL_<name>; when that is empty it reads HOSTLINT_<name>, the name of
// the same setting before the project was renamed (ADR 0017). An empty value counts as unset, so a CI job
// that exports an empty VMSCTL_TOKEN still gets a HOSTLINT_TOKEN it already had.
func env(name string) string {
	if v := os.Getenv("VMSCTL_" + name); v != "" {
		return v
	}
	return os.Getenv("HOSTLINT_" + name)
}
