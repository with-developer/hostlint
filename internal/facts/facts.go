// Package facts holds the building blocks of the facts collectors expose to
// rules (ADR 0006 §2). Fact types are the public contract for rule authors:
// their `json` tags are the names rules use in CEL and in test fact documents.
package facts

import (
	"fmt"
	"reflect"
)

// Setting is one configuration value, in one of three states:
//   - explicit: set in a configuration file (Explicit is true);
//   - default: not set, and the default for the installed software version
//     is known (Explicit is false);
//   - unknown: not set and no default is known. Unknown settings are absent
//     from their map, so a rule reading one fails instead of guessing.
//
// Values are the effective value as text, never reinterpreted: a "-1" that
// means "no limit" stays "-1".
type Setting struct {
	Value    string `json:"value"`
	Explicit bool   `json:"explicit"`
	// Source is where the value came from, e.g. "/etc/login.defs:25",
	// "default (OpenSSH 9.6)" or "sshd -T".
	Source string `json:"source"`
}

// CheckType reports whether t (a struct type) only uses field types that CEL
// handles unambiguously: string, int64, bool, slices, string-keyed maps and
// nested structs. Pointers, unsigned integers and time.Time are rejected: CEL
// reads a nil pointer as a zero value and treats zero as "unset", and a uint
// does not compare with int literals. Every fact field needs a json tag.
func CheckType(t reflect.Type) error {
	return checkType(t, t.Name(), map[reflect.Type]bool{})
}

func checkType(t reflect.Type, where string, seen map[reflect.Type]bool) error {
	switch t.Kind() {
	case reflect.String, reflect.Int64, reflect.Bool:
		return nil
	case reflect.Slice:
		return checkType(t.Elem(), where+"[]", seen)
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return fmt.Errorf("%s: map keys must be strings", where)
		}
		return checkType(t.Elem(), where+"[]", seen)
	case reflect.Struct:
		if t.PkgPath() == "time" {
			return fmt.Errorf("%s: time.Time is not allowed; use an int64 or a string", where)
		}
		if seen[t] {
			return nil
		}
		seen[t] = true
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name := f.Tag.Get("json")
			if name == "" || name == "-" {
				return fmt.Errorf("%s.%s: exported fact fields need a json tag", where, f.Name)
			}
			if err := checkType(f.Type, where+"."+name, seen); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("%s: %s is not allowed in facts (use string, int64, bool, slices, maps or structs)", where, t)
	}
}

// OS describes the target's operating system: the `os` variable.
type OS struct {
	ID           string   `json:"id"`
	IDLike       []string `json:"id_like"`
	VersionID    string   `json:"version_id"`
	VersionMajor int64    `json:"version_major"`
	Name         string   `json:"name"`
	Family       string   `json:"family"` // debian, rhel or unknown
	Supported    bool     `json:"supported"`
}
