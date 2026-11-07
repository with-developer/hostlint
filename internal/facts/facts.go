// Package facts holds the building blocks of the facts collectors expose to
// rules (ADR 0006 §2). Fact types are the public contract for rule authors:
// their `json` tags are the names rules use in CEL and in test fact documents.
package facts

import (
	"fmt"
	"reflect"
	"strings"
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
	// Value is the effective value as text.
	Value string `json:"value"`
	// Explicit is true when the value is set in a configuration file, false when it is a default.
	Explicit bool `json:"explicit"`
	// Source is where the value came from, e.g. "/etc/login.defs:25",
	// "default (OpenSSH 9.6)" or "sshd -T".
	Source string `json:"source"`
}

// CheckType reports whether t (a struct type) only uses field types that CEL
// handles unambiguously: string, int64, bool, slices, string-keyed maps and
// named nested structs. Rejected:
//   - pointers, unsigned integers and time.Time: CEL reads a nil pointer as
//     a zero value, which reads as "unset", and a uint does not compare with
//     int literals;
//   - a Setting outside a map: only a map can leave an unknown setting out
//     (see Setting), while a field always holds a value;
//   - embedded fields and anonymous struct types, whose fields CEL resolves
//     differently from Go.
//
// Every fact field needs a json tag.
func CheckType(t reflect.Type) error {
	return checkType(t, t.Name(), false, map[reflect.Type]bool{})
}

var settingType = reflect.TypeFor[Setting]()

func checkType(t reflect.Type, where string, mapValue bool, seen map[reflect.Type]bool) error {
	switch t.Kind() {
	case reflect.String, reflect.Int64, reflect.Bool:
		return nil
	case reflect.Slice:
		return checkType(t.Elem(), where+"[]", false, seen)
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return fmt.Errorf("%s: map keys must be strings", where)
		}
		return checkType(t.Elem(), where+"[]", true, seen)
	case reflect.Struct:
		switch {
		case t.PkgPath() == "time":
			return fmt.Errorf("%s: time.Time is not allowed; use an int64 or a string", where)
		case t == settingType && !mapValue:
			return fmt.Errorf("%s: a Setting must be a map value, so that an unknown setting can be absent", where)
		case t.Name() == "":
			return fmt.Errorf("%s: anonymous struct types are not allowed; declare a named type", where)
		}
		if seen[t] {
			return nil
		}
		seen[t] = true
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.Anonymous {
				return fmt.Errorf("%s: embedded field %s is not allowed", where, f.Name)
			}
			if !f.IsExported() {
				continue
			}
			name := f.Tag.Get("json")
			if name == "" || name == "-" {
				return fmt.Errorf("%s.%s: exported fact fields need a json tag", where, f.Name)
			}
			if err := checkType(f.Type, where+"."+name, false, seen); err != nil {
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

// Target describes what is being scanned: the `target` variable.
type Target struct {
	// Live is true when the target is the running system, so live facts
	// (running services, sockets) describe it; false for a mounted root
	// (--root), where nothing runs. Checks use it to require live facts on
	// live targets only.
	Live bool `json:"live"`
}

// InvalidPrefix starts the value of a Setting that the program reading it
// cannot parse (login.defs "090" for a number): the program falls back to its
// default, so the value must not satisfy a check. Use Invalid to make one and
// IsInvalid to recognize it.
const InvalidPrefix = "invalid: "

// Invalid is the value of a setting the program cannot read as value.
func Invalid(value string) string { return InvalidPrefix + value }

// IsInvalid reports whether value was made by Invalid.
func IsInvalid(value string) bool { return strings.HasPrefix(value, InvalidPrefix) }
