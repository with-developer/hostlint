package engine

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/with-developer/vmsctl/internal/facts"
)

// FactField is one name a rule can read: a path through the facts of a collector.
type FactField struct {
	// Path is how a rule writes it, for example sshd.config or accounts.users[].uid: "[]" stands for an
	// element of a list, "{}" for the value under any key of a map.
	Path string
	// Type is what is there: string, int, bool, setting (a configuration value: value, explicit,
	// source), a list or a map of something.
	Type string
	// Go is "Type.Field" of the Go declaration, for finding its documentation comment.
	Go string
}

// FactCatalog lists every fact path of every collector of the engine, sorted by collector and then in the
// order of the declarations: the names that checks and policy packs can read.
func (e *Engine) FactCatalog() []FactField {
	var out []FactField
	for _, name := range sortedKeys(e.collectors) {
		t := e.collectors[name].Type()
		out = append(out, FactField{Path: name, Type: "object", Go: t.Name()})
		out = append(out, walkFacts(name, t, 0)...)
	}
	return out
}

// maxFactDepth bounds how deep the catalog follows nested objects (a fact type that recurses would never end).
const maxFactDepth = 5

var settingFactType = reflect.TypeFor[facts.Setting]()

func walkFacts(prefix string, t reflect.Type, depth int) []FactField {
	var out []FactField
	if t.Kind() != reflect.Struct {
		return nil
	}
	if depth > maxFactDepth {
		return []FactField{{Path: prefix + ".…", Type: "(deeper fields are not listed)", Go: t.Name()}}
	}
	for i := range t.NumField() {
		f := t.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		path := prefix + "." + tag
		out = append(out, FactField{Path: path, Type: factTypeName(f.Type), Go: t.Name() + "." + f.Name})
		out = append(out, walkElem(path, f.Type, depth)...)
	}
	return out
}

// walkElem descends into the struct of a field, a list's element or a map's value.
func walkElem(path string, t reflect.Type, depth int) []FactField {
	switch t.Kind() {
	case reflect.Slice:
		return walkElem(path+"[]", t.Elem(), depth)
	case reflect.Map:
		return walkElem(path+"{}", t.Elem(), depth)
	case reflect.Struct:
		if t == settingFactType {
			return []FactField{
				{Path: path + ".value", Type: "string", Go: "Setting.Value"},
				{Path: path + ".explicit", Type: "bool", Go: "Setting.Explicit"},
				{Path: path + ".source", Type: "string", Go: "Setting.Source"},
			}
		}
		return walkFacts(path, t, depth+1)
	default:
	}
	return nil
}

func factTypeName(t reflect.Type) string {
	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Int64, reflect.Int:
		return "int"
	case reflect.Bool:
		return "bool"
	case reflect.Slice:
		return "list of " + factTypeName(t.Elem())
	case reflect.Map:
		return "map of " + factTypeName(t.Elem())
	case reflect.Struct:
		if t == settingFactType {
			return "setting"
		}
		return "object"
	default:
	}
	return fmt.Sprint(t.Kind())
}

// FactCollectors lists the names of the collectors, whose facts a rule reads as variables.
func (e *Engine) FactCollectors() []string { return sortedKeys(e.collectors) }
