package engine

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"cel.dev/cel-go/cel"
	celast "cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/ext"

	"github.com/with-developer/hostlint/internal/facts"
)

// Evaluation limits for every CEL program (ADR 0006 §3). A violations check
// runs where, key and text once per element; together they may cost at most
// celCheckBudget.
const (
	celCostLimit      = 1_000_000
	celCheckBudget    = 10 * celCostLimit
	celInterruptEvery = 100
)

// celTypeName is the CEL name cel-go gives a Go struct type.
func celTypeName(t reflect.Type) string {
	pkg := t.PkgPath()
	return pkg[strings.LastIndex(pkg, "/")+1:] + "." + t.Name()
}

// newBaseEnv declares one variable per collector, with the collector's fact
// type. Fact field names come from their json tags.
func newBaseEnv(collectors map[string]Collector) (*cel.Env, error) {
	nativeArgs := []any{types.ParseStructTag("json")}
	var vars []cel.EnvOption
	for _, name := range sortedKeys(collectors) {
		c := collectors[name]
		t := c.Type()
		if t.Kind() != reflect.Struct {
			return nil, fmt.Errorf("collector %s: facts must be a struct, not %s", name, t)
		}
		if err := facts.CheckType(t); err != nil {
			return nil, fmt.Errorf("collector %s: %w", name, err)
		}
		nativeArgs = append(nativeArgs, t)
		vars = append(vars, cel.Variable(name, cel.ObjectType(celTypeName(t))))
	}
	opts := []cel.EnvOption{
		cel.OptionalTypes(),
		ext.Strings(), ext.Lists(), ext.Sets(), ext.Math(),
		ext.NativeTypes(nativeArgs...),
	}
	return cel.NewEnv(append(opts, vars...)...)
}

// compiledCheck holds a check's CEL programs, ready to evaluate.
type compiledCheck struct {
	check   *Check
	env     *cel.Env // base env plus params
	elemEnv *cel.Env // env plus the violations element variable
	applies *program
	expect  *program
	setting *program // the Setting fact, optionally selected
	over    *program
	where   *program
	key     *program
	text    *program
	show    *program
	// evidencePaths are the fact paths an expect expression reads, and
	// appliesPaths those applies reads.
	evidencePaths, appliesPaths []evidencePath
	// vars are the collector variables any expression references.
	vars []string
}

// evidencePath is a fact path compiled for evidence.
type evidencePath struct {
	factPath
	prog *program
}

// program is one compiled expression.
type program struct {
	source string
	ast    *cel.Ast
	prg    cel.Program
	vars   []string // referenced collector variables
}

// compileCheck compiles every expression of c against base, which declares
// the collectors in known.
func compileCheck(base *cel.Env, known map[string]Collector, c *Check) (*compiledCheck, error) {
	var paramVars []cel.EnvOption
	for _, name := range sortedKeys(c.Params) {
		t := cel.IntType
		if c.Params[name].Type == "string" {
			t = cel.StringType
		}
		paramVars = append(paramVars, cel.Variable("params."+name, t))
	}
	env, err := base.Extend(paramVars...)
	if err != nil {
		return nil, err
	}
	cc := &compiledCheck{check: c, env: env}
	compile := func(e *cel.Env, what, src string, want *cel.Type) (*program, error) {
		return compileExpr(e, known, what, src, want)
	}

	if c.Applies != "" {
		if cc.applies, err = compile(env, "applies", c.Applies, cel.BoolType); err != nil {
			return nil, err
		}
		if cc.appliesPaths, err = compilePaths(env, known, cc.applies); err != nil {
			return nil, err
		}
	}
	switch {
	case c.Expect != "":
		if cc.expect, err = compile(env, "expect", c.Expect, cel.BoolType); err != nil {
			return nil, err
		}
		if hasComprehension(cc.expect) {
			return nil, fmt.Errorf("expect: comprehensions (all, exists, filter, map) belong in a violations check")
		}
		if cc.evidencePaths, err = compilePaths(env, known, cc.expect); err != nil {
			return nil, err
		}
	case c.Setting != nil:
		src, err := optionalLast(c.Setting.Fact)
		if err != nil {
			return nil, err
		}
		settingT := cel.OptionalType(cel.ObjectType(celTypeName(reflect.TypeFor[facts.Setting]())))
		if cc.setting, err = compile(env, "setting.fact", src, settingT); err != nil {
			return nil, err
		}
	case c.Violations != nil:
		v := c.Violations
		if cc.over, err = compile(env, "violations.over", v.Over, nil); err != nil {
			return nil, err
		}
		elem, ok := listElem(cc.over)
		if !ok {
			return nil, fmt.Errorf("violations.over must be a list, not %s", cc.over.outputType())
		}
		envElem, err := env.Extend(cel.Variable(v.As, elem))
		if err != nil {
			return nil, err
		}
		cc.elemEnv = envElem
		if cc.where, err = compile(envElem, "violations.where", v.Where, cel.BoolType); err != nil {
			return nil, err
		}
		if cc.key, err = compile(envElem, "violations.key", v.Key, cel.StringType); err != nil {
			return nil, err
		}
		if cc.text, err = compile(envElem, "violations.text", v.Text, cel.StringType); err != nil {
			return nil, err
		}
	case c.Manual != nil && c.Manual.Show != "":
		if cc.show, err = compile(env, "manual.show", c.Manual.Show, nil); err != nil {
			return nil, err
		}
	}

	seen := map[string]bool{}
	for _, p := range []*program{cc.applies, cc.expect, cc.setting, cc.over, cc.where, cc.key, cc.text, cc.show} {
		if p == nil {
			continue
		}
		for _, v := range p.vars {
			seen[v] = true
		}
	}
	cc.vars = sortedKeys(seen)
	return cc, nil
}

// compilePaths compiles the fact paths p reads, for evidence.
func compilePaths(env *cel.Env, known map[string]Collector, p *program) ([]evidencePath, error) {
	var out []evidencePath
	for _, fp := range factPaths(p, known) {
		pp, err := compileExpr(env, known, "evidence", fp.path, nil)
		if err != nil {
			return nil, err
		}
		out = append(out, evidencePath{fp, pp})
	}
	return out, nil
}

// compileExpr type-checks src and builds a cost-limited program that supports
// partial evaluation. want, if set, is the required output type.
func compileExpr(env *cel.Env, known map[string]Collector, what, src string, want *cel.Type) (*program, error) {
	ast, iss := env.Compile(src)
	if iss.Err() != nil {
		return nil, fmt.Errorf("%s: %w", what, iss.Err())
	}
	if want != nil && !ast.OutputType().IsExactType(want) {
		return nil, fmt.Errorf("%s: must be %s, not %s", what, want, ast.OutputType())
	}
	prg, err := env.Program(ast,
		cel.EvalOptions(cel.OptPartialEval),
		cel.CostLimit(celCostLimit),
		cel.InterruptCheckFrequency(celInterruptEvery),
	)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	p := &program{source: src, prg: prg, ast: ast}
	seen := map[string]bool{}
	for _, ref := range ast.NativeRep().ReferenceMap() {
		if _, ok := known[ref.Name]; ok && !seen[ref.Name] {
			seen[ref.Name] = true
			p.vars = append(p.vars, ref.Name)
		}
	}
	sort.Strings(p.vars)
	return p, nil
}

// hasComprehension reports whether the expression uses a macro that iterates.
func hasComprehension(p *program) bool {
	found := false
	celast.PreOrderVisit(p.ast.NativeRep().Expr(), celast.NewExprVisitor(func(e celast.Expr) {
		if e.Kind() == celast.ComprehensionKind {
			found = true
		}
	}))
	return found
}

// factPath is a fact path an expression reads, e.g. sshd.config.permitrootlogin.
type factPath struct {
	path string
	// mapKey is true when a step selects a map key, which the host may not
	// have; selecting the path then fails.
	mapKey bool
}

// factPaths returns the distinct fact paths an expression reads, sorted,
// without paths contained in others.
func factPaths(p *program, known map[string]Collector) []factPath {
	ast := p.ast.NativeRep()
	isMap := func(e celast.Expr) bool { return ast.GetType(e.ID()).Kind() == types.MapKind }
	var walk func(e celast.Expr) (factPath, bool)
	walk = func(e celast.Expr) (factPath, bool) {
		switch e.Kind() {
		case celast.IdentKind:
			name := e.AsIdent()
			_, ok := known[name]
			return factPath{path: name}, ok
		case celast.SelectKind:
			sel := e.AsSelect()
			if sel.IsTestOnly() {
				return factPath{}, false
			}
			base, ok := walk(sel.Operand())
			return factPath{base.path + "." + sel.FieldName(), base.mapKey || isMap(sel.Operand())}, ok
		case celast.CallKind:
			call := e.AsCall()
			if call.FunctionName() == "_[_]" && len(call.Args()) == 2 && call.Args()[1].Kind() == celast.LiteralKind {
				if s, isStr := call.Args()[1].AsLiteral().Value().(string); isStr {
					base, ok := walk(call.Args()[0])
					return factPath{base.path + "[" + strconv.Quote(s) + "]", base.mapKey || isMap(call.Args()[0])}, ok
				}
			}
		default:
		}
		return factPath{}, false
	}
	var paths []factPath
	seen := map[string]bool{}
	celast.PreOrderVisit(ast.Expr(), celast.NewExprVisitor(func(e celast.Expr) {
		if e.Kind() != celast.SelectKind && e.Kind() != celast.CallKind {
			return
		}
		if fp, ok := walk(e); ok && strings.ContainsAny(fp.path, ".[") && !seen[fp.path] {
			seen[fp.path] = true
			paths = append(paths, fp)
		}
	}))
	// Keep only maximal paths: drop "a.b" when "a.b.c" is also read.
	sort.Slice(paths, func(i, j int) bool { return len(paths[i].path) > len(paths[j].path) })
	var out []factPath
	for _, p := range paths {
		contained := false
		for _, q := range out {
			if strings.HasPrefix(q.path, p.path+".") || strings.HasPrefix(q.path, p.path+"[") {
				contained = true
				break
			}
		}
		if !contained {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

var lastIndexRe = regexp.MustCompile(`^(.*)\[("[^"\\]+")\]$`)

// optionalLast turns a fact path into an optional selection of its last
// element: a.b.c → a.b.?c, a.b["k"] → a.b[?"k"].
func optionalLast(path string) (string, error) {
	if m := lastIndexRe.FindStringSubmatch(path); m != nil {
		return m[1] + "[?" + m[2] + "]", nil
	}
	i := strings.LastIndex(path, ".")
	if i < 0 {
		return "", fmt.Errorf("fact path %q needs at least one field", path)
	}
	return path[:i] + ".?" + path[i+1:], nil
}

// listElem returns the element type of a list-typed program.
func listElem(p *program) (*cel.Type, bool) {
	t := p.outputType()
	if t.Kind() != types.ListKind || len(t.Parameters()) != 1 {
		return nil, false
	}
	return t.Parameters()[0], true
}

func (p *program) outputType() *cel.Type { return p.ast.OutputType() }
