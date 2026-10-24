package policy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
)

// DefaultCostLimit bounds the evaluation cost of a single rule. CEL is not
// Turing-complete, but comprehensions over large lists can still be costly;
// the limit makes worst-case evaluation time a configuration-time constant.
const DefaultCostLimit = 10_000

// Engine compiles rules against the shared, typed environment.
type Engine struct {
	env       *cel.Env
	costLimit uint64
}

// NewEngine builds the CEL environment. costLimit <= 0 uses DefaultCostLimit.
func NewEngine(costLimit uint64) (*Engine, error) {
	if costLimit == 0 {
		costLimit = DefaultCostLimit
	}
	env, err := cel.NewEnv(
		ext.NativeTypes(
			reflect.TypeFor[Identity](),
			reflect.TypeFor[Device](),
			reflect.TypeFor[Request](),
			ext.ParseStructTags(true),
		),
		cel.Variable("identity", cel.ObjectType("policy.Identity")),
		cel.Variable("device", cel.ObjectType("policy.Device")),
		cel.Variable("request", cel.ObjectType("policy.Request")),
		ext.Strings(),
		ext.Sets(),
		cel.Function("in_cidr",
			cel.MemberOverload("string_in_cidr_string",
				[]*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(inCIDR))),
	)
	if err != nil {
		return nil, fmt.Errorf("policy: build env: %w", err)
	}
	return &Engine{env: env, costLimit: costLimit}, nil
}

var prefixCache sync.Map // string -> netip.Prefix

// inCIDR implements ip.in_cidr(cidr). Prefixes are parsed once and cached;
// malformed input evaluates to an error (which fails closed).
func inCIDR(ipVal, cidrVal ref.Val) ref.Val {
	ipStr, ok1 := ipVal.Value().(string)
	cidrStr, ok2 := cidrVal.Value().(string)
	if !ok1 || !ok2 {
		return types.NewErr("in_cidr: expected strings")
	}
	var prefix netip.Prefix
	if p, ok := prefixCache.Load(cidrStr); ok {
		prefix = p.(netip.Prefix)
	} else {
		p, err := netip.ParsePrefix(cidrStr)
		if err != nil {
			return types.NewErr("in_cidr: bad cidr %q", cidrStr)
		}
		prefix = p.Masked()
		prefixCache.Store(cidrStr, prefix)
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return types.NewErr("in_cidr: bad ip %q", ipStr)
	}
	return types.Bool(prefix.Contains(addr.Unmap()))
}

// Rule is a compiled rule.
type Rule struct {
	Name   string
	Effect Effect
	Expr   string
	prg    cel.Program
}

// Policy is the compiled rule set for one route.
type Policy struct {
	denies []Rule
	allows []Rule
}

// Compile type-checks and plans every rule. Expressions must be boolean.
func (e *Engine) Compile(specs []RuleSpec) (*Policy, error) {
	p := &Policy{}
	seen := map[string]bool{}
	var errs []error
	for i, s := range specs {
		name := s.Name
		if name == "" {
			name = fmt.Sprintf("rule[%d]", i)
		}
		if seen[name] {
			errs = append(errs, fmt.Errorf("rule %q: duplicate name", name))
			continue
		}
		seen[name] = true
		r, err := e.compileRule(name, s)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if r.Effect == Deny {
			p.denies = append(p.denies, r)
		} else {
			p.allows = append(p.allows, r)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return p, nil
}

func (e *Engine) compileRule(name string, s RuleSpec) (Rule, error) {
	if s.Effect != Allow && s.Effect != Deny {
		return Rule{}, fmt.Errorf("rule %q: effect must be allow or deny, got %q", name, s.Effect)
	}
	if strings.TrimSpace(s.Expr) == "" {
		return Rule{}, fmt.Errorf("rule %q: empty expression", name)
	}
	ast, iss := e.env.Compile(s.Expr)
	if iss.Err() != nil {
		return Rule{}, fmt.Errorf("rule %q: %w", name, iss.Err())
	}
	if ast.OutputType() != cel.BoolType {
		return Rule{}, fmt.Errorf("rule %q: expression must be bool, is %s", name, ast.OutputType())
	}
	prg, err := e.env.Program(ast,
		cel.CostLimit(e.costLimit),
		cel.EvalOptions(cel.OptOptimize, cel.OptTrackCost),
		cel.InterruptCheckFrequency(100),
	)
	if err != nil {
		return Rule{}, fmt.Errorf("rule %q: plan: %w", name, err)
	}
	return Rule{Name: name, Effect: s.Effect, Expr: s.Expr, prg: prg}, nil
}

// Rules returns the compiled rules (deny rules first).
func (p *Policy) Rules() []Rule { return append(append([]Rule{}, p.denies...), p.allows...) }

// Evaluate applies deny-overrides semantics:
//
//  1. any deny rule that is true, or that fails to evaluate, denies
//     (fail closed);
//  2. otherwise the first allow rule that is true allows;
//  3. otherwise the request is denied by default.
//
// Allow rules that error are recorded and treated as false.
func (p *Policy) Evaluate(ctx context.Context, in Input) Decision {
	act := map[string]any{"identity": in.Identity, "device": in.Device, "request": in.Request}
	var d Decision
	if len(p.denies)+len(p.allows) == 0 {
		d.Reason = ReasonNoRules
		return d
	}
	for _, r := range p.denies {
		v, cost, err := r.eval(ctx, act)
		d.Cost += cost
		if err != nil {
			d.Errors = append(d.Errors, r.Name+": "+err.Error())
			d.Rule, d.Reason = r.Name, errReason(err, ReasonDenyError)
			return d
		}
		if v {
			d.Rule, d.Reason = r.Name, ReasonDenied
			return d
		}
	}
	for _, r := range p.allows {
		v, cost, err := r.eval(ctx, act)
		d.Cost += cost
		if err != nil {
			d.Errors = append(d.Errors, r.Name+": "+err.Error())
			continue
		}
		if v {
			d.Allowed, d.Rule, d.Reason = true, r.Name, ReasonAllowed
			return d
		}
	}
	d.Reason = ReasonNoAllow
	return d
}

func (r Rule) eval(ctx context.Context, act map[string]any) (bool, uint64, error) {
	out, det, err := r.prg.ContextEval(ctx, act)
	var cost uint64
	if det != nil && det.ActualCost() != nil {
		cost = *det.ActualCost()
	}
	if err != nil {
		return false, cost, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, cost, fmt.Errorf("non-bool result %v", out)
	}
	return b, cost, nil
}

func errReason(err error, fallback string) string {
	if strings.Contains(err.Error(), "cost limit exceeded") {
		return ReasonCostExhausted
	}
	return fallback
}
