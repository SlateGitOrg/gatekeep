package policy

import (
	"context"
	"fmt"
	"io"

	"go.yaml.in/yaml/v3"
)

// Case is one policy unit test: an input, the route whose policy applies and
// the expected outcome.
type Case struct {
	Name   string `yaml:"name"`
	Route  string `yaml:"route"`
	Input  Input  `yaml:"input"`
	Expect Effect `yaml:"expect"`
	// Rule optionally pins the deciding rule's name.
	Rule string `yaml:"rule"`
}

// CaseResult is the outcome of one case.
type CaseResult struct {
	Case     Case
	Decision Decision
	Pass     bool
	Problem  string
}

// LoadCases parses a YAML document of the form {cases: [...]}.
func LoadCases(r io.Reader) ([]Case, error) {
	var doc struct {
		Cases []Case `yaml:"cases"`
	}
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("policy: parse cases: %w", err)
	}
	for i, c := range doc.Cases {
		if c.Expect != Allow && c.Expect != Deny {
			return nil, fmt.Errorf("policy: case %d (%s): expect must be allow or deny", i, c.Name)
		}
	}
	return doc.Cases, nil
}

// RunCases evaluates each case against the named route policies.
func RunCases(ctx context.Context, policies map[string]*Policy, cases []Case) []CaseResult {
	out := make([]CaseResult, 0, len(cases))
	for _, c := range cases {
		res := CaseResult{Case: c}
		p, ok := policies[c.Route]
		if !ok {
			res.Problem = fmt.Sprintf("unknown route %q", c.Route)
			out = append(out, res)
			continue
		}
		c.Input.Request.Route = c.Route
		res.Decision = p.Evaluate(ctx, c.Input)
		got := Deny
		if res.Decision.Allowed {
			got = Allow
		}
		switch {
		case got != c.Expect:
			res.Problem = fmt.Sprintf("expected %s, got %s (rule=%q reason=%s)", c.Expect, got, res.Decision.Rule, res.Decision.Reason)
		case c.Rule != "" && c.Rule != res.Decision.Rule:
			res.Problem = fmt.Sprintf("expected deciding rule %q, got %q", c.Rule, res.Decision.Rule)
		default:
			res.Pass = true
		}
		out = append(out, res)
	}
	return out
}
