// Package policy evaluates per-route access rules written in CEL over three
// typed inputs: identity (from the OIDC session), device (from verified
// posture) and request (from the HTTP request).
//
// Inputs are Go structs exposed through cel-go native types, so policies are
// type-checked when the configuration loads: a misspelled attribute such as
// identity.grups is a startup error, not a silent deny at request time.
package policy

import "time"

// Identity describes the authenticated user.
type Identity struct {
	Authenticated bool          `cel:"authenticated" yaml:"authenticated"`
	Subject       string        `cel:"sub" yaml:"sub"`
	Email         string        `cel:"email" yaml:"email"`
	EmailVerified bool          `cel:"email_verified" yaml:"email_verified"`
	Name          string        `cel:"name" yaml:"name"`
	Groups        []string      `cel:"groups" yaml:"groups"`
	Issuer        string        `cel:"issuer" yaml:"issuer"`
	AuthAge       time.Duration `cel:"auth_age" yaml:"auth_age"`
}

// Device describes the requesting device as attested by a fresh, verified
// posture assertion. When no fresh posture exists Present is false and every
// other field is zero.
type Device struct {
	Present         bool          `cel:"present" yaml:"present"`
	ID              string        `cel:"id" yaml:"id"`
	OS              string        `cel:"os" yaml:"os"`
	OSVersion       string        `cel:"os_version" yaml:"os_version"`
	Arch            string        `cel:"arch" yaml:"arch"`
	DiskEncrypted   bool          `cel:"disk_encrypted" yaml:"disk_encrypted"`
	FirewallEnabled bool          `cel:"firewall_enabled" yaml:"firewall_enabled"`
	ScreenLock      bool          `cel:"screen_lock" yaml:"screen_lock"`
	PatchAgeDays    int           `cel:"patch_age_days" yaml:"patch_age_days"`
	Age             time.Duration `cel:"age" yaml:"age"`
}

// Request describes the HTTP request being authorised.
type Request struct {
	Method   string            `cel:"method" yaml:"method"`
	Host     string            `cel:"host" yaml:"host"`
	Path     string            `cel:"path" yaml:"path"`
	Query    map[string]string `cel:"query" yaml:"query"`
	Headers  map[string]string `cel:"headers" yaml:"headers"`
	ClientIP string            `cel:"ip" yaml:"ip"`
	Time     time.Time         `cel:"time" yaml:"time"`
	Route    string            `cel:"route" yaml:"route"`
}

// Input is everything a rule can see.
type Input struct {
	Identity Identity `yaml:"identity"`
	Device   Device   `yaml:"device"`
	Request  Request  `yaml:"request"`
}

// Effect is a rule's outcome when its expression is true.
type Effect string

// Rule effects.
const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
)

// RuleSpec is the configuration form of a rule.
type RuleSpec struct {
	Name   string `yaml:"name"`
	Effect Effect `yaml:"effect"`
	Expr   string `yaml:"expr"`
}

// Decision is the outcome of evaluating a route policy.
type Decision struct {
	Allowed bool
	// Rule is the deciding rule's name ("" for the default deny).
	Rule string
	// Reason is a stable machine-readable code for the audit log.
	Reason string
	// Errors lists rules that failed to evaluate (name: message).
	Errors []string
	// Cost is the summed CEL evaluation cost.
	Cost uint64
}

// Decision reason codes.
const (
	ReasonAllowed       = "allowed_by_rule"
	ReasonDenied        = "denied_by_rule"
	ReasonDenyError     = "deny_rule_error"
	ReasonNoAllow       = "no_matching_allow"
	ReasonNoRules       = "no_rules"
	ReasonCostExhausted = "policy_cost_exceeded"
)
