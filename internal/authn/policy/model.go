// Package policy compiles the authentication metadata declared in the
// canonical OpenAPI specification into an immutable, read-only, validated
// representation for a future authentication runtime (M4.2).
//
// It answers exactly one question: "which credential kind, or combination of
// credential kinds, can satisfy the authentication requirement of this
// operation?" It does NOT authenticate requests, read HTTP, extract
// credentials, verify tokens, or decide authorization.
//
// The compiled policy is derived only from the canonical spec returned by
// openapi.GetSpec(). The canonical spec object is never mutated.
package policy

import (
	"sort"
	"strings"
)

// CredentialKind is one of the six contractually distinct authentication
// credential kinds declared by the OpenAPI v0.1.1 contract.
//
// The set is closed: any scheme name outside this set is a compile error.
// TemporaryPrincipalToken remains an independent kind even though it is
// transported as an HTTP bearer credential; its concrete bootstrap and
// verification mechanism is deferred (OPEN-003).
//
// There is deliberately no CredentialKindPublic: the absence of an
// application credential is a property of an operation's policy, not a
// credential kind.
type CredentialKind string

const (
	CredentialKindHumanOIDC               CredentialKind = "HumanOIDC"
	CredentialKindAdminOIDC               CredentialKind = "AdminOIDC"
	CredentialKindTemporaryPrincipalToken CredentialKind = "TemporaryPrincipalToken"
	CredentialKindRequestAccessToken      CredentialKind = "RequestAccessToken"
	CredentialKindEnrollmentAccessToken   CredentialKind = "EnrollmentAccessToken"
	CredentialKindDeviceMTLS              CredentialKind = "DeviceMTLS"
)

// allCredentialKinds is the exhaustive, closed set of supported kinds. It is
// the single source of truth for scheme-name recognition.
var allCredentialKinds = []CredentialKind{
	CredentialKindHumanOIDC,
	CredentialKindAdminOIDC,
	CredentialKindTemporaryPrincipalToken,
	CredentialKindRequestAccessToken,
	CredentialKindEnrollmentAccessToken,
	CredentialKindDeviceMTLS,
}

// ParseCredentialKind maps a contractual scheme name to its CredentialKind.
// Recognition is nominal: the scheme NAME is authoritative, never the
// transport format (bearer vs mutualTLS). Unknown names return ok=false.
func ParseCredentialKind(name string) (CredentialKind, bool) {
	for _, k := range allCredentialKinds {
		if string(k) == name {
			return k, true
		}
	}
	return "", false
}

// Conjunction is the immutable AND-set of credential kinds required together
// by a single OpenAPI Security Requirement Object. Kinds are held in a
// deterministic (sorted) order.
type Conjunction struct {
	kinds []CredentialKind // sorted, no duplicates, immutable
}

// newConjunction builds a Conjunction from the given kinds, normalizing them
// into a deterministic sorted order with duplicates removed.
func newConjunction(kinds ...CredentialKind) Conjunction {
	if len(kinds) == 0 {
		return Conjunction{kinds: nil}
	}
	seen := make(map[CredentialKind]struct{}, len(kinds))
	out := make([]CredentialKind, 0, len(kinds))
	for _, k := range kinds {
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return Conjunction{kinds: out}
}

// Kinds returns a defensive copy of the kinds in this conjunction.
func (c Conjunction) Kinds() []CredentialKind {
	return append([]CredentialKind(nil), c.kinds...)
}

// Len reports the number of kinds in this conjunction.
func (c Conjunction) Len() int { return len(c.kinds) }

// IsEmpty reports whether this conjunction requires no kinds. A compiled
// operation never exposes an empty conjunction; the empty array security: []
// is represented as OperationPolicy.noApplicationCredential instead.
func (c Conjunction) IsEmpty() bool { return len(c.kinds) == 0 }

// hasKind reports whether the conjunction contains the given kind.
func (c Conjunction) hasKind(k CredentialKind) bool {
	for _, x := range c.kinds {
		if x == k {
			return true
		}
	}
	return false
}

// String renders a deterministic, human-readable form. A single kind renders
// as its name; multiple kinds render parenthesized and AND-joined.
func (c Conjunction) String() string {
	switch len(c.kinds) {
	case 0:
		return ""
	case 1:
		return string(c.kinds[0])
	default:
		names := make([]string, len(c.kinds))
		for i, k := range c.kinds {
			names[i] = string(k)
		}
		return "(" + strings.Join(names, " AND ") + ")"
	}
}

// ConditionalCase is one mapping from a discriminator value to the credential
// requirement it mandates.
type ConditionalCase struct {
	discriminatorValue string
	requirement        Conjunction
}

// DiscriminatorValue returns the discriminator value this case keys on.
func (c ConditionalCase) DiscriminatorValue() string { return c.discriminatorValue }

// Requirement returns the credential requirement for this case.
func (c ConditionalCase) Requirement() Conjunction { return c.requirement }

// ConditionalSecurity is the compiled x-security-conditions extension for an
// operation whose required credential depends on a request-body discriminator
// value. It is additive to the operation's base security alternatives.
type ConditionalSecurity struct {
	discriminator string
	cases         []ConditionalCase // sorted by discriminatorValue
}

// Discriminator returns the discriminator property name.
func (c *ConditionalSecurity) Discriminator() string {
	if c == nil {
		return ""
	}
	return c.discriminator
}

// Cases returns a defensive copy of the conditional cases, in deterministic
// order.
func (c *ConditionalSecurity) Cases() []ConditionalCase {
	if c == nil {
		return nil
	}
	return append([]ConditionalCase(nil), c.cases...)
}

// RequirementFor returns the credential requirement for a discriminator
// value, or ok=false if the value has no declared case.
func (c *ConditionalSecurity) RequirementFor(value string) (Conjunction, bool) {
	if c == nil {
		return Conjunction{}, false
	}
	for _, cs := range c.cases {
		if cs.discriminatorValue == value {
			return cs.requirement, true
		}
	}
	return Conjunction{}, false
}

// String renders a deterministic human-readable form of the conditional
// mapping, e.g. "operation: INITIAL->RequestAccessToken, RENEWAL->DeviceMTLS".
func (c *ConditionalSecurity) String() string {
	if c == nil {
		return ""
	}
	parts := make([]string, len(c.cases))
	for i, cs := range c.cases {
		parts[i] = cs.discriminatorValue + "->" + cs.requirement.String()
	}
	return c.discriminator + ": " + strings.Join(parts, ", ")
}

// OperationPolicy is the compiled authentication policy for a single
// operation. It is immutable and safe for concurrent reads.
type OperationPolicy struct {
	operationID             string
	method                  string
	path                    string
	noApplicationCredential bool
	alternatives            []Conjunction // OR of ANDs, sorted deterministically
	conditional             *ConditionalSecurity
}

// OperationID returns the operation's unique operationId.
func (p *OperationPolicy) OperationID() string { return p.operationID }

// Method returns the uppercase HTTP method (for diagnostics).
func (p *OperationPolicy) Method() string { return p.method }

// Path returns the operation's path template (for diagnostics).
func (p *OperationPolicy) Path() string { return p.path }

// NoApplicationCredential reports whether the operation requires no
// application credential (compiled from security: []).
//
// This is the only meaning of "PUBLIC" in this package. It does NOT mean the
// endpoint is directly exposed to the Internet, bypasses the Reverse Proxy,
// lacks TLS, or lacks network controls. The Reverse Proxy remains the only
// externally exposed component regardless of this flag.
func (p *OperationPolicy) NoApplicationCredential() bool { return p.noApplicationCredential }

// Alternatives returns a defensive copy of the OR alternatives. Each
// alternative is an AND-set (Conjunction). The caller must satisfy at least
// one alternative.
func (p *OperationPolicy) Alternatives() []Conjunction {
	return append([]Conjunction(nil), p.alternatives...)
}

// Conditional returns the compiled conditional security, or nil if the
// operation has none. The returned value is a shallow copy of the internal
// conditional metadata; it shares no mutable state.
func (p *OperationPolicy) Conditional() *ConditionalSecurity {
	if p.conditional == nil {
		return nil
	}
	cp := *p.conditional
	return &cp
}

// String renders a deterministic human-readable summary of the policy.
func (p *OperationPolicy) String() string {
	if p.noApplicationCredential {
		return p.operationID + ": NO_APPLICATION_CREDENTIAL"
	}
	parts := make([]string, len(p.alternatives))
	for i, alt := range p.alternatives {
		parts[i] = alt.String()
	}
	s := p.operationID + ": " + strings.Join(parts, " OR ")
	if p.conditional != nil {
		s += " [" + p.conditional.String() + "]"
	}
	return s
}

// Policy is the compiled, immutable, read-only authentication policy for all
// operations, indexed by operationId. It is safe for concurrent reads and
// exposes no mutable state.
type Policy struct {
	byID       map[string]*OperationPolicy
	operations []*OperationPolicy // sorted by operationId
}

// Operation returns the compiled policy for an operationId, or ok=false.
func (p *Policy) Operation(operationID string) (*OperationPolicy, bool) {
	op, ok := p.byID[operationID]
	return op, ok
}

// Operations returns a defensive copy of all compiled policies in
// deterministic (operationId-sorted) order.
func (p *Policy) Operations() []*OperationPolicy {
	return append([]*OperationPolicy(nil), p.operations...)
}

// OperationCount returns the number of compiled operations.
func (p *Policy) OperationCount() int { return len(p.operations) }
