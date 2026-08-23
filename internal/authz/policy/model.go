// Package policy compiles the operation-level domain authorization metadata
// declared in the canonical OpenAPI specification into an immutable, read-only,
// validated representation for the authorization runtime (M5.1).
//
// The compiled policy answers: "what operation-level domain authorization rules
// (confirmed scopes or OPEN policy requirements) apply to this operation?"
//
// It does NOT evaluate permissions, look up principals, or enforce partner/resource
// policies (which remain for subsequent M5 submilestones).
//
// The compiled policy is derived only from the canonical spec returned by
// openapi.GetSpec(). The canonical spec object is never mutated.
package policy

import (
	"strings"
)

// PolicyKind distinguishes the operation-level authorization requirements
// compiled from the OpenAPI contract.
type PolicyKind string

const (
	// PolicyKindNone means the operation carries no operation-level
	// authorization metadata in the OpenAPI contract. In M5.1, no
	// operation-level authorization gate is imposed.
	PolicyKindNone PolicyKind = "NONE"

	// PolicyKindConfirmedScopes means the operation has confirmed required
	// domain scope(s) (e.g. device:approve, certificate:revoke) that must
	// be possessed by the authenticated principal.
	PolicyKindConfirmedScopes PolicyKind = "CONFIRMED_SCOPES"

	// PolicyKindOpen means the operation carries explicitly OPEN domain
	// authorization metadata (e.g. OPEN_SCOPE_NAME, OPEN_READ_SCOPE_NAME)
	// and requires an explicit decision from an injected policy evaluator.
	PolicyKindOpen PolicyKind = "OPEN"
)

// ScopeStatus is the value of x-domain-authorization.scopeStatus.
type ScopeStatus string

const (
	ScopeStatusConfirmed ScopeStatus = "CONFIRMED_OR_CONSOLIDATED"
)

// OpenStatus is the value of x-domain-authorization.status for OPEN operations.
type OpenStatus string

const (
	OpenStatusScopeName     OpenStatus = "OPEN_SCOPE_NAME"
	OpenStatusReadScopeName OpenStatus = "OPEN_READ_SCOPE_NAME"
)

// OpenMetadata holds the preserved OpenAPI contract metadata for operations
// with OPEN domain-authorization requirements (or confirmed operations with
// extra highImpact/stepUpPolicy metadata).
type OpenMetadata struct {
	Status                OpenStatus
	HighImpact            bool
	StepUpPolicy          string
	ResourceScope         string
	GrantedPrincipalScope string
	ScopeStatus           ScopeStatus
}

// OperationPolicy is the compiled authorization policy for a single operation.
// It is immutable and safe for concurrent reads.
type OperationPolicy struct {
	operationID    string
	method         string
	path           string
	kind           PolicyKind
	requiredScopes []string      // sorted, deduplicated, non-empty when kind == PolicyKindConfirmedScopes
	openMetadata   *OpenMetadata // non-nil when kind == PolicyKindOpen or extra metadata exists
}

// OperationID returns the unique operationId.
func (p *OperationPolicy) OperationID() string { return p.operationID }

// Method returns the uppercase HTTP method.
func (p *OperationPolicy) Method() string { return p.method }

// Path returns the route path template.
func (p *OperationPolicy) Path() string { return p.path }

// Kind returns the policy classification for this operation.
func (p *OperationPolicy) Kind() PolicyKind { return p.kind }

// RequiredScopes returns a defensive copy of the confirmed required scopes,
// in deterministic (sorted) order.
func (p *OperationPolicy) RequiredScopes() []string {
	if len(p.requiredScopes) == 0 {
		return nil
	}
	return append([]string(nil), p.requiredScopes...)
}

// HasScope reports whether the operation requires the given confirmed scope.
func (p *OperationPolicy) HasScope(scope string) bool {
	for _, s := range p.requiredScopes {
		if s == scope {
			return true
		}
	}
	return false
}

// OpenMetadata returns a defensive copy of the OPEN policy metadata, or nil
// if none is present.
func (p *OperationPolicy) OpenMetadata() *OpenMetadata {
	if p.openMetadata == nil {
		return nil
	}
	cp := *p.openMetadata
	return &cp
}

// HighImpact reports whether the operation is marked high-impact in OpenAPI.
func (p *OperationPolicy) HighImpact() bool {
	if p.openMetadata == nil {
		return false
	}
	return p.openMetadata.HighImpact
}

// StepUpPolicy returns the stepUpPolicy metadata string, or "".
func (p *OperationPolicy) StepUpPolicy() string {
	if p.openMetadata == nil {
		return ""
	}
	return p.openMetadata.StepUpPolicy
}

// ResourceScope returns the resourceScope metadata string, or "".
func (p *OperationPolicy) ResourceScope() string {
	if p.openMetadata == nil {
		return ""
	}
	return p.openMetadata.ResourceScope
}

// GrantedPrincipalScope returns the grantedPrincipalScope metadata string, or "".
func (p *OperationPolicy) GrantedPrincipalScope() string {
	if p.openMetadata == nil {
		return ""
	}
	return p.openMetadata.GrantedPrincipalScope
}

// String renders a deterministic human-readable summary of the authorization policy.
func (p *OperationPolicy) String() string {
	switch p.kind {
	case PolicyKindNone:
		return p.operationID + ": NO_OPERATION_LEVEL_AUTHZ"
	case PolicyKindConfirmedScopes:
		s := p.operationID + ": REQUIRED_SCOPES[" + strings.Join(p.requiredScopes, ", ") + "]"
		if p.openMetadata != nil && p.openMetadata.HighImpact {
			s += " (highImpact)"
		}
		return s
	case PolicyKindOpen:
		s := p.operationID + ": OPEN[" + string(p.openMetadata.Status) + "]"
		if p.openMetadata.HighImpact {
			s += " (highImpact)"
		}
		if p.openMetadata.ResourceScope != "" {
			s += " (resourceScope=" + p.openMetadata.ResourceScope + ")"
		}
		if p.openMetadata.GrantedPrincipalScope != "" {
			s += " (grantedPrincipalScope=" + p.openMetadata.GrantedPrincipalScope + ")"
		}
		return s
	default:
		return p.operationID + ": UNKNOWN"
	}
}

// Policy is the compiled, immutable, read-only authorization policy for all
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

// Operations returns a defensive copy of all compiled operation policies in
// deterministic (operationId-sorted) order.
func (p *Policy) Operations() []*OperationPolicy {
	return append([]*OperationPolicy(nil), p.operations...)
}

// OperationCount returns the number of compiled operations.
func (p *Policy) OperationCount() int { return len(p.operations) }
