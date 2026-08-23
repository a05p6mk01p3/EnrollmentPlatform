// Package resourceownership implements the M5.3 resource ownership and
// visibility boundary: provider-neutral resolution of resource ownership
// and evaluation of Human visibility for pre-onboarding requests.
//
// It contains NO concrete PostgreSQL/database integration, no authentication
// mechanism, and no HTTP transport. Concrete ownership sources plug in
// through the resolver ports; deterministic test doubles live in testutil.go.
// The generated OpenAPI transport types are deliberately not referenced here:
// this package owns the handwritten domain/application model.
package resourceownership

// OwnershipStatus classifies the resolution status of an authoritative
// resource ownership lookup.
type OwnershipStatus uint8

const (
	// OwnershipStatusUnknown is the uninitialized zero value and must never
	// be treated as found or valid.
	OwnershipStatusUnknown OwnershipStatus = iota

	// OwnershipStatusFound indicates the resource exists and has an
	// authoritative partner_id.
	OwnershipStatusFound

	// OwnershipStatusNotFound indicates the resource does not exist in
	// authoritative storage.
	OwnershipStatusNotFound
)

func (s OwnershipStatus) String() string {
	switch s {
	case OwnershipStatusFound:
		return "FOUND"
	case OwnershipStatusNotFound:
		return "NOT_FOUND"
	default:
		return "UNKNOWN"
	}
}

// ResourceOwnership holds the minimal authoritative ownership metadata
// needed for visibility evaluation.
type ResourceOwnership struct {
	ResourceID string
	PartnerID  string
}

// OwnershipResult is the typed result of an authoritative resource ownership
// lookup.
type OwnershipResult struct {
	Status    OwnershipStatus
	Ownership ResourceOwnership
}

// OwnershipFound returns a valid FOUND ownership result.
func OwnershipFound(resourceID, partnerID string) OwnershipResult {
	return OwnershipResult{
		Status: OwnershipStatusFound,
		Ownership: ResourceOwnership{
			ResourceID: resourceID,
			PartnerID:  partnerID,
		},
	}
}

// OwnershipNotFound returns a valid NOT_FOUND ownership result.
func OwnershipNotFound() OwnershipResult {
	return OwnershipResult{
		Status: OwnershipStatusNotFound,
	}
}

// VisibilityDecision is the typed result of a Human visibility evaluation.
// The zero value (VisibilityUnknown) fails closed.
type VisibilityDecision uint8

const (
	// VisibilityUnknown is the zero value and must never mean allow.
	VisibilityUnknown VisibilityDecision = iota

	// VisibilityAllowed means the resource exists, its authoritative partner_id
	// belongs to the caller's current Human partner authorization set, and
	// protected read may proceed.
	VisibilityAllowed

	// VisibilityHiddenNotFound means the resource either does not exist OR
	// exists for a partner outside the caller's current authorization set. The
	// external response must be generic 404 RESOURCE_NOT_FOUND without
	// disclosing existence or partner identity.
	VisibilityHiddenNotFound

	// VisibilityIndeterminate means visibility could not be established
	// deterministically (dependency unavailable, malformed state, ambiguous
	// metadata). The external response must fail closed (503
	// DEPENDENCY_UNAVAILABLE).
	VisibilityIndeterminate
)

func (d VisibilityDecision) String() string {
	switch d {
	case VisibilityAllowed:
		return "ALLOWED"
	case VisibilityHiddenNotFound:
		return "HIDDEN_NOT_FOUND"
	case VisibilityIndeterminate:
		return "INDETERMINATE"
	default:
		return "UNKNOWN"
	}
}
