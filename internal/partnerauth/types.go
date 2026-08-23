// Package partnerauth implements the M5.2 partner authorization boundary: a
// provider-neutral resolution of the current effective partner authorizations
// for server-authenticated principals, plus partner/scope selection for
// protected operations.
//
// It contains NO concrete Keycloak/SAP/PostgreSQL integration, no
// authentication mechanism, and no HTTP transport. Concrete authorization
// sources plug in through the resolver ports; deterministic test doubles live
// in testutil.go. The generated OpenAPI transport types are deliberately not
// referenced here: this package owns the handwritten domain/application model.
package partnerauth

import "time"

// ScopeDevicePreOnboard is the partner-scoped effective permission required to
// create a pre-onboarding request. It is a partner-scoped selection scope, not
// an M5.1 operation-level authorization requirement, and must not be added to
// the OpenAPI x-required-scopes metadata.
const ScopeDevicePreOnboard = "device:preonboard"

// HumanPrincipal is the server-authenticated reference to a human principal,
// established by the HumanOIDC authentication boundary (issuer + subject). It
// carries no partner authority, scopes, roles or eligibility by itself.
type HumanPrincipal struct {
	Issuer  string
	Subject string
}

// TemporaryPrincipalID is the server-authenticated reference to a Temporary
// Principal authorization record, established by the authentication boundary.
type TemporaryPrincipalID string

// PartnerAuthorization is one current effective partner authorization entry.
// DisplayName is response metadata only and never influences authorization.
type PartnerAuthorization struct {
	PartnerID   string
	DisplayName string
	Scopes      []string
}

// HumanAuthorizations is the resolved current effective authorization state
// for a human principal: a local principal_id and zero-or-more partners.
type HumanAuthorizations struct {
	PrincipalID string
	Partners    []PartnerAuthorization
}

// TemporaryPrincipalStatus is the current lifecycle status of a Temporary
// Principal authorization record.
type TemporaryPrincipalStatus string

const (
	// TemporaryPrincipalStatusActive means the local authorization record is
	// currently enabled and not disabled.
	TemporaryPrincipalStatusActive TemporaryPrincipalStatus = "ACTIVE"
	// TemporaryPrincipalStatusDisabled means the local authorization record
	// has been disabled.
	TemporaryPrincipalStatusDisabled TemporaryPrincipalStatus = "DISABLED"
)

// TemporaryPrincipalAuthorization is the current local authorization record of
// a Temporary Principal. It is resolved server-side from the authenticated
// temporary_principal_id and is never supplied by the request body.
type TemporaryPrincipalAuthorization struct {
	TemporaryPrincipalID string
	PartnerID            string
	Scopes               []string
	Status               TemporaryPrincipalStatus
	ExpiresAt            *time.Time
}
