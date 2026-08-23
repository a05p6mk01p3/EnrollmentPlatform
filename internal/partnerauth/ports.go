package partnerauth

import "context"

// HumanAuthorizationResolver resolves the current effective partner
// authorizations for a server-authenticated human principal.
//
// A result returned with err == nil is a successful evaluation, including the
// valid empty state (zero partners). A non-nil error means the current
// authorization could not be established deterministically (dependency
// unavailable, malformed provider result, ambiguous state); callers MUST fail
// closed and must never interpret an error as an empty authorization set.
type HumanAuthorizationResolver interface {
	ResolveHumanAuthorizations(ctx context.Context, principal HumanPrincipal) (HumanAuthorizations, error)
}

// TemporaryPrincipalAuthorizationResolver resolves the current local
// authorization record for a server-authenticated Temporary Principal.
//
// A result returned with err == nil is a successful evaluation. A non-nil error
// means the current local authorization could not be established; callers MUST
// fail closed.
type TemporaryPrincipalAuthorizationResolver interface {
	ResolveTemporaryPrincipal(ctx context.Context, id TemporaryPrincipalID) (TemporaryPrincipalAuthorization, error)
}
