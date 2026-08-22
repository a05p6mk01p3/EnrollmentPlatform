package runtime

import (
	"context"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
)

// AuthenticationContext is the immutable, request-local result of Phase A
// base authentication.
//
// It contains only authentication-boundary information: the canonical
// operationId, the credential kinds that authenticated, and the conjunctions
// that were fully satisfied. It deliberately contains NO raw bearer token,
// no Authorization header, no key/certificate material, no scopes, no
// partner/admin authorization and no eligibility decisions.
//
// A fresh instance is created per request; it is never mutated after
// construction and is safe for concurrent reads within the request. Accessors
// return copies, so callers cannot corrupt the shared state.
type AuthenticationContext struct {
	operationID string
	kinds       []authpolicy.CredentialKind // sorted, immutable
	bindings    map[authpolicy.CredentialKind]Binding
	satisfied   []authpolicy.Conjunction // conjunctions fully satisfied
}

// OperationID returns the canonical operationId this context was built for.
func (ac *AuthenticationContext) OperationID() string { return ac.operationID }

// Kinds returns a defensive copy of the authenticated credential kinds, in
// deterministic order.
func (ac *AuthenticationContext) Kinds() []authpolicy.CredentialKind {
	return append([]authpolicy.CredentialKind(nil), ac.kinds...)
}

// Has reports whether the given credential kind authenticated.
func (ac *AuthenticationContext) Has(kind authpolicy.CredentialKind) bool {
	for _, k := range ac.kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// SatisfiedAlternatives returns a defensive copy of the fully satisfied
// conjunctions (each an AND-set of the operation's OR alternatives).
func (ac *AuthenticationContext) SatisfiedAlternatives() []authpolicy.Conjunction {
	return append([]authpolicy.Conjunction(nil), ac.satisfied...)
}

// Binding returns the authenticated binding for a credential kind, if that
// kind authenticated. The returned value is an immutable typed binding.
func (ac *AuthenticationContext) Binding(kind authpolicy.CredentialKind) (Binding, bool) {
	b, ok := ac.bindings[kind]
	return b, ok
}

// Bindings returns a defensive copy of all authenticated bindings as value
// objects (no pointers, no mutable internal state).
func (ac *AuthenticationContext) Bindings() []Binding {
	out := make([]Binding, 0, len(ac.bindings))
	for _, b := range ac.bindings {
		out = append(out, b)
	}
	return out
}

type authenticationContextKey struct{}

// WithAuthenticationContext stores the authentication context in ctx. It
// must only be attached by Phase A; consumers read it via
// AuthenticationContextFrom.
func WithAuthenticationContext(ctx context.Context, ac *AuthenticationContext) context.Context {
	return context.WithValue(ctx, authenticationContextKey{}, ac)
}

// AuthenticationContextFrom returns the request-local authentication context,
// if Phase A attached one.
func AuthenticationContextFrom(ctx context.Context) (*AuthenticationContext, bool) {
	ac, ok := ctx.Value(authenticationContextKey{}).(*AuthenticationContext)
	return ac, ok
}
