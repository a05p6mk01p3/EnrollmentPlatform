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

// ConditionalRequirement is the trusted, immutable, request-local result of
// Phase B's effective conditional selection: the discriminator value the
// request body carried and the exact CredentialKind it requires.
//
// Fields are unexported and there is no public setter: only Phase B (through
// newConditionalRequirement) constructs one, and the resource-binding step
// re-validates it against the compiled M4.1 policy rather than trusting it
// merely because it is present in the context.
type ConditionalRequirement struct {
	discriminator      string
	discriminatorValue string
	requiredKind       authpolicy.CredentialKind
}

// newConditionalRequirement is the only construction path for a conditional
// requirement; it is owned by Phase B.
func newConditionalRequirement(discriminator, discriminatorValue string, requiredKind authpolicy.CredentialKind) *ConditionalRequirement {
	return &ConditionalRequirement{
		discriminator:      discriminator,
		discriminatorValue: discriminatorValue,
		requiredKind:       requiredKind,
	}
}

// Discriminator returns the discriminator property name.
func (cr *ConditionalRequirement) Discriminator() string {
	if cr == nil {
		return ""
	}
	return cr.discriminator
}

// DiscriminatorValue returns the resolved discriminator value.
func (cr *ConditionalRequirement) DiscriminatorValue() string {
	if cr == nil {
		return ""
	}
	return cr.discriminatorValue
}

// RequiredKind returns the exact credential kind the effective case mandates.
func (cr *ConditionalRequirement) RequiredKind() authpolicy.CredentialKind {
	if cr == nil {
		return ""
	}
	return cr.requiredKind
}

type conditionalRequirementKey struct{}

// withConditionalRequirement stores the effective conditional requirement in
// ctx. It is attached by Phase B after the discriminator has been resolved.
// The helpers are package-private: unrelated code cannot inject an arbitrary
// requirement into a request context.
func withConditionalRequirement(ctx context.Context, cr *ConditionalRequirement) context.Context {
	return context.WithValue(ctx, conditionalRequirementKey{}, cr)
}

// conditionalRequirementFrom returns the effective conditional requirement,
// if Phase B resolved one.
func conditionalRequirementFrom(ctx context.Context) (*ConditionalRequirement, bool) {
	cr, ok := ctx.Value(conditionalRequirementKey{}).(*ConditionalRequirement)
	return cr, ok
}
