package capability

import (
	"context"
	"errors"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
)

// RequestAccessAuthenticator authenticates opaque RequestAccessToken bearer
// capabilities. It is lifecycle-aware and READ-ONLY: it never consumes the
// token. Consumption belongs to the atomic INITIAL enrollment exchange, not
// to authentication.
type RequestAccessAuthenticator struct {
	verifier Verifier
	store    Store
	clock    Clock
}

// NewRequestAccessAuthenticator wires a RequestAccessToken authenticator. A
// nil clock defaults to the system clock.
func NewRequestAccessAuthenticator(verifier Verifier, store Store, clock Clock) *RequestAccessAuthenticator {
	if clock == nil {
		clock = SystemClock{}
	}
	return &RequestAccessAuthenticator{verifier: verifier, store: store, clock: clock}
}

// Kind returns the credential kind this authenticator serves.
func (a *RequestAccessAuthenticator) Kind() authpolicy.CredentialKind {
	return authpolicy.CredentialKindRequestAccessToken
}

// Authenticate verifies the bearer token as a RequestAccessToken capability.
//
// ACTIVE + valid verifier + unexpired => Authenticated with a
// RequestAccessBinding. Unknown/mismatch/expired/consumed => Rejected.
// Verifier/store infrastructure failure => Indeterminate.
func (a *RequestAccessAuthenticator) Authenticate(ctx context.Context, c *runtime.Credential) runtime.AuthenticationResult {
	if c.BearerToken == "" {
		return runtime.AuthenticationResult{Decision: runtime.DecisionRejected}
	}
	key, err := a.verifier.Derive(authpolicy.CredentialKindRequestAccessToken, c.BearerToken)
	if err != nil {
		return runtime.AuthenticationResult{Decision: runtime.DecisionIndeterminate}
	}
	rec, err := a.store.LookupRequestAccess(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return runtime.AuthenticationResult{Decision: runtime.DecisionRejected}
	}
	if err != nil {
		return runtime.AuthenticationResult{Decision: runtime.DecisionIndeterminate}
	}
	if rec.State != StateActive {
		return runtime.AuthenticationResult{Decision: runtime.DecisionRejected}
	}
	if !a.clock.Now().Before(rec.ExpiresAt) {
		return runtime.AuthenticationResult{Decision: runtime.DecisionRejected}
	}
	b, err := runtime.NewRequestAccessBinding(rec.PreOnboardingRequestID)
	if err != nil {
		return runtime.AuthenticationResult{Decision: runtime.DecisionIndeterminate}
	}
	return runtime.AuthenticationResult{Decision: runtime.DecisionAuthenticated, Binding: b}
}

// EnrollmentAccessAuthenticator authenticates opaque EnrollmentAccessToken
// bearer capabilities. Successful activation remains DeviceMTLS, not this
// credential kind.
type EnrollmentAccessAuthenticator struct {
	verifier Verifier
	store    Store
	clock    Clock
}

// NewEnrollmentAccessAuthenticator wires an EnrollmentAccessToken
// authenticator. A nil clock defaults to the system clock.
func NewEnrollmentAccessAuthenticator(verifier Verifier, store Store, clock Clock) *EnrollmentAccessAuthenticator {
	if clock == nil {
		clock = SystemClock{}
	}
	return &EnrollmentAccessAuthenticator{verifier: verifier, store: store, clock: clock}
}

// Kind returns the credential kind this authenticator serves.
func (a *EnrollmentAccessAuthenticator) Kind() authpolicy.CredentialKind {
	return authpolicy.CredentialKindEnrollmentAccessToken
}

// Authenticate verifies the bearer token as an EnrollmentAccessToken
// capability. Unknown/mismatch/expired => Rejected; verifier/store
// infrastructure failure => Indeterminate.
func (a *EnrollmentAccessAuthenticator) Authenticate(ctx context.Context, c *runtime.Credential) runtime.AuthenticationResult {
	if c.BearerToken == "" {
		return runtime.AuthenticationResult{Decision: runtime.DecisionRejected}
	}
	key, err := a.verifier.Derive(authpolicy.CredentialKindEnrollmentAccessToken, c.BearerToken)
	if err != nil {
		return runtime.AuthenticationResult{Decision: runtime.DecisionIndeterminate}
	}
	rec, err := a.store.LookupEnrollmentAccess(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return runtime.AuthenticationResult{Decision: runtime.DecisionRejected}
	}
	if err != nil {
		return runtime.AuthenticationResult{Decision: runtime.DecisionIndeterminate}
	}
	if !a.clock.Now().Before(rec.ExpiresAt) {
		return runtime.AuthenticationResult{Decision: runtime.DecisionRejected}
	}
	b, err := runtime.NewEnrollmentAccessBinding(rec.EnrollmentID)
	if err != nil {
		return runtime.AuthenticationResult{Decision: runtime.DecisionIndeterminate}
	}
	return runtime.AuthenticationResult{Decision: runtime.DecisionAuthenticated, Binding: b}
}
