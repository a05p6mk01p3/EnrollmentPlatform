package oidc

import (
	"context"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
)

// oidcAuthenticator adapts a Verifier to the M4.2 runtime.Authenticator
// interface for a single CredentialKind.
type oidcAuthenticator struct {
	kind     authpolicy.CredentialKind
	verifier *Verifier
}

// Kind returns the CredentialKind this authenticator serves.
func (a *oidcAuthenticator) Kind() authpolicy.CredentialKind { return a.kind }

// Authenticate verifies the bearer token as an OIDC JWT for this kind.
func (a *oidcAuthenticator) Authenticate(ctx context.Context, c *runtime.Credential) runtime.AuthenticationResult {
	return a.verifier.Verify(ctx, c.BearerToken)
}

// NewHumanOIDCAuthenticator builds a HumanOIDC authenticator. The provider
// config must be for the HumanOIDC kind; any other kind is a construction
// error (fail fast).
func NewHumanOIDCAuthenticator(config *ProviderConfig, clock Clock) (runtime.Authenticator, error) {
	if err := validateAuthenticatorConfig(config, authpolicy.CredentialKindHumanOIDC); err != nil {
		return nil, err
	}
	return &oidcAuthenticator{
		kind:     authpolicy.CredentialKindHumanOIDC,
		verifier: NewVerifier(config, clock),
	}, nil
}

// NewAdminOIDCAuthenticator builds an AdminOIDC authenticator. The provider
// config must be for the AdminOIDC kind; any other kind is a construction
// error (fail fast).
func NewAdminOIDCAuthenticator(config *ProviderConfig, clock Clock) (runtime.Authenticator, error) {
	if err := validateAuthenticatorConfig(config, authpolicy.CredentialKindAdminOIDC); err != nil {
		return nil, err
	}
	return &oidcAuthenticator{
		kind:     authpolicy.CredentialKindAdminOIDC,
		verifier: NewVerifier(config, clock),
	}, nil
}

// validateAuthenticatorConfig enforces that the provider config matches the
// requested CredentialKind, so HumanOIDC and AdminOIDC remain distinct nominal
// kinds with independent trusted configuration.
func validateAuthenticatorConfig(config *ProviderConfig, want authpolicy.CredentialKind) error {
	if config == nil {
		return &ConfigError{Kind: want, Field: "config", Reason: "must not be nil"}
	}
	if config.kind != want {
		return &ConfigError{Kind: want, Field: "kind", Reason: "provider config kind does not match the authenticator"}
	}
	return nil
}
