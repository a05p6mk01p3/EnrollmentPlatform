// Package composition assembles the concrete authentication components
// accepted in M4.3 (opaque capability), M4.4 (OIDC verification) and M4.5
// (trusted-proxy DeviceMTLS) into the M4.2 runtime boundary, and validates
// the assembled registry against the compiled M4.1 policy at startup (M4.6).
//
// It is a composition root, not a new authentication mechanism: it reuses the
// exported constructors and ports of the passed milestones and contributes
// only the explicit TemporaryPrincipalToken fail-closed seam. The
// TemporaryPrincipalToken bootstrap/verification mechanism is separately
// outside the current protocol (not an OPEN-003 concern, which is specifically
// the HUMAN_OIDC Agent login-acquisition flow).
package composition

import (
	"context"
	"errors"
	"fmt"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/devicemtls"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/oidc"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
)

// Config supplies the concrete ports for the six contractual credential
// kinds. All bearer-verifying components are required: a nil value is a
// construction error rather than a silent fail-open or a silent substitution.
type Config struct {
	// Capability (M4.3): non-reversible verifier + persistence-neutral store.
	CapabilityVerifier capability.Verifier
	CapabilityStore    capability.Store
	// CapabilityClock is optional; nil means the system clock.
	CapabilityClock capability.Clock

	// OIDC (M4.4): trusted provider configuration per logical scheme.
	HumanOIDC *oidc.ProviderConfig
	AdminOIDC *oidc.ProviderConfig
	// OIDCClock is optional; nil means the system clock.
	OIDCClock oidc.Clock

	// DeviceMTLSSource is the M4.5 trusted-proxy source. A nil value makes the
	// DeviceMTLS kind unreachable and is rejected by Build's validation, since
	// the canonical policy references DeviceMTLS.
	DeviceMTLSSource authruntime.DeviceMTLSSource

	// TemporaryPrincipal overrides the default explicit fail-closed adapter for
	// the TemporaryPrincipalToken kind. Leave nil to use the default adapter;
	// the kind can never be silently omitted or downgraded.
	TemporaryPrincipal authruntime.Authenticator
}

// ConfigError reports a missing or invalid composition input. It is a typed
// construction error and carries no credential material.
type ConfigError struct {
	Field  string
	Reason string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("composition: invalid %s: %s", e.Field, e.Reason)
}

// UnavailableTemporaryPrincipal is the explicit fail-closed runtime adapter
// for the TemporaryPrincipalToken credential kind. The concrete bootstrap and
// verification mechanism for temporary principals is separately outside the
// current protocol (intentionally unspecified, and distinct from OPEN-003,
// which is specifically the HUMAN_OIDC Agent login-acquisition flow), so no
// credential can ever be verified as a temporary principal yet.
//
// It returns DecisionRejected — never DecisionAuthenticated and never
// DecisionIndeterminate. Rejected is the only correct fail-closed outcome
// here: an Indeterminate result would make the whole request fail closed even
// when a sibling OR alternative (HumanOIDC on createPreOnboardingRequest)
// authenticated, because the runtime treats any eligible authenticator's
// Indeterminate as a hard dependency failure. Rejected keeps the sibling
// alternative usable while guaranteeing no bearer token is ever treated as a
// temporary principal.
type UnavailableTemporaryPrincipal struct{}

// NewUnavailableTemporaryPrincipal constructs the fail-closed adapter.
func NewUnavailableTemporaryPrincipal() *UnavailableTemporaryPrincipal {
	return &UnavailableTemporaryPrincipal{}
}

// Kind returns TemporaryPrincipalToken.
func (UnavailableTemporaryPrincipal) Kind() authpolicy.CredentialKind {
	return authpolicy.CredentialKindTemporaryPrincipalToken
}

// Authenticate always rejects: the concrete verifier does not exist yet, so no
// bearer token can be authenticated as a temporary principal.
func (UnavailableTemporaryPrincipal) Authenticate(_ context.Context, _ *authruntime.Credential) authruntime.AuthenticationResult {
	return authruntime.AuthenticationResult{Decision: authruntime.DecisionRejected}
}

// Registry assembles the six-kind authenticator registry from the concrete
// ports. Every required port must be non-nil; TemporaryPrincipalToken defaults
// to the explicit fail-closed adapter when no override is supplied. DeviceMTLS
// always gets its stateless authenticator; its trusted-proxy source is
// validated separately by Build.
func Registry(cfg Config) (*authruntime.Registry, error) {
	if cfg.CapabilityVerifier == nil {
		return nil, &ConfigError{Field: "capability_verifier", Reason: "must not be nil"}
	}
	if cfg.CapabilityStore == nil {
		return nil, &ConfigError{Field: "capability_store", Reason: "must not be nil"}
	}
	if cfg.HumanOIDC == nil {
		return nil, &ConfigError{Field: "human_oidc", Reason: "must not be nil"}
	}
	if cfg.AdminOIDC == nil {
		return nil, &ConfigError{Field: "admin_oidc", Reason: "must not be nil"}
	}

	human, err := oidc.NewHumanOIDCAuthenticator(cfg.HumanOIDC, cfg.OIDCClock)
	if err != nil {
		return nil, fmt.Errorf("composition: human OIDC authenticator: %w", err)
	}
	admin, err := oidc.NewAdminOIDCAuthenticator(cfg.AdminOIDC, cfg.OIDCClock)
	if err != nil {
		return nil, fmt.Errorf("composition: admin OIDC authenticator: %w", err)
	}

	temporary := cfg.TemporaryPrincipal
	if temporary == nil {
		temporary = NewUnavailableTemporaryPrincipal()
	}

	return authruntime.NewRegistry(
		capability.NewRequestAccessAuthenticator(cfg.CapabilityVerifier, cfg.CapabilityStore, cfg.CapabilityClock),
		capability.NewEnrollmentAccessAuthenticator(cfg.CapabilityVerifier, cfg.CapabilityStore, cfg.CapabilityClock),
		human,
		admin,
		temporary,
		devicemtls.NewAuthenticator(),
	)
}

// Build assembles the full runtime authentication composition and validates it
// against the compiled canonical policy at startup. It returns the registry and
// the trusted-proxy device source for wiring into httpapi.WithAuthnRegistry and
// httpapi.WithDeviceMTLSSource.
//
// Validation rejects a missing authenticator for any policy-referenced kind and
// a nil DeviceMTLSSource (the canonical policy references DeviceMTLS); absence
// is an explicit error, never a weakened policy.
func Build(cfg Config) (*authruntime.Registry, authruntime.DeviceMTLSSource, error) {
	spec, err := openapi.GetSpec()
	if err != nil {
		return nil, nil, fmt.Errorf("composition: loading canonical spec: %w", err)
	}
	compiled, err := authpolicy.Compile(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("composition: compiling authentication policy: %w", err)
	}

	registry, err := Registry(cfg)
	if err != nil {
		return nil, nil, err
	}
	if err := authruntime.ValidateRegistry(compiled, registry, cfg.DeviceMTLSSource); err != nil {
		var mae *authruntime.MissingAuthenticatorError
		if errors.As(err, &mae) {
			return nil, nil, fmt.Errorf("composition: %w", err)
		}
		return nil, nil, fmt.Errorf("composition: validating registry: %w", err)
	}
	return registry, cfg.DeviceMTLSSource, nil
}
