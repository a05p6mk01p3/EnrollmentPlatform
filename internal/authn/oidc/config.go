package oidc

import (
	"fmt"
	"reflect"
	"time"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
)

// supportedAlgorithms is the closed set of asymmetric JOSE signature
// algorithms this verifier may be configured to accept. Symmetric algorithms
// (HS*) and "none" are deliberately absent: they cannot be used with a public
// JWKS verification-key boundary without unsafe key-type confusion.
var supportedAlgorithms = map[string]struct{}{
	"RS256": {},
	"RS384": {},
	"RS512": {},
	"PS256": {},
	"PS384": {},
	"PS512": {},
	"ES256": {},
	"ES384": {},
	"ES512": {},
	"EdDSA": {},
}

// ProviderConfig is immutable trusted verification configuration for exactly
// one OIDC CredentialKind. All deployment-specific values (issuer, audience,
// algorithms, skew, key source, refresh TTL) are injected; none is hardcoded.
type ProviderConfig struct {
	kind       authpolicy.CredentialKind
	issuer     string
	audiences  []string
	algorithms []string
	clockSkew  time.Duration
	keySource  KeySetSource
	refreshTTL time.Duration
}

// ConfigError reports statically unsafe provider configuration. It is a typed
// construction error (never an HTTP error type).
type ConfigError struct {
	Kind   authpolicy.CredentialKind
	Field  string
	Reason string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("oidc: invalid %s provider config (%s): %s", e.Kind, e.Field, e.Reason)
}

// NewProviderConfig validates and builds an immutable provider configuration.
// It fails closed at construction for empty issuer, empty audience set, empty
// algorithm allowlist, invalid/unsupported algorithm, negative clock skew,
// non-positive refresh TTL, or a missing key source. It copies the slice
// inputs so the configuration cannot be mutated afterward.
func NewProviderConfig(kind authpolicy.CredentialKind, issuer string, audiences, algorithms []string, keySource KeySetSource, clockSkew, refreshTTL time.Duration) (*ProviderConfig, error) {
	if kind != authpolicy.CredentialKindHumanOIDC && kind != authpolicy.CredentialKindAdminOIDC {
		return nil, &ConfigError{Kind: kind, Field: "kind", Reason: "only HumanOIDC and AdminOIDC are supported"}
	}
	if issuer == "" {
		return nil, &ConfigError{Kind: kind, Field: "issuer", Reason: "must not be empty"}
	}
	if len(audiences) == 0 {
		return nil, &ConfigError{Kind: kind, Field: "audiences", Reason: "accepted audience set must not be empty"}
	}
	for _, a := range audiences {
		if a == "" {
			return nil, &ConfigError{Kind: kind, Field: "audiences", Reason: "audience entries must not be empty"}
		}
	}
	if len(algorithms) == 0 {
		return nil, &ConfigError{Kind: kind, Field: "algorithms", Reason: "algorithm allowlist must not be empty"}
	}
	for _, alg := range algorithms {
		if _, ok := supportedAlgorithms[alg]; !ok {
			return nil, &ConfigError{Kind: kind, Field: "algorithms", Reason: fmt.Sprintf("unsupported or invalid algorithm %q", alg)}
		}
	}
	if clockSkew < 0 {
		return nil, &ConfigError{Kind: kind, Field: "clock_skew", Reason: "must be non-negative"}
	}
	if refreshTTL <= 0 {
		return nil, &ConfigError{Kind: kind, Field: "refresh_ttl", Reason: "must be positive"}
	}
	if isNilInterfaceValue(keySource) {
		return nil, &ConfigError{Kind: kind, Field: "key_source", Reason: "must not be nil (including typed-nil implementations)"}
	}

	return &ProviderConfig{
		kind:       kind,
		issuer:     issuer,
		audiences:  append([]string(nil), audiences...),
		algorithms: append([]string(nil), algorithms...),
		clockSkew:  clockSkew,
		keySource:  keySource,
		refreshTTL: refreshTTL,
	}, nil
}

// Kind returns the CredentialKind this provider config is for.
func (c *ProviderConfig) Kind() authpolicy.CredentialKind { return c.kind }

// Issuer returns the exact configured issuer.
func (c *ProviderConfig) Issuer() string { return c.issuer }

// algorithmAllowed reports whether alg is in the configured allowlist.
func (c *ProviderConfig) algorithmAllowed(alg string) bool {
	for _, a := range c.algorithms {
		if a == alg {
			return true
		}
	}
	return false
}

// audienceMatches reports whether at least one trusted configured audience
// exactly matches one of the token's audiences (no prefix/substring match).
func (c *ProviderConfig) audienceMatches(audiences []string) bool {
	for _, got := range audiences {
		for _, trusted := range c.audiences {
			if got == trusted {
				return true
			}
		}
	}
	return false
}

// isNilInterfaceValue detects typed-nil interface values (SOL-M4.4-004 and
// SOL-M4.4-005): a
// KeySetSourceFunc(nil) or a nil pointer implementation satisfies the
// interface comparison but would panic when called. This check inspects the
// dynamic value only for nilable kinds, so non-nilable concrete
// implementations (structs) are never misclassified and never panic.
func isNilInterfaceValue(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan, reflect.Interface:
		return rv.IsNil()
	}
	return false
}
