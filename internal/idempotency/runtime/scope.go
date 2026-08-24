package runtime

import (
	"fmt"
	"strings"

	authnpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
)

// CredentialScope is the opaque, immutable, exact identifier for the
// already-authenticated credential/identity scope established by M4.x. It is
// the idempotency kernel's only notion of "who": a narrow kind discriminator
// plus an opaque, non-secret server-authenticated binding value.
//
// It is deliberately NOT a god-principal, NOT a raw bearer token, NOT an
// Authorization header, NOT a client-supplied partner_id, NOT raw certificate
// material, and NOT a private key. Idempotency is not authentication or
// authorization.
type CredentialScope struct {
	kind    authnpolicy.CredentialKind
	binding string
}

// NewCredentialScope constructs a CredentialScope from a recognized credential
// kind and an opaque, non-secret, already-authenticated binding value. It
// fails closed on an unrecognized kind or an empty binding.
func NewCredentialScope(kind authnpolicy.CredentialKind, binding string) (CredentialScope, error) {
	if _, recognized := authnpolicy.ParseCredentialKind(string(kind)); !recognized {
		return CredentialScope{}, fmt.Errorf("credential scope: unrecognized credential kind %q", kind)
	}
	if binding == "" {
		return CredentialScope{}, fmt.Errorf("credential scope: binding must be non-empty")
	}
	return CredentialScope{kind: kind, binding: binding}, nil
}

// Kind returns the credential-kind discriminator of this scope.
func (c CredentialScope) Kind() authnpolicy.CredentialKind { return c.kind }

// Binding returns the exact opaque, non-secret server-authenticated binding
// value. Together with Kind it is the stable adapter-facing persistence
// representation for the credential scope. It is not a diagnostic format and
// carries no raw credential.
func (c CredentialScope) Binding() string { return c.binding }

// IsZero reports whether the scope is the unusable zero value.
func (c CredentialScope) IsZero() bool { return c.kind == "" && c.binding == "" }

// Equal reports exact scope equality.
func (c CredentialScope) Equal(other CredentialScope) bool { return c == other }

// String renders a deterministic, diagnostic-only form. It is not an
// authentication verifier and is not itself stored as authority.
func (c CredentialScope) String() string {
	return string(c.kind) + ":" + c.binding
}

// EffectiveScope is the exact Protocol §6.3 effective idempotency scope:
//
//	trusted authenticated credential scope
//	+ canonical HTTP method
//	+ canonical OpenAPI route template
//	+ exact Idempotency-Key
//
// Any exact component change maps to a different scope. All fields are
// comparable value strings, so EffectiveScope is comparable and safe to use
// as a coordination map key.
type EffectiveScope struct {
	credential CredentialScope
	method     string
	route      string
	key        IdempotencyKey
}

// NewEffectiveScope constructs an EffectiveScope. It fails closed on a
// zero-value credential scope/key or an empty/non-canonical method or route;
// it never canonicalizes authority into validity.
func NewEffectiveScope(cred CredentialScope, method, route string, key IdempotencyKey) (EffectiveScope, error) {
	if cred.IsZero() {
		return EffectiveScope{}, fmt.Errorf("effective scope: credential scope must not be zero")
	}
	if method == "" || method != strings.ToUpper(method) {
		return EffectiveScope{}, fmt.Errorf("effective scope: method must be a non-empty canonical uppercase HTTP method")
	}
	if route == "" {
		return EffectiveScope{}, fmt.Errorf("effective scope: route template must be non-empty")
	}
	if key.IsZero() {
		return EffectiveScope{}, fmt.Errorf("effective scope: idempotency key must not be zero")
	}
	return EffectiveScope{credential: cred, method: method, route: route, key: key}, nil
}

// Credential returns the credential scope component.
func (s EffectiveScope) Credential() CredentialScope { return s.credential }

// Method returns the canonical HTTP method component.
func (s EffectiveScope) Method() string { return s.method }

// Route returns the canonical OpenAPI route template component.
func (s EffectiveScope) Route() string { return s.route }

// Key returns the exact Idempotency-Key component.
func (s EffectiveScope) Key() IdempotencyKey { return s.key }

// IsZero reports whether the scope is the unusable zero value.
func (s EffectiveScope) IsZero() bool {
	return s.credential.IsZero() && s.method == "" && s.route == "" && s.key.IsZero()
}

// Equal reports exact effective-scope equality.
func (s EffectiveScope) Equal(other EffectiveScope) bool { return s == other }
