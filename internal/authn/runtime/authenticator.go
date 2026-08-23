// Package runtime implements the M4.2 authentication runtime boundary. It
// consumes the immutable policy compiled by internal/authn/policy and enforces
// it at request time in two phases:
//
//	Phase A (base authentication): after the generated router matched a
//	route and before M3 contract enforcement, extracts the available
//	credential signals, dispatches them to the scheme-specific authenticators
//	relevant to the operation's policy, evaluates the OpenAPI OR/AND
//	requirements, and produces an immutable request-local AuthenticationContext.
//
//	Phase B (conditional authentication): after M3 contract enforcement,
//	resolves the compiled x-security-conditions for the validated request
//	body and verifies the authenticated credential kinds satisfy the case.
//
// This package authenticates requests generically. It contains NO concrete
// authentication mechanism: no JWT/OIDC/Keycloak, no opaque-token verifier,
// no DeviceMTLS/proxy implementation. Those belong to later milestones and
// plug in through the Authenticator and DeviceMTLSSource ports.
package runtime

import (
	"context"
	"fmt"
	"net/http"
	"reflect"

	"github.com/go-chi/chi/v5"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
)

// CredentialKind is an alias for the M4.1 policy CredentialKind: the closed
// set of six contractual credential kinds. It is the outer discriminator of
// every authenticated Binding.
type CredentialKind = authpolicy.CredentialKind

// Decision is the outcome of one authenticator evaluation for one credential
// signal.
//
// The zero value is DecisionRejected: a naive or buggy authenticator can
// never authenticate by default.
type Decision int

const (
	// DecisionRejected means the credential definitely does not belong to
	// this authenticator's CredentialKind.
	DecisionRejected Decision = iota
	// DecisionAuthenticated means the credential definitely belongs to this
	// authenticator's CredentialKind.
	DecisionAuthenticated
	// DecisionIndeterminate means the authenticator could not decide
	// (missing runtime support or an internal/dependency failure). The
	// runtime fails closed and never treats this as "rejected".
	DecisionIndeterminate
)

// DeviceCredential is the candidate device-mTLS credential signal produced
// by the trusted-proxy source (M4.5). It carries ONLY the server-resolved
// identifiers produced by that source; it never carries raw certificate,
// fingerprint, serial, TLS or proxy-header material. M4.2 carries it from the
// source port to the DeviceMTLS authenticator port without inspecting the
// contents beyond their non-emptiness at the authenticator.
type DeviceCredential struct {
	DeviceID              string
	CertificateID         string
	IssuedForEnrollmentID string
}

// Credential is the physical credential signal presented for one request,
// delivered to exactly one scheme-specific authenticator. Exactly one carrier
// field is relevant for any given CredentialKind:
//
//   - bearer-carrier kinds read BearerToken;
//   - DeviceMTLS reads Device.
//
// The runtime never stores this struct beyond the immediate dispatch.
type Credential struct {
	// BearerToken is the strictly extracted opaque bearer string. Empty when
	// the request presented no bearer credential.
	BearerToken string
	// Device is the candidate device-mTLS credential signal, or nil.
	Device *DeviceCredential
}

// Authenticator authenticates a credential for exactly one CredentialKind.
// Implementations must never log or surface the credential itself, and must
// return DecisionIndeterminate rather than DecisionRejected when they cannot
// decide (dependency down, verification unsupported, internal failure).
//
// A successful (Authenticated) result MUST carry a valid Binding whose Kind
// matches the authenticator's Kind; the runtime fails closed otherwise.
type Authenticator interface {
	// Kind returns the CredentialKind this authenticator serves.
	Kind() authpolicy.CredentialKind
	// Authenticate evaluates the credential and returns a result.
	Authenticate(ctx context.Context, c *Credential) AuthenticationResult
}

// AuthenticationResult is the outcome of one authenticator evaluation.
//
// The zero value is a rejected result. When Decision is Authenticated,
// Binding must be non-nil and its Kind must equal the authenticator's Kind;
// any other combination fails closed at the runtime. For Rejected and
// Indeterminate results the Binding is ignored and must not be relied upon.
type AuthenticationResult struct {
	Decision Decision
	Binding  *Binding
}

// Binding is the closed, typed, request-local authenticated identity
// established by a successful authenticator. CredentialKind is the outer
// discriminator; exactly one typed variant is populated and only the matching
// accessor succeeds.
//
// It is the abstraction boundary only: M4.3-M4.5 supply concrete bindings.
// A Binding carries typed facts — never the raw credential, never an
// Authorization header, never a token verifier/hash, never raw certificate or
// private material, and never a generic string payload. There is deliberately
// no god-principal.
type Binding struct {
	kind CredentialKind

	oidc             OIDCIdentityBinding
	requestAccess    RequestAccessBinding
	enrollmentAccess EnrollmentAccessBinding
	temporary        TemporaryPrincipalBinding
	deviceMTLS       DeviceMTLSBinding
}

// OIDCIdentityBinding is the authenticated identity for the HumanOIDC and
// AdminOIDC credential kinds: the issuer that minted the credential and the
// subject it identifies. It deliberately carries no partner_id, scopes,
// roles, permissions or authorization.
type OIDCIdentityBinding struct {
	Issuer  string
	Subject string
}

// RequestAccessBinding is the authenticated binding for RequestAccessToken:
// the exact pre-onboarding request the credential was verified against.
type RequestAccessBinding struct {
	PreOnboardingRequestID string
}

// EnrollmentAccessBinding is the authenticated binding for
// EnrollmentAccessToken: the exact enrollment the credential was verified
// against.
type EnrollmentAccessBinding struct {
	EnrollmentID string
}

// TemporaryPrincipalBinding is the authenticated binding for
// TemporaryPrincipalToken. Its bootstrap and verification mechanism remain
// deferred; it is NOT classified as JWT or opaque-capability here.
type TemporaryPrincipalBinding struct {
	TemporaryPrincipalID string
}

// DeviceMTLSBinding is the authenticated binding for DeviceMTLS: the
// server-resolved device identity, certificate identity and the enrollment
// that certificate was issued for. It carries no raw certificate/header/TLS
// material; all three IDs are resolved server-side by the M4.5 trusted-proxy
// source.
type DeviceMTLSBinding struct {
	DeviceID              string
	CertificateID         string
	IssuedForEnrollmentID string
}

// NewHumanOIDCBinding constructs a HumanOIDC binding. issuer and subject are
// both mandatory.
func NewHumanOIDCBinding(issuer, subject string) (*Binding, error) {
	if issuer == "" || subject == "" {
		return nil, errEmptyBindingField("HumanOIDC", "issuer/subject")
	}
	return &Binding{kind: authpolicy.CredentialKindHumanOIDC, oidc: OIDCIdentityBinding{Issuer: issuer, Subject: subject}}, nil
}

// NewAdminOIDCBinding constructs an AdminOIDC binding. issuer and subject are
// both mandatory. AdminOIDC shares the OIDC identity value type with
// HumanOIDC but its CredentialKind stays distinct.
func NewAdminOIDCBinding(issuer, subject string) (*Binding, error) {
	if issuer == "" || subject == "" {
		return nil, errEmptyBindingField("AdminOIDC", "issuer/subject")
	}
	return &Binding{kind: authpolicy.CredentialKindAdminOIDC, oidc: OIDCIdentityBinding{Issuer: issuer, Subject: subject}}, nil
}

// NewRequestAccessBinding constructs a RequestAccessToken binding. requestID
// is mandatory.
func NewRequestAccessBinding(requestID string) (*Binding, error) {
	if requestID == "" {
		return nil, errEmptyBindingField("RequestAccessToken", "pre_onboarding_request_id")
	}
	return &Binding{kind: authpolicy.CredentialKindRequestAccessToken, requestAccess: RequestAccessBinding{PreOnboardingRequestID: requestID}}, nil
}

// NewEnrollmentAccessBinding constructs an EnrollmentAccessToken binding.
// enrollmentID is mandatory.
func NewEnrollmentAccessBinding(enrollmentID string) (*Binding, error) {
	if enrollmentID == "" {
		return nil, errEmptyBindingField("EnrollmentAccessToken", "enrollment_id")
	}
	return &Binding{kind: authpolicy.CredentialKindEnrollmentAccessToken, enrollmentAccess: EnrollmentAccessBinding{EnrollmentID: enrollmentID}}, nil
}

// NewTemporaryPrincipalBinding constructs a TemporaryPrincipalToken binding.
// temporaryPrincipalID is mandatory.
func NewTemporaryPrincipalBinding(temporaryPrincipalID string) (*Binding, error) {
	if temporaryPrincipalID == "" {
		return nil, errEmptyBindingField("TemporaryPrincipalToken", "temporary_principal_id")
	}
	return &Binding{kind: authpolicy.CredentialKindTemporaryPrincipalToken, temporary: TemporaryPrincipalBinding{TemporaryPrincipalID: temporaryPrincipalID}}, nil
}

// NewDeviceMTLSBinding constructs a DeviceMTLS binding. deviceID,
// certificateID and issuedForEnrollmentID are all mandatory.
func NewDeviceMTLSBinding(deviceID, certificateID, issuedForEnrollmentID string) (*Binding, error) {
	if deviceID == "" || certificateID == "" || issuedForEnrollmentID == "" {
		return nil, errEmptyBindingField("DeviceMTLS", "device_id/certificate_id/issued_for_enrollment_id")
	}
	return &Binding{kind: authpolicy.CredentialKindDeviceMTLS, deviceMTLS: DeviceMTLSBinding{DeviceID: deviceID, CertificateID: certificateID, IssuedForEnrollmentID: issuedForEnrollmentID}}, nil
}

func errEmptyBindingField(kind, field string) error {
	return fmt.Errorf("runtime: %s binding requires non-empty %s", kind, field)
}

// Kind returns the CredentialKind this binding belongs to.
func (b *Binding) Kind() CredentialKind {
	if b == nil {
		return ""
	}
	return b.kind
}

// OIDCIdentity returns the OIDC identity binding, ok only for HumanOIDC and
// AdminOIDC bindings.
func (b *Binding) OIDCIdentity() (OIDCIdentityBinding, bool) {
	if b == nil || (b.kind != authpolicy.CredentialKindHumanOIDC && b.kind != authpolicy.CredentialKindAdminOIDC) {
		return OIDCIdentityBinding{}, false
	}
	return b.oidc, true
}

// RequestAccess returns the request-access binding, ok only for
// RequestAccessToken bindings.
func (b *Binding) RequestAccess() (RequestAccessBinding, bool) {
	if b == nil || b.kind != authpolicy.CredentialKindRequestAccessToken {
		return RequestAccessBinding{}, false
	}
	return b.requestAccess, true
}

// EnrollmentAccess returns the enrollment-access binding, ok only for
// EnrollmentAccessToken bindings.
func (b *Binding) EnrollmentAccess() (EnrollmentAccessBinding, bool) {
	if b == nil || b.kind != authpolicy.CredentialKindEnrollmentAccessToken {
		return EnrollmentAccessBinding{}, false
	}
	return b.enrollmentAccess, true
}

// TemporaryPrincipal returns the temporary-principal binding, ok only for
// TemporaryPrincipalToken bindings.
func (b *Binding) TemporaryPrincipal() (TemporaryPrincipalBinding, bool) {
	if b == nil || b.kind != authpolicy.CredentialKindTemporaryPrincipalToken {
		return TemporaryPrincipalBinding{}, false
	}
	return b.temporary, true
}

// DeviceMTLS returns the device-mTLS binding, ok only for DeviceMTLS
// bindings.
func (b *Binding) DeviceMTLS() (DeviceMTLSBinding, bool) {
	if b == nil || b.kind != authpolicy.CredentialKindDeviceMTLS {
		return DeviceMTLSBinding{}, false
	}
	return b.deviceMTLS, true
}

// DeviceMTLSSource obtains the candidate device-mTLS credential signal for a
// request. It is the ONLY way the runtime receives DeviceMTLS candidates.
//
// The trusted Reverse Proxy boundary (M4.5) provides the concrete
// implementation. A nil source means no candidate is ever available and the
// DeviceMTLS kind can never authenticate (fail closed).
type DeviceMTLSSource interface {
	// DeviceCredential returns the candidate device credential signal for
	// the request.
	//
	//   - (nil, nil) means the request presented no valid DeviceMTLS
	//     credential (the runtime classifies this as Rejected).
	//   - (credential, nil) carries the server-resolved device identity.
	//   - (_, non-nil error) means a trusted dependency could not be
	//     evaluated (the runtime classifies this as Indeterminate).
	DeviceCredential(r *http.Request) (*DeviceCredential, error)
}

// Registry maps each CredentialKind to exactly one Authenticator. It is
// immutable after construction and safe for concurrent use.
type Registry struct {
	byKind map[authpolicy.CredentialKind]Authenticator
}

// NilAuthenticatorError reports an Authenticator that is nil or holds a
// typed-nil value (a nil pointer/interface/map/slice/func/channel implementing
// Authenticator). Such a value is not a usable runtime component and must fail
// registry construction rather than be stored, skipped, or returned later.
type NilAuthenticatorError struct{}

func (e *NilAuthenticatorError) Error() string {
	return "runtime: nil or typed-nil authenticator is not a usable component"
}

// isNilLike reports whether v is nil or holds a typed-nil value of a nilable
// kind. A typed-nil pointer (or interface/map/slice/func/channel) implementing
// Authenticator or DeviceMTLSSource is not a usable runtime component even
// though the surrounding interface is non-nil. IsNil is only called for
// nilable kinds, so a concrete non-pointer implementation can never panic.
func isNilLike(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

// NewRegistry builds a registry from the given authenticators. Two
// authenticators for the same CredentialKind are a construction error, as is
// any nil or typed-nil authenticator (SOL-M4.6-003): an effectively nil
// component must never become a retrievable registry entry.
func NewRegistry(authenticators ...Authenticator) (*Registry, error) {
	r := &Registry{byKind: make(map[authpolicy.CredentialKind]Authenticator, len(authenticators))}
	for _, a := range authenticators {
		if isNilLike(a) {
			return nil, &NilAuthenticatorError{}
		}
		if _, dup := r.byKind[a.Kind()]; dup {
			return nil, &DuplicateKindError{Kind: a.Kind()}
		}
		r.byKind[a.Kind()] = a
	}
	return r, nil
}

// Get returns the authenticator for a kind. A nil or typed-nil authenticator
// is reported as unavailable (ok=false): the registry never exposes an
// effectively nil component as usable, even defensively (SOL-M4.6-003).
func (r *Registry) Get(kind authpolicy.CredentialKind) (Authenticator, bool) {
	a, ok := r.byKind[kind]
	if !ok || isNilLike(a) {
		return nil, false
	}
	return a, true
}

// DefaultDenyRegistry returns the production placeholder registry: every
// contractual CredentialKind is present with an authenticator that rejects
// every credential. Until the concrete authenticators (M4.3+) and the
// trusted-proxy boundary (M4.5) exist, no credential can ever authenticate by
// default.
func DefaultDenyRegistry() *Registry {
	var auths []Authenticator
	for _, kind := range allCredentialKinds {
		auths = append(auths, BearerTestAuthenticator{
			KindValue: kind,
			Decide: func(token string) Decision {
				return DecisionRejected
			},
		})
	}
	r, _ := NewRegistry(auths...)
	return r
}

// DuplicateKindError reports two authenticators registered for the same kind.
type DuplicateKindError struct {
	Kind authpolicy.CredentialKind
}

func (e *DuplicateKindError) Error() string {
	return "runtime: duplicate authenticator for credential kind " + string(e.Kind)
}

// --- deterministic test doubles ---

// BearerTestAuthenticator is a deterministic test double for a bearer-carrier
// CredentialKind. Its Decide function receives the strictly extracted bearer
// token (empty when the request presented none). On success it produces a
// typed binding for KindValue with obviously synthetic IDs that are never the
// bearer token.
type BearerTestAuthenticator struct {
	KindValue authpolicy.CredentialKind
	Decide    func(token string) Decision
}

// Kind returns the kind this double serves.
func (a BearerTestAuthenticator) Kind() authpolicy.CredentialKind { return a.KindValue }

// Authenticate evaluates the bearer token.
func (a BearerTestAuthenticator) Authenticate(ctx context.Context, c *Credential) AuthenticationResult {
	d := DecisionRejected
	if a.Decide != nil {
		d = a.Decide(c.BearerToken)
	}
	if d != DecisionAuthenticated {
		return AuthenticationResult{Decision: d}
	}
	b, err := a.binding(ctx)
	if err != nil {
		return AuthenticationResult{Decision: DecisionIndeterminate}
	}
	return AuthenticationResult{Decision: DecisionAuthenticated, Binding: b}
}

// binding builds the typed synthetic binding for this double's kind. For the
// capability kinds it uses the matched "id" path parameter (when present in
// the request context) so the M4.3 resource-binding enforcement sees a
// matching resource; unit tests without a route context fall back to a fixed
// synthetic id.
func (a BearerTestAuthenticator) binding(ctx context.Context) (*Binding, error) {
	switch a.KindValue {
	case authpolicy.CredentialKindHumanOIDC:
		return NewHumanOIDCBinding("test-issuer", "test-subject-human")
	case authpolicy.CredentialKindAdminOIDC:
		return NewAdminOIDCBinding("test-issuer", "test-subject-admin")
	case authpolicy.CredentialKindRequestAccessToken:
		return NewRequestAccessBinding(pathParamOr(ctx, "id", "test-por-request-access"))
	case authpolicy.CredentialKindEnrollmentAccessToken:
		return NewEnrollmentAccessBinding(pathParamOr(ctx, "id", "test-enr-enrollment-access"))
	case authpolicy.CredentialKindTemporaryPrincipalToken:
		return NewTemporaryPrincipalBinding("test-tp-temporary-principal")
	default:
		return nil, fmt.Errorf("runtime: test double for %q has no typed binding", a.KindValue)
	}
}

// DeviceTestAuthenticator is a deterministic test double for the DeviceMTLS
// kind. Its Decide function receives the candidate device credential (or nil
// when the source provided none).
type DeviceTestAuthenticator struct {
	Decide func(device *DeviceCredential) Decision
}

// Kind returns DeviceMTLS.
func (a DeviceTestAuthenticator) Kind() authpolicy.CredentialKind {
	return authpolicy.CredentialKindDeviceMTLS
}

// Authenticate evaluates the device credential. On success it builds a typed
// DeviceMTLS binding with synthetic IDs.
func (a DeviceTestAuthenticator) Authenticate(ctx context.Context, c *Credential) AuthenticationResult {
	d := DecisionRejected
	if a.Decide != nil {
		d = a.Decide(c.Device)
	}
	if d != DecisionAuthenticated {
		return AuthenticationResult{Decision: d}
	}
	b, err := NewDeviceMTLSBinding("test-device-id", "test-certificate-id", pathParamOr(ctx, "id", "test-enrollment-id"))
	if err != nil {
		return AuthenticationResult{Decision: DecisionIndeterminate}
	}
	return AuthenticationResult{Decision: DecisionAuthenticated, Binding: b}
}

// DeviceTestSource is a deterministic test double for DeviceMTLSSource. Its
// Credential function produces the candidate device credential per request.
type DeviceTestSource struct {
	Credential func(r *http.Request) (*DeviceCredential, error)
}

// DeviceCredential returns the candidate device credential for the request.
func (s DeviceTestSource) DeviceCredential(r *http.Request) (*DeviceCredential, error) {
	if s.Credential == nil {
		return nil, nil
	}
	return s.Credential(r)
}

// pathParamOr returns a matched chi path parameter by name, or fallback when
// there is no route context or no such parameter (unit tests use the
// fallback).
func pathParamOr(ctx context.Context, name, fallback string) string {
	if v, ok := pathParam(chi.RouteContext(ctx), name); ok {
		return v
	}
	return fallback
}

// allCredentialKinds is the closed set of the six contractual credential
// kinds, mirroring the M4.1 policy package's closed set. The runtime needs it
// only for the production deny-by-default registry.
var allCredentialKinds = []authpolicy.CredentialKind{
	authpolicy.CredentialKindHumanOIDC,
	authpolicy.CredentialKindAdminOIDC,
	authpolicy.CredentialKindTemporaryPrincipalToken,
	authpolicy.CredentialKindRequestAccessToken,
	authpolicy.CredentialKindEnrollmentAccessToken,
	authpolicy.CredentialKindDeviceMTLS,
}
