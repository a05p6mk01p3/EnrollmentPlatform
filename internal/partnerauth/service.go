package partnerauth

import (
	"context"
	"errors"
	"reflect"
	"time"
)

// Service is the M5.2 partner authorization application boundary. It resolves
// current effective authorizations through provider-neutral resolver ports,
// enforces authorization-set integrity, and evaluates partner/scope selection.
//
// It is immutable after construction, holds no mutable global state, and does
// not cache authoritative results across requests. It is safe for concurrent
// use. Every resolution is current for the request it serves.
type Service struct {
	human HumanAuthorizationResolver
	temp  TemporaryPrincipalAuthorizationResolver
	now   func() time.Time
}

// ServiceOption customizes Service construction.
type ServiceOption func(*Service)

// WithClock injects a deterministic clock used for Temporary Principal expiry
// evaluation. The default is time.Now.
func WithClock(now func() time.Time) ServiceOption {
	return func(s *Service) { s.now = now }
}

// NewService constructs a Service. Both resolver ports are mandatory: a nil or
// typed-nil resolver fails construction. There is no permissive fallback and
// no silent empty-success provider.
func NewService(human HumanAuthorizationResolver, temp TemporaryPrincipalAuthorizationResolver, opts ...ServiceOption) (*Service, error) {
	if isNilLike(human) {
		return nil, errors.New("partnerauth: human authorization resolver must not be nil or typed-nil")
	}
	if isNilLike(temp) {
		return nil, errors.New("partnerauth: temporary principal authorization resolver must not be nil or typed-nil")
	}
	s := &Service{human: human, temp: temp, now: time.Now}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// Validate reports whether the Service is structurally usable at startup:
// both mandatory resolver ports (human and Temporary Principal) and the clock
// must be present. It exists because Service is an exported type and the
// composition root must revalidate mandatory runtime dependencies at the
// startup boundary rather than relying solely on the constructor having been
// used: a zero-value &partnerauth.Service{} is non-nil but fails here, as do
// services whose resolver fields are nil or typed-nil.
//
// A Service produced by NewService always validates, and
// NewUnavailableService also validates: its resolvers exist and
// deterministically report dependency-unavailable. The request-time fail-
// closed checks remain as defense in depth.
func (s *Service) Validate() error {
	if s == nil {
		return errors.New("partnerauth: nil service")
	}
	if isNilLike(s.human) {
		return errors.New("partnerauth: human authorization resolver missing or typed-nil")
	}
	if isNilLike(s.temp) {
		return errors.New("partnerauth: temporary principal authorization resolver missing or typed-nil")
	}
	if s.now == nil {
		return errors.New("partnerauth: clock missing")
	}
	return nil
}

// ResolveMyAuthorizations resolves, integrity-validates and returns the current
// effective authorizations of a human principal. A successful empty result
// (zero partners) is returned with err == nil and is NOT an error.
func (s *Service) ResolveMyAuthorizations(ctx context.Context, principal HumanPrincipal) (HumanAuthorizations, error) {
	if s == nil || isNilLike(s.human) {
		return HumanAuthorizations{}, ErrDependencyUnavailable
	}
	raw, err := s.human.ResolveHumanAuthorizations(ctx, principal)
	if err != nil {
		return HumanAuthorizations{}, err
	}
	return validateHumanAuthorizations(raw)
}

// AuthorizeHumanPreOnboarding resolves and evaluates the partner/scope
// selection for a human principal attempting to create a pre-onboarding
// request. A non-nil error must be treated as SelectionIndeterminate by the
// caller (dependency unavailable, malformed or ambiguous state).
func (s *Service) AuthorizeHumanPreOnboarding(ctx context.Context, principal HumanPrincipal, requestedPartnerID string) (SelectionDecision, error) {
	set, err := s.ResolveMyAuthorizations(ctx, principal)
	if err != nil {
		return SelectionIndeterminate, err
	}
	return SelectHumanPreOnboarding(set, requestedPartnerID, ScopeDevicePreOnboard), nil
}

// AuthorizeTemporaryPrincipalPreOnboarding resolves, integrity-validates and
// evaluates the Temporary Principal partner/scope/local-lifecycle selection
// sub-gate. A non-nil error must be treated as SelectionIndeterminate.
//
// This evaluates ONLY the M5.2 selection sub-gate. It does not consume
// max_submissions/quota and does not establish that the production HTTP path
// may return 201; those gates remain deferred.
func (s *Service) AuthorizeTemporaryPrincipalPreOnboarding(ctx context.Context, id TemporaryPrincipalID, requestedPartnerID string) (SelectionDecision, error) {
	if s == nil || isNilLike(s.temp) || s.now == nil {
		return SelectionIndeterminate, ErrDependencyUnavailable
	}
	raw, err := s.temp.ResolveTemporaryPrincipal(ctx, id)
	if err != nil {
		return SelectionIndeterminate, err
	}
	validated, err := validateTemporaryPrincipalAuthorization(id, raw)
	if err != nil {
		return SelectionIndeterminate, err
	}
	return SelectTemporaryPrincipalPreOnboarding(validated, requestedPartnerID, ScopeDevicePreOnboard, s.now()), nil
}

// isNilLike reports whether v is nil or holds a typed-nil value of a nilable kind.
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
