package partnerauth

import (
	"context"
	"testing"
)

// typedNilHumanResolver is a pointer-backed resolver whose nil pointer is the
// typed-nil human-resolver case.
type typedNilHumanResolver struct{}

func (*typedNilHumanResolver) ResolveHumanAuthorizations(context.Context, HumanPrincipal) (HumanAuthorizations, error) {
	return HumanAuthorizations{}, ErrDependencyUnavailable
}

// typedNilTempResolver is a pointer-backed resolver whose nil pointer is the
// typed-nil temporary-principal-resolver case.
type typedNilTempResolver struct{}

func (*typedNilTempResolver) ResolveTemporaryPrincipal(context.Context, TemporaryPrincipalID) (TemporaryPrincipalAuthorization, error) {
	return TemporaryPrincipalAuthorization{}, ErrDependencyUnavailable
}

func TestNewServiceRejectsNilResolvers(t *testing.T) {
	if _, err := NewService(nil, UnavailableTemporaryPrincipalResolver{}); err == nil {
		t.Fatal("nil human resolver must fail construction")
	}
	if _, err := NewService(UnavailableHumanResolver{}, nil); err == nil {
		t.Fatal("nil temporary principal resolver must fail construction")
	}
	if _, err := NewService(nil, nil); err == nil {
		t.Fatal("nil resolvers must fail construction")
	}
}

func TestNewServiceRejectsTypedNilResolvers(t *testing.T) {
	var h *typedNilHumanResolver
	var human HumanAuthorizationResolver = h
	if _, err := NewService(human, UnavailableTemporaryPrincipalResolver{}); err == nil {
		t.Fatal("typed-nil human resolver must fail construction")
	}

	var tp *typedNilTempResolver
	var temp TemporaryPrincipalAuthorizationResolver = tp
	if _, err := NewService(UnavailableHumanResolver{}, temp); err == nil {
		t.Fatal("typed-nil temporary principal resolver must fail construction")
	}
}

func TestNewServiceRejectsNilClock(t *testing.T) {
	s, err := NewService(UnavailableHumanResolver{}, UnavailableTemporaryPrincipalResolver{}, WithClock(nil))
	if err != nil {
		t.Fatalf("nil clock should fall back to time.Now: %v", err)
	}
	if s.now == nil {
		t.Fatal("clock must not remain nil after construction")
	}
}

// M5.2-CHATGPT-004: the exported Service type must expose explicit startup
// integrity validation, because other packages can legally construct a
// zero-value &partnerauth.Service{} that is non-nil but has no usable
// mandatory resolver state.
func TestServiceValidateRejectsZeroValue(t *testing.T) {
	if err := (&Service{}).Validate(); err == nil {
		t.Fatal("zero-value Service must fail startup validation")
	}
	if err := (*Service)(nil).Validate(); err == nil {
		t.Fatal("nil Service must fail startup validation")
	}
}

func TestServiceValidateRejectsTypedNilResolvers(t *testing.T) {
	var h *typedNilHumanResolver
	var human HumanAuthorizationResolver = h
	var tp *typedNilTempResolver
	var temp TemporaryPrincipalAuthorizationResolver = tp

	if err := (&Service{human: human, temp: temp}).Validate(); err == nil {
		t.Fatal("typed-nil resolvers must fail startup validation")
	}
	if err := (&Service{human: UnavailableHumanResolver{}, temp: temp}).Validate(); err == nil {
		t.Fatal("typed-nil temporary principal resolver must fail startup validation")
	}
	if err := (&Service{human: human, temp: UnavailableTemporaryPrincipalResolver{}}).Validate(); err == nil {
		t.Fatal("typed-nil human resolver must fail startup validation")
	}
}

func TestServiceValidateRejectsMissingClock(t *testing.T) {
	if err := (&Service{human: UnavailableHumanResolver{}, temp: UnavailableTemporaryPrincipalResolver{}, now: nil}).Validate(); err == nil {
		t.Fatal("missing clock must fail startup validation")
	}
}

func TestServiceValidateAcceptsConstructedServices(t *testing.T) {
	s, err := NewService(UnavailableHumanResolver{}, UnavailableTemporaryPrincipalResolver{})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("constructed Service must validate: %v", err)
	}
	if err := NewUnavailableService().Validate(); err != nil {
		t.Fatalf("explicitly unavailable Service must validate: %v", err)
	}
}
