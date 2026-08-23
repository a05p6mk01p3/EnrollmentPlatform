package partnerauth

import (
	"context"
	"errors"
)

// ErrDependencyUnavailable reports that the current authorization dependency
// is unavailable and the effective authorization cannot be established.
var ErrDependencyUnavailable = errors.New("partnerauth: authorization dependency unavailable")

// UnavailableHumanResolver is an explicit fail-closed resolver that
// deterministically reports the human authorization dependency as unavailable.
// It cannot be mistaken for an operational provider and never returns an
// empty-success result.
type UnavailableHumanResolver struct{}

// ResolveHumanAuthorizations always reports the dependency as unavailable.
func (UnavailableHumanResolver) ResolveHumanAuthorizations(_ context.Context, _ HumanPrincipal) (HumanAuthorizations, error) {
	return HumanAuthorizations{}, ErrDependencyUnavailable
}

// UnavailableTemporaryPrincipalResolver is an explicit fail-closed resolver
// that deterministically reports the Temporary Principal authorization
// dependency as unavailable.
type UnavailableTemporaryPrincipalResolver struct{}

// ResolveTemporaryPrincipal always reports the dependency as unavailable.
func (UnavailableTemporaryPrincipalResolver) ResolveTemporaryPrincipal(_ context.Context, _ TemporaryPrincipalID) (TemporaryPrincipalAuthorization, error) {
	return TemporaryPrincipalAuthorization{}, ErrDependencyUnavailable
}

// NewUnavailableService returns a Service wired with the explicit fail-closed
// unavailable resolvers. It is the production-composition default while no
// real partner authorization provider exists: every resolution fails closed
// and no protected mutation can proceed.
func NewUnavailableService() *Service {
	s, err := NewService(UnavailableHumanResolver{}, UnavailableTemporaryPrincipalResolver{})
	if err != nil {
		// Unreachable: both resolvers are non-nil concrete values.
		panic(err)
	}
	return s
}
