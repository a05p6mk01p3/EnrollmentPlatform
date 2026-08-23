package resourceownership

import (
	"context"
	"errors"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
)

// ErrOwnershipDependencyUnavailable reports that the resource ownership
// lookup dependency is unavailable and the authoritative ownership cannot be
// established.
var ErrOwnershipDependencyUnavailable = errors.New("resourceownership: ownership dependency unavailable")

// UnavailablePreOnboardingOwnershipResolver is an explicit fail-closed
// resolver that deterministically reports the resource ownership dependency as
// unavailable. It cannot be mistaken for an operational provider and never
// returns a NOT_FOUND or FOUND result.
type UnavailablePreOnboardingOwnershipResolver struct{}

// ResolvePreOnboardingOwnership always reports the dependency as unavailable.
func (UnavailablePreOnboardingOwnershipResolver) ResolvePreOnboardingOwnership(_ context.Context, _ string) (OwnershipResult, error) {
	return OwnershipResult{}, ErrOwnershipDependencyUnavailable
}

// NewUnavailableService returns a Service wired with the explicit fail-closed
// unavailable ownership resolver. It is the production-composition default
// while no real resource ownership provider exists: every ownership lookup
// fails closed with dependency-unavailable.
func NewUnavailableService(humanAuth *partnerauth.Service) *Service {
	s, err := NewService(UnavailablePreOnboardingOwnershipResolver{}, humanAuth)
	if err != nil {
		panic(err)
	}
	return s
}
