package application

import (
	"context"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
)

// UnavailableUnitOfWorkManager is a structurally valid but fail-closed UoW manager.
type UnavailableUnitOfWorkManager struct{}

func (UnavailableUnitOfWorkManager) Begin(ctx context.Context) (UnitOfWork, error) {
	return nil, ErrDependencyUnavailable
}

func (UnavailableUnitOfWorkManager) Validate() error { return nil }

// UnavailableDeviceAllocator is a structurally valid but fail-closed device allocator.
type UnavailableDeviceAllocator struct{}

func (UnavailableDeviceAllocator) AllocateDeviceID(ctx context.Context, req *domain.PreOnboardingRequest) (string, error) {
	return "", ErrDependencyUnavailable
}

func (UnavailableDeviceAllocator) Validate() error { return nil }

// UnavailablePartnerAuthorityChecker is a structurally valid but fail-closed partner authority checker.
type UnavailablePartnerAuthorityChecker struct{}

func (UnavailablePartnerAuthorityChecker) HasPartnerAuthority(ctx context.Context, admin AdminPrincipal, partnerID string) (bool, error) {
	return false, ErrDependencyUnavailable
}

func (UnavailablePartnerAuthorityChecker) GetAuthorizedPartners(ctx context.Context, admin AdminPrincipal) ([]string, error) {
	return nil, ErrDependencyUnavailable
}

func (UnavailablePartnerAuthorityChecker) Validate() error { return nil }

// UnavailablePartnerEligibilityChecker is a structurally valid but fail-closed partner eligibility checker.
type UnavailablePartnerEligibilityChecker struct{}

func (UnavailablePartnerEligibilityChecker) IsPartnerEligible(ctx context.Context, partnerID string) (bool, error) {
	return false, ErrDependencyUnavailable
}

func (UnavailablePartnerEligibilityChecker) Validate() error { return nil }

// NewUnavailableService returns a Service wired with explicit fail-closed unavailable
// dependencies. It passes structural validation at startup, but every request-time
// operation fails closed with ErrDependencyUnavailable.
func NewUnavailableService() *Service {
	s, err := NewService(ServiceConfig{
		UOWManager:         UnavailableUnitOfWorkManager{},
		Clock:              SystemClock{},
		DeviceAllocator:    UnavailableDeviceAllocator{},
		PartnerAuth:        UnavailablePartnerAuthorityChecker{},
		PartnerEligibility: UnavailablePartnerEligibilityChecker{},
		RetentionPolicy:    StaticIdempotencyRetentionPolicy{Duration: time.Hour},
	})
	if err != nil {
		panic(err)
	}
	return s
}
