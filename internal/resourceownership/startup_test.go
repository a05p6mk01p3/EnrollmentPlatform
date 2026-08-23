package resourceownership_test

import (
	"context"
	"testing"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/resourceownership"
)

func TestStartupIntegrity(t *testing.T) {
	validOwnership := resourceownership.StaticPreOnboardingOwnershipResolver{}
	validHumanAuth := partnerauth.NewUnavailableService()

	t.Run("nil ownership resolver rejected", func(t *testing.T) {
		if _, err := resourceownership.NewService(nil, validHumanAuth); err == nil {
			t.Fatal("NewService with nil ownership resolver must fail")
		}
	})

	t.Run("typed nil ownership resolver rejected", func(t *testing.T) {
		var typedNil *resourceownership.SpyPreOnboardingOwnershipResolver
		if _, err := resourceownership.NewService(typedNil, validHumanAuth); err == nil {
			t.Fatal("NewService with typed-nil ownership resolver must fail")
		}
	})

	t.Run("nil partner authorization service rejected", func(t *testing.T) {
		if _, err := resourceownership.NewService(validOwnership, nil); err == nil {
			t.Fatal("NewService with nil partner authorization service must fail")
		}
	})

	t.Run("typed nil partner authorization service rejected", func(t *testing.T) {
		var typedNil *partnerauth.Service
		if _, err := resourceownership.NewService(validOwnership, typedNil); err == nil {
			t.Fatal("NewService with typed-nil partner authorization service must fail")
		}
	})

	t.Run("invalid zero-value partner authorization service rejected", func(t *testing.T) {
		invalidPartnerSvc := &partnerauth.Service{}
		if _, err := resourceownership.NewService(validOwnership, invalidPartnerSvc); err == nil {
			t.Fatal("NewService with invalid partner authorization service must fail")
		}
	})

	t.Run("zero-value Service rejected by Validate", func(t *testing.T) {
		zeroSvc := &resourceownership.Service{}
		if err := zeroSvc.Validate(); err == nil {
			t.Fatal("zero-value &resourceownership.Service{} must fail Validate()")
		}
	})

	t.Run("nil Service pointer rejected by Validate", func(t *testing.T) {
		var nilSvc *resourceownership.Service
		if err := nilSvc.Validate(); err == nil {
			t.Fatal("nil *resourceownership.Service must fail Validate()")
		}
	})

	t.Run("ValidateWithPartnerAuth matching instance succeeds", func(t *testing.T) {
		svc, err := resourceownership.NewService(validOwnership, validHumanAuth)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}
		if err := svc.ValidateWithPartnerAuth(validHumanAuth); err != nil {
			t.Fatalf("ValidateWithPartnerAuth matching instance must succeed: %v", err)
		}
	})

	t.Run("ValidateWithPartnerAuth mismatching instance fails", func(t *testing.T) {
		otherPartnerSvc, err := partnerauth.NewService(
			partnerauth.StaticHumanResolver{
				Resolve: func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
					return partnerauth.HumanAuthorizations{PrincipalID: "other"}, nil
				},
			},
			partnerauth.UnavailableTemporaryPrincipalResolver{},
		)
		if err != nil {
			t.Fatalf("NewService other partner: %v", err)
		}

		svc, err := resourceownership.NewService(validOwnership, validHumanAuth)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}

		if err := svc.ValidateWithPartnerAuth(otherPartnerSvc); err == nil {
			t.Fatal("ValidateWithPartnerAuth with different partnerauth.Service instance must fail")
		}
	})

	t.Run("ValidateWithPartnerAuth nil expected fails", func(t *testing.T) {
		svc, err := resourceownership.NewService(validOwnership, validHumanAuth)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}
		if err := svc.ValidateWithPartnerAuth(nil); err == nil {
			t.Fatal("ValidateWithPartnerAuth with nil expected must fail")
		}
	})

	t.Run("NewUnavailableService is structurally valid", func(t *testing.T) {
		svc := resourceownership.NewUnavailableService(validHumanAuth)
		if err := svc.Validate(); err != nil {
			t.Fatalf("NewUnavailableService must validate successfully: %v", err)
		}
		if err := svc.ValidateWithPartnerAuth(validHumanAuth); err != nil {
			t.Fatalf("NewUnavailableService ValidateWithPartnerAuth must succeed: %v", err)
		}
	})
}
