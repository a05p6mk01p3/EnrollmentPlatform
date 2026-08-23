package resourceownership_test

import (
	"context"
	"sync"
	"testing"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/resourceownership"
)

func TestServiceConcurrencyIsolation(t *testing.T) {
	humanAuth := testPartnerAuthService(t, func(_ context.Context, principal partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
		switch principal.Subject {
		case "user-A":
			return partnerauth.HumanAuthorizations{
				PrincipalID: "user-A",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1"},
				},
			}, nil
		case "user-B":
			return partnerauth.HumanAuthorizations{
				PrincipalID: "user-B",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P2", DisplayName: "Partner 2"},
				},
			}, nil
		default:
			return partnerauth.HumanAuthorizations{
				PrincipalID: principal.Subject,
				Partners:    []partnerauth.PartnerAuthorization{},
			}, nil
		}
	})

	ownership := resourceownership.StaticPreOnboardingOwnershipResolver{
		Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
			switch id {
			case "por-1":
				return resourceownership.OwnershipFound("por-1", "P1"), nil
			case "por-2":
				return resourceownership.OwnershipFound("por-2", "P2"), nil
			default:
				return resourceownership.OwnershipNotFound(), nil
			}
		},
	}

	svc, err := resourceownership.NewService(ownership, humanAuth)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	var wg sync.WaitGroup
	workers := 50
	iterations := 100

	ctx := context.Background()

	for w := 0; w < workers; w++ {
		wg.Add(4)

		// Case 1: User A -> por-1 (P1) -> must be Allowed
		go func(workerID int) {
			defer wg.Done()
			principal := partnerauth.HumanPrincipal{Issuer: "https://auth.example.com", Subject: "user-A"}
			for i := 0; i < iterations; i++ {
				dec, partnerID, err := svc.EvaluateHumanVisibility(ctx, principal, "por-1")
				if err != nil || dec != resourceownership.VisibilityAllowed || partnerID != "P1" {
					t.Errorf("worker %d: User A por-1 expected (Allowed, P1), got (%v, %q, %v)", workerID, dec, partnerID, err)
					return
				}
			}
		}(w)

		// Case 2: User A -> por-2 (P2) -> must be HiddenNotFound
		go func(workerID int) {
			defer wg.Done()
			principal := partnerauth.HumanPrincipal{Issuer: "https://auth.example.com", Subject: "user-A"}
			for i := 0; i < iterations; i++ {
				dec, _, err := svc.EvaluateHumanVisibility(ctx, principal, "por-2")
				if err != nil || dec != resourceownership.VisibilityHiddenNotFound {
					t.Errorf("worker %d: User A por-2 expected HiddenNotFound, got (%v, %v)", workerID, dec, err)
					return
				}
			}
		}(w)

		// Case 3: User B -> por-2 (P2) -> must be Allowed
		go func(workerID int) {
			defer wg.Done()
			principal := partnerauth.HumanPrincipal{Issuer: "https://auth.example.com", Subject: "user-B"}
			for i := 0; i < iterations; i++ {
				dec, partnerID, err := svc.EvaluateHumanVisibility(ctx, principal, "por-2")
				if err != nil || dec != resourceownership.VisibilityAllowed || partnerID != "P2" {
					t.Errorf("worker %d: User B por-2 expected (Allowed, P2), got (%v, %q, %v)", workerID, dec, partnerID, err)
					return
				}
			}
		}(w)

		// Case 4: User B -> por-1 (P1) -> must be HiddenNotFound
		go func(workerID int) {
			defer wg.Done()
			principal := partnerauth.HumanPrincipal{Issuer: "https://auth.example.com", Subject: "user-B"}
			for i := 0; i < iterations; i++ {
				dec, _, err := svc.EvaluateHumanVisibility(ctx, principal, "por-1")
				if err != nil || dec != resourceownership.VisibilityHiddenNotFound {
					t.Errorf("worker %d: User B por-1 expected HiddenNotFound, got (%v, %v)", workerID, dec, err)
					return
				}
			}
		}(w)
	}

	wg.Wait()
}
