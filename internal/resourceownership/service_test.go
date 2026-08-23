package resourceownership_test

import (
	"context"
	"errors"
	"testing"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/resourceownership"
)

func testPartnerAuthService(t *testing.T, resolve func(ctx context.Context, principal partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error)) *partnerauth.Service {
	t.Helper()
	svc, err := partnerauth.NewService(
		partnerauth.StaticHumanResolver{Resolve: resolve},
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	if err != nil {
		t.Fatalf("partnerauth.NewService: %v", err)
	}
	return svc
}

func TestEvaluateHumanVisibility(t *testing.T) {
	ctx := context.Background()
	principal := partnerauth.HumanPrincipal{Issuer: "https://auth.example.com", Subject: "user-1"}

	t.Run("same partner visible allows and returns partner", func(t *testing.T) {
		humanAuth := testPartnerAuthService(t, func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
			return partnerauth.HumanAuthorizations{
				PrincipalID: "user-1",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1"},
				},
			}, nil
		})
		ownership := resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
				if id == "por-1" {
					return resourceownership.OwnershipFound("por-1", "P1"), nil
				}
				return resourceownership.OwnershipNotFound(), nil
			},
		}

		svc, err := resourceownership.NewService(ownership, humanAuth)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}

		dec, partnerID, err := svc.EvaluateHumanVisibility(ctx, principal, "por-1")
		if err != nil {
			t.Fatalf("EvaluateHumanVisibility: %v", err)
		}
		if dec != resourceownership.VisibilityAllowed {
			t.Fatalf("got decision %v, want VisibilityAllowed", dec)
		}
		if partnerID != "P1" {
			t.Fatalf("got partnerID %q, want P1", partnerID)
		}
	})

	t.Run("cross partner resource returns hidden not found", func(t *testing.T) {
		humanAuth := testPartnerAuthService(t, func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
			return partnerauth.HumanAuthorizations{
				PrincipalID: "user-1",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1"},
				},
			}, nil
		})
		ownership := resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
				if id == "por-2" {
					return resourceownership.OwnershipFound("por-2", "P2"), nil
				}
				return resourceownership.OwnershipNotFound(), nil
			},
		}

		svc, err := resourceownership.NewService(ownership, humanAuth)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}

		dec, _, err := svc.EvaluateHumanVisibility(ctx, principal, "por-2")
		if err != nil {
			t.Fatalf("EvaluateHumanVisibility: %v", err)
		}
		if dec != resourceownership.VisibilityHiddenNotFound {
			t.Fatalf("got decision %v, want VisibilityHiddenNotFound", dec)
		}
	})

	t.Run("nonexistent resource returns hidden not found", func(t *testing.T) {
		humanAuth := testPartnerAuthService(t, func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
			return partnerauth.HumanAuthorizations{
				PrincipalID: "user-1",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1"},
				},
			}, nil
		})
		ownership := resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, _ string) (resourceownership.OwnershipResult, error) {
				return resourceownership.OwnershipNotFound(), nil
			},
		}

		svc, err := resourceownership.NewService(ownership, humanAuth)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}

		dec, _, err := svc.EvaluateHumanVisibility(ctx, principal, "por-999")
		if err != nil {
			t.Fatalf("EvaluateHumanVisibility: %v", err)
		}
		if dec != resourceownership.VisibilityHiddenNotFound {
			t.Fatalf("got decision %v, want VisibilityHiddenNotFound", dec)
		}
	})

	t.Run("valid-empty human authorization set short circuits without calling ownership", func(t *testing.T) {
		humanAuth := testPartnerAuthService(t, func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
			return partnerauth.HumanAuthorizations{
				PrincipalID: "user-1",
				Partners:    []partnerauth.PartnerAuthorization{}, // empty
			}, nil
		})
		spyOwnership := resourceownership.NewSpyPreOnboardingOwnershipResolver(nil)

		svc, err := resourceownership.NewService(spyOwnership, humanAuth)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}

		dec, _, err := svc.EvaluateHumanVisibility(ctx, principal, "por-1")
		if err != nil {
			t.Fatalf("EvaluateHumanVisibility: %v", err)
		}
		if dec != resourceownership.VisibilityHiddenNotFound {
			t.Fatalf("got decision %v, want VisibilityHiddenNotFound", dec)
		}
		if spyOwnership.Total() != 0 {
			t.Fatalf("ownership resolver was called %d times, want 0 (short-circuit)", spyOwnership.Total())
		}
	})

	t.Run("human auth dependency failure returns indeterminate", func(t *testing.T) {
		humanAuth := testPartnerAuthService(t, func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
			return partnerauth.HumanAuthorizations{}, errors.New("auth provider unreachable")
		})
		ownership := resourceownership.StaticPreOnboardingOwnershipResolver{}

		svc, err := resourceownership.NewService(ownership, humanAuth)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}

		dec, _, err := svc.EvaluateHumanVisibility(ctx, principal, "por-1")
		if err == nil {
			t.Fatal("expected error on human auth dependency failure")
		}
		if dec != resourceownership.VisibilityIndeterminate {
			t.Fatalf("got decision %v, want VisibilityIndeterminate", dec)
		}
	})

	t.Run("malformed M5.2 human authorization (empty principal ID) fails closed through canonical M5.2 validation", func(t *testing.T) {
		humanAuth := testPartnerAuthService(t, func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
			return partnerauth.HumanAuthorizations{
				PrincipalID: "", // empty principal_id violates M5.2 integrity
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1"},
				},
			}, nil
		})
		ownership := resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
				return resourceownership.OwnershipFound("por-1", "P1"), nil
			},
		}

		svc, err := resourceownership.NewService(ownership, humanAuth)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}

		dec, _, err := svc.EvaluateHumanVisibility(ctx, principal, "por-1")
		if err == nil {
			t.Fatal("expected error when M5.2 human authorization is malformed")
		}
		if dec != resourceownership.VisibilityIndeterminate {
			t.Fatalf("got decision %v, want VisibilityIndeterminate", dec)
		}
	})

	t.Run("malformed M5.2 human authorization (padded partner ID) fails closed through canonical M5.2 validation", func(t *testing.T) {
		humanAuth := testPartnerAuthService(t, func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
			return partnerauth.HumanAuthorizations{
				PrincipalID: "user-1",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: " P1 ", DisplayName: "Partner 1"}, // padded partner_id violates M5.2 integrity
				},
			}, nil
		})
		ownership := resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
				return resourceownership.OwnershipFound("por-1", "P1"), nil
			},
		}

		svc, err := resourceownership.NewService(ownership, humanAuth)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}

		dec, _, err := svc.EvaluateHumanVisibility(ctx, principal, "por-1")
		if err == nil {
			t.Fatal("expected error when M5.2 partner ID is padded")
		}
		if dec != resourceownership.VisibilityIndeterminate {
			t.Fatalf("got decision %v, want VisibilityIndeterminate", dec)
		}
	})

	t.Run("ownership dependency failure returns indeterminate", func(t *testing.T) {
		humanAuth := testPartnerAuthService(t, func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
			return partnerauth.HumanAuthorizations{
				PrincipalID: "user-1",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1"},
				},
			}, nil
		})
		ownership := resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, _ string) (resourceownership.OwnershipResult, error) {
				return resourceownership.OwnershipResult{}, errors.New("database unreachable")
			},
		}

		svc, err := resourceownership.NewService(ownership, humanAuth)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}

		dec, _, err := svc.EvaluateHumanVisibility(ctx, principal, "por-1")
		if err == nil {
			t.Fatal("expected error on ownership dependency failure")
		}
		if dec != resourceownership.VisibilityIndeterminate {
			t.Fatalf("got decision %v, want VisibilityIndeterminate", dec)
		}
	})

	t.Run("malformed ownership result returns indeterminate", func(t *testing.T) {
		humanAuth := testPartnerAuthService(t, func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
			return partnerauth.HumanAuthorizations{
				PrincipalID: "user-1",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1"},
				},
			}, nil
		})
		ownership := resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, _ string) (resourceownership.OwnershipResult, error) {
				// Mismatched resource ID in FOUND result
				return resourceownership.OwnershipFound("other-id", "P1"), nil
			},
		}

		svc, err := resourceownership.NewService(ownership, humanAuth)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}

		dec, _, err := svc.EvaluateHumanVisibility(ctx, principal, "por-1")
		if err == nil {
			t.Fatal("expected error on malformed ownership result")
		}
		if dec != resourceownership.VisibilityIndeterminate {
			t.Fatalf("got decision %v, want VisibilityIndeterminate", dec)
		}
	})

	t.Run("human authorization freshness: authority change immediately revokes visibility", func(t *testing.T) {
		partnerList := []partnerauth.PartnerAuthorization{
			{PartnerID: "P1", DisplayName: "Partner 1"},
		}
		humanAuth := testPartnerAuthService(t, func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
			return partnerauth.HumanAuthorizations{
				PrincipalID: "user-1",
				Partners:    partnerList,
			}, nil
		})
		ownership := resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
				if id == "por-1" {
					return resourceownership.OwnershipFound("por-1", "P1"), nil
				}
				return resourceownership.OwnershipNotFound(), nil
			},
		}

		svc, err := resourceownership.NewService(ownership, humanAuth)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}

		// Request A: user has P1 -> visible
		decA, _, err := svc.EvaluateHumanVisibility(ctx, principal, "por-1")
		if err != nil || decA != resourceownership.VisibilityAllowed {
			t.Fatalf("Request A: got %v, %v; want VisibilityAllowed", decA, err)
		}

		// Between requests: user loses P1
		partnerList = []partnerauth.PartnerAuthorization{}

		// Request B: same resource -> hidden 404
		decB, _, err := svc.EvaluateHumanVisibility(ctx, principal, "por-1")
		if err != nil || decB != resourceownership.VisibilityHiddenNotFound {
			t.Fatalf("Request B: got %v, %v; want VisibilityHiddenNotFound", decB, err)
		}
	})

	t.Run("ownership freshness: resource re-assignment immediately revokes visibility", func(t *testing.T) {
		currentPartner := "P1"
		humanAuth := testPartnerAuthService(t, func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
			return partnerauth.HumanAuthorizations{
				PrincipalID: "user-1",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1"},
				},
			}, nil
		})
		ownership := resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
				if id == "por-1" {
					return resourceownership.OwnershipFound("por-1", currentPartner), nil
				}
				return resourceownership.OwnershipNotFound(), nil
			},
		}

		svc, err := resourceownership.NewService(ownership, humanAuth)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}

		// Request A: resource is P1 -> visible
		decA, _, err := svc.EvaluateHumanVisibility(ctx, principal, "por-1")
		if err != nil || decA != resourceownership.VisibilityAllowed {
			t.Fatalf("Request A: got %v, %v; want VisibilityAllowed", decA, err)
		}

		// Between requests: resource ownership is changed to P2
		currentPartner = "P2"

		// Request B: user still has P1 -> hidden 404
		decB, _, err := svc.EvaluateHumanVisibility(ctx, principal, "por-1")
		if err != nil || decB != resourceownership.VisibilityHiddenNotFound {
			t.Fatalf("Request B: got %v, %v; want VisibilityHiddenNotFound", decB, err)
		}
	})
}
