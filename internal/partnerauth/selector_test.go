package partnerauth

import (
	"testing"
	"time"
)

func TestSelectHumanPreOnboardingOutcomes(t *testing.T) {
	set := HumanAuthorizations{
		PrincipalID: "principal-123",
		Partners: []PartnerAuthorization{
			{PartnerID: "P1", DisplayName: "A", Scopes: []string{"device:preonboard"}},
			{PartnerID: "P2", DisplayName: "B", Scopes: []string{"device:preonboard"}},
			{PartnerID: "P3", DisplayName: "C", Scopes: []string{"device:approve"}},
		},
	}

	cases := []struct {
		name          string
		requested     string
		requiredScope string
		want          SelectionDecision
	}{
		{"allow present with scope", "P1", "device:preonboard", SelectionAllowed},
		{"deny partner absent", "P404", "device:preonboard", SelectionDeniedPartner},
		{"deny scope present but missing scope", "P3", "device:preonboard", SelectionDeniedScope},
		{"deny scope present with wrong scope", "P1", "device:approve", SelectionDeniedScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SelectHumanPreOnboarding(set, tc.requested, tc.requiredScope); got != tc.want {
				t.Fatalf("decision = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSelectHumanPreOnboardingEmptySetDeniesPartner(t *testing.T) {
	if got := SelectHumanPreOnboarding(HumanAuthorizations{PrincipalID: "p"}, "P1", "device:preonboard"); got != SelectionDeniedPartner {
		t.Fatalf("decision = %v, want %v", got, SelectionDeniedPartner)
	}
}

func TestSelectTemporaryPrincipalPreOnboardingLifecycle(t *testing.T) {
	now := nowPlusHours(t, 0)

	t.Run("allow active unexpired matching with scope", func(t *testing.T) {
		a := activeTP("tp-1", "P1", []string{"device:preonboard"}, nowPlusHours(t, 1))
		if got := SelectTemporaryPrincipalPreOnboarding(a, "P1", "device:preonboard", now); got != SelectionAllowed {
			t.Fatalf("decision = %v, want ALLOW", got)
		}
	})

	t.Run("deny disabled", func(t *testing.T) {
		a := activeTP("tp-1", "P1", []string{"device:preonboard"}, nowPlusHours(t, 1))
		a.Status = TemporaryPrincipalStatusDisabled
		if got := SelectTemporaryPrincipalPreOnboarding(a, "P1", "device:preonboard", now); got != SelectionDeniedPartner {
			t.Fatalf("decision = %v, want DENY_PARTNER", got)
		}
	})

	t.Run("deny expired", func(t *testing.T) {
		a := activeTP("tp-1", "P1", []string{"device:preonboard"}, now.Add(-time.Hour))
		if got := SelectTemporaryPrincipalPreOnboarding(a, "P1", "device:preonboard", now); got != SelectionDeniedPartner {
			t.Fatalf("decision = %v, want DENY_PARTNER", got)
		}
	})

	t.Run("indeterminate nil expiry", func(t *testing.T) {
		a := activeTP("tp-1", "P1", []string{"device:preonboard"}, nowPlusHours(t, 1))
		a.ExpiresAt = nil
		if got := SelectTemporaryPrincipalPreOnboarding(a, "P1", "device:preonboard", now); got != SelectionIndeterminate {
			t.Fatalf("decision = %v, want INDETERMINATE", got)
		}
	})

	t.Run("deny cross partner", func(t *testing.T) {
		a := activeTP("tp-1", "P1", []string{"device:preonboard"}, nowPlusHours(t, 1))
		if got := SelectTemporaryPrincipalPreOnboarding(a, "P2", "device:preonboard", now); got != SelectionDeniedPartner {
			t.Fatalf("decision = %v, want DENY_PARTNER", got)
		}
	})

	t.Run("deny scope missing", func(t *testing.T) {
		a := activeTP("tp-1", "P1", []string{"device:approve"}, nowPlusHours(t, 1))
		if got := SelectTemporaryPrincipalPreOnboarding(a, "P1", "device:preonboard", now); got != SelectionDeniedScope {
			t.Fatalf("decision = %v, want DENY_SCOPE", got)
		}
	})
}

func TestTemporaryPrincipalDoesNotGainAdminAuthority(t *testing.T) {
	// The Temporary Principal seam has no generic scope-grant surface: it can
	// only ever evaluate the fixed pre-onboarding authority. A Temporary
	// Principal carrying unrelated admin scopes must still be denied the
	// pre-onboarding selection when device:preonboard is absent.
	now := nowPlusHours(t, 0)
	a := activeTP("tp-1", "P1", []string{"device:approve", "certificate:revoke"}, nowPlusHours(t, 1))
	if got := SelectTemporaryPrincipalPreOnboarding(a, "P1", "device:preonboard", now); got != SelectionDeniedScope {
		t.Fatalf("decision = %v, want DENY_SCOPE (admin scopes must not broaden pre-onboarding authority)", got)
	}
}
