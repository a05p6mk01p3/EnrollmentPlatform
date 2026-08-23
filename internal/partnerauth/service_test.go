package partnerauth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func principalWith(issuer, subject string) HumanPrincipal {
	return HumanPrincipal{Issuer: issuer, Subject: subject}
}

func mustService(t *testing.T, human HumanAuthorizationResolver, temp TemporaryPrincipalAuthorizationResolver, opts ...ServiceOption) *Service {
	t.Helper()
	s, err := NewService(human, temp, opts...)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return s
}

func TestResolveMyAuthorizationsEmptyIsNotFailure(t *testing.T) {
	resolver := StaticHumanResolver{
		Resolve: func(_ context.Context, _ HumanPrincipal) (HumanAuthorizations, error) {
			return HumanAuthorizations{PrincipalID: "principal-123", Partners: nil}, nil
		},
	}
	s := mustService(t, resolver, UnavailableTemporaryPrincipalResolver{})
	got, err := s.ResolveMyAuthorizations(context.Background(), principalWith("iss", "sub"))
	if err != nil {
		t.Fatalf("valid empty result must not be an error: %v", err)
	}
	if got.PrincipalID != "principal-123" || len(got.Partners) != 0 {
		t.Fatalf("unexpected set: %+v", got)
	}
}

func TestResolveMyAuthorizationsDependencyFailure(t *testing.T) {
	resolver := StaticHumanResolver{
		Resolve: func(_ context.Context, _ HumanPrincipal) (HumanAuthorizations, error) {
			return HumanAuthorizations{}, ErrDependencyUnavailable
		},
	}
	s := mustService(t, resolver, UnavailableTemporaryPrincipalResolver{})
	_, err := s.ResolveMyAuthorizations(context.Background(), principalWith("iss", "sub"))
	if err == nil {
		t.Fatal("dependency failure must be an error, not an empty result")
	}
}

func TestResolveMyAuthorizationsMalformedFailsClosed(t *testing.T) {
	resolver := StaticHumanResolver{
		Resolve: func(_ context.Context, _ HumanPrincipal) (HumanAuthorizations, error) {
			return HumanAuthorizations{PrincipalID: "", Partners: []PartnerAuthorization{{PartnerID: "P1"}}}, nil
		},
	}
	s := mustService(t, resolver, UnavailableTemporaryPrincipalResolver{})
	_, err := s.ResolveMyAuthorizations(context.Background(), principalWith("iss", "sub"))
	if err == nil {
		t.Fatal("malformed authorization state must fail closed")
	}
}

func TestAuthorizeHumanPreOnboarding(t *testing.T) {
	bySubject := map[string]HumanAuthorizations{
		"sub-A": {PrincipalID: "principal-A", Partners: []PartnerAuthorization{{PartnerID: "P1", DisplayName: "A", Scopes: []string{"device:preonboard"}}}},
		"sub-B": {PrincipalID: "principal-B", Partners: []PartnerAuthorization{{PartnerID: "P2", DisplayName: "B", Scopes: []string{"device:preonboard"}}}},
		"sub-C": {PrincipalID: "principal-C", Partners: []PartnerAuthorization{{PartnerID: "P1", DisplayName: "C", Scopes: []string{"device:approve"}}}},
	}
	resolver := StaticHumanResolver{
		Resolve: func(_ context.Context, p HumanPrincipal) (HumanAuthorizations, error) {
			if v, ok := bySubject[p.Subject]; ok {
				return v, nil
			}
			return HumanAuthorizations{PrincipalID: "principal-" + p.Subject}, nil
		},
	}
	s := mustService(t, resolver, UnavailableTemporaryPrincipalResolver{})

	t.Run("allow", func(t *testing.T) {
		d, err := s.AuthorizeHumanPreOnboarding(context.Background(), principalWith("iss", "sub-A"), "P1")
		if err != nil || d != SelectionAllowed {
			t.Fatalf("decision = %v, err = %v; want ALLOW", d, err)
		}
	})
	t.Run("deny partner", func(t *testing.T) {
		d, err := s.AuthorizeHumanPreOnboarding(context.Background(), principalWith("iss", "sub-A"), "P2")
		if err != nil || d != SelectionDeniedPartner {
			t.Fatalf("decision = %v, err = %v; want DENY_PARTNER", d, err)
		}
	})
	t.Run("deny scope", func(t *testing.T) {
		d, err := s.AuthorizeHumanPreOnboarding(context.Background(), principalWith("iss", "sub-C"), "P1")
		if err != nil || d != SelectionDeniedScope {
			t.Fatalf("decision = %v, err = %v; want DENY_SCOPE", d, err)
		}
	})
}

func TestAuthorizeHumanPreOnboardingFreshnessAcrossRequests(t *testing.T) {
	var mu sync.RWMutex
	state := HumanAuthorizations{PrincipalID: "principal-A", Partners: []PartnerAuthorization{{PartnerID: "P1", DisplayName: "A", Scopes: []string{"device:preonboard"}}}}
	resolver := StaticHumanResolver{
		Resolve: func(_ context.Context, _ HumanPrincipal) (HumanAuthorizations, error) {
			mu.RLock()
			defer mu.RUnlock()
			return state, nil
		},
	}
	s := mustService(t, resolver, UnavailableTemporaryPrincipalResolver{})

	d, err := s.AuthorizeHumanPreOnboarding(context.Background(), principalWith("iss", "sub-A"), "P1")
	if err != nil || d != SelectionAllowed {
		t.Fatalf("request A: decision = %v, err = %v; want ALLOW", d, err)
	}

	// Backing authorization changes: P1 is no longer authorized.
	mu.Lock()
	state = HumanAuthorizations{PrincipalID: "principal-A", Partners: []PartnerAuthorization{{PartnerID: "P2", DisplayName: "A", Scopes: []string{"device:preonboard"}}}}
	mu.Unlock()

	d, err = s.AuthorizeHumanPreOnboarding(context.Background(), principalWith("iss", "sub-A"), "P1")
	if err != nil || d != SelectionDeniedPartner {
		t.Fatalf("request B: decision = %v, err = %v; want DENY_PARTNER (no stale authority)", d, err)
	}
}

func TestAuthorizeHumanPreOnboardingServerSideBeatsClientHint(t *testing.T) {
	// The resolver is keyed exclusively by the authenticated issuer+subject and
	// returns P2. The request selects P1; the selection must deny P1 even
	// though the caller asked for it.
	resolver := StaticHumanResolver{
		Resolve: func(_ context.Context, p HumanPrincipal) (HumanAuthorizations, error) {
			return HumanAuthorizations{
				PrincipalID: "principal-" + p.Subject,
				Partners:    []PartnerAuthorization{{PartnerID: "P2", DisplayName: "B", Scopes: []string{"device:preonboard"}}},
			}, nil
		},
	}
	s := mustService(t, resolver, UnavailableTemporaryPrincipalResolver{})
	d, err := s.AuthorizeHumanPreOnboarding(context.Background(), principalWith("iss", "sub-hint-P1"), "P1")
	if err != nil || d != SelectionDeniedPartner {
		t.Fatalf("decision = %v, err = %v; want DENY_PARTNER (server-side authority only)", d, err)
	}
}

func TestAuthorizeTemporaryPrincipalPreOnboarding(t *testing.T) {
	future := nowPlusHours(t, 1)
	resolver := StaticTemporaryPrincipalResolver{
		Resolve: func(_ context.Context, id TemporaryPrincipalID) (TemporaryPrincipalAuthorization, error) {
			return activeTP(string(id), "P1", []string{"device:preonboard"}, future), nil
		},
	}
	s := mustService(t, UnavailableHumanResolver{}, resolver, WithClock(func() time.Time { return nowPlusHours(t, 0) }))

	t.Run("allow same partner", func(t *testing.T) {
		d, err := s.AuthorizeTemporaryPrincipalPreOnboarding(context.Background(), "tp-1", "P1")
		if err != nil || d != SelectionAllowed {
			t.Fatalf("decision = %v, err = %v; want ALLOW", d, err)
		}
	})
	t.Run("deny cross partner", func(t *testing.T) {
		d, err := s.AuthorizeTemporaryPrincipalPreOnboarding(context.Background(), "tp-1", "P2")
		if err != nil || d != SelectionDeniedPartner {
			t.Fatalf("decision = %v, err = %v; want DENY_PARTNER", d, err)
		}
	})
}

func TestAuthorizeTemporaryPrincipalDependencyFailure(t *testing.T) {
	resolver := StaticTemporaryPrincipalResolver{
		Resolve: func(_ context.Context, _ TemporaryPrincipalID) (TemporaryPrincipalAuthorization, error) {
			return TemporaryPrincipalAuthorization{}, ErrDependencyUnavailable
		},
	}
	s := mustService(t, UnavailableHumanResolver{}, resolver)
	d, err := s.AuthorizeTemporaryPrincipalPreOnboarding(context.Background(), "tp-1", "P1")
	if err == nil || d != SelectionIndeterminate {
		t.Fatalf("decision = %v, err = %v; want INDETERMINATE + error", d, err)
	}
}

func TestUnavailableServiceNeverAllows(t *testing.T) {
	s := NewUnavailableService()
	if _, err := s.ResolveMyAuthorizations(context.Background(), principalWith("iss", "sub")); !errors.Is(err, ErrDependencyUnavailable) {
		t.Fatalf("unavailable resolver err = %v; want ErrDependencyUnavailable", err)
	}
	d, err := s.AuthorizeHumanPreOnboarding(context.Background(), principalWith("iss", "sub"), "P1")
	if err == nil || d != SelectionIndeterminate {
		t.Fatalf("decision = %v, err = %v; want INDETERMINATE", d, err)
	}
}

// M5.2-CHATGPT-002: padded authoritative identifiers in resolver output are
// malformed and fail closed; they are never trimmed into authority and never
// produce an allow decision.
func TestAuthorizeHumanPreOnboardingPaddedIdentifiersNeverAllow(t *testing.T) {
	t.Run("padded partner id", func(t *testing.T) {
		resolver := StaticHumanResolver{
			Resolve: func(_ context.Context, _ HumanPrincipal) (HumanAuthorizations, error) {
				return HumanAuthorizations{
					PrincipalID: "principal-123",
					Partners:    []PartnerAuthorization{{PartnerID: " P1 ", DisplayName: "A", Scopes: []string{"device:preonboard"}}},
				}, nil
			},
		}
		s := mustService(t, resolver, UnavailableTemporaryPrincipalResolver{})
		d, err := s.AuthorizeHumanPreOnboarding(context.Background(), principalWith("iss", "sub"), "P1")
		if err == nil || d != SelectionIndeterminate {
			t.Fatalf("decision = %v, err = %v; want INDETERMINATE (padded partner id must not become authority)", d, err)
		}
	})

	t.Run("padded scope", func(t *testing.T) {
		resolver := StaticHumanResolver{
			Resolve: func(_ context.Context, _ HumanPrincipal) (HumanAuthorizations, error) {
				return HumanAuthorizations{
					PrincipalID: "principal-123",
					Partners:    []PartnerAuthorization{{PartnerID: "P1", DisplayName: "A", Scopes: []string{" device:preonboard "}}},
				}, nil
			},
		}
		s := mustService(t, resolver, UnavailableTemporaryPrincipalResolver{})
		d, err := s.AuthorizeHumanPreOnboarding(context.Background(), principalWith("iss", "sub"), "P1")
		if err == nil || d != SelectionIndeterminate {
			t.Fatalf("decision = %v, err = %v; want INDETERMINATE (padded scope must not become authority)", d, err)
		}
	})
}

// M5.2-CHATGPT-002: a padded Temporary Principal scope cannot authorize the
// selection seam.
func TestAuthorizeTemporaryPrincipalPaddedScopeNeverAllows(t *testing.T) {
	future := nowPlusHours(t, 1)
	resolver := StaticTemporaryPrincipalResolver{
		Resolve: func(_ context.Context, id TemporaryPrincipalID) (TemporaryPrincipalAuthorization, error) {
			return TemporaryPrincipalAuthorization{
				TemporaryPrincipalID: string(id),
				PartnerID:            "P1",
				Scopes:               []string{" device:preonboard "},
				Status:               TemporaryPrincipalStatusActive,
				ExpiresAt:            &future,
			}, nil
		},
	}
	s := mustService(t, UnavailableHumanResolver{}, resolver)
	d, err := s.AuthorizeTemporaryPrincipalPreOnboarding(context.Background(), "tp-1", "P1")
	if err == nil || d != SelectionIndeterminate {
		t.Fatalf("decision = %v, err = %v; want INDETERMINATE (padded scope must not become authority)", d, err)
	}
}
