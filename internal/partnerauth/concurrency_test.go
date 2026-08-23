package partnerauth

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// TestServiceConcurrentIsolation proves request-local isolation at the
// application authorization boundary: concurrent evaluations for different
// principals/partners must not cross-talk and no shared mutable decision state
// may leak. Runs under -race.
func TestServiceConcurrentIsolation(t *testing.T) {
	bySubject := map[string]HumanAuthorizations{
		"A": {PrincipalID: "principal-A", Partners: []PartnerAuthorization{{PartnerID: "P1", DisplayName: "A", Scopes: []string{"device:preonboard"}}}},
		"B": {PrincipalID: "principal-B", Partners: []PartnerAuthorization{{PartnerID: "P2", DisplayName: "B", Scopes: []string{"device:preonboard"}}}},
	}
	resolver := StaticHumanResolver{
		Resolve: func(_ context.Context, p HumanPrincipal) (HumanAuthorizations, error) {
			return bySubject[p.Subject], nil
		},
	}
	s := mustService(t, resolver, UnavailableTemporaryPrincipalResolver{})

	type want struct {
		subject  string
		partner  string
		decision SelectionDecision
	}
	cases := []want{
		{"A", "P1", SelectionAllowed},
		{"B", "P2", SelectionAllowed},
		{"A", "P2", SelectionDeniedPartner},
		{"B", "P1", SelectionDeniedPartner},
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(cases)*200)
	for i := 0; i < 200; i++ {
		for _, c := range cases {
			wg.Add(1)
			go func(c want) {
				defer wg.Done()
				got, err := s.AuthorizeHumanPreOnboarding(context.Background(), principalWith("iss", c.subject), c.partner)
				if err != nil {
					errs <- err
					return
				}
				if got != c.decision {
					errs <- fmt.Errorf("subject %s partner %s: got %v want %v", c.subject, c.partner, got, c.decision)
				}
			}(c)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}
