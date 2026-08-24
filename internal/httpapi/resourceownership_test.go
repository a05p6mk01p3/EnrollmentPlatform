package httpapi_test

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/config"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
	preonboardingapp "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	preonboardingruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/resourceownership"
)

type countingPartnerResolver struct {
	mu    sync.Mutex
	calls int
	fn    func(ctx context.Context, p partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error)
}

func (c *countingPartnerResolver) ResolveHumanAuthorizations(ctx context.Context, p partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	if c.fn != nil {
		return c.fn(ctx, p)
	}
	return partnerauth.HumanAuthorizations{PrincipalID: "p1"}, nil
}

func (c *countingPartnerResolver) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

type staticRequestAccessAuthenticator struct {
	tokens map[string]string
}

func (a staticRequestAccessAuthenticator) Kind() authpolicy.CredentialKind {
	return authpolicy.CredentialKindRequestAccessToken
}

func (a staticRequestAccessAuthenticator) Authenticate(_ context.Context, c *authruntime.Credential) authruntime.AuthenticationResult {
	resID, ok := a.tokens[c.BearerToken]
	if !ok {
		return authruntime.AuthenticationResult{Decision: authruntime.DecisionRejected}
	}
	b, err := authruntime.NewRequestAccessBinding(resID)
	if err != nil {
		return authruntime.AuthenticationResult{Decision: authruntime.DecisionIndeterminate}
	}
	return authruntime.AuthenticationResult{Decision: authruntime.DecisionAuthenticated, Binding: b}
}

type customVisitorProbeResponse struct {
	mu     sync.Mutex
	called bool
}

func (c *customVisitorProbeResponse) VisitGetPreOnboardingRequestResponse(w http.ResponseWriter) error {
	c.mu.Lock()
	c.called = true
	c.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(`{"pre_onboarding_request_id":"por-custom","partner_id":"P1"}`))
	return err
}

func (c *customVisitorProbeResponse) wasVisited() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.called
}

// customPreOnboardProbeSSI allows configuring custom GetPreOnboardingRequest responses.
type customPreOnboardProbeSSI struct {
	probeSSI
	getFn func(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error)
}

func (c *customPreOnboardProbeSSI) GetPreOnboardingRequest(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error) {
	c.record("GetPreOnboardingRequest")
	if c.getFn != nil {
		return c.getFn(ctx, request)
	}
	return openapi.GetPreOnboardingRequest200JSONResponse{
		Body: openapi.PreOnboardingRequest{
			PreOnboardingRequestId: request.Id,
			PartnerId:              "P1",
		},
	}, nil
}

func (c *customPreOnboardProbeSSI) OverrideGetPreOnboardingRequest(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, bool, error) {
	if c.getFn != nil {
		resp, err := c.GetPreOnboardingRequest(ctx, request)
		return resp, true, err
	}
	return nil, false, nil
}

func testPreOnboardingServiceWithRequests(requests ...*domain.PreOnboardingRequest) *preonboardingapp.Service {
	rec := preonboardingruntime.NewMemoryAuditRecorder()
	st := preonboardingruntime.NewMemoryStore(rec)
	now := time.Now()
	clk := preonboardingruntime.NewMockClock(now)
	for _, req := range requests {
		st.SeedRequest(req)
	}
	auth := preonboardingruntime.NewMemoryPartnerAuthorityChecker()
	elig := preonboardingruntime.NewMemoryPartnerEligibilityChecker()
	svc, _ := preonboardingapp.NewService(preonboardingapp.ServiceConfig{
		UOWManager:         st,
		Clock:              clk,
		DeviceAllocator:    preonboardingruntime.DefaultDeviceAllocator{},
		PartnerAuth:        auth,
		PartnerEligibility: elig,
		RetentionPolicy:    preonboardingapp.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
	})
	return svc
}

func newOwnershipTestServer(t *testing.T, partnerSvc *partnerauth.Service, ownershipSvc *resourceownership.Service, customReg *authruntime.Registry, ssi openapi.StrictServerInterface) http.Handler {
	t.Helper()
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	reg := testAuthnRegistry()
	if customReg != nil {
		reg = customReg
	}
	now := time.Now()
	req1, _ := domain.NewRequest("por-1", "P1", domain.ClaimedDevice{Hostname: "h1"}, domain.Agent{}, now, now.Add(time.Hour))
	req2, _ := domain.NewRequest("por-2", "P2", domain.ClaimedDevice{Hostname: "h2"}, domain.Agent{}, now, now.Add(time.Hour))
	req3, _ := domain.NewRequest("por-3", "P1", domain.ClaimedDevice{Hostname: "h3"}, domain.Agent{}, now, now.Add(time.Hour))
	exp1, _ := domain.NewRequest("por-expired-p1", "P1", domain.ClaimedDevice{Hostname: "h4"}, domain.Agent{}, now.Add(-time.Hour), now.Add(-10*time.Minute))
	exp2, _ := domain.NewRequest("por-expired-p2", "P2", domain.ClaimedDevice{Hostname: "h5"}, domain.Agent{}, now.Add(-time.Hour), now.Add(-10*time.Minute))
	expPtr, _ := domain.NewRequest("por-expired-ptr", "P1", domain.ClaimedDevice{Hostname: "h6"}, domain.Agent{}, now.Add(-time.Hour), now.Add(-10*time.Minute))
	preonboardSvc := testPreOnboardingServiceWithRequests(req1, req2, req3, exp1, exp2, expPtr)

	srv, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(reg),
		httpapi.WithDeviceMTLSSource(testDeviceSource()),
		httpapi.WithAuthzRegistry(testAuthzRegistry()),
		httpapi.WithPartnerAuthService(partnerSvc),
		httpapi.WithResourceOwnershipService(ownershipSvc),
		httpapi.WithPreOnboardingService(preonboardSvc),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv.Handler(ssi)
}

// M5.3-AC-001: Human caller authorized for P1 accesses R1 (owned by P1).
// Protected read executes exactly once. No invented read scope.
func TestHumanSamePartnerVisibility(t *testing.T) {
	partnerSvc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {
				PrincipalID: "user-1",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1"},
				},
			},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	ownershipSvc, err := resourceownership.NewService(
		resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
				if id == "por-1" {
					return resourceownership.OwnershipFound("por-1", "P1"), nil
				}
				return resourceownership.OwnershipNotFound(), nil
			},
		},
		partnerSvc,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	p := &probeSSI{calls: map[string]int{}}
	h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, p)

	rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
		"Authorization": humanBearer(),
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("GetPreOnboardingRequest") != 0 {
		t.Fatalf("protected read count = %d, want 0 (answered by M5.5 boundary)", p.count("GetPreOnboardingRequest"))
	}
	body := jsonBody(t, rr)
	if body["pre_onboarding_request_id"] != "por-1" {
		t.Fatalf("body pre_onboarding_request_id = %v, want por-1", body["pre_onboarding_request_id"])
	}
	if body["partner_id"] != "P1" {
		t.Fatalf("body partner_id = %v, want P1", body["partner_id"])
	}
}

// M5.3-AC-002: Human caller authorized only for P1 attempts to access R2 (owned by P2).
// External result must be 404 RESOURCE_NOT_FOUND (no 403 signal), and protected read count = 0.
func TestHumanCrossPartnerConcealed(t *testing.T) {
	partnerSvc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {
				PrincipalID: "user-1",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1"},
				},
			},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	ownershipSvc, err := resourceownership.NewService(
		resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
				if id == "por-2" {
					return resourceownership.OwnershipFound("por-2", "P2"), nil
				}
				return resourceownership.OwnershipNotFound(), nil
			},
		},
		partnerSvc,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	p := &probeSSI{calls: map[string]int{}}
	h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, p)

	rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-2", "", map[string]string{
		"Authorization": humanBearer(),
	})

	assertProblem(t, rr, http.StatusNotFound, "RESOURCE_NOT_FOUND")
	if p.count("GetPreOnboardingRequest") != 0 {
		t.Fatalf("protected read count = %d, want 0", p.count("GetPreOnboardingRequest"))
	}
}

// M5.3-AC-003: Nonexistent resource and inaccessible existing resource produce identical 404 shape.
func TestNonexistentAndInaccessibleShareExternalResult(t *testing.T) {
	partnerSvc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {
				PrincipalID: "user-1",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1"},
				},
			},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	ownershipSvc, err := resourceownership.NewService(
		resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
				if id == "por-other" {
					return resourceownership.OwnershipFound("por-other", "P2"), nil
				}
				return resourceownership.OwnershipNotFound(), nil
			},
		},
		partnerSvc,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	p := &probeSSI{calls: map[string]int{}}
	h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, p)

	// Nonexistent lookup
	rrNone := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-nonexistent", "", map[string]string{
		"Authorization": humanBearer(),
	})
	assertProblem(t, rrNone, http.StatusNotFound, "RESOURCE_NOT_FOUND")

	// Other partner existing lookup
	rrOther := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-other", "", map[string]string{
		"Authorization": humanBearer(),
	})
	assertProblem(t, rrOther, http.StatusNotFound, "RESOURCE_NOT_FOUND")

	// Verify both response bodies are structurally equivalent and do not leak ownership
	bodyNone := jsonBody(t, rrNone)
	bodyOther := jsonBody(t, rrOther)

	if bodyNone["type"] != bodyOther["type"] {
		t.Errorf("type mismatch: %v vs %v", bodyNone["type"], bodyOther["type"])
	}
	if bodyNone["error_code"] != bodyOther["error_code"] {
		t.Errorf("error_code mismatch: %v vs %v", bodyNone["error_code"], bodyOther["error_code"])
	}
	if bodyNone["status"] != bodyOther["status"] {
		t.Errorf("status mismatch: %v vs %v", bodyNone["status"], bodyOther["status"])
	}
	if bodyNone["title"] != bodyOther["title"] {
		t.Errorf("title mismatch: %v vs %v", bodyNone["title"], bodyOther["title"])
	}
	if _, exists := bodyOther["partner_id"]; exists {
		t.Errorf("partner_id leaked in other-partner 404 response")
	}
	if p.count("GetPreOnboardingRequest") != 0 {
		t.Fatalf("protected read count = %d, want 0", p.count("GetPreOnboardingRequest"))
	}
}

// M5.3-AC-004: Valid-empty Human authorization sees no resource (404) and skips ownership resolver.
func TestValidEmptyHumanAuthorizationSkipsOwnership(t *testing.T) {
	partnerSvc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {
				PrincipalID: "user-1",
				Partners:    []partnerauth.PartnerAuthorization{}, // empty
			},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	spyOwnership := resourceownership.NewSpyPreOnboardingOwnershipResolver(func(_ context.Context, _ string) (resourceownership.OwnershipResult, error) {
		return resourceownership.OwnershipFound("por-1", "P1"), nil
	})
	ownershipSvc, err := resourceownership.NewService(spyOwnership, partnerSvc)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	p := &probeSSI{calls: map[string]int{}}
	h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, p)

	rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
		"Authorization": humanBearer(),
	})

	assertProblem(t, rr, http.StatusNotFound, "RESOURCE_NOT_FOUND")
	if p.count("GetPreOnboardingRequest") != 0 {
		t.Fatalf("protected read count = %d, want 0", p.count("GetPreOnboardingRequest"))
	}
	if spyOwnership.Total() != 0 {
		t.Fatalf("ownership resolver total calls = %d, want 0 (short-circuit)", spyOwnership.Total())
	}
}

// M5.3-AC-005: Human authorization freshness across requests.
func TestHumanAuthorizationFreshness(t *testing.T) {
	partnerList := []partnerauth.PartnerAuthorization{
		{PartnerID: "P1", DisplayName: "Partner 1"},
	}
	partnerSvc := partnerService(t,
		partnerauth.StaticHumanResolver{
			Resolve: func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
				return partnerauth.HumanAuthorizations{
					PrincipalID: "user-1",
					Partners:    partnerList,
				}, nil
			},
		},
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	ownershipSvc, err := resourceownership.NewService(
		resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
				return resourceownership.OwnershipFound("por-1", "P1"), nil
			},
		},
		partnerSvc,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	p := &probeSSI{calls: map[string]int{}}
	h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, p)

	// Request A: user has P1 -> 200
	rrA := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
		"Authorization": humanBearer(),
	})
	if rrA.Code != http.StatusOK {
		t.Fatalf("Request A: status = %d, want 200", rrA.Code)
	}

	// Between requests: user loses P1
	partnerList = []partnerauth.PartnerAuthorization{}

	// Request B: same resource -> hidden 404
	rrB := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
		"Authorization": humanBearer(),
	})
	assertProblem(t, rrB, http.StatusNotFound, "RESOURCE_NOT_FOUND")
}

// M5.3-AC-006: Ownership freshness across requests.
func TestOwnershipFreshness(t *testing.T) {
	currentOwner := "P1"
	partnerSvc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {
				PrincipalID: "user-1",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1"},
				},
			},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	ownershipSvc, err := resourceownership.NewService(
		resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
				return resourceownership.OwnershipFound("por-1", currentOwner), nil
			},
		},
		partnerSvc,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	p := &probeSSI{calls: map[string]int{}}
	h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, p)

	// Request A: resource is owned by P1 -> 200
	rrA := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
		"Authorization": humanBearer(),
	})
	if rrA.Code != http.StatusOK {
		t.Fatalf("Request A: status = %d, want 200", rrA.Code)
	}

	// Between requests: resource owner changes to P2
	currentOwner = "P2"

	// Request B: same user still has P1 -> hidden 404
	rrB := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
		"Authorization": humanBearer(),
	})
	assertProblem(t, rrB, http.StatusNotFound, "RESOURCE_NOT_FOUND")
}

// M5.3-AC-007: Human authorization dependency failure yields 503, protected read count = 0.
func TestHumanAuthorizationDependencyFailure(t *testing.T) {
	partnerSvc := partnerService(t,
		partnerauth.StaticHumanResolver{
			Resolve: func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
				return partnerauth.HumanAuthorizations{}, errors.New("keycloak unavailable")
			},
		},
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	ownershipSvc, err := resourceownership.NewService(
		resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
				return resourceownership.OwnershipFound("por-1", "P1"), nil
			},
		},
		partnerSvc,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	p := &probeSSI{calls: map[string]int{}}
	h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, p)

	rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
		"Authorization": humanBearer(),
	})

	assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	if p.count("GetPreOnboardingRequest") != 0 {
		t.Fatalf("protected read count = %d, want 0", p.count("GetPreOnboardingRequest"))
	}
}

// M5.3-AC-008: Ownership dependency failure yields 503, protected read count = 0.
func TestOwnershipDependencyFailure(t *testing.T) {
	partnerSvc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {
				PrincipalID: "user-1",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1"},
				},
			},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	ownershipSvc, err := resourceownership.NewService(
		resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
				return resourceownership.OwnershipResult{}, errors.New("db unavailable")
			},
		},
		partnerSvc,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	p := &probeSSI{calls: map[string]int{}}
	h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, p)

	rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
		"Authorization": humanBearer(),
	})

	assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	if p.count("GetPreOnboardingRequest") != 0 {
		t.Fatalf("protected read count = %d, want 0", p.count("GetPreOnboardingRequest"))
	}
}

// M5.3-AC-009: Malformed ownership state never allows.
func TestMalformedOwnershipStateFailClosed(t *testing.T) {
	partnerSvc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {
				PrincipalID: "user-1",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1"},
				},
			},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)

	cases := []struct {
		name   string
		result resourceownership.OwnershipResult
	}{
		{
			name:   "FOUND with empty resource ID",
			result: resourceownership.OwnershipFound("", "P1"),
		},
		{
			name:   "FOUND with mismatched resource ID",
			result: resourceownership.OwnershipFound("por-other", "P1"),
		},
		{
			name:   "FOUND with empty partner ID",
			result: resourceownership.OwnershipFound("por-1", ""),
		},
		{
			name:   "FOUND with padded resource ID",
			result: resourceownership.OwnershipFound(" por-1 ", "P1"),
		},
		{
			name:   "FOUND with padded partner ID",
			result: resourceownership.OwnershipFound("por-1", " P1 "),
		},
		{
			name: "contradictory NOT_FOUND with resource ID",
			result: resourceownership.OwnershipResult{
				Status: resourceownership.OwnershipStatusNotFound,
				Ownership: resourceownership.ResourceOwnership{
					ResourceID: "por-1",
				},
			},
		},
		{
			name: "contradictory NOT_FOUND with partner ID",
			result: resourceownership.OwnershipResult{
				Status: resourceownership.OwnershipStatusNotFound,
				Ownership: resourceownership.ResourceOwnership{
					PartnerID: "P1",
				},
			},
		},
		{
			name:   "zero status unknown",
			result: resourceownership.OwnershipResult{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ownershipSvc, err := resourceownership.NewService(
				resourceownership.StaticPreOnboardingOwnershipResolver{
					Resolve: func(_ context.Context, _ string) (resourceownership.OwnershipResult, error) {
						return tc.result, nil
					},
				},
				partnerSvc,
			)
			if err != nil {
				t.Fatalf("NewService: %v", err)
			}

			p := &probeSSI{calls: map[string]int{}}
			h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, p)

			rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
				"Authorization": humanBearer(),
			})

			assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
			if p.count("GetPreOnboardingRequest") != 0 {
				t.Fatalf("protected read count = %d, want 0", p.count("GetPreOnboardingRequest"))
			}
		})
	}
}

// M5.3-AC-010: RequestAccessToken exact-resource access preserved without Human partner resolution.
func TestRequestAccessTokenExactResourceAccess(t *testing.T) {
	partnerSpy := &countingPartnerResolver{
		fn: func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
			return partnerauth.HumanAuthorizations{PrincipalID: "human"}, nil
		},
	}
	partnerSvc := partnerService(t, partnerSpy, partnerauth.UnavailableTemporaryPrincipalResolver{})
	ownershipSvc, err := resourceownership.NewService(
		resourceownership.StaticPreOnboardingOwnershipResolver{},
		partnerSvc,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	customAuth := staticRequestAccessAuthenticator{
		tokens: map[string]string{
			"rat-por-1": "por-1",
		},
	}
	reg := completeTestRegistry(t, registry(t, customAuth))

	p := &probeSSI{calls: map[string]int{}}
	h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, reg, p)

	rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
		"Authorization": "Bearer rat-por-1",
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("GetPreOnboardingRequest") != 0 {
		t.Fatalf("protected read count = %d, want 0 (answered by M5.5 boundary)", p.count("GetPreOnboardingRequest"))
	}
	if partnerSpy.count() != 0 {
		t.Fatalf("human partner resolver called %d times, want 0 on RequestAccessToken branch", partnerSpy.count())
	}
}

// M5.3-AC-011: RequestAccessToken cross-resource rejection preserved by M4.3.
func TestRequestAccessTokenCrossResourceRejection(t *testing.T) {
	partnerSvc := partnerService(t,
		humanResolver(nil),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	ownershipSvc, err := resourceownership.NewService(
		resourceownership.StaticPreOnboardingOwnershipResolver{},
		partnerSvc,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	customAuth := staticRequestAccessAuthenticator{
		tokens: map[string]string{
			"rat-por-1": "por-1",
		},
	}
	reg := completeTestRegistry(t, registry(t, customAuth))

	p := &probeSSI{calls: map[string]int{}}
	h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, reg, p)

	// Token bound to por-1 used against por-2 -> rejected upstream by M4.3 resource binding
	rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-2", "", map[string]string{
		"Authorization": "Bearer rat-por-1",
	})

	if rr.Code == http.StatusOK {
		t.Fatal("expected status != 200 on cross-resource RequestAccessToken access")
	}
	// Upstream M4.3 rejects before strict handler
	if p.count("GetPreOnboardingRequest") != 0 {
		t.Fatalf("protected read count = %d, want 0", p.count("GetPreOnboardingRequest"))
	}
}

// M5.3-AC-012 & M5.3-CHATGPT-001: Successful response identity consistency before 200 disclosure.
func TestResponseIdentityConsistency(t *testing.T) {
	partnerSvc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {
				PrincipalID: "user-1",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1"},
				},
			},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	ownershipSvc, err := resourceownership.NewService(
		resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
				return resourceownership.OwnershipFound("por-1", "P1"), nil
			},
		},
		partnerSvc,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	t.Run("Human: value 200 mismatched resource ID -> fail closed 503", func(t *testing.T) {
		customProbe := &customPreOnboardProbeSSI{
			probeSSI: probeSSI{calls: map[string]int{}},
			getFn: func(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error) {
				return openapi.GetPreOnboardingRequest200JSONResponse{
					Body: openapi.PreOnboardingRequest{
						PreOnboardingRequestId: "por-mismatched",
						PartnerId:              "P1",
					},
				}, nil
			},
		}
		h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, customProbe)

		rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
			"Authorization": humanBearer(),
		})

		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	})

	t.Run("Human: value 200 mismatched partner ID -> fail closed 503", func(t *testing.T) {
		customProbe := &customPreOnboardProbeSSI{
			probeSSI: probeSSI{calls: map[string]int{}},
			getFn: func(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error) {
				return openapi.GetPreOnboardingRequest200JSONResponse{
					Body: openapi.PreOnboardingRequest{
						PreOnboardingRequestId: "por-1",
						PartnerId:              "P2", // mismatched partner
					},
				}, nil
			},
		}
		h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, customProbe)

		rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
			"Authorization": humanBearer(),
		})

		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	})

	t.Run("Human: pointer 200 mismatched resource ID -> fail closed 503", func(t *testing.T) {
		customProbe := &customPreOnboardProbeSSI{
			probeSSI: probeSSI{calls: map[string]int{}},
			getFn: func(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error) {
				return &openapi.GetPreOnboardingRequest200JSONResponse{
					Body: openapi.PreOnboardingRequest{
						PreOnboardingRequestId: "por-mismatched",
						PartnerId:              "P1",
					},
				}, nil
			},
		}
		h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, customProbe)

		rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
			"Authorization": humanBearer(),
		})

		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	})

	t.Run("Human: pointer 200 mismatched partner ID -> fail closed 503", func(t *testing.T) {
		customProbe := &customPreOnboardProbeSSI{
			probeSSI: probeSSI{calls: map[string]int{}},
			getFn: func(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error) {
				return &openapi.GetPreOnboardingRequest200JSONResponse{
					Body: openapi.PreOnboardingRequest{
						PreOnboardingRequestId: "por-1",
						PartnerId:              "P2", // mismatched partner
					},
				}, nil
			},
		}
		h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, customProbe)

		rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
			"Authorization": humanBearer(),
		})

		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	})

	t.Run("Human: consistent pointer 200 succeeds", func(t *testing.T) {
		customProbe := &customPreOnboardProbeSSI{
			probeSSI: probeSSI{calls: map[string]int{}},
			getFn: func(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error) {
				return &openapi.GetPreOnboardingRequest200JSONResponse{
					Body: openapi.PreOnboardingRequest{
						PreOnboardingRequestId: "por-1",
						PartnerId:              "P1",
					},
				}, nil
			},
		}
		h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, customProbe)

		rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
			"Authorization": humanBearer(),
		})

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
		}
		body := jsonBody(t, rr)
		if body["pre_onboarding_request_id"] != "por-1" || body["partner_id"] != "P1" {
			t.Fatalf("unexpected body: %v", body)
		}
	})

	t.Run("RequestAccessToken: value 200 mismatched resource ID -> fail closed 503", func(t *testing.T) {
		customAuth := staticRequestAccessAuthenticator{
			tokens: map[string]string{
				"rat-por-1": "por-1",
			},
		}
		reg := completeTestRegistry(t, registry(t, customAuth))

		customProbe := &customPreOnboardProbeSSI{
			probeSSI: probeSSI{calls: map[string]int{}},
			getFn: func(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error) {
				return openapi.GetPreOnboardingRequest200JSONResponse{
					Body: openapi.PreOnboardingRequest{
						PreOnboardingRequestId: "por-different",
						PartnerId:              "P1",
					},
				}, nil
			},
		}
		h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, reg, customProbe)

		rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
			"Authorization": "Bearer rat-por-1",
		})

		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	})

	t.Run("RequestAccessToken: pointer 200 mismatched resource ID -> fail closed 503", func(t *testing.T) {
		customAuth := staticRequestAccessAuthenticator{
			tokens: map[string]string{
				"rat-por-1": "por-1",
			},
		}
		reg := completeTestRegistry(t, registry(t, customAuth))

		customProbe := &customPreOnboardProbeSSI{
			probeSSI: probeSSI{calls: map[string]int{}},
			getFn: func(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error) {
				return &openapi.GetPreOnboardingRequest200JSONResponse{
					Body: openapi.PreOnboardingRequest{
						PreOnboardingRequestId: "por-different",
						PartnerId:              "P1",
					},
				}, nil
			},
		}
		h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, reg, customProbe)

		rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
			"Authorization": "Bearer rat-por-1",
		})

		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	})

	t.Run("RequestAccessToken: consistent pointer 200 succeeds", func(t *testing.T) {
		customAuth := staticRequestAccessAuthenticator{
			tokens: map[string]string{
				"rat-por-1": "por-1",
			},
		}
		reg := completeTestRegistry(t, registry(t, customAuth))

		customProbe := &customPreOnboardProbeSSI{
			probeSSI: probeSSI{calls: map[string]int{}},
			getFn: func(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error) {
				return &openapi.GetPreOnboardingRequest200JSONResponse{
					Body: openapi.PreOnboardingRequest{
						PreOnboardingRequestId: "por-1",
						PartnerId:              "P1",
					},
				}, nil
			},
		}
		h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, reg, customProbe)

		rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
			"Authorization": "Bearer rat-por-1",
		})

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
		}
		body := jsonBody(t, rr)
		if body["pre_onboarding_request_id"] != "por-1" {
			t.Fatalf("unexpected body: %v", body)
		}
	})

	t.Run("Custom response object implementation fails closed without invoking visitor", func(t *testing.T) {
		customResp := &customVisitorProbeResponse{}
		customProbe := &customPreOnboardProbeSSI{
			probeSSI: probeSSI{calls: map[string]int{}},
			getFn: func(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error) {
				return customResp, nil
			},
		}
		h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, customProbe)

		rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
			"Authorization": humanBearer(),
		})

		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
		if customResp.wasVisited() {
			t.Fatal("custom response object visitor must never be invoked")
		}
	})

	t.Run("Typed-nil pointer 200 response fails closed 503", func(t *testing.T) {
		customProbe := &customPreOnboardProbeSSI{
			probeSSI: probeSSI{calls: map[string]int{}},
			getFn: func(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error) {
				var nil200 *openapi.GetPreOnboardingRequest200JSONResponse
				return nil200, nil
			},
		}
		h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, customProbe)

		rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
			"Authorization": humanBearer(),
		})

		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	})

	t.Run("Typed-nil pointer 410 response fails closed 503", func(t *testing.T) {
		customProbe := &customPreOnboardProbeSSI{
			probeSSI: probeSSI{calls: map[string]int{}},
			getFn: func(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error) {
				var nil410 *openapi.GetPreOnboardingRequest410ApplicationProblemPlusJSONResponse
				return nil410, nil
			},
		}
		h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, customProbe)

		rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
			"Authorization": humanBearer(),
		})

		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	})

	t.Run("Nil response object fails closed 503", func(t *testing.T) {
		customProbe := &customPreOnboardProbeSSI{
			probeSSI: probeSSI{calls: map[string]int{}},
			getFn: func(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error) {
				return nil, nil
			},
		}
		h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, customProbe)

		rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
			"Authorization": humanBearer(),
		})

		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	})
}

// M5.3-AC-013: Expiration does not bypass concealment; authorized same-partner expired passes 410 through.
func TestExpirationSemantics(t *testing.T) {
	partnerSvc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {
				PrincipalID: "user-1",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1"},
				},
			},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	ownershipSvc, err := resourceownership.NewService(
		resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
				switch id {
				case "por-expired-p1", "por-expired-ptr":
					return resourceownership.OwnershipFound(id, "P1"), nil
				case "por-expired-p2":
					return resourceownership.OwnershipFound("por-expired-p2", "P2"), nil
				default:
					return resourceownership.OwnershipNotFound(), nil
				}
			},
		},
		partnerSvc,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	customProbe := &customPreOnboardProbeSSI{
		probeSSI: probeSSI{calls: map[string]int{}},
		getFn: func(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error) {
			if request.Id == "por-expired-p1" {
				return openapi.GetPreOnboardingRequest410ApplicationProblemPlusJSONResponse{
					GoneApplicationProblemPlusJSONResponse: openapi.GoneApplicationProblemPlusJSONResponse{
						Body: openapi.ProblemDetail{
							Type:      "https://pki.example/errors/resource-expired",
							Title:     "Resource expired",
							Status:    http.StatusGone,
							ErrorCode: "RESOURCE_EXPIRED",
						},
					},
				}, nil
			}
			if request.Id == "por-expired-ptr" {
				return &openapi.GetPreOnboardingRequest410ApplicationProblemPlusJSONResponse{
					GoneApplicationProblemPlusJSONResponse: openapi.GoneApplicationProblemPlusJSONResponse{
						Body: openapi.ProblemDetail{
							Type:      "https://pki.example/errors/resource-expired",
							Title:     "Resource expired",
							Status:    http.StatusGone,
							ErrorCode: "RESOURCE_EXPIRED",
						},
					},
				}, nil
			}
			return openapi.GetPreOnboardingRequest200JSONResponse{}, nil
		},
	}
	h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, customProbe)

	// Case 1: Expired R2 owned by P2 with Human having only P1 -> 404 RESOURCE_NOT_FOUND (protected read count = 0)
	rrP2 := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-expired-p2", "", map[string]string{
		"Authorization": humanBearer(),
	})
	assertProblem(t, rrP2, http.StatusNotFound, "RESOURCE_NOT_FOUND")
	if customProbe.count("GetPreOnboardingRequest") != 0 {
		t.Fatalf("protected read count = %d, want 0 on concealed expired resource", customProbe.count("GetPreOnboardingRequest"))
	}

	// Case 2: Expired R1 owned by P1 with Human having P1 (value 410) -> passes visibility, application returns 410
	rrP1 := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-expired-p1", "", map[string]string{
		"Authorization": humanBearer(),
	})
	assertProblem(t, rrP1, http.StatusGone, "RESOURCE_EXPIRED")
	if customProbe.count("GetPreOnboardingRequest") != 1 {
		t.Fatalf("protected read count = %d, want 1 for authorized expired resource", customProbe.count("GetPreOnboardingRequest"))
	}

	// Case 3: Expired R1 owned by P1 with Human having P1 (pointer 410) -> passes visibility, application returns 410
	rrPtr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-expired-ptr", "", map[string]string{
		"Authorization": humanBearer(),
	})
	assertProblem(t, rrPtr, http.StatusGone, "RESOURCE_EXPIRED")
	if customProbe.count("GetPreOnboardingRequest") != 2 {
		t.Fatalf("protected read count = %d, want 2 for authorized expired resource pointer", customProbe.count("GetPreOnboardingRequest"))
	}
}

// M5.3-AC-014: Authentication/error precedence preserved.
func TestAuthenticationPrecedencePreserved(t *testing.T) {
	partnerSvc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {
				PrincipalID: "user-1",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1"},
				},
			},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	ownershipSvc, err := resourceownership.NewService(
		resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
				return resourceownership.OwnershipFound("por-1", "P1"), nil
			},
		},
		partnerSvc,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	p := &probeSSI{calls: map[string]int{}}
	h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, p)

	// Missing token -> 401 AUTHENTICATION_REQUIRED
	rrNoAuth := do(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", nil)
	assertProblem(t, rrNoAuth, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	if p.count("GetPreOnboardingRequest") != 0 {
		t.Fatal("protected read must not be invoked on missing authentication")
	}

	// Invalid token -> 401 AUTHENTICATION_REQUIRED
	rrBadAuth := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
		"Authorization": "Bearer invalid-token",
	})
	assertProblem(t, rrBadAuth, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	if p.count("GetPreOnboardingRequest") != 0 {
		t.Fatal("protected read must not be invoked on invalid authentication")
	}
}

// M5.3-AC-015: Mandatory Handler composition prevents bypass.
func TestMandatoryHandlerComposition(t *testing.T) {
	partnerSvc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {
				PrincipalID: "user-1",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1"},
				},
			},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	// Ownership resolver denies by saying por-2 is P2
	ownershipSvc, err := resourceownership.NewService(
		resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
				return resourceownership.OwnershipFound("por-2", "P2"), nil
			},
		},
		partnerSvc,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	srv, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(testAuthnRegistry()),
		httpapi.WithDeviceMTLSSource(testDeviceSource()),
		httpapi.WithAuthzRegistry(testAuthzRegistry()),
		httpapi.WithPartnerAuthService(partnerSvc),
		httpapi.WithResourceOwnershipService(ownershipSvc),
		httpapi.WithPreOnboardingService(preonboardingapp.NewUnavailableService()),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	p := &probeSSI{calls: map[string]int{}}
	// Canonical Server.Handler invocation
	h := srv.Handler(p)

	rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-2", "", map[string]string{
		"Authorization": humanBearer(),
	})
	assertProblem(t, rr, http.StatusNotFound, "RESOURCE_NOT_FOUND")
	if p.count("GetPreOnboardingRequest") != 0 {
		t.Fatal("canonical Server.Handler must enforce M5.3 and deny access")
	}
}

// M5.3-AC-016: Request-local concurrent isolation under race detector.
func TestHTTPConcurrentIsolation(t *testing.T) {
	partial := registry(t, subjectMappingHumanAuthenticator{subjects: map[string]string{
		"tok-A": "subject-A",
		"tok-B": "subject-B",
	}})
	reg := completeTestRegistry(t, partial)

	bySubject := map[string]partnerauth.HumanAuthorizations{
		"subject-A": {PrincipalID: "principal-A", Partners: []partnerauth.PartnerAuthorization{{PartnerID: "P1", DisplayName: "A"}}},
		"subject-B": {PrincipalID: "principal-B", Partners: []partnerauth.PartnerAuthorization{{PartnerID: "P2", DisplayName: "B"}}},
	}
	partnerSvc := partnerService(t,
		partnerauth.StaticHumanResolver{
			Resolve: func(_ context.Context, p partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
				return bySubject[p.Subject], nil
			},
		},
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	ownershipSvc, err := resourceownership.NewService(
		resourceownership.StaticPreOnboardingOwnershipResolver{
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
		},
		partnerSvc,
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	customProbe := &customPreOnboardProbeSSI{
		probeSSI: probeSSI{calls: map[string]int{}},
		getFn: func(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error) {
			partner := "P1"
			if request.Id == "por-2" {
				partner = "P2"
			}
			return openapi.GetPreOnboardingRequest200JSONResponse{
				Body: openapi.PreOnboardingRequest{
					PreOnboardingRequestId: request.Id,
					PartnerId:              partner,
				},
			}, nil
		},
	}

	h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, reg, customProbe)

	var wg sync.WaitGroup
	workers := 25
	iterations := 50

	for w := 0; w < workers; w++ {
		wg.Add(4)

		// User A -> por-1 (P1) -> 200
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{"Authorization": "Bearer tok-A"})
				if rr.Code != http.StatusOK {
					t.Errorf("worker %d: User A por-1 got status %d, want 200", workerID, rr.Code)
					return
				}
			}
		}(w)

		// User A -> por-2 (P2) -> 404
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-2", "", map[string]string{"Authorization": "Bearer tok-A"})
				if rr.Code != http.StatusNotFound {
					t.Errorf("worker %d: User A por-2 got status %d, want 404", workerID, rr.Code)
					return
				}
			}
		}(w)

		// User B -> por-2 (P2) -> 200
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-2", "", map[string]string{"Authorization": "Bearer tok-B"})
				if rr.Code != http.StatusOK {
					t.Errorf("worker %d: User B por-2 got status %d, want 200", workerID, rr.Code)
					return
				}
			}
		}(w)

		// User B -> por-1 (P1) -> 404
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{"Authorization": "Bearer tok-B"})
				if rr.Code != http.StatusNotFound {
					t.Errorf("worker %d: User B por-1 got status %d, want 404", workerID, rr.Code)
					return
				}
			}
		}(w)
	}

	wg.Wait()
}

// M5.3-AC-017: Startup integrity on Server construction.
func TestResourceOwnershipStartupIntegrity(t *testing.T) {
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	partnerSvc := partnerauth.NewUnavailableService()

	t.Run("omitted WithResourceOwnershipService fails construction", func(t *testing.T) {
		if _, err := httpapi.NewServer(cfg,
			httpapi.WithAuthnRegistry(testAuthnRegistry()),
			httpapi.WithDeviceMTLSSource(testDeviceSource()),
			httpapi.WithAuthzRegistry(testAuthzRegistry()),
			httpapi.WithPartnerAuthService(partnerSvc),
		); err == nil {
			t.Fatal("NewServer without WithResourceOwnershipService must fail")
		}
	})

	t.Run("nil resource ownership service fails construction", func(t *testing.T) {
		if _, err := httpapi.NewServer(cfg,
			httpapi.WithAuthnRegistry(testAuthnRegistry()),
			httpapi.WithDeviceMTLSSource(testDeviceSource()),
			httpapi.WithAuthzRegistry(testAuthzRegistry()),
			httpapi.WithPartnerAuthService(partnerSvc),
			httpapi.WithResourceOwnershipService(nil),
			httpapi.WithPreOnboardingService(preonboardingapp.NewUnavailableService()),
		); err == nil {
			t.Fatal("NewServer with nil resource ownership service must fail")
		}
	})

	t.Run("zero-value &resourceownership.Service{} fails construction", func(t *testing.T) {
		if _, err := httpapi.NewServer(cfg,
			httpapi.WithAuthnRegistry(testAuthnRegistry()),
			httpapi.WithDeviceMTLSSource(testDeviceSource()),
			httpapi.WithAuthzRegistry(testAuthzRegistry()),
			httpapi.WithPartnerAuthService(partnerSvc),
			httpapi.WithResourceOwnershipService(&resourceownership.Service{}),
			httpapi.WithPreOnboardingService(preonboardingapp.NewUnavailableService()),
		); err == nil {
			t.Fatal("NewServer with zero-value &resourceownership.Service{} must fail")
		}
	})

	t.Run("different valid *partnerauth.Service instances rejected (provenance mismatch)", func(t *testing.T) {
		partnerA := testPartnerAuthService()
		partnerB := testPartnerAuthService()
		ownershipSvc := resourceownership.NewUnavailableService(partnerB)

		if _, err := httpapi.NewServer(cfg,
			httpapi.WithAuthnRegistry(testAuthnRegistry()),
			httpapi.WithDeviceMTLSSource(testDeviceSource()),
			httpapi.WithAuthzRegistry(testAuthzRegistry()),
			httpapi.WithPartnerAuthService(partnerA),
			httpapi.WithResourceOwnershipService(ownershipSvc),
			httpapi.WithPreOnboardingService(preonboardingapp.NewUnavailableService()),
		); err == nil {
			t.Fatal("NewServer with different partnerauth.Service instances between partner auth and resource ownership must fail")
		}
	})

	t.Run("explicit unavailable service with same instance is valid startup composition and fails closed at request time", func(t *testing.T) {
		partnerSvc := testPartnerAuthService()
		srv, err := httpapi.NewServer(cfg,
			httpapi.WithAuthnRegistry(testAuthnRegistry()),
			httpapi.WithDeviceMTLSSource(testDeviceSource()),
			httpapi.WithAuthzRegistry(testAuthzRegistry()),
			httpapi.WithPartnerAuthService(partnerSvc),
			httpapi.WithResourceOwnershipService(resourceownership.NewUnavailableService(partnerSvc)),
			httpapi.WithPreOnboardingService(preonboardingapp.NewUnavailableService()),
		)
		if err != nil {
			t.Fatalf("NewServer with explicit unavailable service must succeed: %v", err)
		}
		p := &probeSSI{calls: map[string]int{}}
		h := srv.Handler(p)

		rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
			"Authorization": humanBearer(),
		})
		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
		if p.count("GetPreOnboardingRequest") != 0 {
			t.Fatal("protected read must not be invoked when ownership is unavailable")
		}
	})
}

// SOL-M5.3-001: Malformed M5.2 Human authorization cannot authorize M5.3 visibility.
func TestMalformedHumanAuthorizationsFailClosed(t *testing.T) {
	ownership := resourceownership.StaticPreOnboardingOwnershipResolver{
		Resolve: func(_ context.Context, id string) (resourceownership.OwnershipResult, error) {
			return resourceownership.OwnershipFound("por-1", "P1"), nil
		},
	}

	t.Run("empty principal ID fails closed with 503", func(t *testing.T) {
		partnerSvc := partnerService(t,
			partnerauth.StaticHumanResolver{
				Resolve: func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
					return partnerauth.HumanAuthorizations{
						PrincipalID: "", // empty principal_id violates M5.2 integrity
						Partners: []partnerauth.PartnerAuthorization{
							{PartnerID: "P1", DisplayName: "Partner 1"},
						},
					}, nil
				},
			},
			partnerauth.UnavailableTemporaryPrincipalResolver{},
		)
		ownershipSvc, err := resourceownership.NewService(ownership, partnerSvc)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}

		p := &probeSSI{calls: map[string]int{}}
		h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, p)

		rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
			"Authorization": humanBearer(),
		})
		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
		if p.count("GetPreOnboardingRequest") != 0 {
			t.Fatal("protected read must not be invoked when M5.2 human authorization is malformed")
		}
	})

	t.Run("padded partner ID fails closed with 503", func(t *testing.T) {
		partnerSvc := partnerService(t,
			partnerauth.StaticHumanResolver{
				Resolve: func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
					return partnerauth.HumanAuthorizations{
						PrincipalID: "user-1",
						Partners: []partnerauth.PartnerAuthorization{
							{PartnerID: " P1 ", DisplayName: "Partner 1"}, // padded partner_id violates M5.2 integrity
						},
					}, nil
				},
			},
			partnerauth.UnavailableTemporaryPrincipalResolver{},
		)
		ownershipSvc, err := resourceownership.NewService(ownership, partnerSvc)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}

		p := &probeSSI{calls: map[string]int{}}
		h := newOwnershipTestServer(t, partnerSvc, ownershipSvc, nil, p)

		rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-1", "", map[string]string{
			"Authorization": humanBearer(),
		})
		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
		if p.count("GetPreOnboardingRequest") != 0 {
			t.Fatal("protected read must not be invoked when M5.2 partner ID is padded")
		}
	})
}
