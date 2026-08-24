package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/config"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/resourceownership"
)

const testHumanSubject = "test-subject-human"

func humanBearer() string {
	return "Bearer " + m3BearerToken(authpolicy.CredentialKindHumanOIDC)
}

func tempBearer() string {
	return "Bearer " + m3BearerToken(authpolicy.CredentialKindTemporaryPrincipalToken)
}

func preOnboardJSON(partnerID string) string {
	return fmt.Sprintf(`{"partner_id":%q,"claimed_device":{"hostname":"PC-001"},"agent":{"version":"1.0.0","platform":"windows"}}`, partnerID)
}

func partnerService(t *testing.T, human partnerauth.HumanAuthorizationResolver, temp partnerauth.TemporaryPrincipalAuthorizationResolver) *partnerauth.Service {
	t.Helper()
	svc, err := partnerauth.NewService(human, temp)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func humanResolver(m map[string]partnerauth.HumanAuthorizations) partnerauth.HumanAuthorizationResolver {
	return partnerauth.StaticHumanResolver{
		Resolve: func(_ context.Context, p partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
			if v, ok := m[p.Subject]; ok {
				return v, nil
			}
			return partnerauth.HumanAuthorizations{PrincipalID: "principal-" + p.Subject}, nil
		},
	}
}

func newPartnerTestHandler(t *testing.T, svc *partnerauth.Service) (http.Handler, *probeSSI) {
	t.Helper()
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	srv, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(testAuthnRegistry()),
		httpapi.WithDeviceMTLSSource(testDeviceSource()),
		httpapi.WithAuthzRegistry(testAuthzRegistry()),
		httpapi.WithPartnerAuthService(svc),
		httpapi.WithResourceOwnershipService(resourceownership.NewUnavailableService(svc)),
		httpapi.WithPreOnboardingService(testPreOnboardingService()),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	p := &probeSSI{calls: map[string]int{}}
	// The canonical Server.Handler path: M5.2 is a mandatory part of that
	// composition (there is no opt-in path to bypass it).
	return srv.Handler(p), p
}

func jsonBody(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("response body is not JSON: %v (%q)", err, rr.Body.String())
	}
	return m
}

// M5.2-AC-001: a principal authorized for P1 and P2 discovers both partners.
func TestPartnerAuthMultiPartnerDiscovery(t *testing.T) {
	svc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {
				PrincipalID: "principal-123",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Revenda A", Scopes: []string{"device:preonboard"}},
					{PartnerID: "P2", DisplayName: "Revenda B", Scopes: []string{"device:preonboard"}},
				},
			},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	h, _ := newPartnerTestHandler(t, svc)
	rr := doAuth(t, h, "GET", "/v1/me/authorizations", "", map[string]string{"Authorization": humanBearer()})

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	body := jsonBody(t, rr)
	if body["principal_id"] != "principal-123" {
		t.Fatalf("principal_id = %v", body["principal_id"])
	}
	partners, ok := body["partners"].([]any)
	if !ok || len(partners) != 2 {
		t.Fatalf("partners = %v, want 2 entries", body["partners"])
	}
	ids := map[string]bool{}
	for _, p := range partners {
		pm, ok := p.(map[string]any)
		if !ok {
			t.Fatalf("partner entry is not an object: %v", p)
		}
		ids[pm["partner_id"].(string)] = true
	}
	if !ids["P1"] || !ids["P2"] {
		t.Fatalf("partner ids = %v, want P1 and P2", ids)
	}
}

// M5.2-AC-017: a successfully resolved empty authorization set is 200 with an
// empty partners array, not a 503.
func TestPartnerAuthEmptyAuthorizationsAreNotDependencyFailure(t *testing.T) {
	svc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {PrincipalID: "principal-123", Partners: nil},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	h, _ := newPartnerTestHandler(t, svc)
	rr := doAuth(t, h, "GET", "/v1/me/authorizations", "", map[string]string{"Authorization": humanBearer()})

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	body := jsonBody(t, rr)
	partners, ok := body["partners"].([]any)
	if !ok || len(partners) != 0 {
		t.Fatalf("partners = %v, want empty array", body["partners"])
	}
}

// M5.2-AC-002: server-side authority beats the client-selected partner_id.
func TestPartnerAuthServerSideBeatsClientHint(t *testing.T) {
	svc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {
				PrincipalID: "principal-123",
				Partners:    []partnerauth.PartnerAuthorization{{PartnerID: "P2", DisplayName: "B", Scopes: []string{"device:preonboard"}}},
			},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	h, p := newPartnerTestHandler(t, svc)
	rr := doAuth(t, h, "POST", "/v1/pre-onboarding-requests", preOnboardJSON("P1"), map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   humanBearer(),
	})
	assertProblem(t, rr, http.StatusForbidden, "PARTNER_NOT_AUTHORIZED")
	if p.count("CreatePreOnboardingRequest") != 0 {
		t.Fatal("protected mutation must not be invoked")
	}
}

// M5.2-AC-003: authorized partner with device:preonboard reaches the mutation seam.
func TestPartnerAuthHumanSelectionAllow(t *testing.T) {
	svc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {
				PrincipalID: "principal-123",
				Partners:    []partnerauth.PartnerAuthorization{{PartnerID: "P1", DisplayName: "A", Scopes: []string{"device:preonboard"}}},
			},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	h, p := newPartnerTestHandler(t, svc)
	rr := doAuth(t, h, "POST", "/v1/pre-onboarding-requests", preOnboardJSON("P1"), map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   humanBearer(),
	})
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %s)", rr.Code, rr.Body.String())
	}
	assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	if p.count("CreatePreOnboardingRequest") != 0 {
		t.Fatalf("protected mutation calls = %d, want 0", p.count("CreatePreOnboardingRequest"))
	}
}

// M5.2-AC-004 + M5.2-AC-008: denied partner/scope never reach the mutation seam.
func TestPartnerAuthHumanSelectionDeny(t *testing.T) {
	t.Run("partner absent", func(t *testing.T) {
		svc := partnerService(t,
			humanResolver(map[string]partnerauth.HumanAuthorizations{
				testHumanSubject: {PrincipalID: "principal-123", Partners: nil},
			}),
			partnerauth.UnavailableTemporaryPrincipalResolver{},
		)
		h, p := newPartnerTestHandler(t, svc)
		rr := doAuth(t, h, "POST", "/v1/pre-onboarding-requests", preOnboardJSON("P1"), map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
			"Authorization":   humanBearer(),
		})
		assertProblem(t, rr, http.StatusForbidden, "PARTNER_NOT_AUTHORIZED")
		if p.count("CreatePreOnboardingRequest") != 0 {
			t.Fatal("protected mutation must not be invoked")
		}
	})

	t.Run("partner present without scope", func(t *testing.T) {
		svc := partnerService(t,
			humanResolver(map[string]partnerauth.HumanAuthorizations{
				testHumanSubject: {
					PrincipalID: "principal-123",
					Partners:    []partnerauth.PartnerAuthorization{{PartnerID: "P1", DisplayName: "A", Scopes: []string{"device:approve"}}},
				},
			}),
			partnerauth.UnavailableTemporaryPrincipalResolver{},
		)
		h, p := newPartnerTestHandler(t, svc)
		rr := doAuth(t, h, "POST", "/v1/pre-onboarding-requests", preOnboardJSON("P1"), map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
			"Authorization":   humanBearer(),
		})
		assertProblem(t, rr, http.StatusForbidden, "SCOPE_DENIED")
		if p.count("CreatePreOnboardingRequest") != 0 {
			t.Fatal("protected mutation must not be invoked")
		}
	})
}

// M5.2-AC-005: authorization freshness is observed per request.
func TestPartnerAuthFreshnessAcrossRequests(t *testing.T) {
	var mu sync.RWMutex
	state := partnerauth.HumanAuthorizations{
		PrincipalID: "principal-123",
		Partners:    []partnerauth.PartnerAuthorization{{PartnerID: "P1", DisplayName: "A", Scopes: []string{"device:preonboard"}}},
	}
	svc := partnerService(t,
		partnerauth.StaticHumanResolver{Resolve: func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
			mu.RLock()
			defer mu.RUnlock()
			return state, nil
		}},
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	h, _ := newPartnerTestHandler(t, svc)

	headers := map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   humanBearer(),
	}
	rr := doAuth(t, h, "POST", "/v1/pre-onboarding-requests", preOnboardJSON("P1"), headers)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("request A status = %d, want 503 (body %s)", rr.Code, rr.Body.String())
	}
	assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")

	mu.Lock()
	state = partnerauth.HumanAuthorizations{PrincipalID: "principal-123", Partners: []partnerauth.PartnerAuthorization{{PartnerID: "P2", DisplayName: "B", Scopes: []string{"device:preonboard"}}}}
	mu.Unlock()

	rr = doAuth(t, h, "POST", "/v1/pre-onboarding-requests", preOnboardJSON("P1"), headers)
	assertProblem(t, rr, http.StatusForbidden, "PARTNER_NOT_AUTHORIZED")
}

// M5.2-AC-006 + M5.2-AC-007: dependency failure / indeterminate fails closed.
func TestPartnerAuthDependencyFailureFailsClosed(t *testing.T) {
	svc := partnerService(t,
		partnerauth.StaticHumanResolver{Resolve: func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
			return partnerauth.HumanAuthorizations{}, partnerauth.ErrDependencyUnavailable
		}},
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	h, p := newPartnerTestHandler(t, svc)
	rr := doAuth(t, h, "POST", "/v1/pre-onboarding-requests", preOnboardJSON("P1"), map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   humanBearer(),
	})
	assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	if p.count("CreatePreOnboardingRequest") != 0 {
		t.Fatal("protected mutation must not be invoked")
	}
}

// Malformed authorization state fails closed (503), never 200+empty or 201.
func TestPartnerAuthMalformedStateFailsClosed(t *testing.T) {
	svc := partnerService(t,
		partnerauth.StaticHumanResolver{Resolve: func(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
			return partnerauth.HumanAuthorizations{PrincipalID: "", Partners: []partnerauth.PartnerAuthorization{{PartnerID: "P1"}}}, nil
		}},
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	h, p := newPartnerTestHandler(t, svc)

	rr := doAuth(t, h, "GET", "/v1/me/authorizations", "", map[string]string{"Authorization": humanBearer()})
	assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")

	rr = doAuth(t, h, "POST", "/v1/pre-onboarding-requests", preOnboardJSON("P1"), map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   humanBearer(),
	})
	assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	if p.count("CreatePreOnboardingRequest") != 0 {
		t.Fatal("protected mutation must not be invoked")
	}
}

// M5.2-AC-012: authentication precedence — missing credentials are rejected by
// the M4 boundary (401), never rewritten by M5.2 into 403/503.
func TestPartnerAuthAuthenticationPrecedence(t *testing.T) {
	svc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {PrincipalID: "principal-123", Partners: []partnerauth.PartnerAuthorization{{PartnerID: "P1", DisplayName: "A", Scopes: []string{"device:preonboard"}}}},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	h, p := newPartnerTestHandler(t, svc)
	rr := doAuth(t, h, "POST", "/v1/pre-onboarding-requests", preOnboardJSON("P1"), map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
	})
	assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	if p.count("CreatePreOnboardingRequest") != 0 {
		t.Fatal("protected mutation must not be invoked")
	}
}

// A synthetically/server-authenticated Temporary Principal (established here
// by the injected deterministic test authenticator, not by a concrete
// production verifier) is blocked by the full HTTP path BEFORE the protected
// mutation: the later mandatory gates — the concrete TemporaryPrincipalToken
// production verifier/bootstrap and transactional max_submissions/quota
// consumption — are NOT implemented, so the M5.2 selection sub-gate alone must
// never yield a 201. The test asserts the harness-observed fail-closed
// behavior; it does not claim what the concrete production stack would return.
func TestPartnerAuthTemporaryPrincipalBlockedBeforeMutation(t *testing.T) {
	svc := partnerService(t,
		partnerauth.UnavailableHumanResolver{},
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	h, p := newPartnerTestHandler(t, svc)
	rr := doAuth(t, h, "POST", "/v1/pre-onboarding-requests", preOnboardJSON("P1"), map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   tempBearer(),
	})
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want fail-closed 503 in this harness (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("CreatePreOnboardingRequest") != 0 {
		t.Fatal("protected mutation must not be invoked for a Temporary Principal")
	}
	m := problemBody(t, rr)
	if m["error_code"] != "DEPENDENCY_UNAVAILABLE" {
		t.Fatalf("error_code = %v, want DEPENDENCY_UNAVAILABLE", m["error_code"])
	}
}

// M5.2-AC-018: a nil partner authorization service fails construction.
func TestPartnerAuthNilServiceRejected(t *testing.T) {
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	if _, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(testAuthnRegistry()),
		httpapi.WithDeviceMTLSSource(testDeviceSource()),
		httpapi.WithAuthzRegistry(testAuthzRegistry()),
		httpapi.WithPartnerAuthService(nil),
		httpapi.WithResourceOwnershipService(resourceownership.NewUnavailableService(partnerauth.NewUnavailableService())),
		httpapi.WithPreOnboardingService(testPreOnboardingService()),
	); err == nil {
		t.Fatal("NewServer with a nil partner authorization service must fail")
	}
}

// M5.2-CHATGPT-004: a zero-value (non-nil) &partnerauth.Service{} that
// bypasses the constructor is rejected at NewServer construction. The startup
// boundary revalidates the Service's own structural integrity instead of
// deferring the defect to request-time DEPENDENCY_UNAVAILABLE.
func TestPartnerAuthZeroValueServiceRejected(t *testing.T) {
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	if _, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(testAuthnRegistry()),
		httpapi.WithDeviceMTLSSource(testDeviceSource()),
		httpapi.WithAuthzRegistry(testAuthzRegistry()),
		httpapi.WithPartnerAuthService(&partnerauth.Service{}),
		httpapi.WithResourceOwnershipService(resourceownership.NewUnavailableService(partnerauth.NewUnavailableService())),
		httpapi.WithPreOnboardingService(testPreOnboardingService()),
	); err == nil {
		t.Fatal("NewServer with a zero-value partner authorization service must fail construction")
	}
}

// M5.2-CHATGPT-004: the explicitly unavailable service remains a VALID M5.2
// startup composition (its resolvers exist and deterministically report
// dependency-unavailable); requests to M5.2-owned routes then fail closed at
// request time rather than at startup.
func TestPartnerAuthUnavailableServiceValidStartup(t *testing.T) {
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	partnerSvc := partnerauth.NewUnavailableService()
	srv, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(testAuthnRegistry()),
		httpapi.WithDeviceMTLSSource(testDeviceSource()),
		httpapi.WithAuthzRegistry(testAuthzRegistry()),
		httpapi.WithPartnerAuthService(partnerSvc),
		httpapi.WithResourceOwnershipService(resourceownership.NewUnavailableService(partnerSvc)),
		httpapi.WithPreOnboardingService(testPreOnboardingService()),
	)
	if err != nil {
		t.Fatalf("NewServer with the explicitly unavailable M5.2 service must succeed: %v", err)
	}
	p := &probeSSI{calls: map[string]int{}}
	h := srv.Handler(p)

	rr := doAuth(t, h, "GET", "/v1/me/authorizations", "", map[string]string{"Authorization": humanBearer()})
	assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	if p.count("GetMyAuthorizations") != 0 {
		t.Fatal("inner handler must not be invoked when the authorization dependency is unavailable")
	}
}

// M5.2-CHATGPT-003 regression: omitting the mandatory M5.2 dependency must
// fail construction. There is no implicit unavailable/permissive fallback.
func TestNewServerWithoutPartnerAuthServiceFails(t *testing.T) {
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	_, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(testAuthnRegistry()),
		httpapi.WithDeviceMTLSSource(testDeviceSource()),
		httpapi.WithAuthzRegistry(testAuthzRegistry()),
		httpapi.WithResourceOwnershipService(resourceownership.NewUnavailableService(partnerauth.NewUnavailableService())),
	)
	if err == nil {
		t.Fatal("NewServer without WithPartnerAuthService must fail construction")
	}
	if _, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(testAuthnRegistry()),
		httpapi.WithDeviceMTLSSource(testDeviceSource()),
		httpapi.WithAuthzRegistry(testAuthzRegistry()),
		httpapi.WithPartnerAuthService(nil),
		httpapi.WithResourceOwnershipService(resourceownership.NewUnavailableService(partnerauth.NewUnavailableService())),
	); err == nil {
		t.Fatal("NewServer with a nil partner authorization service must fail construction")
	}
}

// M5.2-CHATGPT-001 regression: the canonical Server.Handler composition
// enforces M5.2. A HumanOIDC request selecting P1 while the resolver only
// authorizes P2 returns 403 PARTNER_NOT_AUTHORIZED and invokes the protected
// mutation zero times — there is no Handler construction path that skips
// partner authorization.
func TestPartnerAuthMandatoryCompositionDeniesWithoutDelegation(t *testing.T) {
	svc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {
				PrincipalID: "principal-123",
				Partners:    []partnerauth.PartnerAuthorization{{PartnerID: "P2", DisplayName: "B", Scopes: []string{"device:preonboard"}}},
			},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	srv, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(testAuthnRegistry()),
		httpapi.WithDeviceMTLSSource(testDeviceSource()),
		httpapi.WithAuthzRegistry(testAuthzRegistry()),
		httpapi.WithPartnerAuthService(svc),
		httpapi.WithResourceOwnershipService(resourceownership.NewUnavailableService(svc)),
		httpapi.WithPreOnboardingService(testPreOnboardingService()),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	p := &probeSSI{calls: map[string]int{}}
	h := srv.Handler(p)

	rr := doAuth(t, h, "POST", "/v1/pre-onboarding-requests", preOnboardJSON("P1"), map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   humanBearer(),
	})
	assertProblem(t, rr, http.StatusForbidden, "PARTNER_NOT_AUTHORIZED")
	if p.count("CreatePreOnboardingRequest") != 0 {
		t.Fatal("protected mutation must not be invoked")
	}
}

// countingHumanResolver is a spy: it counts resolver invocations and returns
// a valid empty authorization set.
type countingHumanResolver struct {
	mu    sync.Mutex
	calls int
}

func (r *countingHumanResolver) ResolveHumanAuthorizations(_ context.Context, _ partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	return partnerauth.HumanAuthorizations{PrincipalID: "principal-spy"}, nil
}

func (r *countingHumanResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// M5.2-CHATGPT-001 regression (anonymous trust bundle): through the same
// mandatory M5.2-composed Server.Handler, GET /v1/pki/trust-bundles/current
// stays anonymous and never invokes partner authorization resolution.
func TestPartnerAuthTrustBundleSkipsPartnerResolution(t *testing.T) {
	spy := &countingHumanResolver{}
	svc := partnerService(t, spy, partnerauth.UnavailableTemporaryPrincipalResolver{})
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	srv, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(testAuthnRegistry()),
		httpapi.WithDeviceMTLSSource(testDeviceSource()),
		httpapi.WithAuthzRegistry(testAuthzRegistry()),
		httpapi.WithPartnerAuthService(svc),
		httpapi.WithResourceOwnershipService(resourceownership.NewUnavailableService(svc)),
		httpapi.WithPreOnboardingService(testPreOnboardingService()),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	p := &probeSSI{calls: map[string]int{}}
	h := srv.Handler(p)

	rr := do(t, h, "GET", "/v1/pki/trust-bundles/current", "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("GetCurrentTrustBundle") != 1 {
		t.Fatalf("GetCurrentTrustBundle calls = %d, want 1", p.count("GetCurrentTrustBundle"))
	}
	if spy.count() != 0 {
		t.Fatalf("partner resolution invoked %d times for the anonymous trust bundle; want 0", spy.count())
	}
}

// M5.2-CHATGPT-002 regressions: leading/trailing whitespace in authoritative
// provider identifiers is malformed and fails closed; it is never
// canonicalized into authority, and the protected mutation is never invoked.
func TestPartnerAuthPaddedIdentifiersFailClosed(t *testing.T) {
	t.Run("padded partner id cannot authorize", func(t *testing.T) {
		svc := partnerService(t,
			humanResolver(map[string]partnerauth.HumanAuthorizations{
				testHumanSubject: {
					PrincipalID: "principal-123",
					Partners:    []partnerauth.PartnerAuthorization{{PartnerID: " P1 ", DisplayName: "A", Scopes: []string{"device:preonboard"}}},
				},
			}),
			partnerauth.UnavailableTemporaryPrincipalResolver{},
		)
		h, p := newPartnerTestHandler(t, svc)
		rr := doAuth(t, h, "POST", "/v1/pre-onboarding-requests", preOnboardJSON("P1"), map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
			"Authorization":   humanBearer(),
		})
		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
		if p.count("CreatePreOnboardingRequest") != 0 {
			t.Fatal("protected mutation must not be invoked")
		}
	})

	t.Run("padded scope cannot authorize", func(t *testing.T) {
		svc := partnerService(t,
			humanResolver(map[string]partnerauth.HumanAuthorizations{
				testHumanSubject: {
					PrincipalID: "principal-123",
					Partners:    []partnerauth.PartnerAuthorization{{PartnerID: "P1", DisplayName: "A", Scopes: []string{" device:preonboard "}}},
				},
			}),
			partnerauth.UnavailableTemporaryPrincipalResolver{},
		)
		h, p := newPartnerTestHandler(t, svc)
		rr := doAuth(t, h, "POST", "/v1/pre-onboarding-requests", preOnboardJSON("P1"), map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
			"Authorization":   humanBearer(),
		})
		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
		if p.count("CreatePreOnboardingRequest") != 0 {
			t.Fatal("protected mutation must not be invoked")
		}
	})
}

// subjectMappingHumanAuthenticator binds each bearer token to a distinct human
// subject, for concurrent principal-isolation tests.
type subjectMappingHumanAuthenticator struct {
	subjects map[string]string
}

func (a subjectMappingHumanAuthenticator) Kind() authpolicy.CredentialKind {
	return authpolicy.CredentialKindHumanOIDC
}

func (a subjectMappingHumanAuthenticator) Authenticate(_ context.Context, c *authruntime.Credential) authruntime.AuthenticationResult {
	sub, ok := a.subjects[c.BearerToken]
	if !ok {
		return authruntime.AuthenticationResult{Decision: authruntime.DecisionRejected}
	}
	b, err := authruntime.NewHumanOIDCBinding("test-issuer", sub)
	if err != nil {
		return authruntime.AuthenticationResult{Decision: authruntime.DecisionIndeterminate}
	}
	return authruntime.AuthenticationResult{Decision: authruntime.DecisionAuthenticated, Binding: b}
}

// M5.2-AC-016: concurrent requests for different principals/partners do not
// leak authorization state across the full HTTP boundary. Runs under -race.
func TestPartnerAuthConcurrentRequestIsolation(t *testing.T) {
	partial := registry(t, subjectMappingHumanAuthenticator{subjects: map[string]string{
		"tok-A": "subject-A",
		"tok-B": "subject-B",
	}})
	reg := completeTestRegistry(t, partial)
	src := completeTestDeviceSource(nil)

	bySubject := map[string]partnerauth.HumanAuthorizations{
		"subject-A": {PrincipalID: "principal-A", Partners: []partnerauth.PartnerAuthorization{{PartnerID: "P1", DisplayName: "A", Scopes: []string{"device:preonboard"}}}},
		"subject-B": {PrincipalID: "principal-B", Partners: []partnerauth.PartnerAuthorization{{PartnerID: "P2", DisplayName: "B", Scopes: []string{"device:preonboard"}}}},
	}
	svc := partnerService(t,
		partnerauth.StaticHumanResolver{Resolve: func(_ context.Context, p partnerauth.HumanPrincipal) (partnerauth.HumanAuthorizations, error) {
			return bySubject[p.Subject], nil
		}},
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)

	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	srv, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(reg),
		httpapi.WithDeviceMTLSSource(src),
		httpapi.WithAuthzRegistry(testAuthzRegistry()),
		httpapi.WithPartnerAuthService(svc),
		httpapi.WithResourceOwnershipService(resourceownership.NewUnavailableService(svc)),
		httpapi.WithPreOnboardingService(testPreOnboardingService()),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	p := &probeSSI{calls: map[string]int{}}
	// Canonical Server.Handler path (M5.2 is mandatory in it).
	h := srv.Handler(p)

	type want struct {
		token    string
		partner  string
		wantCode int
	}
	cases := []want{
		{"tok-A", "P1", http.StatusServiceUnavailable},
		{"tok-B", "P2", http.StatusServiceUnavailable},
		{"tok-A", "P2", http.StatusForbidden},
		{"tok-B", "P1", http.StatusForbidden},
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(cases)*100)
	for i := 0; i < 100; i++ {
		for _, c := range cases {
			wg.Add(1)
			go func(c want) {
				defer wg.Done()
				rr := doAuth(t, h, "POST", "/v1/pre-onboarding-requests", preOnboardJSON(c.partner), map[string]string{
					"Content-Type":    "application/json",
					"Idempotency-Key": validIdempotencyKey,
					"Authorization":   "Bearer " + c.token,
				})
				if rr.Code != c.wantCode {
					errs <- fmt.Errorf("token %s partner %s: got %d want %d (body %s)", c.token, c.partner, rr.Code, c.wantCode, rr.Body.String())
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

// GetMyAuthorizations never delegates to the protected handler; it is answered
// directly from the resolver.
func TestPartnerAuthGetMyAuthorizationsDoesNotDelegate(t *testing.T) {
	svc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {PrincipalID: "principal-123", Partners: nil},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)
	h, p := newPartnerTestHandler(t, svc)
	rr := doAuth(t, h, "GET", "/v1/me/authorizations", "", map[string]string{"Authorization": humanBearer()})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if p.count("GetMyAuthorizations") != 0 {
		t.Fatal("GetMyAuthorizations must be answered by the M5.2 boundary, not the inner handler")
	}
}
