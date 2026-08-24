package httpapi_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	authzruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authz/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/config"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
	preonboardingapp "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	preonboardingruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/resourceownership"
)

type httpTestContext struct {
	store       *preonboardingruntime.MemoryStore
	recorder    *preonboardingruntime.MemoryAuditRecorder
	clock       *preonboardingruntime.MockClock
	partnerAuth *preonboardingruntime.MemoryPartnerAuthorityChecker
	partnerElig *preonboardingruntime.MemoryPartnerEligibilityChecker
	handler     http.Handler
}

func newPreOnboardingTestContext(t *testing.T, initialTime time.Time) *httpTestContext {
	t.Helper()

	recorder := preonboardingruntime.NewMemoryAuditRecorder()
	store := preonboardingruntime.NewMemoryStore(recorder)
	clock := preonboardingruntime.NewMockClock(initialTime)
	partnerAuth := preonboardingruntime.NewMemoryPartnerAuthorityChecker()
	partnerElig := preonboardingruntime.NewMemoryPartnerEligibilityChecker()

	preonboardSvc, err := preonboardingapp.NewService(preonboardingapp.ServiceConfig{
		UOWManager:         store,
		Clock:              clock,
		DeviceAllocator:    preonboardingruntime.DefaultDeviceAllocator{},
		PartnerAuth:        partnerAuth,
		PartnerEligibility: partnerElig,
		RetentionPolicy:    preonboardingapp.StaticIdempotencyRetentionPolicy{Duration: 24 * time.Hour},
	})
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	// Authorize device:approve for admin token in authz registry
	authorizer := authzruntime.StaticScopeAuthorizer{
		Decide: func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req authzruntime.ScopeAuthorizationRequest) (authzruntime.Decision, error) {
			for _, sc := range req.RequiredScopes {
				if sc == "device:approve" {
					return authzruntime.DecisionAllowed, nil
				}
			}
			return authzruntime.DecisionDenied, nil
		},
	}
	authzReg, err := authzruntime.NewRegistry(authorizer, authzruntime.DenyAllOpenEvaluator(), nil)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	// Setup partner authorization service for human/temporary principal (P1 authorized, P2 unauthorized)
	humanPartnerSvc := partnerService(t,
		humanResolver(map[string]partnerauth.HumanAuthorizations{
			testHumanSubject: {
				PrincipalID: "principal-123",
				Partners: []partnerauth.PartnerAuthorization{
					{PartnerID: "P1", DisplayName: "Partner 1", Scopes: []string{"device:preonboard"}},
				},
			},
		}),
		partnerauth.UnavailableTemporaryPrincipalResolver{},
	)

	// Setup resource ownership service
	ownershipSvc, err := resourceownership.NewService(
		resourceownership.StaticPreOnboardingOwnershipResolver{
			Resolve: func(ctx context.Context, id string) (resourceownership.OwnershipResult, error) {
				req, ok := store.GetRequest(domain.ID(id))
				if !ok {
					return resourceownership.OwnershipNotFound(), nil
				}
				return resourceownership.OwnershipFound(id, string(req.PartnerID())), nil
			},
		},
		humanPartnerSvc,
	)
	if err != nil {
		t.Fatalf("resourceownership.NewService failed: %v", err)
	}

	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	srv, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(matrixRegistry(t)),
		httpapi.WithDeviceMTLSSource(matrixDeviceSource()),
		httpapi.WithAuthzRegistry(authzReg),
		httpapi.WithPartnerAuthService(humanPartnerSvc),
		httpapi.WithResourceOwnershipService(ownershipSvc),
		httpapi.WithPreOnboardingService(preonboardSvc),
	)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	p := &probeSSI{calls: map[string]int{}}
	h := srv.Handler(p)

	return &httpTestContext{
		store:       store,
		recorder:    recorder,
		clock:       clock,
		partnerAuth: partnerAuth,
		partnerElig: partnerElig,
		handler:     h,
	}
}

// 1. Production Create Fail-Closed & M5.2 Precedence (M55-SOL-001)
func TestHTTP_CreatePreOnboarding_FailClosedAndM52Precedence(t *testing.T) {
	tc := newPreOnboardingTestContext(t, time.Now())

	// Authorized partner P1 -> passes M5.2 gate, reaches M5.5 fail-closed 503
	bodyP1 := `{"partner_id":"P1","agent":{"platform":"windows","version":"1.0"},"claimed_device":{"hostname":"node-1"}}`
	rrP1 := doAuth(t, tc.handler, "POST", "/v1/pre-onboarding-requests", bodyP1, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokHuman,
		"Idempotency-Key": validIdempotencyKey,
	})
	if rrP1.Code != http.StatusServiceUnavailable {
		t.Fatalf("status for authorized P1 = %d, want 503 DEPENDENCY_UNAVAILABLE, body: %s", rrP1.Code, rrP1.Body.String())
	}
	assertProblem(t, rrP1, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")

	// Unauthorized partner P2 -> rejected by M5.2 with 403 PARTNER_NOT_AUTHORIZED BEFORE reaching M5.5's 503
	bodyP2 := `{"partner_id":"P2","agent":{"platform":"windows","version":"1.0"},"claimed_device":{"hostname":"node-2"}}`
	rrP2 := doAuth(t, tc.handler, "POST", "/v1/pre-onboarding-requests", bodyP2, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokHuman,
		"Idempotency-Key": validIdempotencyKey,
	})
	if rrP2.Code != http.StatusForbidden {
		t.Fatalf("status for unauthorized P2 = %d, want 403 PARTNER_NOT_AUTHORIZED (M5.2 gate), body: %s", rrP2.Code, rrP2.Body.String())
	}
	assertProblem(t, rrP2, http.StatusForbidden, "PARTNER_NOT_AUTHORIZED")

	// Ensure zero side effects
	if tc.store.CountRequests() != 0 {
		t.Errorf("stored requests = %d, want 0", tc.store.CountRequests())
	}
	if tc.recorder.Count() != 0 {
		t.Errorf("audit events = %d, want 0", tc.recorder.Count())
	}
}

// 2. Public Read Scenarios & M5.3 Visibility Precedence (M55-SOL-001)
func TestHTTP_PublicGet_ScenariosAndM53Precedence(t *testing.T) {
	now := time.Now()
	tc := newPreOnboardingTestContext(t, now)

	reqP1, _ := domain.NewRequest("por-pub-p1", "P1", domain.ClaimedDevice{Hostname: "host-pub-1"}, domain.Agent{}, now, now.Add(10*time.Minute))
	reqP2, _ := domain.NewRequest("por-pub-p2", "P2", domain.ClaimedDevice{Hostname: "host-pub-2"}, domain.Agent{}, now, now.Add(10*time.Minute))
	tc.store.SeedRequest(reqP1)
	tc.store.SeedRequest(reqP2)
	etagP1 := domain.ComputeETag(reqP1, now)

	// Valid read before expiry for authorized partner P1
	rr := doAuth(t, tc.handler, "GET", "/v1/pre-onboarding-requests/por-pub-p1", "", map[string]string{
		"Authorization": "Bearer " + tokHuman,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("ETag") != etagP1 {
		t.Errorf("ETag header = %s, want %s", rr.Header().Get("ETag"), etagP1)
	}
	if rr.Header().Get("X-Correlation-ID") == "" {
		t.Error("X-Correlation-ID header must be present")
	}

	// Resource belonging to unauthorized partner P2 -> concealed by M5.3 as 404 RESOURCE_NOT_FOUND
	rrP2 := doAuth(t, tc.handler, "GET", "/v1/pre-onboarding-requests/por-pub-p2", "", map[string]string{
		"Authorization": "Bearer " + tokHuman,
	})
	if rrP2.Code != http.StatusNotFound {
		t.Fatalf("unauthorized partner public GET status = %d, want 404 RESOURCE_NOT_FOUND (M5.3 gate), body: %s", rrP2.Code, rrP2.Body.String())
	}
	assertProblem(t, rrP2, http.StatusNotFound, "RESOURCE_NOT_FOUND")

	// Advance clock past expiration => 410 RESOURCE_EXPIRED
	tc.clock.Advance(15 * time.Minute)
	rrExp := doAuth(t, tc.handler, "GET", "/v1/pre-onboarding-requests/por-pub-p1", "", map[string]string{
		"Authorization": "Bearer " + tokHuman,
	})
	if rrExp.Code != http.StatusGone {
		t.Fatalf("expired public GET status = %d, want 410 RESOURCE_EXPIRED, body: %s", rrExp.Code, rrExp.Body.String())
	}
	assertProblem(t, rrExp, http.StatusGone, "RESOURCE_EXPIRED")
}

// 3. Admin List Scenarios (GET /v1/admin/pre-onboarding-requests)
func TestHTTP_AdminList_Scenarios(t *testing.T) {
	now := time.Now()
	tc := newPreOnboardingTestContext(t, now)
	admin := preonboardingapp.AdminPrincipal{Issuer: "test-issuer", Subject: "test-subject-admin"}

	// Grant admin authority only for P1 and P2 (P3 unauthorized)
	tc.partnerAuth.GrantPartnerAuthority(admin, "P1")
	tc.partnerAuth.GrantPartnerAuthority(admin, "P2")

	req1, _ := domain.NewRequest("por-admin-1", "P1", domain.ClaimedDevice{Hostname: "h1"}, domain.Agent{}, now, now.Add(10*time.Minute))
	req2, _ := domain.NewRequest("por-admin-2", "P2", domain.ClaimedDevice{Hostname: "h2"}, domain.Agent{}, now, now.Add(10*time.Minute))
	req3, _ := domain.NewRequest("por-admin-3", "P3", domain.ClaimedDevice{Hostname: "h3"}, domain.Agent{}, now, now.Add(10*time.Minute))
	tc.store.SeedRequest(req1)
	tc.store.SeedRequest(req2)
	tc.store.SeedRequest(req3)

	// List all authorized partners
	rr := doAuth(t, tc.handler, "GET", "/v1/admin/pre-onboarding-requests", "", map[string]string{
		"Authorization": "Bearer " + tokAdmin,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rr.Code, rr.Body.String())
	}
	body := jsonBody(t, rr)
	items, ok := body["items"].([]any)
	if !ok {
		t.Fatalf("items field missing or not array: %+v", body)
	}
	if len(items) != 2 {
		t.Errorf("items count = %d, want 2 (P3 excluded)", len(items))
	}

	// Filter by query partner_id=P1
	rrP1 := doAuth(t, tc.handler, "GET", "/v1/admin/pre-onboarding-requests?partner_id=P1", "", map[string]string{
		"Authorization": "Bearer " + tokAdmin,
	})
	if rrP1.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rrP1.Code, rrP1.Body.String())
	}
	bodyP1 := jsonBody(t, rrP1)
	itemsP1 := bodyP1["items"].([]any)
	if len(itemsP1) != 1 {
		t.Errorf("items count for partner_id=P1 = %d, want 1", len(itemsP1))
	}

	// Filter by unauthorized partner_id=P3 returns empty list
	rrP3 := doAuth(t, tc.handler, "GET", "/v1/admin/pre-onboarding-requests?partner_id=P3", "", map[string]string{
		"Authorization": "Bearer " + tokAdmin,
	})
	if rrP3.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rrP3.Code, rrP3.Body.String())
	}
	bodyP3 := jsonBody(t, rrP3)
	itemsP3 := bodyP3["items"].([]any)
	if len(itemsP3) != 0 {
		t.Errorf("items count for unauthorized partner_id=P3 = %d, want 0", len(itemsP3))
	}

	// Advance clock past expiration: items observable as effective EXPIRED
	tc.clock.Advance(15 * time.Minute)
	rrExp := doAuth(t, tc.handler, "GET", "/v1/admin/pre-onboarding-requests?status=EXPIRED", "", map[string]string{
		"Authorization": "Bearer " + tokAdmin,
	})
	if rrExp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rrExp.Code, rrExp.Body.String())
	}
	bodyExp := jsonBody(t, rrExp)
	itemsExp := bodyExp["items"].([]any)
	if len(itemsExp) != 2 {
		t.Errorf("expired items count = %d, want 2", len(itemsExp))
	}
}

// 4. Admin Get Scenarios (GET /v1/admin/pre-onboarding-requests/{id})
func TestHTTP_AdminGet_Scenarios(t *testing.T) {
	now := time.Now()
	tc := newPreOnboardingTestContext(t, now)
	admin := preonboardingapp.AdminPrincipal{Issuer: "test-issuer", Subject: "test-subject-admin"}

	// Grant admin authority only for P1
	tc.partnerAuth.GrantPartnerAuthority(admin, "P1")

	reqP1, _ := domain.NewRequest("por-admin-p1", "P1", domain.ClaimedDevice{Hostname: "h1"}, domain.Agent{}, now, now.Add(10*time.Minute))
	reqP2, _ := domain.NewRequest("por-admin-p2", "P2", domain.ClaimedDevice{Hostname: "h2"}, domain.Agent{}, now, now.Add(10*time.Minute))
	tc.store.SeedRequest(reqP1)
	tc.store.SeedRequest(reqP2)
	etagP1 := domain.ComputeETag(reqP1, now)

	// 1. Authorized read succeeds with 200 and strong ETag
	rr := doAuth(t, tc.handler, "GET", "/v1/admin/pre-onboarding-requests/por-admin-p1", "", map[string]string{
		"Authorization": "Bearer " + tokAdmin,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("ETag") != etagP1 {
		t.Errorf("ETag = %s, want %s", rr.Header().Get("ETag"), etagP1)
	}

	// 2. Unauthorized partner resource concealed as 404 RESOURCE_NOT_FOUND (M5.5-DEC-002)
	rrP2 := doAuth(t, tc.handler, "GET", "/v1/admin/pre-onboarding-requests/por-admin-p2", "", map[string]string{
		"Authorization": "Bearer " + tokAdmin,
	})
	if rrP2.Code != http.StatusNotFound {
		t.Fatalf("unauthorized partner read status = %d, want 404, body: %s", rrP2.Code, rrP2.Body.String())
	}
	assertProblem(t, rrP2, http.StatusNotFound, "RESOURCE_NOT_FOUND")

	// 3. Expired resource for authorized partner returns 200 OK with status EXPIRED (never 410 on admin read)
	tc.clock.Advance(15 * time.Minute)
	rrExp := doAuth(t, tc.handler, "GET", "/v1/admin/pre-onboarding-requests/por-admin-p1", "", map[string]string{
		"Authorization": "Bearer " + tokAdmin,
	})
	if rrExp.Code != http.StatusOK {
		t.Fatalf("admin GET expired status = %d, want 200, body: %s", rrExp.Code, rrExp.Body.String())
	}
	bodyExp := jsonBody(t, rrExp)
	if bodyExp["status"] != "EXPIRED" {
		t.Errorf("status = %v, want EXPIRED", bodyExp["status"])
	}
	if rrExp.Header().Get("ETag") == etagP1 {
		t.Error("ETag for expired resource must differ from pre-expiry ETag")
	}
}

// 5. Admin Approve Scenarios (POST /v1/admin/pre-onboarding-requests/{id}/approve)
func TestHTTP_AdminApprove_Scenarios(t *testing.T) {
	now := time.Now()
	tc := newPreOnboardingTestContext(t, now)
	admin := preonboardingapp.AdminPrincipal{Issuer: "test-issuer", Subject: "test-subject-admin"}
	tc.partnerAuth.GrantPartnerAuthority(admin, "P1")

	req, _ := domain.NewRequest("por-app-1", "P1", domain.ClaimedDevice{Hostname: "h1"}, domain.Agent{}, now, now.Add(10*time.Minute))
	tc.store.SeedRequest(req)
	preExpiryETag := domain.ComputeETag(req, now)

	approveBody := `{"expected_status":"PENDING_APPROVAL","reason":"approved hardware"}`

	// 1. Missing partner authority => 403 PARTNER_NOT_AUTHORIZED
	tc.partnerAuth.RevokePartnerAuthority(admin, "P1")
	rrNoAuth := doAuth(t, tc.handler, "POST", "/v1/admin/pre-onboarding-requests/por-app-1/approve", approveBody, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokAdmin,
		"If-Match":        preExpiryETag,
		"Idempotency-Key": validIdempotencyKey,
	})
	if rrNoAuth.Code != http.StatusForbidden {
		t.Fatalf("status without partner authority = %d, want 403, body: %s", rrNoAuth.Code, rrNoAuth.Body.String())
	}
	assertProblem(t, rrNoAuth, http.StatusForbidden, "PARTNER_NOT_AUTHORIZED")

	// Restore partner authority
	tc.partnerAuth.GrantPartnerAuthority(admin, "P1")

	// 2. Ineligible partner => 403 PARTNER_NOT_AUTHORIZED
	tc.partnerElig.SetPartnerIneligible("P1", true)
	rrInelig := doAuth(t, tc.handler, "POST", "/v1/admin/pre-onboarding-requests/por-app-1/approve", approveBody, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokAdmin,
		"If-Match":        preExpiryETag,
		"Idempotency-Key": validIdempotencyKey,
	})
	if rrInelig.Code != http.StatusForbidden {
		t.Fatalf("status with ineligible partner = %d, want 403, body: %s", rrInelig.Code, rrInelig.Body.String())
	}
	assertProblem(t, rrInelig, http.StatusForbidden, "PARTNER_NOT_AUTHORIZED")

	// Restore partner eligibility
	tc.partnerElig.SetPartnerIneligible("P1", false)

	// 3. Stale If-Match => 412 PRECONDITION_FAILED
	rrStale := doAuth(t, tc.handler, "POST", "/v1/admin/pre-onboarding-requests/por-app-1/approve", approveBody, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokAdmin,
		"If-Match":        `"stale-etag-00000"`,
		"Idempotency-Key": validIdempotencyKey,
	})
	if rrStale.Code != http.StatusPreconditionFailed {
		t.Fatalf("status on stale If-Match = %d, want 412, body: %s", rrStale.Code, rrStale.Body.String())
	}
	assertProblem(t, rrStale, http.StatusPreconditionFailed, "PRECONDITION_FAILED")

	// 4. Successful NEW approval => 200 OK + PreOnboardingApprovalResponse
	rrSuccess := doAuth(t, tc.handler, "POST", "/v1/admin/pre-onboarding-requests/por-app-1/approve", approveBody, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokAdmin,
		"If-Match":        preExpiryETag,
		"Idempotency-Key": "idem-key-approve-success",
	})
	if rrSuccess.Code != http.StatusOK {
		t.Fatalf("status on successful approve = %d, want 200, body: %s", rrSuccess.Code, rrSuccess.Body.String())
	}
	bodySuccess := jsonBody(t, rrSuccess)
	if bodySuccess["status"] != "ENROLLMENT_READY" {
		t.Errorf("status = %v, want ENROLLMENT_READY", bodySuccess["status"])
	}
	devID, ok := bodySuccess["device_id"].(string)
	if !ok || devID == "" {
		t.Errorf("device_id = %v, want non-empty string", bodySuccess["device_id"])
	}
	approvedETag := rrSuccess.Header().Get("ETag")
	if approvedETag == "" || approvedETag == preExpiryETag {
		t.Errorf("approved ETag must be non-empty and differ from pre-approval ETag: %s", approvedETag)
	}

	// 5. Idempotent REPLAY => identical 200 OK, same device ID, same ETag, no duplicate audit event
	rrReplay := doAuth(t, tc.handler, "POST", "/v1/admin/pre-onboarding-requests/por-app-1/approve", approveBody, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokAdmin,
		"If-Match":        preExpiryETag,
		"Idempotency-Key": "idem-key-approve-success",
	})
	if rrReplay.Code != http.StatusOK {
		t.Fatalf("replay status = %d, want 200, body: %s", rrReplay.Code, rrReplay.Body.String())
	}
	bodyReplay := jsonBody(t, rrReplay)
	if bodyReplay["device_id"] != devID {
		t.Errorf("replay device_id = %v, want %s", bodyReplay["device_id"], devID)
	}
	if rrReplay.Header().Get("ETag") != approvedETag {
		t.Errorf("replay ETag = %s, want %s", rrReplay.Header().Get("ETag"), approvedETag)
	}
	if tc.recorder.CountByType(preonboardingapp.AuditEventApproved) != 1 {
		t.Errorf("audit events after replay = %d, want 1", tc.recorder.CountByType(preonboardingapp.AuditEventApproved))
	}

	// 6. Replay after partner becomes ineligible STILL succeeds (does not re-evaluate eligibility)
	tc.partnerElig.SetPartnerIneligible("P1", true)
	rrReplayInelig := doAuth(t, tc.handler, "POST", "/v1/admin/pre-onboarding-requests/por-app-1/approve", approveBody, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokAdmin,
		"If-Match":        preExpiryETag,
		"Idempotency-Key": "idem-key-approve-success",
	})
	if rrReplayInelig.Code != http.StatusOK {
		t.Fatalf("replay after ineligibility status = %d, want 200, body: %s", rrReplayInelig.Code, rrReplayInelig.Body.String())
	}

	// 7. Replay after admin loses partner authority MUST fail closed
	tc.partnerAuth.RevokePartnerAuthority(admin, "P1")
	rrReplayNoAuth := doAuth(t, tc.handler, "POST", "/v1/admin/pre-onboarding-requests/por-app-1/approve", approveBody, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokAdmin,
		"If-Match":        preExpiryETag,
		"Idempotency-Key": "idem-key-approve-success",
	})
	if rrReplayNoAuth.Code != http.StatusForbidden {
		t.Fatalf("replay without partner authority status = %d, want 403, body: %s", rrReplayNoAuth.Code, rrReplayNoAuth.Body.String())
	}
	assertProblem(t, rrReplayNoAuth, http.StatusForbidden, "PARTNER_NOT_AUTHORIZED")
}

// 6. Admin Reject Scenarios (POST /v1/admin/pre-onboarding-requests/{id}/reject)
func TestHTTP_AdminReject_Scenarios(t *testing.T) {
	now := time.Now()
	tc := newPreOnboardingTestContext(t, now)
	admin := preonboardingapp.AdminPrincipal{Issuer: "test-issuer", Subject: "test-subject-admin"}
	tc.partnerAuth.GrantPartnerAuthority(admin, "P1")

	// Set partner P1 as INELIGIBLE to prove rejection does not require partner eligibility
	tc.partnerElig.SetPartnerIneligible("P1", true)

	req, _ := domain.NewRequest("por-rej-1", "P1", domain.ClaimedDevice{Hostname: "h1"}, domain.Agent{}, now, now.Add(10*time.Minute))
	tc.store.SeedRequest(req)
	etag := domain.ComputeETag(req, now)

	rejectBody := `{"expected_status":"PENDING_APPROVAL","reason":"failed hardware validation"}`

	// 1. Rejection succeeds for ineligible partner
	rr := doAuth(t, tc.handler, "POST", "/v1/admin/pre-onboarding-requests/por-rej-1/reject", rejectBody, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokAdmin,
		"If-Match":        etag,
		"Idempotency-Key": "idem-key-reject-success",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status on reject = %d, want 200, body: %s", rr.Code, rr.Body.String())
	}
	body := jsonBody(t, rr)
	if body["status"] != "REJECTED" {
		t.Errorf("status = %v, want REJECTED", body["status"])
	}
	if body["device_id"] != nil {
		t.Errorf("rejection must never set device_id: %v", body["device_id"])
	}
	if tc.recorder.CountByType(preonboardingapp.AuditEventRejected) != 1 {
		t.Errorf("PREONBOARD_REJECTED audit events = %d, want 1", tc.recorder.CountByType(preonboardingapp.AuditEventRejected))
	}

	// 2. Exact REPLAY of rejection
	rrReplay := doAuth(t, tc.handler, "POST", "/v1/admin/pre-onboarding-requests/por-rej-1/reject", rejectBody, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokAdmin,
		"If-Match":        etag,
		"Idempotency-Key": "idem-key-reject-success",
	})
	if rrReplay.Code != http.StatusOK {
		t.Fatalf("reject replay status = %d, want 200, body: %s", rrReplay.Code, rrReplay.Body.String())
	}
	if tc.recorder.CountByType(preonboardingapp.AuditEventRejected) != 1 {
		t.Errorf("audit events after reject replay = %d, want 1", tc.recorder.CountByType(preonboardingapp.AuditEventRejected))
	}

	// 3. Conflict on different reason => 409 IDEMPOTENCY_CONFLICT
	diffBody := `{"expected_status":"PENDING_APPROVAL","reason":"different reason"}`
	rrConflict := doAuth(t, tc.handler, "POST", "/v1/admin/pre-onboarding-requests/por-rej-1/reject", diffBody, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokAdmin,
		"If-Match":        etag,
		"Idempotency-Key": "idem-key-reject-success",
	})
	if rrConflict.Code != http.StatusConflict {
		t.Fatalf("conflict status = %d, want 409, body: %s", rrConflict.Code, rrConflict.Body.String())
	}
	assertProblem(t, rrConflict, http.StatusConflict, "IDEMPOTENCY_CONFLICT")
}

// 7. If-Match & Expiry Precedence Ordering (M55-SOL-006)
func TestHTTP_AdminApprove_ExpiryPrecedence(t *testing.T) {
	now := time.Now()
	tc := newPreOnboardingTestContext(t, now)
	admin := preonboardingapp.AdminPrincipal{Issuer: "test-issuer", Subject: "test-subject-admin"}
	tc.partnerAuth.GrantPartnerAuthority(admin, "P1")

	req, _ := domain.NewRequest("por-exp-order", "P1", domain.ClaimedDevice{Hostname: "h1"}, domain.Agent{}, now, now.Add(10*time.Minute))
	tc.store.SeedRequest(req)
	preExpiryETag := domain.ComputeETag(req, now)

	// Advance clock past expiration
	tc.clock.Advance(15 * time.Minute)

	approveBody := `{"expected_status":"PENDING_APPROVAL","reason":"approved"}`

	// 1. Caller presents pre-expiry ETag after expiry => 412 PRECONDITION_FAILED
	rrPreExp := doAuth(t, tc.handler, "POST", "/v1/admin/pre-onboarding-requests/por-exp-order/approve", approveBody, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokAdmin,
		"If-Match":        preExpiryETag,
		"Idempotency-Key": "idem-key-pre-exp-order",
	})
	if rrPreExp.Code != http.StatusPreconditionFailed {
		t.Fatalf("pre-expiry If-Match after expiry status = %d, want 412, body: %s", rrPreExp.Code, rrPreExp.Body.String())
	}
	assertProblem(t, rrPreExp, http.StatusPreconditionFailed, "PRECONDITION_FAILED")

	// 2. Caller gets current expired ETag and attempts approve => 409 STATE_CONFLICT
	reqStored, _ := tc.store.GetRequest("por-exp-order")
	currentExpiredETag := domain.ComputeETag(reqStored, tc.clock.Now())
	rrPostExp := doAuth(t, tc.handler, "POST", "/v1/admin/pre-onboarding-requests/por-exp-order/approve", approveBody, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokAdmin,
		"If-Match":        currentExpiredETag,
		"Idempotency-Key": "idem-key-post-exp-order",
	})
	if rrPostExp.Code != http.StatusConflict {
		t.Fatalf("current expired ETag on approve status = %d, want 409 STATE_CONFLICT, body: %s", rrPostExp.Code, rrPostExp.Body.String())
	}
	assertProblem(t, rrPostExp, http.StatusConflict, "STATE_CONFLICT")
}

// 8. Idempotency Conflict Scenarios
func TestHTTP_AdminApprove_IdempotencyConflict(t *testing.T) {
	now := time.Now()
	tc := newPreOnboardingTestContext(t, now)
	admin := preonboardingapp.AdminPrincipal{Issuer: "test-issuer", Subject: "test-subject-admin"}
	tc.partnerAuth.GrantPartnerAuthority(admin, "P1")

	req, _ := domain.NewRequest("por-app-conf", "P1", domain.ClaimedDevice{Hostname: "h1"}, domain.Agent{}, now, now.Add(time.Hour))
	tc.store.SeedRequest(req)
	etag := domain.ComputeETag(req, now)

	body1 := `{"expected_status":"PENDING_APPROVAL","reason":"reason 1"}`
	body2 := `{"expected_status":"PENDING_APPROVAL","reason":"different reason 2"}`

	// First execution succeeds
	rr1 := doAuth(t, tc.handler, "POST", "/v1/admin/pre-onboarding-requests/por-app-conf/approve", body1, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokAdmin,
		"If-Match":        etag,
		"Idempotency-Key": "idem-key-approve-conflict",
	})
	if rr1.Code != http.StatusOK {
		t.Fatalf("first approve status = %d, want 200, body: %s", rr1.Code, rr1.Body.String())
	}

	// Same key with different body => 409 IDEMPOTENCY_CONFLICT
	rr2 := doAuth(t, tc.handler, "POST", "/v1/admin/pre-onboarding-requests/por-app-conf/approve", body2, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokAdmin,
		"If-Match":        etag,
		"Idempotency-Key": "idem-key-approve-conflict",
	})
	if rr2.Code != http.StatusConflict {
		t.Fatalf("conflict status = %d, want 409, body: %s", rr2.Code, rr2.Body.String())
	}
	assertProblem(t, rr2, http.StatusConflict, "IDEMPOTENCY_CONFLICT")
}

// 9. Existing Device ID Preservation on Approval and Rejection (M55-SOL-008 & M55-SOL-009)
func TestHTTP_PreservesExistingDeviceID(t *testing.T) {
	now := time.Now()
	tc := newPreOnboardingTestContext(t, now)
	admin := preonboardingapp.AdminPrincipal{Issuer: "test-issuer", Subject: "test-subject-admin"}
	tc.partnerAuth.GrantPartnerAuthority(admin, "P1")

	// 1. Approval preserves existing device_id
	existingDev := "dev-pre-allocated-id"
	reqApp, _ := domain.RestoreRequest("por-pres-app", "P1", domain.ClaimedDevice{Hostname: "h1"}, domain.Agent{}, domain.StatePendingApproval, &existingDev, now, now.Add(time.Hour), 1)
	tc.store.SeedRequest(reqApp)
	etagApp := domain.ComputeETag(reqApp, now)

	approveBody := `{"expected_status":"PENDING_APPROVAL","reason":"approved"}`
	rrApp := doAuth(t, tc.handler, "POST", "/v1/admin/pre-onboarding-requests/por-pres-app/approve", approveBody, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokAdmin,
		"If-Match":        etagApp,
		"Idempotency-Key": "idem-key-preserve-dev-app",
	})
	if rrApp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rrApp.Code, rrApp.Body.String())
	}
	bodyApp := jsonBody(t, rrApp)
	if bodyApp["device_id"] != existingDev {
		t.Errorf("device_id = %v, want preserved %s", bodyApp["device_id"], existingDev)
	}

	// 2. Rejection preserves existing device_id on NEW and REPLAY
	reqRej, _ := domain.RestoreRequest("por-pres-rej", "P1", domain.ClaimedDevice{Hostname: "h2"}, domain.Agent{}, domain.StatePendingApproval, &existingDev, now, now.Add(time.Hour), 1)
	tc.store.SeedRequest(reqRej)
	etagRej := domain.ComputeETag(reqRej, now)

	rejectBody := `{"expected_status":"PENDING_APPROVAL","reason":"rejected"}`
	rrRej := doAuth(t, tc.handler, "POST", "/v1/admin/pre-onboarding-requests/por-pres-rej/reject", rejectBody, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokAdmin,
		"If-Match":        etagRej,
		"Idempotency-Key": "idem-key-preserve-dev-rej",
	})
	if rrRej.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rrRej.Code, rrRej.Body.String())
	}
	bodyRej := jsonBody(t, rrRej)
	if bodyRej["device_id"] != existingDev {
		t.Errorf("NEW reject device_id = %v, want preserved %s", bodyRej["device_id"], existingDev)
	}

	// Replay rejection preserves existing device_id
	rrRejReplay := doAuth(t, tc.handler, "POST", "/v1/admin/pre-onboarding-requests/por-pres-rej/reject", rejectBody, map[string]string{
		"Content-Type":    "application/json",
		"Authorization":   "Bearer " + tokAdmin,
		"If-Match":        etagRej,
		"Idempotency-Key": "idem-key-preserve-dev-rej",
	})
	if rrRejReplay.Code != http.StatusOK {
		t.Fatalf("replay reject status = %d, want 200, body: %s", rrRejReplay.Code, rrRejReplay.Body.String())
	}
	bodyRejReplay := jsonBody(t, rrRejReplay)
	if bodyRejReplay["device_id"] != existingDev {
		t.Errorf("REPLAY reject device_id = %v, want preserved %s", bodyRejReplay["device_id"], existingDev)
	}
}

// 10. Startup Integrity on Server Construction (M55-SOL-002 & M55-SOL-010)
func TestHTTP_StartupIntegrity_MandatoryPreOnboardingService(t *testing.T) {
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	partnerSvc := partnerauth.NewUnavailableService()
	ownershipSvc := resourceownership.NewUnavailableService(partnerSvc)

	t.Run("omitted WithPreOnboardingService fails construction", func(t *testing.T) {
		if _, err := httpapi.NewServer(cfg,
			httpapi.WithAuthnRegistry(testAuthnRegistry()),
			httpapi.WithDeviceMTLSSource(testDeviceSource()),
			httpapi.WithAuthzRegistry(testAuthzRegistry()),
			httpapi.WithPartnerAuthService(partnerSvc),
			httpapi.WithResourceOwnershipService(ownershipSvc),
		); err == nil {
			t.Fatal("NewServer without WithPreOnboardingService must fail")
		}
	})

	t.Run("nil preonboarding service fails construction", func(t *testing.T) {
		if _, err := httpapi.NewServer(cfg,
			httpapi.WithAuthnRegistry(testAuthnRegistry()),
			httpapi.WithDeviceMTLSSource(testDeviceSource()),
			httpapi.WithAuthzRegistry(testAuthzRegistry()),
			httpapi.WithPartnerAuthService(partnerSvc),
			httpapi.WithResourceOwnershipService(ownershipSvc),
			httpapi.WithPreOnboardingService(nil),
		); err == nil {
			t.Fatal("NewServer with nil preonboarding service must fail")
		}
	})

	t.Run("zero-value &preonboardingapp.Service{} fails construction", func(t *testing.T) {
		if _, err := httpapi.NewServer(cfg,
			httpapi.WithAuthnRegistry(testAuthnRegistry()),
			httpapi.WithDeviceMTLSSource(testDeviceSource()),
			httpapi.WithAuthzRegistry(testAuthzRegistry()),
			httpapi.WithPartnerAuthService(partnerSvc),
			httpapi.WithResourceOwnershipService(ownershipSvc),
			httpapi.WithPreOnboardingService(&preonboardingapp.Service{}),
		); err == nil {
			t.Fatal("NewServer with zero-value &preonboardingapp.Service{} must fail")
		}
	})

	t.Run("explicit unavailable service is valid startup composition and fails closed at request time", func(t *testing.T) {
		srv, err := httpapi.NewServer(cfg,
			httpapi.WithAuthnRegistry(matrixRegistry(t)),
			httpapi.WithDeviceMTLSSource(matrixDeviceSource()),
			httpapi.WithAuthzRegistry(testAuthzRegistry()),
			httpapi.WithPartnerAuthService(partnerSvc),
			httpapi.WithResourceOwnershipService(ownershipSvc),
			httpapi.WithPreOnboardingService(preonboardingapp.NewUnavailableService()),
		)
		if err != nil {
			t.Fatalf("NewServer with explicit unavailable service must succeed: %v", err)
		}
		p := &probeSSI{calls: map[string]int{}}
		h := srv.Handler(p)

		rr := doAuth(t, h, "GET", "/v1/admin/pre-onboarding-requests", "", map[string]string{
			"Authorization": "Bearer " + tokAdmin,
		})
		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	})

	t.Run("structurally invalid preonboarding service fails NewServer construction", func(t *testing.T) {
		invalidSvc := &preonboardingapp.Service{}
		if _, err := httpapi.NewServer(cfg,
			httpapi.WithAuthnRegistry(testAuthnRegistry()),
			httpapi.WithDeviceMTLSSource(testDeviceSource()),
			httpapi.WithAuthzRegistry(testAuthzRegistry()),
			httpapi.WithPartnerAuthService(partnerSvc),
			httpapi.WithResourceOwnershipService(ownershipSvc),
			httpapi.WithPreOnboardingService(invalidSvc),
		); err == nil {
			t.Fatal("NewServer with structurally invalid preonboarding service must fail")
		}
	})
}
