package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/config"
	enrollmentapp "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/application"
	enrollmentrecovery "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/recovery"
	enrollmentruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
	preonboardingapp "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	preonboardingdomain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	preonboardingruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/replaycapsule"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/resourceownership"
)

type m57HTTPClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (c *m57HTTPClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}
func (c *m57HTTPClock) Set(t time.Time) {
	c.mu.Lock()
	c.now = t
	c.mu.Unlock()
}
func (c *m57HTTPClock) Validate() error { return nil }

type m57HTTPFixedID string

func (g m57HTTPFixedID) NewEnrollmentID(context.Context) (string, error) { return string(g), nil }

type m57HTTPFixedChallenge byte

func (g m57HTTPFixedChallenge) NewChallengeNonce(context.Context) ([]byte, error) {
	return bytes.Repeat([]byte{byte(g)}, 16), nil
}

type m57HTTPFixedToken string

func (g m57HTTPFixedToken) NewEnrollmentAccessToken(context.Context) (string, error) {
	return string(g), nil
}

type m57HTTPHarness struct {
	clock           *m57HTTPClock
	verifier        capability.Verifier
	authority       *preonboardingruntime.MemoryStore
	store           *enrollmentruntime.MemoryStore
	service         *enrollmentapp.Service
	recognizer      *enrollmentrecovery.Recognizer
	handler         http.Handler
	probe           *probeSSI
	requestKey      capability.VerifierKey
	requestID       string
	requestToken    string
	enrollmentToken string
}

func newM57HTTPHarness(t *testing.T) *m57HTTPHarness {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 8, 28, 19, 30, 0, 0, time.UTC)
	clock := &m57HTTPClock{now: now}
	verifier, err := capability.NewHMACVerifier([]byte("m57-http-verifier-key-material"))
	if err != nil {
		t.Fatal(err)
	}
	authority := preonboardingruntime.NewMemoryStore(nil)
	store, err := enrollmentruntime.NewMemoryStore(authority)
	if err != nil {
		t.Fatal(err)
	}

	requestID := "por-http-m57"
	deviceID := "device-http-m57"
	requestToken := "request-access-http-m57-secret"
	enrollmentToken := "enrollment-access-http-m57-secret"
	req, err := preonboardingdomain.RestoreRequest(
		preonboardingdomain.ID(requestID), preonboardingdomain.PartnerID("partner-http-m57"),
		preonboardingdomain.ClaimedDevice{}, preonboardingdomain.Agent{},
		preonboardingdomain.StateEnrollmentReady, &deviceID,
		now.Add(-time.Hour), now.Add(2*time.Hour), 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	authority.SeedRequest(req)
	requestKey, err := verifier.Derive(authpolicy.CredentialKindRequestAccessToken, requestToken)
	if err != nil {
		t.Fatal(err)
	}
	uow, err := authority.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.RequestAccessWriter().CreateRequestAccess(ctx, requestKey, capability.RequestAccessRecord{
		PreOnboardingRequestID: requestID,
		ExpiresAt:              now.Add(30 * time.Minute),
		State:                  capability.StateActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := uow.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	requirements := enrollmentapp.EvidenceRequirements{
		TPMEvidenceProtocolVersions: []string{"test-v1"},
		MinimumAssurance:            "A1",
		AllowedKeyProfiles:          []string{"test-profile"},
	}
	if err := store.SetInitialPolicy("partner-http-m57", deviceID, "PARTNER_AUTH", true, requirements); err != nil {
		t.Fatal(err)
	}
	protector, err := replaycapsule.NewAEADProtector(bytes.Repeat([]byte{0x51}, 32), "m57-http-capsule-key", func() time.Time {
		return clock.Now().Add(time.Hour)
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := enrollmentapp.NewService(enrollmentapp.ServiceConfig{
		UOWManager:                    store,
		Clock:                         clock,
		RetentionPolicy:               enrollmentapp.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
		ReplayCapsulePolicy:           enrollmentapp.StaticReplayCapsuleRetentionPolicy{Duration: 45 * time.Minute},
		ChallengeLifetime:             enrollmentapp.StaticChallengeLifetimePolicy{Duration: 20 * time.Minute},
		EnrollmentAccessTokenLifetime: enrollmentapp.StaticEnrollmentAccessTokenLifetimePolicy{Duration: time.Hour},
		Create: &enrollmentapp.CreateDependencies{
			IDGenerator:        m57HTTPFixedID("enr-http-m57"),
			ChallengeGenerator: m57HTTPFixedChallenge(0x5A),
			TokenGenerator:     m57HTTPFixedToken(enrollmentToken),
			Verifier:           verifier,
			Protector:          protector,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	recognizer, err := enrollmentrecovery.NewRecognizer(verifier, store)
	if err != nil {
		t.Fatal(err)
	}

	registry, err := authruntime.NewRegistry(
		capability.NewRequestAccessAuthenticator(verifier, store, clock),
		capability.NewEnrollmentAccessAuthenticator(verifier, store, clock),
		authruntime.BearerTestAuthenticator{KindValue: authpolicy.CredentialKindHumanOIDC, Decide: func(string) authruntime.Decision { return authruntime.DecisionRejected }},
		authruntime.BearerTestAuthenticator{KindValue: authpolicy.CredentialKindAdminOIDC, Decide: func(string) authruntime.Decision { return authruntime.DecisionRejected }},
		authruntime.BearerTestAuthenticator{KindValue: authpolicy.CredentialKindTemporaryPrincipalToken, Decide: func(string) authruntime.Decision { return authruntime.DecisionRejected }},
		authruntime.DeviceTestAuthenticator{Decide: func(d *authruntime.DeviceCredential) authruntime.Decision {
			if d == nil {
				return authruntime.DecisionRejected
			}
			return authruntime.DecisionAuthenticated
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	deviceSource := authruntime.DeviceTestSource{Credential: func(r *http.Request) (*authruntime.DeviceCredential, error) {
		if r.Header.Get("X-M57-Test-Device") != "present" {
			return nil, nil
		}
		return &authruntime.DeviceCredential{}, nil
	}}
	partnerSvc := partnerauth.NewUnavailableService()
	server, err := httpapi.NewServer(
		config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20},
		httpapi.WithAuthnRegistry(registry),
		httpapi.WithDeviceMTLSSource(deviceSource),
		httpapi.WithAuthzRegistry(testAuthzRegistry()),
		httpapi.WithPartnerAuthService(partnerSvc),
		httpapi.WithResourceOwnershipService(resourceownership.NewUnavailableService(partnerSvc)),
		httpapi.WithPreOnboardingService(preonboardingapp.NewUnavailableService()),
		httpapi.WithEnrollmentService(service),
		httpapi.WithEnrollmentRecoveryRecognizer(recognizer),
	)
	if err != nil {
		t.Fatal(err)
	}
	probe := &probeSSI{calls: map[string]int{}}
	return &m57HTTPHarness{
		clock: clock, verifier: verifier, authority: authority, store: store, service: service, recognizer: recognizer,
		handler: server.Handler(probe), probe: probe, requestKey: requestKey, requestID: requestID,
		requestToken: requestToken, enrollmentToken: enrollmentToken,
	}
}

func (h *m57HTTPHarness) post(t *testing.T, body, key string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/enrollments", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", key)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	return rr
}

func decodeEnrollmentCreate(t *testing.T, rr *httptest.ResponseRecorder) openapi.EnrollmentCreateResponse {
	t.Helper()
	var out openapi.EnrollmentCreateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode EnrollmentCreateResponse: %v; body=%s", err, rr.Body.String())
	}
	return out
}

func TestM57HTTPInitialNewThenConsumedRecoveryReturnsExactOriginalResult(t *testing.T) {
	h := newM57HTTPHarness(t)
	body := `{"operation":"INITIAL","certificate_usage":"PARTNER_AUTH"}`
	key := "m57-http-idempotency-0001"

	first := h.post(t, body, key, map[string]string{
		"Authorization":    "Bearer " + h.requestToken,
		"X-Correlation-ID": "m57-http-attempt-1",
	})
	if first.Code != http.StatusCreated {
		t.Fatalf("first status=%d want=201 body=%s", first.Code, first.Body.String())
	}
	firstBody := decodeEnrollmentCreate(t, first)
	if firstBody.EnrollmentAccessToken != h.enrollmentToken || firstBody.EnrollmentId != "enr-http-m57" || firstBody.State != openapi.EnrollmentCreateResponseStateCHALLENGEISSUED {
		t.Fatalf("first response=%#v", firstBody)
	}
	if firstBody.Operation != "INITIAL" || firstBody.DeviceId != "device-http-m57" || firstBody.Challenge.ChallengeVersion != 1 ||
		firstBody.Challenge.PopFormat != openapi.ChallengePopFormatEnrollmentPopJws || firstBody.Challenge.Nonce == "" ||
		!firstBody.Challenge.ExpiresAt.Equal(h.clock.Now().Add(20*time.Minute)) {
		t.Fatalf("first challenge/binding=%#v", firstBody)
	}
	if firstBody.EvidenceRequirements.MinimumAssurance != openapi.A1 || len(firstBody.EvidenceRequirements.TpmEvidenceProtocolVersions) != 1 ||
		firstBody.EvidenceRequirements.TpmEvidenceProtocolVersions[0] != "test-v1" || len(firstBody.EvidenceRequirements.AllowedKeyProfiles) != 1 ||
		firstBody.EvidenceRequirements.AllowedKeyProfiles[0] != "test-profile" {
		t.Fatalf("evidence requirements=%#v", firstBody.EvidenceRequirements)
	}
	if first.Header().Get("Location") != "/v1/enrollments/enr-http-m57" {
		t.Fatalf("Location=%q", first.Header().Get("Location"))
	}
	if first.Header().Get("X-Correlation-ID") != "m57-http-attempt-1" {
		t.Fatalf("first correlation=%q", first.Header().Get("X-Correlation-ID"))
	}
	if h.probe.count("CreateEnrollment") != 0 {
		t.Fatal("M5.7 createEnrollment delegated to legacy probe")
	}
	rec, err := h.authority.LookupRequestAccess(context.Background(), h.requestKey)
	if err != nil || rec.State != capability.StateConsumed {
		t.Fatalf("request access after NEW=%#v err=%v", rec, err)
	}

	second := h.post(t, body, key, map[string]string{
		"Authorization":    "Bearer " + h.requestToken,
		"X-Correlation-ID": "m57-http-attempt-2",
	})
	if second.Code != http.StatusCreated {
		t.Fatalf("replay status=%d want=201 body=%s", second.Code, second.Body.String())
	}
	secondBody := decodeEnrollmentCreate(t, second)
	if secondBody.EnrollmentAccessToken != firstBody.EnrollmentAccessToken || secondBody.EnrollmentId != firstBody.EnrollmentId {
		t.Fatalf("replay changed secret/result first=%#v second=%#v", firstBody, secondBody)
	}
	if second.Header().Get("X-Correlation-ID") != "m57-http-attempt-2" {
		t.Fatalf("replay correlation=%q want current attempt", second.Header().Get("X-Correlation-ID"))
	}
	if h.store.CountEnrollments() != 1 || h.store.CountEnrollmentAccess() != 1 || h.store.CountCreateResults() != 1 || h.store.CountIdemCommitted() != 1 || len(h.store.AuditEvents()) != 1 {
		t.Fatalf("replay mutated state enrollments=%d access=%d results=%d idem=%d audits=%d",
			h.store.CountEnrollments(), h.store.CountEnrollmentAccess(), h.store.CountCreateResults(), h.store.CountIdemCommitted(), len(h.store.AuditEvents()))
	}
}

func TestM57HTTPConsumedTokenDifferentKeyCannotCreateSecondEnrollment(t *testing.T) {
	h := newM57HTTPHarness(t)
	body := `{"operation":"INITIAL","certificate_usage":"PARTNER_AUTH"}`
	first := h.post(t, body, "m57-http-idempotency-0001", map[string]string{"Authorization": "Bearer " + h.requestToken})
	if first.Code != http.StatusCreated {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	second := h.post(t, body, "m57-http-idempotency-0002", map[string]string{"Authorization": "Bearer " + h.requestToken})
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("different-key status=%d want=401 body=%s", second.Code, second.Body.String())
	}
	if second.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("WWW-Authenticate=%q want Bearer", second.Header().Get("WWW-Authenticate"))
	}
	if h.store.CountEnrollments() != 1 || h.store.CountEnrollmentAccess() != 1 || len(h.store.AuditEvents()) != 1 {
		t.Fatalf("different-key retry mutated state enrollments=%d access=%d audits=%d", h.store.CountEnrollments(), h.store.CountEnrollmentAccess(), len(h.store.AuditEvents()))
	}
}

func TestM57HTTPConsumedRequestAccessDoesNotAuthenticateOutsideRecoveryRoute(t *testing.T) {
	h := newM57HTTPHarness(t)
	body := `{"operation":"INITIAL","certificate_usage":"PARTNER_AUTH"}`
	first := h.post(t, body, "m57-http-idempotency-0001", map[string]string{"Authorization": "Bearer " + h.requestToken})
	if first.Code != http.StatusCreated {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/pre-onboarding-requests/"+h.requestID, nil)
	req.Header.Set("Authorization", "Bearer "+h.requestToken)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("consumed token ordinary route status=%d want=401 body=%s", rr.Code, rr.Body.String())
	}
}

func TestM57HTTPActiveRequestAccessCannotSatisfyRenewalDeviceMTLS(t *testing.T) {
	h := newM57HTTPHarness(t)
	rr := h.post(t, `{"operation":"RENEWAL","certificate_usage":"PARTNER_AUTH"}`, "m57-http-idempotency-0001", map[string]string{
		"Authorization": "Bearer " + h.requestToken,
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("renewal with ACTIVE RAST status=%d want=401 body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("renewal DeviceMTLS mismatch unexpectedly challenged Bearer: %q", got)
	}
	if h.store.CountEnrollments() != 0 || len(h.store.AuditEvents()) != 0 || h.probe.count("CreateEnrollment") != 0 {
		t.Fatal("wrong active credential/body pairing reached mutation or legacy handler")
	}
}

func TestM57HTTPDeviceMTLSCannotSatisfyInitialRequestAccess(t *testing.T) {
	h := newM57HTTPHarness(t)
	rr := h.post(t, `{"operation":"INITIAL","certificate_usage":"PARTNER_AUTH"}`, "m57-http-idempotency-0001", map[string]string{
		"X-M57-Test-Device": "present",
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("INITIAL with DeviceMTLS status=%d want=401 body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf("INITIAL wrong pairing challenge=%q want Bearer", got)
	}
	if h.store.CountEnrollments() != 0 || len(h.store.AuditEvents()) != 0 || h.probe.count("CreateEnrollment") != 0 {
		t.Fatal("wrong DeviceMTLS/body pairing reached mutation or legacy handler")
	}
}

func TestM57HTTPConsumedRecoveryCannotSatisfyRenewalDeviceMTLS(t *testing.T) {
	h := newM57HTTPHarness(t)
	initial := `{"operation":"INITIAL","certificate_usage":"PARTNER_AUTH"}`
	key := "m57-http-idempotency-0001"
	if rr := h.post(t, initial, key, map[string]string{"Authorization": "Bearer " + h.requestToken}); rr.Code != http.StatusCreated {
		t.Fatalf("first status=%d body=%s", rr.Code, rr.Body.String())
	}

	renewal := `{"operation":"RENEWAL","certificate_usage":"PARTNER_AUTH"}`
	rr := h.post(t, renewal, key, map[string]string{"Authorization": "Bearer " + h.requestToken})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("renewal with consumed RAST status=%d want=401 body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("renewal DeviceMTLS mismatch unexpectedly challenged Bearer: %q", got)
	}
	if h.store.CountEnrollments() != 1 || len(h.store.AuditEvents()) != 1 {
		t.Fatal("wrong-operation recovery mutated enrollment state")
	}
}

func TestM57HTTPAuthenticatedRenewalAndRekeyAreDeferredFailClosed(t *testing.T) {
	for _, operation := range []string{"RENEWAL", "REKEY"} {
		t.Run(operation, func(t *testing.T) {
			h := newM57HTTPHarness(t)
			body := `{"operation":"` + operation + `","certificate_usage":"PARTNER_AUTH"}`
			rr := h.post(t, body, "m57-http-idempotency-0001", map[string]string{"X-M57-Test-Device": "present"})
			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("status=%d want=503 body=%s", rr.Code, rr.Body.String())
			}
			var p map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
			if p["error_code"] != "DEPENDENCY_UNAVAILABLE" {
				t.Fatalf("error_code=%v want DEPENDENCY_UNAVAILABLE", p["error_code"])
			}
			if h.store.CountEnrollments() != 0 || len(h.store.AuditEvents()) != 0 || h.probe.count("CreateEnrollment") != 0 {
				t.Fatal("deferred operation reached mutation or legacy handler")
			}
		})
	}
}

func TestM57HTTPRecoveryStillWorksAfterOriginalRequestAccessExpiry(t *testing.T) {
	h := newM57HTTPHarness(t)
	body := `{"operation":"INITIAL","certificate_usage":"PARTNER_AUTH"}`
	key := "m57-http-idempotency-0001"
	first := h.post(t, body, key, map[string]string{"Authorization": "Bearer " + h.requestToken})
	if first.Code != http.StatusCreated {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	h.clock.Set(h.clock.Now().Add(40 * time.Minute)) // RAST expired; idem/capsule still valid.
	second := h.post(t, body, key, map[string]string{"Authorization": "Bearer " + h.requestToken})
	if second.Code != http.StatusCreated {
		t.Fatalf("recovery status=%d want=201 body=%s", second.Code, second.Body.String())
	}
	if got := decodeEnrollmentCreate(t, second).EnrollmentAccessToken; got != h.enrollmentToken {
		t.Fatalf("recovered token=%q want exact original", got)
	}
}

func TestM57HTTPExpiredReplayCapsuleMapsPermanent409(t *testing.T) {
	h := newM57HTTPHarness(t)
	body := `{"operation":"INITIAL","certificate_usage":"PARTNER_AUTH"}`
	key := "m57-http-idempotency-0001"
	if rr := h.post(t, body, key, map[string]string{"Authorization": "Bearer " + h.requestToken}); rr.Code != http.StatusCreated {
		t.Fatalf("first status=%d body=%s", rr.Code, rr.Body.String())
	}

	h.clock.Set(h.clock.Now().Add(46 * time.Minute)) // idem valid for 1h; capsule valid for only 45m.
	rr := h.post(t, body, key, map[string]string{"Authorization": "Bearer " + h.requestToken})
	if rr.Code != http.StatusConflict {
		t.Fatalf("expired capsule status=%d want=409 body=%s", rr.Code, rr.Body.String())
	}
	var p map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p["error_code"] != "IDEMPOTENCY_REPLAY_UNAVAILABLE" || p["retryable"] != false {
		t.Fatalf("expired capsule problem=%v", p)
	}
	if h.store.CountEnrollments() != 1 || h.store.CountEnrollmentAccess() != 1 || len(h.store.AuditEvents()) != 1 {
		t.Fatal("expired recovery capsule caused a second mutation")
	}
}

func TestM57HTTPEnrollmentBoundaryMustBeConfiguredAsPair(t *testing.T) {
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	partnerSvc := partnerauth.NewUnavailableService()
	base := []httpapi.Option{
		httpapi.WithAuthnRegistry(testAuthnRegistry()),
		httpapi.WithDeviceMTLSSource(testDeviceSource()),
		httpapi.WithAuthzRegistry(testAuthzRegistry()),
		httpapi.WithPartnerAuthService(partnerSvc),
		httpapi.WithResourceOwnershipService(resourceownership.NewUnavailableService(partnerSvc)),
		httpapi.WithPreOnboardingService(preonboardingapp.NewUnavailableService()),
	}

	t.Run("service without recognizer", func(t *testing.T) {
		opts := append(append([]httpapi.Option(nil), base...), httpapi.WithEnrollmentService(enrollmentapp.NewUnavailableService()))
		if _, err := httpapi.NewServer(cfg, opts...); err == nil {
			t.Fatal("NewServer accepted enrollment service without recovery recognizer")
		}
	})
	t.Run("recognizer without service", func(t *testing.T) {
		opts := append(append([]httpapi.Option(nil), base...), httpapi.WithEnrollmentRecoveryRecognizer(enrollmentrecovery.NewUnavailableRecognizer()))
		if _, err := httpapi.NewServer(cfg, opts...); err == nil {
			t.Fatal("NewServer accepted recovery recognizer without enrollment service")
		}
	})
}

func TestM57HTTPBadBearerDoesNotGainRecoveryAuthority(t *testing.T) {
	h := newM57HTTPHarness(t)
	rr := h.post(t, `{"operation":"INITIAL","certificate_usage":"PARTNER_AUTH"}`, "m57-http-idempotency-0001", map[string]string{
		"Authorization": "Bearer not-the-retained-capability",
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want=401 body=%s", rr.Code, rr.Body.String())
	}
	if h.store.CountEnrollments() != 0 || len(h.store.AuditEvents()) != 0 || h.probe.count("CreateEnrollment") != 0 {
		t.Fatal("unrecognized bearer reached enrollment mutation/recovery")
	}
}

func TestM57HTTPEnrollmentAccessTokenAuthenticatesAfterCommit(t *testing.T) {
	h := newM57HTTPHarness(t)
	if rr := h.post(t, `{"operation":"INITIAL","certificate_usage":"PARTNER_AUTH"}`, "m57-http-idempotency-0001", map[string]string{"Authorization": "Bearer " + h.requestToken}); rr.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	key, err := h.verifier.Derive(authpolicy.CredentialKindEnrollmentAccessToken, h.enrollmentToken)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := h.store.LookupEnrollmentAccess(context.Background(), key)
	if err != nil || rec.EnrollmentID != "enr-http-m57" {
		t.Fatalf("EnrollmentAccess verifier rec=%#v err=%v", rec, err)
	}

	auth := capability.NewEnrollmentAccessAuthenticator(h.verifier, h.store, h.clock)
	result := auth.Authenticate(context.Background(), &authruntime.Credential{BearerToken: h.enrollmentToken})
	if result.Decision != authruntime.DecisionAuthenticated {
		t.Fatalf("EnrollmentAccess authentication decision=%v", result.Decision)
	}
}

func TestM57HTTPUnavailableEnrollmentCompositionFailsClosed(t *testing.T) {
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	partnerSvc := partnerauth.NewUnavailableService()
	srv, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(testAuthnRegistry()),
		httpapi.WithDeviceMTLSSource(testDeviceSource()),
		httpapi.WithAuthzRegistry(testAuthzRegistry()),
		httpapi.WithPartnerAuthService(partnerSvc),
		httpapi.WithResourceOwnershipService(resourceownership.NewUnavailableService(partnerSvc)),
		httpapi.WithPreOnboardingService(preonboardingapp.NewUnavailableService()),
		httpapi.WithEnrollmentService(enrollmentapp.NewUnavailableService()),
		httpapi.WithEnrollmentRecoveryRecognizer(enrollmentrecovery.NewUnavailableRecognizer()),
	)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler(&probeSSI{calls: map[string]int{}})
	rr := doAuth(t, h, http.MethodPost, "/v1/enrollments", validEnrollmentBody, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer " + m3BearerToken(authpolicy.CredentialKindRequestAccessToken),
	})
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want=503 body=%s", rr.Code, rr.Body.String())
	}
}
