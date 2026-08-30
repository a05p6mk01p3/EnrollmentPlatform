package httpapi_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/config"
	domain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/domain/enrollment"
	enrollmentapp "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/application"
	enrollmentrecovery "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/recovery"
	enrollmentruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi"
	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
	preonboardingapp "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	preonboardingdomain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	preonboardingruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/replaycapsule"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/resourceownership"
)

type m58CryptoHelper struct {
	priv               *ecdsa.PrivateKey
	csrDer             []byte
	csrB64             string
	csrSha256Hex       string
	publicKeySha256Hex string
}

func newM58CryptoHelper(t *testing.T) *m58CryptoHelper {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "test-device"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	csrB64 := base64.StdEncoding.EncodeToString(csrDer)
	csrHash := sha256.Sum256(csrDer)
	csrSha256Hex := hex.EncodeToString(csrHash[:])

	spkiDer, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	spkiHash := sha256.Sum256(spkiDer)
	publicKeySha256Hex := hex.EncodeToString(spkiHash[:])

	return &m58CryptoHelper{
		priv:               priv,
		csrDer:             csrDer,
		csrB64:             csrB64,
		csrSha256Hex:       csrSha256Hex,
		publicKeySha256Hex: publicKeySha256Hex,
	}
}

func (h *m58CryptoHelper) buildJWS(t *testing.T, enrollmentID, nonce string, challengeVersion int, headerMutator func(map[string]interface{}), payloadMutator func(map[string]interface{})) string {
	t.Helper()
	header := map[string]interface{}{
		"alg": "ES256",
		"typ": "enrollment-pop+jws",
	}
	if headerMutator != nil {
		headerMutator(header)
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	payload := map[string]interface{}{
		"version":           1,
		"purpose":           "enrollment-pop",
		"enrollment_id":     enrollmentID,
		"challenge_version": challengeVersion,
		"nonce":             nonce,
		"csr_sha256":        h.csrSha256Hex,
		"public_key_sha256": h.publicKeySha256Hex,
	}
	if payloadMutator != nil {
		payloadMutator(payload)
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := []byte(headerB64 + "." + payloadB64)
	digest := sha256.Sum256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, h.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)
	r.FillBytes(rBytes)
	s.FillBytes(sBytes)
	sigBytes := append(rBytes, sBytes...)
	sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)

	return headerB64 + "." + payloadB64 + "." + sigB64
}

type m58SequenceChallenge struct {
	mu  sync.Mutex
	seq byte
}

func (s *m58SequenceChallenge) NewChallengeNonce(context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	return bytes.Repeat([]byte{s.seq}, 16), nil
}

type m58HTTPHarness struct {
	clock           *m57HTTPClock
	verifier        capability.Verifier
	authority       *preonboardingruntime.MemoryStore
	store           *enrollmentruntime.MemoryStore
	service         *enrollmentapp.Service
	handler         http.Handler
	enrollmentID    string
	enrollmentToken string
	activeNonce     string
	helper          *m58CryptoHelper
	corruptRefresh  *atomic.Bool
}

func newM58HTTPHarness(t *testing.T) *m58HTTPHarness {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 8, 29, 13, 0, 0, 0, time.UTC)
	clock := &m57HTTPClock{now: now}
	verifier, err := capability.NewHMACVerifier([]byte("m58-http-verifier-key-material"))
	if err != nil {
		t.Fatal(err)
	}
	authority := preonboardingruntime.NewMemoryStore(nil)
	store, err := enrollmentruntime.NewMemoryStore(authority)
	if err != nil {
		t.Fatal(err)
	}

	requestID := "por-http-m58"
	deviceID := "device-http-m58"
	requestToken := "request-access-http-m58-secret"
	enrollmentToken := "enrollment-access-http-m58-secret"
	enrollmentID := "enr-http-m58"

	req, err := preonboardingdomain.RestoreRequest(
		preonboardingdomain.ID(requestID), preonboardingdomain.PartnerID("partner-http-m58"),
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
		TPMEvidenceProtocolVersions: []string{"1"},
		MinimumAssurance:            "A1",
		AllowedKeyProfiles:          []string{"ECDSA_P256"},
	}
	if err := store.SetInitialPolicy("partner-http-m58", deviceID, "PARTNER_AUTH", true, requirements); err != nil {
		t.Fatal(err)
	}
	protector, err := replaycapsule.NewAEADProtector(bytes.Repeat([]byte{0x88}, 32), "m58-http-capsule-key", func() time.Time {
		return clock.Now().Add(time.Hour)
	})
	if err != nil {
		t.Fatal(err)
	}

	challengeGen := &m58SequenceChallenge{seq: 0x10}
	// Test-only failure seam for corrupted/missing committed refresh replay
	// results: the exported production MemoryStore exposes no destructive
	// mutation for committed results (SOL-M5.8-AUDIT-003), so tests corrupt
	// reads through this decorator instead.
	corruptRefresh := &atomic.Bool{}
	refreshUOWManager := &m58CorruptingUOWManager{inner: store, corruptRefresh: corruptRefresh}
	service, err := enrollmentapp.NewService(enrollmentapp.ServiceConfig{
		UOWManager:                    refreshUOWManager,
		Clock:                         clock,
		RetentionPolicy:               enrollmentapp.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
		ReplayCapsulePolicy:           enrollmentapp.StaticReplayCapsuleRetentionPolicy{Duration: 45 * time.Minute},
		ChallengeLifetime:             enrollmentapp.StaticChallengeLifetimePolicy{Duration: 20 * time.Minute},
		EnrollmentAccessTokenLifetime: enrollmentapp.StaticEnrollmentAccessTokenLifetimePolicy{Duration: time.Hour},
		Create: &enrollmentapp.CreateDependencies{
			IDGenerator:        m57HTTPFixedID(enrollmentID),
			ChallengeGenerator: challengeGen,
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
		authruntime.DeviceTestAuthenticator{Decide: func(d *authruntime.DeviceCredential) authruntime.Decision { return authruntime.DecisionRejected }},
	)
	if err != nil {
		t.Fatal(err)
	}
	partnerSvc := partnerauth.NewUnavailableService()
	server, err := httpapi.NewServer(
		config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20},
		httpapi.WithAuthnRegistry(registry),
		httpapi.WithDeviceMTLSSource(testDeviceSource()),
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

	handler := server.Handler(&probeSSI{calls: map[string]int{}})

	// Create initial enrollment
	createRes, err := service.CreateInitial(ctx, enrollmentapp.CreateInitialCommand{
		PreOnboardingRequestID: requestID,
		CertificateUsage:       "PARTNER_AUTH",
		IdempotencyKey:         "m58-create-key-001",
		CorrelationID:          "m58-corr-create",
	})
	if err != nil {
		t.Fatal(err)
	}

	return &m58HTTPHarness{
		clock:           clock,
		verifier:        verifier,
		authority:       authority,
		store:           store,
		service:         service,
		handler:         handler,
		enrollmentID:    enrollmentID,
		enrollmentToken: enrollmentToken,
		activeNonce:     createRes.Snapshot.Challenge.Nonce,
		helper:          newM58CryptoHelper(t),
		corruptRefresh:  corruptRefresh,
	}
}

func (h *m58HTTPHarness) get(path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	return rr
}

func (h *m58HTTPHarness) put(path string, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	return rr
}

func (h *m58HTTPHarness) post(path string, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	return rr
}

func (h *m58HTTPHarness) validEvidenceBody(t *testing.T) string {
	t.Helper()
	jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)
	return fmt.Sprintf(`{
		"challenge_version": 1,
		"csr_der_base64": %q,
		"pop": {
			"format": "enrollment-pop+jws",
			"jws": %q
		},
		"tpm_evidence": {
			"format": "enrollment-tpm-evidence",
			"version": "1",
			"payload": {"tpm": "test-envelope"}
		},
		"agent_assertions": {
			"tpm_ready": true,
			"provider": "Microsoft Platform Crypto Provider",
			"hardware_backed": true,
			"private_key_exportable": false
		}
	}`, h.helper.csrB64, jws)
}

// m58CorruptingUOWManager is a test-only adapter that decorates the refresh
// replay result reads to simulate a missing committed result. It replaces the
// removed production ClearRefreshResultsForTest API (SOL-M5.8-AUDIT-003).
type m58CorruptingUOWManager struct {
	inner          enrollmentapp.UnitOfWorkManager
	corruptRefresh *atomic.Bool
}

func (m *m58CorruptingUOWManager) Begin(ctx context.Context) (enrollmentapp.UnitOfWork, error) {
	uow, err := m.inner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &m58CorruptingUOW{UnitOfWork: uow, m: m}, nil
}

type m58CorruptingUOW struct {
	enrollmentapp.UnitOfWork
	m *m58CorruptingUOWManager
}

func (u *m58CorruptingUOW) EnrollmentContinuation() enrollmentapp.EnrollmentContinuationRepository {
	return u.UnitOfWork.(enrollmentapp.ContinuationUnitOfWork).EnrollmentContinuation()
}

func (u *m58CorruptingUOW) RefreshResults() enrollmentapp.RefreshResultStore {
	inner := u.UnitOfWork.(enrollmentapp.ContinuationUnitOfWork).RefreshResults()
	return &m58CorruptingRefreshStore{inner: inner, m: u.m}
}

type m58CorruptingRefreshStore struct {
	inner enrollmentapp.RefreshResultStore
	m     *m58CorruptingUOWManager
}

func (s *m58CorruptingRefreshStore) SaveChallengeRefreshResult(ctx context.Context, loc idempotencyruntime.ResultLocator, result enrollmentapp.ChallengeRefreshResult) error {
	return s.inner.SaveChallengeRefreshResult(ctx, loc, result)
}

func (s *m58CorruptingRefreshStore) GetChallengeRefreshResult(ctx context.Context, loc idempotencyruntime.ResultLocator) (enrollmentapp.ChallengeRefreshResult, bool, error) {
	if s.m.corruptRefresh.Load() {
		return enrollmentapp.ChallengeRefreshResult{}, false, nil
	}
	return s.inner.GetChallengeRefreshResult(ctx, loc)
}

// 1. AUTHENTICATION / RESOURCE BINDING TESTS
func TestM58HTTPAuthenticationAndResourceBinding(t *testing.T) {
	h := newM58HTTPHarness(t)

	t.Run("EAT A to A works for GET", func(t *testing.T) {
		rr := h.get("/v1/enrollments/"+h.enrollmentID, map[string]string{
			"Authorization": "Bearer " + h.enrollmentToken,
		})
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d want=200 body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("EAT A to B rejected 401 with WWW-Authenticate Bearer", func(t *testing.T) {
		rr := h.get("/v1/enrollments/enr-other-id", map[string]string{
			"Authorization": "Bearer " + h.enrollmentToken,
		})
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d want=401 body=%s", rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Fatalf("WWW-Authenticate=%q want Bearer", got)
		}
	})

	t.Run("missing EAT rejected 401", func(t *testing.T) {
		rr := h.get("/v1/enrollments/"+h.enrollmentID, nil)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d want=401 body=%s", rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Fatalf("WWW-Authenticate=%q want Bearer", got)
		}
	})

	t.Run("invalid EAT rejected 401", func(t *testing.T) {
		rr := h.get("/v1/enrollments/"+h.enrollmentID, map[string]string{
			"Authorization": "Bearer not-a-valid-eat-token",
		})
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d want=401 body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("expired EAT rejected 401", func(t *testing.T) {
		h.clock.Set(h.clock.Now().Add(2 * time.Hour))
		rr := h.get("/v1/enrollments/"+h.enrollmentID, map[string]string{
			"Authorization": "Bearer " + h.enrollmentToken,
		})
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d want=401 body=%s", rr.Code, rr.Body.String())
		}
	})
}

// 2. GET /v1/enrollments/{id}
func TestM58HTTPGetEnrollment(t *testing.T) {
	h := newM58HTTPHarness(t)

	t.Run("persisted state returned with correlation id", func(t *testing.T) {
		rr := h.get("/v1/enrollments/"+h.enrollmentID, map[string]string{
			"Authorization":    "Bearer " + h.enrollmentToken,
			"X-Correlation-ID": "test-corr-get-001",
		})
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d want=200 body=%s", rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get("X-Correlation-ID"); got != "test-corr-get-001" {
			t.Fatalf("X-Correlation-ID=%q want test-corr-get-001", got)
		}
		var enr openapi.Enrollment
		if err := json.Unmarshal(rr.Body.Bytes(), &enr); err != nil {
			t.Fatal(err)
		}
		if enr.EnrollmentId != openapi.ResourceId(h.enrollmentID) || enr.State != "CHALLENGE_ISSUED" ||
			enr.DeviceId != "device-http-m58" || enr.Operation != "INITIAL" || enr.CertificateUsage != "PARTNER_AUTH" {
			t.Fatalf("unexpected enrollment body: %#v", enr)
		}
		if enr.Challenge == nil || enr.Challenge.ChallengeVersion != 1 || enr.Challenge.Nonce != h.activeNonce {
			t.Fatalf("unexpected challenge in GET: %#v", enr.Challenge)
		}
	})

	t.Run("GET causes no mutation", func(t *testing.T) {
		countBefore := h.store.CountEnrollments()
		auditsBefore := len(h.store.AuditEvents())
		h.get("/v1/enrollments/"+h.enrollmentID, map[string]string{
			"Authorization": "Bearer " + h.enrollmentToken,
		})
		if h.store.CountEnrollments() != countBefore || len(h.store.AuditEvents()) != auditsBefore {
			t.Fatal("GET caused mutation in store")
		}
	})
}

// 3. EVIDENCE SUBMISSION HAPPY PATH & IDEMPOTENCY
func TestM58HTTPEvidenceHappyPathAndIdempotency(t *testing.T) {
	h := newM58HTTPHarness(t)
	body := h.validEvidenceBody(t)

	// Happy path: 202 Accepted
	first := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, map[string]string{
		"Authorization":    "Bearer " + h.enrollmentToken,
		"X-Correlation-ID": "m58-evidence-attempt-1",
	})
	if first.Code != http.StatusAccepted {
		t.Fatalf("first evidence submission status=%d want=202 body=%s", first.Code, first.Body.String())
	}
	if got := first.Header().Get("X-Correlation-ID"); got != "m58-evidence-attempt-1" {
		t.Fatalf("correlation header=%q want m58-evidence-attempt-1", got)
	}
	var res openapi.EvidenceAcceptedResponse
	if err := json.Unmarshal(first.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.EnrollmentId != openapi.ResourceId(h.enrollmentID) || res.State != openapi.EVIDENCERECEIVED ||
		res.StatusUrl != "/v1/enrollments/"+h.enrollmentID || res.RetryAfterSeconds != 2 {
		t.Fatalf("unexpected evidence accepted response: %#v", res)
	}

	// Verify state transitioned to EVIDENCE_RECEIVED in GET
	getResp := h.get("/v1/enrollments/"+h.enrollmentID, map[string]string{
		"Authorization": "Bearer " + h.enrollmentToken,
	})
	if getResp.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", getResp.Code, getResp.Body.String())
	}
	var enr openapi.Enrollment
	if err := json.Unmarshal(getResp.Body.Bytes(), &enr); err != nil {
		t.Fatal(err)
	}
	if enr.State != "EVIDENCE_RECEIVED" {
		t.Fatalf("enrollment state=%q want EVIDENCE_RECEIVED", enr.State)
	}

	// Exact accepted retry -> 202 Accepted
	retry := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, map[string]string{
		"Authorization":    "Bearer " + h.enrollmentToken,
		"X-Correlation-ID": "m58-evidence-attempt-2",
	})
	if retry.Code != http.StatusAccepted {
		t.Fatalf("retry status=%d want=202 body=%s", retry.Code, retry.Body.String())
	}
	if got := retry.Header().Get("X-Correlation-ID"); got != "m58-evidence-attempt-2" {
		t.Fatalf("retry correlation header=%q want m58-evidence-attempt-2", got)
	}

	// Retry after clock advancement past challenge lifetime (20m) but before EAT lifetime (60m) -> still 202 Accepted (not 410)
	h.clock.Set(h.clock.Now().Add(30 * time.Minute))
	postExpiryRetry := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, map[string]string{
		"Authorization": "Bearer " + h.enrollmentToken,
	})
	if postExpiryRetry.Code != http.StatusAccepted {
		t.Fatalf("post-expiry retry status=%d want=202 body=%s", postExpiryRetry.Code, postExpiryRetry.Body.String())
	}

	// Conflicting second submission with different CSR -> 409 STATE_CONFLICT
	ev2 := newM58CryptoHelper(t)
	jws2 := ev2.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)
	conflictingBody := fmt.Sprintf(`{
		"challenge_version": 1,
		"csr_der_base64": %q,
		"pop": {"format": "enrollment-pop+jws", "jws": %q},
		"tpm_evidence": {"format": "enrollment-tpm-evidence", "version": "1", "payload": {"tpm": "diff"}}
	}`, ev2.csrB64, jws2)
	conflictResp := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", conflictingBody, map[string]string{
		"Authorization": "Bearer " + h.enrollmentToken,
	})
	if conflictResp.Code != http.StatusConflict {
		t.Fatalf("conflicting submission status=%d want=409 body=%s", conflictResp.Code, conflictResp.Body.String())
	}
	var prob map[string]interface{}
	if err := json.Unmarshal(conflictResp.Body.Bytes(), &prob); err != nil {
		t.Fatal(err)
	}
	if prob["error_code"] != "STATE_CONFLICT" {
		t.Fatalf("error_code=%v want STATE_CONFLICT", prob["error_code"])
	}
}

// 4. CSR VALIDATION ADVERSARIAL TESTS (422 EVIDENCE_INVALID)
func TestM58HTTPCSRValidationAdversarial(t *testing.T) {
	h := newM58HTTPHarness(t)
	jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)

	testCases := []struct {
		name      string
		csrB64    string
		wantCode  int
		wantError string
	}{
		{
			name:      "invalid base64",
			csrB64:    "@@@not-base64@@@",
			wantCode:  http.StatusBadRequest,
			wantError: "INVALID_REQUEST",
		},
		{
			name:      "malformed DER",
			csrB64:    base64.StdEncoding.EncodeToString([]byte("invalid DER content")),
			wantCode:  http.StatusUnprocessableEntity,
			wantError: "EVIDENCE_INVALID",
		},
		{
			name: "disallowed RSA key",
			csrB64: func() string {
				rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
				der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
					Subject: pkix.Name{CommonName: "rsa-device"}, SignatureAlgorithm: x509.SHA256WithRSA,
				}, rsaKey)
				return base64.StdEncoding.EncodeToString(der)
			}(),
			wantCode:  http.StatusUnprocessableEntity,
			wantError: "EVIDENCE_INVALID",
		},
		{
			name: "disallowed curve P-384",
			csrB64: func() string {
				p384Key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
					Subject: pkix.Name{CommonName: "p384-device"}, SignatureAlgorithm: x509.ECDSAWithSHA384,
				}, p384Key)
				return base64.StdEncoding.EncodeToString(der)
			}(),
			wantCode:  http.StatusUnprocessableEntity,
			wantError: "EVIDENCE_INVALID",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{
				"challenge_version": 1,
				"csr_der_base64": %q,
				"pop": {"format": "enrollment-pop+jws", "jws": %q},
				"tpm_evidence": {"format": "enrollment-tpm-evidence", "version": "1", "payload": {}}
			}`, tc.csrB64, jws)
			rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, map[string]string{
				"Authorization": "Bearer " + h.enrollmentToken,
			})
			if rr.Code != tc.wantCode {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, tc.wantCode, rr.Body.String())
			}
			var p map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
			if p["error_code"] != tc.wantError {
				t.Fatalf("error_code=%v want=%s", p["error_code"], tc.wantError)
			}
		})
	}
}

// 5. JWS / PoP VALIDATION ADVERSARIAL TESTS (422 EVIDENCE_INVALID)
func TestM58HTTPJWSValidationAdversarial(t *testing.T) {
	h := newM58HTTPHarness(t)

	testCases := []struct {
		name      string
		jws       string
		wantCode  int
		wantError string
	}{
		{
			name:      "malformed compact serialization",
			jws:       "bad.jws",
			wantCode:  http.StatusBadRequest,
			wantError: "INVALID_REQUEST",
		},
		{
			name: "malformed header JSON",
			jws: func() string {
				hdrB64 := base64.RawURLEncoding.EncodeToString([]byte("not-valid-json"))
				plB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"version":1}`))
				sigB64 := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64))
				return hdrB64 + "." + plB64 + "." + sigB64
			}(),
			wantCode:  http.StatusUnprocessableEntity,
			wantError: "EVIDENCE_INVALID",
		},
		{
			name: "alg=none",
			jws: h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, func(hdr map[string]interface{}) {
				hdr["alg"] = "none"
			}, nil),
			wantCode:  http.StatusUnprocessableEntity,
			wantError: "EVIDENCE_INVALID",
		},
		{
			name: "non-ES256 alg RS256",
			jws: h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, func(hdr map[string]interface{}) {
				hdr["alg"] = "RS256"
			}, nil),
			wantCode:  http.StatusUnprocessableEntity,
			wantError: "EVIDENCE_INVALID",
		},
		{
			name: "wrong typ JWT",
			jws: h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, func(hdr map[string]interface{}) {
				hdr["typ"] = "JWT"
			}, nil),
			wantCode:  http.StatusUnprocessableEntity,
			wantError: "EVIDENCE_INVALID",
		},
		{
			name: "forbidden jwk header",
			jws: h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, func(hdr map[string]interface{}) {
				hdr["jwk"] = map[string]string{"kty": "EC"}
			}, nil),
			wantCode:  http.StatusUnprocessableEntity,
			wantError: "EVIDENCE_INVALID",
		},
		{
			name: "forbidden jku header",
			jws: h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, func(hdr map[string]interface{}) {
				hdr["jku"] = "https://attacker.example/jwks.json"
			}, nil),
			wantCode:  http.StatusUnprocessableEntity,
			wantError: "EVIDENCE_INVALID",
		},
		{
			name: "forbidden x5u header",
			jws: h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, func(hdr map[string]interface{}) {
				hdr["x5u"] = "https://attacker.example/cert.pem"
			}, nil),
			wantCode:  http.StatusUnprocessableEntity,
			wantError: "EVIDENCE_INVALID",
		},
		{
			name: "wrong nonce in payload",
			jws: h.helper.buildJWS(t, h.enrollmentID, "wrong-nonce", 1, nil, func(payload map[string]interface{}) {
				payload["nonce"] = "wrong-nonce"
			}),
			wantCode:  http.StatusUnprocessableEntity,
			wantError: "EVIDENCE_INVALID",
		},
		{
			name: "wrong challenge_version in payload",
			jws: h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, func(payload map[string]interface{}) {
				payload["challenge_version"] = 2
			}),
			wantCode:  http.StatusUnprocessableEntity,
			wantError: "EVIDENCE_INVALID",
		},
		{
			name: "wrong enrollment_id in payload",
			jws: h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, func(payload map[string]interface{}) {
				payload["enrollment_id"] = "enr-other"
			}),
			wantCode:  http.StatusUnprocessableEntity,
			wantError: "EVIDENCE_INVALID",
		},
		{
			name: "wrong CSR hash in payload",
			jws: h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, func(payload map[string]interface{}) {
				payload["csr_sha256"] = strings.Repeat("0", 64)
			}),
			wantCode:  http.StatusUnprocessableEntity,
			wantError: "EVIDENCE_INVALID",
		},
		{
			name: "wrong SPKI hash in payload",
			jws: h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, func(payload map[string]interface{}) {
				payload["public_key_sha256"] = strings.Repeat("0", 64)
			}),
			wantCode:  http.StatusUnprocessableEntity,
			wantError: "EVIDENCE_INVALID",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{
				"challenge_version": 1,
				"csr_der_base64": %q,
				"pop": {"format": "enrollment-pop+jws", "jws": %q},
				"tpm_evidence": {"format": "enrollment-tpm-evidence", "version": "1", "payload": {}}
			}`, h.helper.csrB64, tc.jws)
			rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, map[string]string{
				"Authorization": "Bearer " + h.enrollmentToken,
			})
			if rr.Code != tc.wantCode {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, tc.wantCode, rr.Body.String())
			}
			var p map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
			if p["error_code"] != tc.wantError {
				t.Fatalf("error_code=%v want=%s", p["error_code"], tc.wantError)
			}
		})
	}
}

// 6. CHALLENGE REFRESH TESTS
func TestM58HTTPChallengeRefresh(t *testing.T) {
	h := newM58HTTPHarness(t)
	body := `{"expected_challenge_version": 1}`
	key := "refresh-key-0001"

	// Valid refresh N -> N+1
	first := h.post("/v1/enrollments/"+h.enrollmentID+"/challenge:refresh", body, map[string]string{
		"Authorization":    "Bearer " + h.enrollmentToken,
		"Idempotency-Key":  key,
		"X-Correlation-ID": "m58-refresh-attempt-1",
	})
	if first.Code != http.StatusOK {
		t.Fatalf("refresh status=%d want=200 body=%s", first.Code, first.Body.String())
	}
	var resp openapi.ChallengeRefreshResponse
	if err := json.Unmarshal(first.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.EnrollmentId != openapi.ResourceId(h.enrollmentID) || resp.State != "CHALLENGE_ISSUED" ||
		resp.Challenge.ChallengeVersion != 2 || resp.Challenge.Nonce == h.activeNonce {
		t.Fatalf("unexpected refresh response: %#v", resp)
	}

	// Idempotent replay: same key + same body -> exact replay
	replay := h.post("/v1/enrollments/"+h.enrollmentID+"/challenge:refresh", body, map[string]string{
		"Authorization":    "Bearer " + h.enrollmentToken,
		"Idempotency-Key":  key,
		"X-Correlation-ID": "m58-refresh-attempt-2",
	})
	if replay.Code != http.StatusOK {
		t.Fatalf("refresh replay status=%d want=200 body=%s", replay.Code, replay.Body.String())
	}
	var replayResp openapi.ChallengeRefreshResponse
	if err := json.Unmarshal(replay.Body.Bytes(), &replayResp); err != nil {
		t.Fatal(err)
	}
	if replayResp.Challenge.Nonce != resp.Challenge.Nonce || replayResp.Challenge.ChallengeVersion != resp.Challenge.ChallengeVersion {
		t.Fatalf("replay changed challenge first=%#v replay=%#v", resp, replayResp)
	}

	// Changed request with same key -> 409 IDEMPOTENCY_CONFLICT
	changedBody := `{"expected_challenge_version": 2}`
	conflict := h.post("/v1/enrollments/"+h.enrollmentID+"/challenge:refresh", changedBody, map[string]string{
		"Authorization":   "Bearer " + h.enrollmentToken,
		"Idempotency-Key": key,
	})
	if conflict.Code != http.StatusConflict {
		t.Fatalf("idempotency conflict status=%d want=409 body=%s", conflict.Code, conflict.Body.String())
	}
	var p map[string]interface{}
	if err := json.Unmarshal(conflict.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p["error_code"] != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("error_code=%v want IDEMPOTENCY_CONFLICT", p["error_code"])
	}

	// Stale expected version with new key -> 409 STATE_CONFLICT
	stale := h.post("/v1/enrollments/"+h.enrollmentID+"/challenge:refresh", `{"expected_challenge_version": 1}`, map[string]string{
		"Authorization":   "Bearer " + h.enrollmentToken,
		"Idempotency-Key": "refresh-key-0002",
	})
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale refresh status=%d want=409 body=%s", stale.Code, stale.Body.String())
	}
	var p2 map[string]interface{}
	if err := json.Unmarshal(stale.Body.Bytes(), &p2); err != nil {
		t.Fatal(err)
	}
	if p2["error_code"] != "STATE_CONFLICT" {
		t.Fatalf("error_code=%v want STATE_CONFLICT", p2["error_code"])
	}

	// Old challenge cannot be used for evidence submission
	oldEvidence := h.validEvidenceBody(t)
	oldSub := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", oldEvidence, map[string]string{
		"Authorization": "Bearer " + h.enrollmentToken,
	})
	if oldSub.Code != http.StatusConflict {
		t.Fatalf("old evidence submission status=%d want=409 body=%s", oldSub.Code, oldSub.Body.String())
	}
}

// 7. CRITICAL CONCURRENCY: EVIDENCE VS REFRESH RACE
func TestM58HTTPEvidenceVsRefreshRace(t *testing.T) {
	h := newM58HTTPHarness(t)
	evidenceBody := h.validEvidenceBody(t)
	refreshBody := `{"expected_challenge_version": 1}`

	var wg sync.WaitGroup
	wg.Add(2)

	var evidenceCode, refreshCode int
	var evidenceRespBody, refreshRespBody string

	go func() {
		defer wg.Done()
		rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", evidenceBody, map[string]string{
			"Authorization": "Bearer " + h.enrollmentToken,
		})
		evidenceCode = rr.Code
		evidenceRespBody = rr.Body.String()
	}()

	go func() {
		defer wg.Done()
		rr := h.post("/v1/enrollments/"+h.enrollmentID+"/challenge:refresh", refreshBody, map[string]string{
			"Authorization":   "Bearer " + h.enrollmentToken,
			"Idempotency-Key": "race-refresh-0001",
		})
		refreshCode = rr.Code
		refreshRespBody = rr.Body.String()
	}()

	wg.Wait()

	// Exactly one succeeds: (202, 409) or (409, 200)
	t.Logf("Race result: evidenceCode=%d, refreshCode=%d", evidenceCode, refreshCode)
	if evidenceCode == http.StatusAccepted {
		if refreshCode != http.StatusConflict {
			t.Fatalf("evidence won, but refresh got %d want 409; body=%s", refreshCode, refreshRespBody)
		}
	} else if refreshCode == http.StatusOK {
		if evidenceCode != http.StatusConflict {
			t.Fatalf("refresh won, but evidence got %d want 409; body=%s", evidenceCode, evidenceRespBody)
		}
	} else {
		t.Fatalf("neither won or unexpected codes: evidence=%d (%s) refresh=%d (%s)", evidenceCode, evidenceRespBody, refreshCode, refreshRespBody)
	}

	// Verify authoritative final state
	getResp := h.get("/v1/enrollments/"+h.enrollmentID, map[string]string{
		"Authorization": "Bearer " + h.enrollmentToken,
	})
	if getResp.Code != http.StatusOK {
		t.Fatalf("GET status=%d", getResp.Code)
	}
	var enr openapi.Enrollment
	if err := json.Unmarshal(getResp.Body.Bytes(), &enr); err != nil {
		t.Fatal(err)
	}
	if evidenceCode == http.StatusAccepted {
		if enr.State != "EVIDENCE_RECEIVED" {
			t.Fatalf("final state=%s want EVIDENCE_RECEIVED", enr.State)
		}
	} else {
		if enr.State != "CHALLENGE_ISSUED" || enr.Challenge == nil || enr.Challenge.ChallengeVersion != 2 {
			t.Fatalf("final state=%s challenge=%#v want CHALLENGE_ISSUED version 2", enr.State, enr.Challenge)
		}
	}
}

// 8. MILESTONE BOUNDARY VERIFICATION
func TestM58HTTPMilestoneBoundaryStopsAtEvidenceReceived(t *testing.T) {
	h := newM58HTTPHarness(t)
	body := h.validEvidenceBody(t)

	rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, map[string]string{
		"Authorization": "Bearer " + h.enrollmentToken,
	})
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status=%d want=202 body=%s", rr.Code, rr.Body.String())
	}

	// Verify stored enrollment stops at EVIDENCE_RECEIVED
	rec, ok := h.store.GetEnrollment(h.enrollmentID)
	if !ok {
		t.Fatal("enrollment not found in store")
	}
	if rec.Aggregate.State() != domain.StateEvidenceReceived {
		t.Fatalf("store aggregate state=%s want EVIDENCE_RECEIVED", rec.Aggregate.State())
	}
	// Confirm no AUTHORIZED or CA_REQUESTED transition occurred
	if rec.Aggregate.State() == domain.StateAuthorized || rec.Aggregate.State() == domain.StateCARequested {
		t.Fatalf("illegal milestone progression: state is %s", rec.Aggregate.State())
	}
}

// 9. ROLLBACK AND FAILURE INJECTION
func TestM58HTTPRollbackAndFailureInjection(t *testing.T) {
	h := newM58HTTPHarness(t)
	auditsBefore := len(h.store.AuditEvents())

	// Submission with invalid evidence payload
	badBody := `{"challenge_version": 1, "csr_der_base64": "malformed"}`
	rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", badBody, map[string]string{
		"Authorization": "Bearer " + h.enrollmentToken,
	})
	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unexpected code=%d", rr.Code)
	}

	// Verify no partial state change or audit events
	rec, ok := h.store.GetEnrollment(h.enrollmentID)
	if !ok || rec.Aggregate.State() != domain.StateChallengeIssued || rec.AcceptedEvidence != nil {
		t.Fatalf("state mutated after failure: %#v", rec)
	}
	if len(h.store.AuditEvents()) != auditsBefore {
		t.Fatalf("audit events emitted on failed submission: %d != %d", len(h.store.AuditEvents()), auditsBefore)
	}
}

// 10. SOL-M5.8-POST-002: CSR SIGNATURE ALGORITHM DECOUPLED FROM PUBLIC KEY PROFILE
func TestM58HTTPCSRSignatureAlgorithmDecoupled(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, sigAlg := range []x509.SignatureAlgorithm{x509.ECDSAWithSHA384, x509.ECDSAWithSHA512} {
		t.Run(sigAlg.String(), func(t *testing.T) {
			h := newM58HTTPHarness(t)
			csrDer, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
				Subject:            pkix.Name{CommonName: "http-sigalg-device"},
				SignatureAlgorithm: sigAlg,
			}, priv)
			if err != nil {
				t.Fatal(err)
			}
			csrB64 := base64.StdEncoding.EncodeToString(csrDer)
			csrHash := sha256.Sum256(csrDer)
			csrSha256Hex := hex.EncodeToString(csrHash[:])

			spkiDer, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			spkiHash := sha256.Sum256(spkiDer)
			publicKeySha256Hex := hex.EncodeToString(spkiHash[:])

			// Build valid JWS
			headerJSON, _ := json.Marshal(map[string]interface{}{"alg": "ES256", "typ": "enrollment-pop+jws"})
			headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
			payloadJSON, _ := json.Marshal(map[string]interface{}{
				"version":           1,
				"purpose":           "enrollment-pop",
				"enrollment_id":     h.enrollmentID,
				"challenge_version": 1,
				"nonce":             h.activeNonce,
				"csr_sha256":        csrSha256Hex,
				"public_key_sha256": publicKeySha256Hex,
			})
			payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
			digest := sha256.Sum256([]byte(headerB64 + "." + payloadB64))
			r, sVal, err := ecdsa.Sign(rand.Reader, priv, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			rB := make([]byte, 32)
			sB := make([]byte, 32)
			r.FillBytes(rB)
			sVal.FillBytes(sB)
			sigB64 := base64.RawURLEncoding.EncodeToString(append(rB, sB...))
			jws := headerB64 + "." + payloadB64 + "." + sigB64

			body := fmt.Sprintf(`{
				"challenge_version": 1,
				"csr_der_base64": %q,
				"pop": {"format": "enrollment-pop+jws", "jws": %q},
				"tpm_evidence": {"format": "enrollment-tpm-evidence", "version": "1", "payload": {}}
			}`, csrB64, jws)

			rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, map[string]string{
				"Authorization": "Bearer " + h.enrollmentToken,
			})
			if rr.Code != http.StatusAccepted {
				t.Fatalf("status=%d want=202 body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

// 11. SOL-M5.8-POST-003: DUPLICATE JSON MEMBERS REJECTION
func TestM58HTTPDuplicateJSONMembersRejection(t *testing.T) {
	h := newM58HTTPHarness(t)

	t.Run("duplicate in JWS protected header", func(t *testing.T) {
		hdrJSON := []byte(`{"alg":"ES256","typ":"enrollment-pop+jws","alg":"ES256"}`)
		hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
		plJSON, _ := json.Marshal(map[string]interface{}{
			"version":           1,
			"purpose":           "enrollment-pop",
			"enrollment_id":     h.enrollmentID,
			"challenge_version": 1,
			"nonce":             h.activeNonce,
			"csr_sha256":        h.helper.csrSha256Hex,
			"public_key_sha256": h.helper.publicKeySha256Hex,
		})
		plB64 := base64.RawURLEncoding.EncodeToString(plJSON)
		digest := sha256.Sum256([]byte(hdrB64 + "." + plB64))
		r, sVal, _ := ecdsa.Sign(rand.Reader, h.helper.priv, digest[:])
		rB := make([]byte, 32)
		sB := make([]byte, 32)
		r.FillBytes(rB)
		sVal.FillBytes(sB)
		sigB64 := base64.RawURLEncoding.EncodeToString(append(rB, sB...))
		dupJWS := hdrB64 + "." + plB64 + "." + sigB64

		body := fmt.Sprintf(`{
			"challenge_version": 1,
			"csr_der_base64": %q,
			"pop": {"format": "enrollment-pop+jws", "jws": %q},
			"tpm_evidence": {"format": "enrollment-tpm-evidence", "version": "1", "payload": {}}
		}`, h.helper.csrB64, dupJWS)

		rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, map[string]string{
			"Authorization": "Bearer " + h.enrollmentToken,
		})
		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status=%d want=422 body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("duplicate in JWS payload", func(t *testing.T) {
		hdrJSON, _ := json.Marshal(map[string]interface{}{
			"alg": "ES256",
			"typ": "enrollment-pop+jws",
		})
		hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
		plJSON := []byte(fmt.Sprintf(`{"version":1,"purpose":"enrollment-pop","enrollment_id":%q,"challenge_version":1,"nonce":%q,"csr_sha256":%q,"public_key_sha256":%q,"version":1}`,
			h.enrollmentID, h.activeNonce, h.helper.csrSha256Hex, h.helper.publicKeySha256Hex))
		plB64 := base64.RawURLEncoding.EncodeToString(plJSON)
		digest := sha256.Sum256([]byte(hdrB64 + "." + plB64))
		r, sVal, _ := ecdsa.Sign(rand.Reader, h.helper.priv, digest[:])
		rB := make([]byte, 32)
		sB := make([]byte, 32)
		r.FillBytes(rB)
		sVal.FillBytes(sB)
		sigB64 := base64.RawURLEncoding.EncodeToString(append(rB, sB...))
		dupJWS := hdrB64 + "." + plB64 + "." + sigB64

		body := fmt.Sprintf(`{
			"challenge_version": 1,
			"csr_der_base64": %q,
			"pop": {"format": "enrollment-pop+jws", "jws": %q},
			"tpm_evidence": {"format": "enrollment-tpm-evidence", "version": "1", "payload": {}}
		}`, h.helper.csrB64, dupJWS)

		rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, map[string]string{
			"Authorization": "Bearer " + h.enrollmentToken,
		})
		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status=%d want=422 body=%s", rr.Code, rr.Body.String())
		}
	})
}

// 12. SOL-M5.8-POST-004: REFRESH MISSING/CORRUPT REPLAY RESULT MAPS TO 503 DEPENDENCY_UNAVAILABLE
func TestM58HTTPRefreshMissingReplayResult503(t *testing.T) {
	h := newM58HTTPHarness(t)
	body := `{"expected_challenge_version": 1}`
	key := "refresh-key-corrupt-001"

	// First refresh succeeds 200 OK
	first := h.post("/v1/enrollments/"+h.enrollmentID+"/challenge:refresh", body, map[string]string{
		"Authorization":   "Bearer " + h.enrollmentToken,
		"Idempotency-Key": key,
	})
	if first.Code != http.StatusOK {
		t.Fatalf("first refresh status=%d want=200", first.Code)
	}

	// Corrupt or clear stored refresh results through the test-only adapter
	// (the production store exposes no destructive test mutation).
	h.corruptRefresh.Store(true)

	// Replay attempt with same key must return 503 DEPENDENCY_UNAVAILABLE (NOT 409)
	replay := h.post("/v1/enrollments/"+h.enrollmentID+"/challenge:refresh", body, map[string]string{
		"Authorization":   "Bearer " + h.enrollmentToken,
		"Idempotency-Key": key,
	})
	if replay.Code != http.StatusServiceUnavailable {
		t.Fatalf("corrupted replay status=%d want=503 body=%s", replay.Code, replay.Body.String())
	}
	var p map[string]interface{}
	if err := json.Unmarshal(replay.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p["error_code"] != "DEPENDENCY_UNAVAILABLE" {
		t.Fatalf("error_code=%v want DEPENDENCY_UNAVAILABLE", p["error_code"])
	}
}
