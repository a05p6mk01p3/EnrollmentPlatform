package httpapi_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/config"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
	preonboardingapp "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/resourceownership"
)

// Token conventions for the deterministic fakes below.
const (
	tokHuman     = "tok-human-oidc"
	tokAdmin     = "tok-admin-oidc"
	tokTemp      = "tok-temporary-principal"
	tokReq       = "tok-request-access"
	tokEnroll    = "tok-enrollment-access"
	tokAmbiguous = "tok-ambiguous"
)

// --- test double helpers ---

// acceptOnly authenticates exactly the given token for the given kind.
func acceptOnly(kind authpolicy.CredentialKind, token string) authruntime.Authenticator {
	return authruntime.BearerTestAuthenticator{KindValue: kind, Decide: func(t string) authruntime.Decision {
		if t == token {
			return authruntime.DecisionAuthenticated
		}
		return authruntime.DecisionRejected
	}}
}

// rejectAll rejects every token for the given kind.
func rejectAll(kind authpolicy.CredentialKind) authruntime.Authenticator {
	return authruntime.BearerTestAuthenticator{KindValue: kind, Decide: func(string) authruntime.Decision {
		return authruntime.DecisionRejected
	}}
}

// acceptDeviceMTLS authenticates any device credential.
func acceptDeviceMTLS() authruntime.Authenticator {
	return authruntime.DeviceTestAuthenticator{Decide: func(d *authruntime.DeviceCredential) authruntime.Decision {
		if d == nil {
			return authruntime.DecisionRejected
		}
		return authruntime.DecisionAuthenticated
	}}
}

// presentDeviceSource always provides a device credential.
func presentDeviceSource() authruntime.DeviceMTLSSource {
	return authruntime.DeviceTestSource{Credential: func(r *http.Request) (*authruntime.DeviceCredential, error) {
		return &authruntime.DeviceCredential{}, nil
	}}
}

// registry builds a registry for the given authenticators.
func registry(t *testing.T, auths ...authruntime.Authenticator) *authruntime.Registry {
	t.Helper()
	r, err := authruntime.NewRegistry(auths...)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

// authProbeSSI records authentication contexts and decoded bodies on top of
// the probeSSI call recorder. Methods it shadows take precedence over the
// promoted probeSSI methods.
type authProbeSSI struct {
	probeSSI

	mu       sync.Mutex
	contexts []*authruntime.AuthenticationContext
	created  []openapi.CreateEnrollmentRequestObject
}

func (p *authProbeSSI) recordCtx(ctx context.Context) {
	ac, _ := authruntime.AuthenticationContextFrom(ctx)
	p.mu.Lock()
	p.contexts = append(p.contexts, ac)
	p.mu.Unlock()
}

func (p *authProbeSSI) contextSnapshot() []*authruntime.AuthenticationContext {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*authruntime.AuthenticationContext(nil), p.contexts...)
}

func (p *authProbeSSI) createdSnapshot() []openapi.CreateEnrollmentRequestObject {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]openapi.CreateEnrollmentRequestObject(nil), p.created...)
}

func (p *authProbeSSI) GetMyAuthorizations(ctx context.Context, request openapi.GetMyAuthorizationsRequestObject) (openapi.GetMyAuthorizationsResponseObject, error) {
	p.record("GetMyAuthorizations")
	p.recordCtx(ctx)
	return openapi.GetMyAuthorizations200JSONResponse{}, nil
}

func (p *authProbeSSI) GetEnrollment(ctx context.Context, request openapi.GetEnrollmentRequestObject) (openapi.GetEnrollmentResponseObject, error) {
	p.record("GetEnrollment")
	p.recordCtx(ctx)
	return openapi.GetEnrollment200JSONResponse{}, nil
}

func (p *authProbeSSI) CreateEnrollment(ctx context.Context, request openapi.CreateEnrollmentRequestObject) (openapi.CreateEnrollmentResponseObject, error) {
	p.record("CreateEnrollment")
	p.recordCtx(ctx)
	p.mu.Lock()
	p.created = append(p.created, request)
	p.mu.Unlock()
	return openapi.CreateEnrollment201JSONResponse{}, nil
}

func (p *authProbeSSI) CompleteEnrollment(ctx context.Context, request openapi.CompleteEnrollmentRequestObject) (openapi.CompleteEnrollmentResponseObject, error) {
	p.record("CompleteEnrollment")
	p.recordCtx(ctx)
	return openapi.CompleteEnrollment200JSONResponse{}, nil
}

// newAuthTestHandler builds the full pipeline with the given registry and
// device source (either may be nil; nil registry => production deny default).
func newAuthTestHandler(t *testing.T, reg *authruntime.Registry, source authruntime.DeviceMTLSSource) (http.Handler, *authProbeSSI) {
	t.Helper()
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	partnerSvc := testPartnerAuthService()
	srv, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(completeTestRegistry(t, reg)),
		httpapi.WithDeviceMTLSSource(completeTestDeviceSource(source)),
		httpapi.WithAuthzRegistry(testAuthzRegistry()),
		httpapi.WithPartnerAuthService(partnerSvc),
		httpapi.WithResourceOwnershipService(testResourceOwnershipService(partnerSvc)),
		httpapi.WithPreOnboardingService(testPreOnboardingService()),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	p := &authProbeSSI{probeSSI: probeSSI{calls: map[string]int{}}}
	return srv.Handler(p), p
}

// completeTestRegistry returns a registry covering all six contractual kinds,
// preserving every authenticator the caller supplied and filling any missing
// kind with a fail-closed test double (reject-all bearer, accept-device). The
// M4.6 production constructor (SOL-M4.6-001) validates full registry coverage,
// so per-request behavior tests construct a fully-covered registry here; the
// genuinely-missing-kind -> 503 path is exercised at the runtime package
// level, not through NewServer.
func completeTestRegistry(t *testing.T, reg *authruntime.Registry) *authruntime.Registry {
	t.Helper()
	all := []authpolicy.CredentialKind{
		authpolicy.CredentialKindHumanOIDC,
		authpolicy.CredentialKindAdminOIDC,
		authpolicy.CredentialKindTemporaryPrincipalToken,
		authpolicy.CredentialKindRequestAccessToken,
		authpolicy.CredentialKindEnrollmentAccessToken,
		authpolicy.CredentialKindDeviceMTLS,
	}
	auths := make([]authruntime.Authenticator, 0, len(all))
	for _, kind := range all {
		if reg != nil {
			if a, ok := reg.Get(kind); ok {
				auths = append(auths, a)
				continue
			}
		}
		if kind == authpolicy.CredentialKindDeviceMTLS {
			auths = append(auths, acceptDeviceMTLS())
		} else {
			auths = append(auths, rejectAll(kind))
		}
	}
	r, err := authruntime.NewRegistry(auths...)
	if err != nil {
		t.Fatalf("completeTestRegistry: %v", err)
	}
	return r
}

// completeTestDeviceSource substitutes a no-device source for a nil source so
// the production constructor's DeviceMTLS-source validation passes; in
// per-request tests a nil source means "no device credential present".
func completeTestDeviceSource(source authruntime.DeviceMTLSSource) authruntime.DeviceMTLSSource {
	if source != nil {
		return source
	}
	return authruntime.DeviceTestSource{Credential: func(r *http.Request) (*authruntime.DeviceCredential, error) {
		return nil, nil
	}}
}

// doAuth performs a request with explicit headers (no default credential).
func doAuth(t *testing.T, h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rd *strings.Reader
	if body != "" {
		rd = strings.NewReader(body)
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rd)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func assertProblem(t *testing.T, rr *httptest.ResponseRecorder, status int, errorCode string) map[string]any {
	t.Helper()
	if rr.Code != status {
		t.Fatalf("status = %d, want %d (body %s)", rr.Code, status, rr.Body.String())
	}
	m := problemBody(t, rr)
	if m["error_code"] != errorCode {
		t.Fatalf("error_code = %v, want %v (body %s)", m["error_code"], errorCode, rr.Body.String())
	}
	return m
}

func assertNoHandlerCall(t *testing.T, p *probeSSI) {
	t.Helper()
	if p.total() != 0 {
		t.Fatal("handler must not be called")
	}
}

// --- §15 adversarial tests ---

func TestMissingBearerRejected(t *testing.T) {
	h, p := newAuthTestHandler(t, registry(t, acceptOnly(authpolicy.CredentialKindHumanOIDC, tokHuman)), nil)
	rr := doAuth(t, h, "GET", "/v1/me/authorizations", "", nil)
	assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	if got := rr.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q, want Bearer", got)
	}
	assertNoHandlerCall(t, &p.probeSSI)
}

func TestDuplicateAuthorizationHeaderRejected(t *testing.T) {
	h, p := newAuthTestHandler(t, registry(t, acceptOnly(authpolicy.CredentialKindHumanOIDC, tokHuman)), nil)
	req := httptest.NewRequest("GET", "/v1/me/authorizations", nil)
	req.Header.Add("Authorization", "Bearer "+tokHuman)
	req.Header.Add("Authorization", "Bearer "+tokHuman)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	assertNoHandlerCall(t, &p.probeSSI)
}

func TestCommaCombinedAuthorizationRejected(t *testing.T) {
	h, p := newAuthTestHandler(t, registry(t, acceptOnly(authpolicy.CredentialKindHumanOIDC, tokHuman)), nil)
	rr := doAuth(t, h, "GET", "/v1/me/authorizations", "", map[string]string{
		"Authorization": "Bearer " + tokHuman + ", Bearer " + tokAdmin,
	})
	assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	assertNoHandlerCall(t, &p.probeSSI)
}

func TestMalformedAndEmptyBearerRejected(t *testing.T) {
	h, p := newAuthTestHandler(t, registry(t, acceptOnly(authpolicy.CredentialKindHumanOIDC, tokHuman)), nil)
	for name, value := range map[string]string{
		"non-bearer scheme": "Basic " + tokHuman,
		"empty token":       "Bearer",
		"bare scheme":       "Bearer ",
	} {
		t.Run(name, func(t *testing.T) {
			rr := doAuth(t, h, "GET", "/v1/me/authorizations", "", map[string]string{"Authorization": value})
			assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
			assertNoHandlerCall(t, &p.probeSSI)
		})
	}
}

func TestRawTokenAbsentFromErrorResponse(t *testing.T) {
	const secret = "super-secret-token-that-must-never-leak-000"
	h, p := newAuthTestHandler(t, registry(t, acceptOnly(authpolicy.CredentialKindHumanOIDC, tokHuman)), nil)
	rr := doAuth(t, h, "GET", "/v1/me/authorizations", "", map[string]string{"Authorization": "Bearer " + secret})
	assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	if strings.Contains(rr.Body.String(), secret) {
		t.Fatal("raw token leaked into the error response")
	}
	if strings.Contains(rr.Body.String(), "Bearer "+secret) {
		t.Fatal("Authorization value leaked into the error response")
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q, want Bearer (the header must not carry the token)", got)
	}
	assertNoHandlerCall(t, &p.probeSSI)
}

func TestHumanOIDCCannotSatisfyAdminOIDC(t *testing.T) {
	// Token accepted only by AdminOIDC cannot open the HumanOIDC route.
	h, p := newAuthTestHandler(t, registry(t,
		rejectAll(authpolicy.CredentialKindHumanOIDC),
		acceptOnly(authpolicy.CredentialKindAdminOIDC, tokAdmin),
	), nil)
	rr := doAuth(t, h, "GET", "/v1/me/authorizations", "", map[string]string{"Authorization": "Bearer " + tokAdmin})
	assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	assertNoHandlerCall(t, &p.probeSSI)

	// And a HumanOIDC credential cannot open the AdminOIDC route.
	rr2 := doAuth(t, h, "GET", "/v1/admin/pre-onboarding-requests", "", map[string]string{"Authorization": "Bearer " + tokHuman})
	assertProblem(t, rr2, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	assertNoHandlerCall(t, &p.probeSSI)
}

func TestRequestAccessCannotSatisfyEnrollmentAccess(t *testing.T) {
	h, p := newAuthTestHandler(t, registry(t,
		acceptOnly(authpolicy.CredentialKindRequestAccessToken, tokReq),
		acceptOnly(authpolicy.CredentialKindEnrollmentAccessToken, tokEnroll),
		acceptDeviceMTLS(),
	), nil)

	// Enrollment-access route with a request-access token.
	rr := doAuth(t, h, "GET", "/v1/enrollments/enr-123", "", map[string]string{"Authorization": "Bearer " + tokReq})
	assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	assertNoHandlerCall(t, &p.probeSSI)

	// Request-access route (INITIAL) with an enrollment-access token.
	rr2 := doAuth(t, h, "POST", "/v1/enrollments", validEnrollmentBody, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer " + tokEnroll,
	})
	assertProblem(t, rr2, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	assertNoHandlerCall(t, &p.probeSSI)
}

func TestTemporaryPrincipalRemainsSeparate(t *testing.T) {
	const preOnboardingBody = `{"partner_id":"P1","claimed_device":{"hostname":"PC-001"},"agent":{"version":"1.0.0","platform":"windows"}}`
	h, p := newAuthTestHandler(t, registry(t,
		acceptOnly(authpolicy.CredentialKindHumanOIDC, tokHuman),
		acceptOnly(authpolicy.CredentialKindTemporaryPrincipalToken, tokTemp),
	), nil)

	// A TemporaryPrincipalToken credential authenticates on its own (OR
	// semantics): the request passes authentication and reaches the mandatory
	// M5.2 boundary, which blocks it BEFORE the protected mutation because the
	// later mandatory gates (concrete production token verifier/bootstrap and
	// transactional max_submissions consumption) are unavailable. The boundary
	// answers fail-closed and the mutation seam is never invoked. This asserts
	// the synthetic-harness observable behavior (fail-closed), not a
	// production success path.
	rr := doAuth(t, h, "POST", "/v1/pre-onboarding-requests", preOnboardingBody, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer " + tokTemp,
	})
	assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	if p.count("CreatePreOnboardingRequest") != 0 {
		t.Fatal("TemporaryPrincipalToken must not reach the protected mutation")
	}

	// A HumanOIDC credential also authenticates (OR semantics) and passes the
	// M5.2 gate: the harness authorizes test-subject-human for P1.
	rr2 := doAuth(t, h, "POST", "/v1/pre-onboarding-requests", preOnboardingBody, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer " + tokHuman,
	})
	if rr2.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %s)", rr2.Code, rr2.Body.String())
	}
	if p.count("CreatePreOnboardingRequest") != 0 {
		t.Fatalf("CreatePreOnboardingRequest calls = %d, want 0 (answered by M5.5 boundary)", p.count("CreatePreOnboardingRequest"))
	}
}

func TestAmbiguousBearerFailsClosed(t *testing.T) {
	const preOnboardingBody = `{"partner_id":"P1","claimed_device":{"hostname":"PC-001"},"agent":{"version":"1.0.0","platform":"windows"}}`
	// The same token is accepted by BOTH eligible bearer kinds: fail closed.
	h, p := newAuthTestHandler(t, registry(t,
		authruntime.BearerTestAuthenticator{KindValue: authpolicy.CredentialKindHumanOIDC, Decide: func(t string) authruntime.Decision {
			if t == tokAmbiguous {
				return authruntime.DecisionAuthenticated
			}
			return authruntime.DecisionRejected
		}},
		authruntime.BearerTestAuthenticator{KindValue: authpolicy.CredentialKindTemporaryPrincipalToken, Decide: func(t string) authruntime.Decision {
			if t == tokAmbiguous {
				return authruntime.DecisionAuthenticated
			}
			return authruntime.DecisionRejected
		}},
	), nil)
	rr := doAuth(t, h, "POST", "/v1/pre-onboarding-requests", preOnboardingBody, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer " + tokAmbiguous,
	})
	assertProblem(t, rr, http.StatusInternalServerError, "INTERNAL_ERROR")
	assertNoHandlerCall(t, &p.probeSSI)
}

func TestIndeterminateAuthenticatorFailsClosed(t *testing.T) {
	h, p := newAuthTestHandler(t, registry(t,
		authruntime.BearerTestAuthenticator{KindValue: authpolicy.CredentialKindHumanOIDC, Decide: func(string) authruntime.Decision {
			return authruntime.DecisionIndeterminate
		}},
	), nil)
	rr := doAuth(t, h, "GET", "/v1/me/authorizations", "", map[string]string{"Authorization": "Bearer " + tokHuman})
	assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	assertNoHandlerCall(t, &p.probeSSI)
}

func TestORSemanticsRuntime(t *testing.T) {
	h, p := newAuthTestHandler(t, registry(t,
		acceptOnly(authpolicy.CredentialKindHumanOIDC, tokHuman),
		acceptOnly(authpolicy.CredentialKindRequestAccessToken, tokReq),
	), nil)

	for _, tok := range []string{tokHuman, tokReq} {
		rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-123", "", map[string]string{"Authorization": "Bearer " + tok})
		if rr.Code != http.StatusOK {
			t.Fatalf("token %q: status = %d, want 200 (body %s)", tok, rr.Code, rr.Body.String())
		}
	}
	if p.count("GetPreOnboardingRequest") != 0 {
		t.Fatalf("GetPreOnboardingRequest calls = %d, want 0 (answered by M5.5 boundary)", p.count("GetPreOnboardingRequest"))
	}
}

func TestDeviceMTLSAbsentAndPresent(t *testing.T) {
	reg := registry(t,
		acceptOnly(authpolicy.CredentialKindEnrollmentAccessToken, tokEnroll),
		acceptDeviceMTLS(),
	)

	t.Run("absent source fails INSTALLED", func(t *testing.T) {
		h, p := newAuthTestHandler(t, reg, nil)
		rr := doAuth(t, h, "POST", "/v1/enrollments/enr-123/complete", `{"installation_status":"INSTALLED"}`, map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
			"Authorization":   "Bearer " + tokEnroll,
		})
		assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		assertNoHandlerCall(t, &p.probeSSI)
	})

	t.Run("present source satisfies INSTALLED", func(t *testing.T) {
		h, p := newAuthTestHandler(t, reg, presentDeviceSource())
		rr := doAuth(t, h, "POST", "/v1/enrollments/enr-123/complete", `{"installation_status":"INSTALLED"}`, map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
			"Authorization":   "Bearer " + tokEnroll,
		})
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
		}
		if p.count("CompleteEnrollment") != 1 {
			t.Fatal("handler was not called")
		}
	})
}

func TestSimultaneousBearerAndDeviceNoUniversalPreference(t *testing.T) {
	h, p := newAuthTestHandler(t, registry(t,
		acceptOnly(authpolicy.CredentialKindEnrollmentAccessToken, tokEnroll),
		acceptDeviceMTLS(),
	), presentDeviceSource())

	// INSTALLED: both signals present; the DeviceMTLS case must win by policy,
	// not by a universal preference rule.
	rr := doAuth(t, h, "POST", "/v1/enrollments/enr-123/complete", `{"installation_status":"INSTALLED"}`, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer " + tokEnroll,
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("INSTALLED: status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}

	// FAILED: both signals present; the EnrollmentAccessToken case must win.
	rr2 := doAuth(t, h, "POST", "/v1/enrollments/enr-123/complete", `{"installation_status":"FAILED","error_code":"AGENT_INSTALL_FAILED"}`, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer " + tokEnroll,
	})
	if rr2.Code != http.StatusOK {
		t.Fatalf("FAILED: status = %d, want 200 (body %s)", rr2.Code, rr2.Body.String())
	}
	if p.count("CompleteEnrollment") != 2 {
		t.Fatalf("CompleteEnrollment calls = %d, want 2", p.count("CompleteEnrollment"))
	}
}

func TestCreateEnrollmentConditionalPairing(t *testing.T) {
	reg := registry(t,
		acceptOnly(authpolicy.CredentialKindRequestAccessToken, tokReq),
		acceptOnly(authpolicy.CredentialKindEnrollmentAccessToken, tokEnroll),
		acceptDeviceMTLS(),
	)
	body := `{"operation":"INITIAL","certificate_usage":"PARTNER_AUTH"}`
	headers := func(tok string) map[string]string {
		return map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
			"Authorization":   "Bearer " + tok,
		}
	}

	t.Run("INITIAL with RequestAccessToken passes", func(t *testing.T) {
		h, p := newAuthTestHandler(t, reg, nil)
		rr := doAuth(t, h, "POST", "/v1/enrollments", body, headers(tokReq))
		if rr.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (body %s)", rr.Code, rr.Body.String())
		}
		if p.count("CreateEnrollment") != 1 {
			t.Fatal("handler was not called")
		}
	})

	t.Run("INITIAL with DeviceMTLS only fails", func(t *testing.T) {
		// RequestAccessToken rejects the presented token; only the device
		// authenticates. INITIAL requires RequestAccessToken -> 401.
		h, p := newAuthTestHandler(t, reg, presentDeviceSource())
		rr := doAuth(t, h, "POST", "/v1/enrollments", body, headers(tokEnroll))
		assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		assertNoHandlerCall(t, &p.probeSSI)
	})

	for _, op := range []string{"RENEWAL", "REKEY"} {
		opBody := fmt.Sprintf(`{"operation":%q,"certificate_usage":"PARTNER_AUTH"}`, op)
		t.Run(op+" with DeviceMTLS passes", func(t *testing.T) {
			h, p := newAuthTestHandler(t, reg, presentDeviceSource())
			rr := doAuth(t, h, "POST", "/v1/enrollments", opBody, headers(tokReq))
			if rr.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201 (body %s)", rr.Code, rr.Body.String())
			}
			if p.count("CreateEnrollment") != 1 {
				t.Fatal("handler was not called")
			}
		})
		t.Run(op+" with RequestAccessToken only fails", func(t *testing.T) {
			h, p := newAuthTestHandler(t, reg, nil)
			rr := doAuth(t, h, "POST", "/v1/enrollments", opBody, headers(tokReq))
			assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
			assertNoHandlerCall(t, &p.probeSSI)
		})
	}
}

func TestCompleteEnrollmentConditionalPairing(t *testing.T) {
	reg := registry(t,
		acceptOnly(authpolicy.CredentialKindRequestAccessToken, tokReq),
		acceptOnly(authpolicy.CredentialKindEnrollmentAccessToken, tokEnroll),
		acceptDeviceMTLS(),
	)
	headers := func(tok string) map[string]string {
		return map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
			"Authorization":   "Bearer " + tok,
		}
	}

	t.Run("INSTALLED with DeviceMTLS passes", func(t *testing.T) {
		h, p := newAuthTestHandler(t, reg, presentDeviceSource())
		rr := doAuth(t, h, "POST", "/v1/enrollments/enr-123/complete", `{"installation_status":"INSTALLED"}`, headers(tokEnroll))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
		}
		if p.count("CompleteEnrollment") != 1 {
			t.Fatal("handler was not called")
		}
	})

	t.Run("INSTALLED with EnrollmentAccessToken only fails", func(t *testing.T) {
		h, p := newAuthTestHandler(t, reg, nil)
		rr := doAuth(t, h, "POST", "/v1/enrollments/enr-123/complete", `{"installation_status":"INSTALLED"}`, headers(tokEnroll))
		assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		assertNoHandlerCall(t, &p.probeSSI)
	})

	t.Run("FAILED with EnrollmentAccessToken passes", func(t *testing.T) {
		h, p := newAuthTestHandler(t, reg, nil)
		rr := doAuth(t, h, "POST", "/v1/enrollments/enr-123/complete", `{"installation_status":"FAILED","error_code":"AGENT_INSTALL_FAILED"}`, headers(tokEnroll))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
		}
		if p.count("CompleteEnrollment") != 1 {
			t.Fatal("handler was not called")
		}
	})

	t.Run("FAILED with DeviceMTLS only fails", func(t *testing.T) {
		// EnrollmentAccessToken rejects the presented token; only the device
		// authenticates. FAILED requires EnrollmentAccessToken -> 401.
		h, p := newAuthTestHandler(t, reg, presentDeviceSource())
		rr := doAuth(t, h, "POST", "/v1/enrollments/enr-123/complete", `{"installation_status":"FAILED","error_code":"AGENT_INSTALL_FAILED"}`, headers(tokReq))
		assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		assertNoHandlerCall(t, &p.probeSSI)
	})
}

func TestPublicOperationSkipsAuthenticators(t *testing.T) {
	calls := 0
	var mu sync.Mutex
	counted := authruntime.BearerTestAuthenticator{
		KindValue: authpolicy.CredentialKindHumanOIDC,
		Decide: func(string) authruntime.Decision {
			mu.Lock()
			calls++
			mu.Unlock()
			return authruntime.DecisionRejected
		},
	}
	h, p := newAuthTestHandler(t, registry(t, counted), nil)

	// No credential at all: public route must not consult authenticators.
	rr := doAuth(t, h, "GET", "/v1/pki/trust-bundles/current", "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("GetCurrentTrustBundle") != 1 {
		t.Fatal("handler was not called")
	}

	// An irrelevant Authorization header must not fail the public operation.
	rr2 := doAuth(t, h, "GET", "/v1/pki/trust-bundles/current", "", map[string]string{
		"Authorization": "Bearer irrelevant-token",
	})
	if rr2.Code != http.StatusOK {
		t.Fatalf("with irrelevant Authorization: status = %d, want 200 (body %s)", rr2.Code, rr2.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if calls != 0 {
		t.Fatalf("authenticator invoked %d times for a public operation; want 0", calls)
	}
}

func TestRequestContextsDoNotContaminateConcurrentRequests(t *testing.T) {
	h, p := newAuthTestHandler(t, registry(t,
		acceptOnly(authpolicy.CredentialKindHumanOIDC, tokHuman),
		acceptOnly(authpolicy.CredentialKindEnrollmentAccessToken, tokEnroll),
	), nil)

	const workers = 16
	const rounds = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < rounds; j++ {
				if i%2 == 0 {
					rr := doAuth(t, h, "GET", "/v1/me/authorizations", "", map[string]string{"Authorization": "Bearer " + tokHuman})
					if rr.Code != http.StatusOK {
						errs <- fmt.Errorf("human: status = %d", rr.Code)
						return
					}
				} else {
					rr := doAuth(t, h, "GET", "/v1/enrollments/enr-123", "", map[string]string{"Authorization": "Bearer " + tokEnroll})
					if rr.Code != http.StatusOK {
						errs <- fmt.Errorf("enrollment: status = %d", rr.Code)
						return
					}
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	// Every recorded context must carry exactly the kind of its own request:
	// no cross-request contamination.
	for _, ac := range p.contextSnapshot() {
		if ac == nil {
			t.Fatal("handler observed a nil authentication context")
		}
		kinds := ac.Kinds()
		switch ac.OperationID() {
		case "getMyAuthorizations":
			if len(kinds) != 1 || kinds[0] != authpolicy.CredentialKindHumanOIDC {
				t.Fatalf("getMyAuthorizations context kinds = %v; want [HumanOIDC]", kinds)
			}
		case "getEnrollment":
			if len(kinds) != 1 || kinds[0] != authpolicy.CredentialKindEnrollmentAccessToken {
				t.Fatalf("getEnrollment context kinds = %v; want [EnrollmentAccessToken]", kinds)
			}
		default:
			t.Fatalf("unexpected operation %q in recorded contexts", ac.OperationID())
		}
	}
}

func TestM3StillExecutesAfterSuccessfulAuth(t *testing.T) {
	h, p := newAuthTestHandler(t, registry(t,
		acceptOnly(authpolicy.CredentialKindRequestAccessToken, tokReq),
		acceptDeviceMTLS(),
	), nil)

	// Valid credential + M3-invalid body => 400 from M3 (not 401): base auth
	// passed and M3 enforcement still runs between the two phases.
	rr := doAuth(t, h, "POST", "/v1/enrollments", `{"operation":"INITIAL","certificate_usage":"PARTNER_AUTH","extra":true}`, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer " + tokReq,
	})
	assertProblem(t, rr, http.StatusBadRequest, "INVALID_REQUEST")
	assertNoHandlerCall(t, &p.probeSSI)
}

func TestPhaseAOrderingBeforeM3(t *testing.T) {
	h, p := newAuthTestHandler(t, registry(t,
		acceptOnly(authpolicy.CredentialKindRequestAccessToken, tokReq),
		acceptDeviceMTLS(),
	), nil)

	// Invalid credential + M3-invalid body => 401 (not 400): Phase A runs
	// before M3 contract enforcement.
	rr := doAuth(t, h, "POST", "/v1/enrollments", `{"operation":"INITIAL","certificate_usage":"PARTNER_AUTH","extra":true}`, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer wrong-token",
	})
	assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	assertNoHandlerCall(t, &p.probeSSI)
}

func TestPhaseBAfterM3AndBodyPreservation(t *testing.T) {
	h, p := newAuthTestHandler(t, registry(t,
		acceptOnly(authpolicy.CredentialKindRequestAccessToken, tokReq),
		acceptOnly(authpolicy.CredentialKindEnrollmentAccessToken, tokEnroll),
		acceptDeviceMTLS(),
	), nil)

	// The discriminator is NOT the first field in the raw body: Phase B must
	// find it without disturbing the bytes the strict handler decodes.
	body := `{"certificate_usage":"PARTNER_AUTH","operation":"INITIAL"}`
	rr := doAuth(t, h, "POST", "/v1/enrollments", body, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer " + tokReq,
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %s)", rr.Code, rr.Body.String())
	}
	created := p.createdSnapshot()
	if len(created) != 1 {
		t.Fatalf("CreateEnrollment calls = %d, want 1", len(created))
	}
	initial, err := created[0].Body.AsInitialEnrollmentCreateRequest()
	if err != nil {
		t.Fatalf("decoded body does not resolve to INITIAL variant: %v (body preservation broken)", err)
	}
	if string(initial.CertificateUsage) != "PARTNER_AUTH" {
		t.Fatalf("certificate_usage = %v; want PARTNER_AUTH", initial.CertificateUsage)
	}

	// Same operation with a valid credential but a conditional mismatch
	// proves Phase B runs AFTER M3 (body passed M3, pairing failed).
	rr2 := doAuth(t, h, "POST", "/v1/enrollments", `{"operation":"RENEWAL","certificate_usage":"PARTNER_AUTH"}`, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer " + tokReq,
	})
	assertProblem(t, rr2, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
}

// TestMiddlewareOrderPinned proves the generated wrapper's middleware
// application order is the one the composition relies on: the LAST slice
// element runs FIRST, yielding BaseAuth -> Enforcer -> ConditionalAuth.
// If a future oapi-codegen version changes the wrapping order, these
// assertions fail instead of silently reordering enforcement.
func TestMiddlewareOrderPinned(t *testing.T) {
	reg := registry(t,
		acceptOnly(authpolicy.CredentialKindRequestAccessToken, tokReq),
		acceptOnly(authpolicy.CredentialKindEnrollmentAccessToken, tokEnroll),
		acceptDeviceMTLS(),
	)

	// 1. Valid auth + invalid body => 400: Phase A before M3.
	// 2. Valid auth + valid body + wrong pairing => 401: Phase B after M3.
	// 3. Invalid auth + invalid body => 401: Phase A before M3.
	h, p := newAuthTestHandler(t, reg, nil)

	rr1 := doAuth(t, h, "POST", "/v1/enrollments", `{"operation":"INITIAL","certificate_usage":"PARTNER_AUTH","x":1}`, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer " + tokReq,
	})
	assertProblem(t, rr1, http.StatusBadRequest, "INVALID_REQUEST")

	rr2 := doAuth(t, h, "POST", "/v1/enrollments", `{"operation":"RENEWAL","certificate_usage":"PARTNER_AUTH"}`, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer " + tokReq,
	})
	assertProblem(t, rr2, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")

	rr3 := doAuth(t, h, "POST", "/v1/enrollments", `{"operation":"INITIAL","x":1}`, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer wrong-token",
	})
	assertProblem(t, rr3, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	assertNoHandlerCall(t, &p.probeSSI)
}

// TestProductionStartupRequiresCompleteAuthenticationComposition is the
// SOL-M4.6-001 regression: the production constructor itself must refuse to
// build a server when a compiled-policy-referenced runtime component is
// absent, before any request can be served. composition.Build is not the only
// gate — NewServer is.
func TestProductionStartupRequiresCompleteAuthenticationComposition(t *testing.T) {
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}

	// No options: the default registry covers every kind fail-closed, but the
	// canonical policy references DeviceMTLS and no trusted-proxy source is
	// wired -> construction must fail.
	_, err := httpapi.NewServer(cfg)
	if err == nil {
		t.Fatal("NewServer with no options must fail: DeviceMTLS trusted-proxy source is missing")
	}
	var mae *authruntime.MissingAuthenticatorError
	if !errors.As(err, &mae) || mae.Kind != authpolicy.CredentialKindDeviceMTLS {
		t.Fatalf("NewServer error = %v; want MissingAuthenticatorError{DeviceMTLS}", err)
	}

	// A device source alone is not enough: a registry missing a referenced
	// bearer kind must also fail construction.
	missingHuman := registry(t,
		acceptOnly(authpolicy.CredentialKindAdminOIDC, tokAdmin),
		acceptOnly(authpolicy.CredentialKindTemporaryPrincipalToken, tokTemp),
		acceptOnly(authpolicy.CredentialKindRequestAccessToken, tokReq),
		acceptOnly(authpolicy.CredentialKindEnrollmentAccessToken, tokEnroll),
		acceptDeviceMTLS(),
	)
	_, err = httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(missingHuman),
		httpapi.WithDeviceMTLSSource(completeTestDeviceSource(nil)),
	)
	if err == nil {
		t.Fatal("NewServer must fail: HumanOIDC is referenced by the policy but has no authenticator")
	}
	if !errors.As(err, &mae) || mae.Kind != authpolicy.CredentialKindHumanOIDC {
		t.Fatalf("NewServer error = %v; want MissingAuthenticatorError{HumanOIDC}", err)
	}

	// A complete registry plus a real source constructs successfully. The M5.2
	// partner authorization service is a mandatory dependency and is wired
	// explicitly (here: the fail-closed unavailable provider; this test never
	// touches M5.2-owned routes).
	partnerSvc := partnerauth.NewUnavailableService()
	if _, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(completeTestRegistry(t, nil)),
		httpapi.WithDeviceMTLSSource(completeTestDeviceSource(nil)),
		httpapi.WithPartnerAuthService(partnerSvc),
		httpapi.WithResourceOwnershipService(resourceownership.NewUnavailableService(partnerSvc)),
		httpapi.WithPreOnboardingService(preonboardingapp.NewUnavailableService()),
	); err != nil {
		t.Fatalf("NewServer with a complete composition should succeed: %v", err)
	}
}

// typedNilBearerImpl is a pointer-backed Authenticator whose nil pointer is the
// typed-nil bearer-authenticator case for the M4.6-003 regressions.
type typedNilBearerImpl struct{}

func (*typedNilBearerImpl) Kind() authpolicy.CredentialKind {
	return authpolicy.CredentialKindHumanOIDC
}

func (*typedNilBearerImpl) Authenticate(context.Context, *authruntime.Credential) authruntime.AuthenticationResult {
	return authruntime.AuthenticationResult{Decision: authruntime.DecisionRejected}
}

// typedNilDeviceSourceImpl is a pointer-backed DeviceMTLSSource whose nil
// pointer is the typed-nil device-source case.
type typedNilDeviceSourceImpl struct{}

func (*typedNilDeviceSourceImpl) DeviceCredential(*http.Request) (*authruntime.DeviceCredential, error) {
	return nil, nil
}

// TestNewServerRejectsTypedNilBearerAuthenticator is the M4.6-003 regression
// for the bearer component: a typed-nil Authenticator cannot be assembled into
// the registry that feeds httpapi.NewServer. The registry constructor is the
// first boundary of the production construction path, so the composition fails
// there with a typed startup error and no Server can be constructed.
func TestNewServerRejectsTypedNilBearerAuthenticator(t *testing.T) {
	var ptr *typedNilBearerImpl
	var human authruntime.Authenticator = ptr

	reg, err := authruntime.NewRegistry(
		human,
		acceptOnly(authpolicy.CredentialKindAdminOIDC, tokAdmin),
		acceptOnly(authpolicy.CredentialKindTemporaryPrincipalToken, tokTemp),
		acceptOnly(authpolicy.CredentialKindRequestAccessToken, tokReq),
		acceptOnly(authpolicy.CredentialKindEnrollmentAccessToken, tokEnroll),
		acceptDeviceMTLS(),
	)
	if reg != nil {
		t.Fatal("registry must be nil: typed-nil bearer authenticator must not become a usable entry")
	}
	var ne *authruntime.NilAuthenticatorError
	if !errors.As(err, &ne) {
		t.Fatalf("NewRegistry err = %v; want NilAuthenticatorError", err)
	}
}

// TestNewServerRejectsTypedNilDeviceSource is the M4.6-003 regression for the
// DeviceMTLS component through the real production constructor: a typed-nil
// trusted-proxy source must be treated exactly like an absent source and fail
// startup validation.
func TestNewServerRejectsTypedNilDeviceSource(t *testing.T) {
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	var ptr *typedNilDeviceSourceImpl
	var src authruntime.DeviceMTLSSource = ptr

	_, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(completeTestRegistry(t, nil)),
		httpapi.WithDeviceMTLSSource(src),
	)
	var mae *authruntime.MissingAuthenticatorError
	if !errors.As(err, &mae) || mae.Kind != authpolicy.CredentialKindDeviceMTLS {
		t.Fatalf("NewServer err = %v; want MissingAuthenticatorError{DeviceMTLS}", err)
	}
}

// TestConditionalWWWAuthenticateFromEffectiveRequirement pins SOL-M4.2-001:
// the 401 WWW-Authenticate challenge is selected from the EFFECTIVE required
// conditional kind, not the operation's base policy.
func TestConditionalWWWAuthenticateFromEffectiveRequirement(t *testing.T) {
	post := func(h http.Handler, path, body, tok string) *httptest.ResponseRecorder {
		return doAuth(t, h, "POST", path, body, map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
			"Authorization":   "Bearer " + tok,
		})
	}

	t.Run("INITIAL requires RequestAccessToken -> Bearer", func(t *testing.T) {
		h, p := newAuthTestHandler(t, registry(t,
			rejectAll(authpolicy.CredentialKindRequestAccessToken),
			acceptDeviceMTLS(),
		), presentDeviceSource())
		// Only DeviceMTLS authenticates; INITIAL requires RequestAccessToken.
		rr := post(h, "/v1/enrollments", `{"operation":"INITIAL","certificate_usage":"PARTNER_AUTH"}`, "irrelevant")
		assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		if got := rr.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Fatalf("WWW-Authenticate = %q; want Bearer", got)
		}
		assertNoHandlerCall(t, &p.probeSSI)
	})

	for _, op := range []string{"RENEWAL", "REKEY"} {
		t.Run(op+" requires DeviceMTLS -> no Bearer", func(t *testing.T) {
			h, p := newAuthTestHandler(t, registry(t,
				acceptOnly(authpolicy.CredentialKindRequestAccessToken, tokReq),
				acceptDeviceMTLS(),
			), nil) // no device source: only RequestAccessToken authenticates
			body := fmt.Sprintf(`{"operation":%q,"certificate_usage":"PARTNER_AUTH"}`, op)
			rr := post(h, "/v1/enrollments", body, tokReq)
			assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
			if got := rr.Header().Get("WWW-Authenticate"); got != "" {
				t.Fatalf("WWW-Authenticate = %q; want empty (no Bearer challenge for DeviceMTLS)", got)
			}
			assertNoHandlerCall(t, &p.probeSSI)
		})
	}

	t.Run("INSTALLED requires DeviceMTLS -> no Bearer", func(t *testing.T) {
		h, p := newAuthTestHandler(t, registry(t,
			acceptOnly(authpolicy.CredentialKindEnrollmentAccessToken, tokEnroll),
			acceptDeviceMTLS(),
		), nil)
		// Only EnrollmentAccessToken authenticates; INSTALLED requires DeviceMTLS.
		rr := post(h, "/v1/enrollments/enr-123/complete", `{"installation_status":"INSTALLED"}`, tokEnroll)
		assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		if got := rr.Header().Get("WWW-Authenticate"); got != "" {
			t.Fatalf("WWW-Authenticate = %q; want empty (no Bearer challenge for DeviceMTLS)", got)
		}
		assertNoHandlerCall(t, &p.probeSSI)
	})

	t.Run("FAILED requires EnrollmentAccessToken -> Bearer", func(t *testing.T) {
		h, p := newAuthTestHandler(t, registry(t,
			rejectAll(authpolicy.CredentialKindEnrollmentAccessToken),
			acceptDeviceMTLS(),
		), presentDeviceSource())
		// Only DeviceMTLS authenticates; FAILED requires EnrollmentAccessToken.
		rr := post(h, "/v1/enrollments/enr-123/complete", `{"installation_status":"FAILED","error_code":"AGENT_INSTALL_FAILED"}`, "irrelevant")
		assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		if got := rr.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Fatalf("WWW-Authenticate = %q; want Bearer", got)
		}
		assertNoHandlerCall(t, &p.probeSSI)
	})
}

// TestM3RegistryMultiBearerKindRoutesReachM3 pins SOL-M4.2-003: the M3 test
// registry uses kind-specific tokens, so the two multi-bearer-kind routes can
// authenticate a single kind without triggering artificial ambiguity.
func TestM3RegistryMultiBearerKindRoutesReachM3(t *testing.T) {
	h, p := newTestHandler(t)

	// HumanOIDC OR TemporaryPrincipalToken: a TemporaryPrincipalToken token
	// authenticates exactly one kind without artificial ambiguity, passes M3
	// (a malformed body would be 400, a wrong credential 401), and reaches the
	// mandatory M5.2 boundary — which blocks it before the protected mutation
	// because the later mandatory Temporary Principal gates are unavailable.
	rr := doAuth(t, h, "POST", "/v1/pre-onboarding-requests",
		`{"partner_id":"P1","claimed_device":{"hostname":"PC-001"},"agent":{"version":"1.0.0","platform":"windows"}}`,
		map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
			"Authorization":   "Bearer " + m3BearerToken(authpolicy.CredentialKindTemporaryPrincipalToken),
		})
	assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	if p.count("CreatePreOnboardingRequest") != 0 {
		t.Fatal("CreatePreOnboardingRequest must not be reached for a Temporary Principal")
	}

	// HumanOIDC OR RequestAccessToken: a HumanOIDC token authenticates
	// exactly one kind and reaches M3 + the handler.
	rr2 := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-123", "", map[string]string{
		"Authorization": "Bearer " + m3BearerToken(authpolicy.CredentialKindHumanOIDC),
	})
	if rr2.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr2.Code, rr2.Body.String())
	}
	if p.count("GetPreOnboardingRequest") != 0 {
		t.Fatal("GetPreOnboardingRequest must be answered by M5.5 boundary")
	}
}
