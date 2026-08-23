package httpapi_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	authzruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authz/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/config"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi"
)

// probeSSI implements openapi.StrictServerInterface without any business
// logic. It records which operations were invoked and returns zero-value
// success responses. It exists only to prove where the pipeline stops.
type probeSSI struct {
	mu    sync.Mutex
	calls map[string]int
}

func (p *probeSSI) record(op string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls[op]++
}

func (p *probeSSI) count(op string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[op]
}

func (p *probeSSI) total() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, c := range p.calls {
		n += c
	}
	return n
}

func (p *probeSSI) GetMyAuthorizations(ctx context.Context, request openapi.GetMyAuthorizationsRequestObject) (openapi.GetMyAuthorizationsResponseObject, error) {
	p.record("GetMyAuthorizations")
	return openapi.GetMyAuthorizations200JSONResponse{}, nil
}

func (p *probeSSI) CreatePreOnboardingRequest(ctx context.Context, request openapi.CreatePreOnboardingRequestRequestObject) (openapi.CreatePreOnboardingRequestResponseObject, error) {
	p.record("CreatePreOnboardingRequest")
	return openapi.CreatePreOnboardingRequest201JSONResponse{}, nil
}

func (p *probeSSI) GetPreOnboardingRequest(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error) {
	p.record("GetPreOnboardingRequest")
	return openapi.GetPreOnboardingRequest200JSONResponse{}, nil
}

func (p *probeSSI) CreateEnrollment(ctx context.Context, request openapi.CreateEnrollmentRequestObject) (openapi.CreateEnrollmentResponseObject, error) {
	p.record("CreateEnrollment")
	return openapi.CreateEnrollment201JSONResponse{}, nil
}

func (p *probeSSI) GetEnrollment(ctx context.Context, request openapi.GetEnrollmentRequestObject) (openapi.GetEnrollmentResponseObject, error) {
	p.record("GetEnrollment")
	return openapi.GetEnrollment200JSONResponse{}, nil
}

func (p *probeSSI) SubmitEnrollmentEvidence(ctx context.Context, request openapi.SubmitEnrollmentEvidenceRequestObject) (openapi.SubmitEnrollmentEvidenceResponseObject, error) {
	p.record("SubmitEnrollmentEvidence")
	return openapi.SubmitEnrollmentEvidence202JSONResponse{}, nil
}

func (p *probeSSI) RefreshEnrollmentChallenge(ctx context.Context, request openapi.RefreshEnrollmentChallengeRequestObject) (openapi.RefreshEnrollmentChallengeResponseObject, error) {
	p.record("RefreshEnrollmentChallenge")
	return openapi.RefreshEnrollmentChallenge200JSONResponse{}, nil
}

func (p *probeSSI) GetEnrollmentCertificate(ctx context.Context, request openapi.GetEnrollmentCertificateRequestObject) (openapi.GetEnrollmentCertificateResponseObject, error) {
	p.record("GetEnrollmentCertificate")
	return openapi.GetEnrollmentCertificate200JSONResponse{}, nil
}

func (p *probeSSI) CompleteEnrollment(ctx context.Context, request openapi.CompleteEnrollmentRequestObject) (openapi.CompleteEnrollmentResponseObject, error) {
	p.record("CompleteEnrollment")
	return openapi.CompleteEnrollment200JSONResponse{}, nil
}

func (p *probeSSI) GetCurrentTrustBundle(ctx context.Context, request openapi.GetCurrentTrustBundleRequestObject) (openapi.GetCurrentTrustBundleResponseObject, error) {
	p.record("GetCurrentTrustBundle")
	return openapi.GetCurrentTrustBundle200JSONResponse{}, nil
}

func (p *probeSSI) AdminListPreOnboardingRequests(ctx context.Context, request openapi.AdminListPreOnboardingRequestsRequestObject) (openapi.AdminListPreOnboardingRequestsResponseObject, error) {
	p.record("AdminListPreOnboardingRequests")
	return openapi.AdminListPreOnboardingRequests200JSONResponse{}, nil
}

func (p *probeSSI) AdminApprovePreOnboardingRequest(ctx context.Context, request openapi.AdminApprovePreOnboardingRequestRequestObject) (openapi.AdminApprovePreOnboardingRequestResponseObject, error) {
	p.record("AdminApprovePreOnboardingRequest")
	return openapi.AdminApprovePreOnboardingRequest200JSONResponse{}, nil
}

func (p *probeSSI) AdminRejectPreOnboardingRequest(ctx context.Context, request openapi.AdminRejectPreOnboardingRequestRequestObject) (openapi.AdminRejectPreOnboardingRequestResponseObject, error) {
	p.record("AdminRejectPreOnboardingRequest")
	return openapi.AdminRejectPreOnboardingRequest200JSONResponse{}, nil
}

func (p *probeSSI) AdminCreateDeviceRebindRequest(ctx context.Context, request openapi.AdminCreateDeviceRebindRequestRequestObject) (openapi.AdminCreateDeviceRebindRequestResponseObject, error) {
	p.record("AdminCreateDeviceRebindRequest")
	return openapi.AdminCreateDeviceRebindRequest201JSONResponse{}, nil
}

func (p *probeSSI) AdminApproveDeviceRebindRequest(ctx context.Context, request openapi.AdminApproveDeviceRebindRequestRequestObject) (openapi.AdminApproveDeviceRebindRequestResponseObject, error) {
	p.record("AdminApproveDeviceRebindRequest")
	return openapi.AdminApproveDeviceRebindRequest200JSONResponse{}, nil
}

func (p *probeSSI) AdminCreateRevocationRequest(ctx context.Context, request openapi.AdminCreateRevocationRequestRequestObject) (openapi.AdminCreateRevocationRequestResponseObject, error) {
	p.record("AdminCreateRevocationRequest")
	return openapi.AdminCreateRevocationRequest202JSONResponse{}, nil
}

func (p *probeSSI) AdminCreateTemporaryPrincipal(ctx context.Context, request openapi.AdminCreateTemporaryPrincipalRequestObject) (openapi.AdminCreateTemporaryPrincipalResponseObject, error) {
	p.record("AdminCreateTemporaryPrincipal")
	return openapi.AdminCreateTemporaryPrincipal201JSONResponse{}, nil
}

func (p *probeSSI) AdminDisableTemporaryPrincipal(ctx context.Context, request openapi.AdminDisableTemporaryPrincipalRequestObject) (openapi.AdminDisableTemporaryPrincipalResponseObject, error) {
	p.record("AdminDisableTemporaryPrincipal")
	return openapi.AdminDisableTemporaryPrincipal200JSONResponse{}, nil
}

func (p *probeSSI) AdminGetRevocationRequest(ctx context.Context, request openapi.AdminGetRevocationRequestRequestObject) (openapi.AdminGetRevocationRequestResponseObject, error) {
	p.record("AdminGetRevocationRequest")
	return openapi.AdminGetRevocationRequest200JSONResponse{}, nil
}

func (p *probeSSI) AdminListRevocationCertificates(ctx context.Context, request openapi.AdminListRevocationCertificatesRequestObject) (openapi.AdminListRevocationCertificatesResponseObject, error) {
	p.record("AdminListRevocationCertificates")
	return openapi.AdminListRevocationCertificates200JSONResponse{}, nil
}

const (
	validIdempotencyKey = "0123456789abcdef"
	validEnrollmentBody = `{"operation":"INITIAL","certificate_usage":"PARTNER_AUTH"}`
)

// m3BearerToken returns the deterministic harness bearer token for a kind.
func m3BearerToken(kind authpolicy.CredentialKind) string {
	return "m3-token-" + string(kind)
}

// testAuthnRegistry returns a deterministic registry whose bearer kinds each
// authenticate ONLY their own deterministic token, and whose DeviceMTLS kind
// accepts any device credential. One arbitrary bearer token can never
// authenticate as multiple kinds (SOL-M4.2-003), so multi-bearer-kind routes
// do not trigger artificial ambiguity.
func testAuthnRegistry() *authruntime.Registry {
	var auths []authruntime.Authenticator
	for _, kind := range []authpolicy.CredentialKind{
		authpolicy.CredentialKindHumanOIDC,
		authpolicy.CredentialKindAdminOIDC,
		authpolicy.CredentialKindTemporaryPrincipalToken,
		authpolicy.CredentialKindRequestAccessToken,
		authpolicy.CredentialKindEnrollmentAccessToken,
	} {
		want := m3BearerToken(kind)
		auths = append(auths, authruntime.BearerTestAuthenticator{
			KindValue: kind,
			Decide: func(token string) authruntime.Decision {
				if token == want {
					return authruntime.DecisionAuthenticated
				}
				return authruntime.DecisionRejected
			},
		})
	}
	auths = append(auths, authruntime.DeviceTestAuthenticator{
		Decide: func(device *authruntime.DeviceCredential) authruntime.Decision {
			if device == nil {
				return authruntime.DecisionRejected
			}
			return authruntime.DecisionAuthenticated
		},
	})
	r, err := authruntime.NewRegistry(auths...)
	if err != nil {
		panic(err)
	}
	return r
}

// testDeviceSource always provides a device credential (deterministic double).
func testDeviceSource() authruntime.DeviceMTLSSource {
	return authruntime.DeviceTestSource{Credential: func(r *http.Request) (*authruntime.DeviceCredential, error) {
		return &authruntime.DeviceCredential{}, nil
	}}
}

// m3RouteTokens derives, once, the deterministic harness bearer token for
// every contract route that has exactly one eligible bearer CredentialKind.
// Public routes and multi-bearer-kind routes are omitted; those tests pass an
// explicit Authorization header.
var m3RouteTokens = sync.OnceValue(func() map[string]string {
	spec, err := openapi.GetSpec()
	if err != nil {
		return nil
	}
	pol, err := authpolicy.Compile(spec)
	if err != nil {
		return nil
	}
	m := map[string]string{}
	for _, op := range pol.Operations() {
		if op.NoApplicationCredential() {
			continue
		}
		var bearer []authpolicy.CredentialKind
		for _, alt := range op.Alternatives() {
			for _, k := range alt.Kinds() {
				if k != authpolicy.CredentialKindDeviceMTLS {
					bearer = appendUniqueKind(bearer, k)
				}
			}
		}
		if len(bearer) == 1 {
			m[strings.ToUpper(op.Method())+" "+op.Path()] = m3BearerToken(bearer[0])
		}
	}
	return m
})

// m3TokenForRoute resolves the harness bearer token for a concrete method and
// path, matching the spec path templates (exact first, then template).
func m3TokenForRoute(method, path string) string {
	path = strings.SplitN(path, "?", 2)[0]
	method = strings.ToUpper(method)
	key := method + " " + path
	if tok, ok := m3RouteTokens()[key]; ok {
		return tok
	}
	for key, tok := range m3RouteTokens() {
		sep := strings.IndexByte(key, ' ')
		if sep < 0 || key[:sep] != method {
			continue
		}
		if templateMatches(key[sep+1:], path) {
			return tok
		}
	}
	return ""
}

func templateMatches(template, concrete string) bool {
	t := strings.Split(strings.Trim(template, "/"), "/")
	c := strings.Split(strings.Trim(concrete, "/"), "/")
	if len(t) != len(c) {
		return false
	}
	for i := range t {
		if strings.HasPrefix(t[i], "{") && strings.HasSuffix(t[i], "}") {
			continue
		}
		if t[i] != c[i] {
			return false
		}
	}
	return true
}

func appendUniqueKind(kinds []authpolicy.CredentialKind, k authpolicy.CredentialKind) []authpolicy.CredentialKind {
	for _, x := range kinds {
		if x == k {
			return kinds
		}
	}
	return append(kinds, k)
}

func testAuthzRegistry() *authzruntime.Registry {
	r, _ := authzruntime.NewRegistry(authzruntime.AllowAllScopeAuthorizer(), authzruntime.AllowAllOpenEvaluator(), nil)
	return r
}

func newTestHandler(t testing.TB) (http.Handler, *probeSSI) {
	t.Helper()
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	srv, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(testAuthnRegistry()),
		httpapi.WithDeviceMTLSSource(testDeviceSource()),
		httpapi.WithAuthzRegistry(testAuthzRegistry()),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	p := &probeSSI{calls: map[string]int{}}
	return srv.Handler(p), p
}

func do(t testing.TB, h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if _, ok := headers["Authorization"]; !ok {
		// M4.2 authenticates before M3 enforcement; authenticated routes need
		// a kind-specific credential to reach the M3 boundary under test. The
		// token is derived from the contract route (not a handwritten table).
		if tok := m3TokenForRoute(method, path); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func problemBody(t testing.TB, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("response body is not JSON: %v (%q)", err, rr.Body.String())
	}
	return m
}

// A valid, unauthenticated route reaches the business handler and the server
// generates a correlation ID.
func TestTrustBundleRequestReachesHandler(t *testing.T) {
	h, p := newTestHandler(t)
	rr := do(t, h, "GET", "/v1/pki/trust-bundles/current", "", nil)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("GetCurrentTrustBundle") != 1 {
		t.Fatalf("handler calls = %d, want 1", p.count("GetCurrentTrustBundle"))
	}
	corr := rr.Header().Get("X-Correlation-ID")
	if len(corr) != 32 {
		t.Fatalf("generated correlation ID %q must be 32 hex chars", corr)
	}
}

// A provided, valid correlation ID is preserved end to end.
func TestCorrelationIDProvidedPreserved(t *testing.T) {
	h, p := newTestHandler(t)
	rr := do(t, h, "GET", "/v1/pki/trust-bundles/current", "", map[string]string{
		"X-Correlation-ID": "corr-abc-123",
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("X-Correlation-ID"); got != "corr-abc-123" {
		t.Fatalf("X-Correlation-ID = %q, want %q", got, "corr-abc-123")
	}
	if p.count("GetCurrentTrustBundle") != 1 {
		t.Fatal("handler was not called")
	}
}

// An invalid provided correlation ID fails the request; the response carries a
// fresh server-generated identifier.
func TestCorrelationIDInvalidRejected(t *testing.T) {
	h, p := newTestHandler(t)
	rr := do(t, h, "GET", "/v1/pki/trust-bundles/current", "", map[string]string{
		"X-Correlation-ID": "bad\nid",
	})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rr.Code, rr.Body.String())
	}
	if p.total() != 0 {
		t.Fatal("handler must not be called")
	}
	if got := rr.Header().Get("X-Correlation-ID"); got == "" || got == "bad\nid" {
		t.Fatalf("X-Correlation-ID = %q, want a fresh generated value", got)
	}
	m := problemBody(t, rr)
	if m["error_code"] != "INVALID_REQUEST" {
		t.Fatalf("error_code = %v", m["error_code"])
	}
}

// A fully valid POST /v1/enrollments passes enforcement and reaches the
// handler.
func TestValidEnrollmentRequestReachesHandler(t *testing.T) {
	h, p := newTestHandler(t)
	rr := do(t, h, "POST", "/v1/enrollments", validEnrollmentBody, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
	})

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("CreateEnrollment") != 1 {
		t.Fatal("CreateEnrollment handler was not called")
	}
}

// Content-Type parameters such as charset are accepted via media-type parsing.
func TestCharsetContentTypeAccepted(t *testing.T) {
	h, p := newTestHandler(t)
	rr := do(t, h, "POST", "/v1/enrollments", validEnrollmentBody, map[string]string{
		"Content-Type":    "application/json; charset=utf-8",
		"Idempotency-Key": validIdempotencyKey,
	})

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("CreateEnrollment") != 1 {
		t.Fatal("CreateEnrollment handler was not called")
	}
}

// Non-JSON media types are rejected with 415 before any processing.
func TestUnsupportedMediaType(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
	}{
		{"text/plain", "text/plain"},
		{"application/xml", "application/xml"},
		{"missing content type", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, p := newTestHandler(t)
			headers := map[string]string{"Idempotency-Key": validIdempotencyKey}
			if tc.contentType != "" {
				headers["Content-Type"] = tc.contentType
			}
			rr := do(t, h, "POST", "/v1/enrollments", validEnrollmentBody, headers)

			if rr.Code != http.StatusUnsupportedMediaType {
				t.Fatalf("status = %d, want 415 (body %s)", rr.Code, rr.Body.String())
			}
			if p.total() != 0 {
				t.Fatal("handler must not be called")
			}
			m := problemBody(t, rr)
			if m["error_code"] != "UNSUPPORTED_MEDIA_TYPE" {
				t.Fatalf("error_code = %v", m["error_code"])
			}
		})
	}
}

// Bodies over the effective JSON limit are rejected with 413. The 4 MiB+1
// stream below exceeds both the 256 KiB general JSON default and the 4 MiB
// absolute ceiling (the platform backstop).
func TestPayloadTooLargeWithContentLength(t *testing.T) {
	h, p := newTestHandler(t)
	big := strings.Repeat("a", 4<<20+1)
	rr := do(t, h, "POST", "/v1/enrollments", big, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
	})

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rr.Code)
	}
	if p.total() != 0 {
		t.Fatal("handler must not be called")
	}
	m := problemBody(t, rr)
	if m["error_code"] != "PAYLOAD_TOO_LARGE" {
		t.Fatalf("error_code = %v", m["error_code"])
	}
}

// The effective JSON limit also protects chunked streams without a trusted
// Content-Length.
func TestPayloadTooLargeChunked(t *testing.T) {
	h, p := newTestHandler(t)
	req := httptest.NewRequest("POST", "/v1/enrollments", nil)
	req.Body = io.NopCloser(strings.NewReader(strings.Repeat("a", 4<<20+1)))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", validIdempotencyKey)
	req.Header.Set("Authorization", "Bearer "+m3TokenForRoute("POST", "/v1/enrollments"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rr.Code)
	}
	if p.total() != 0 {
		t.Fatal("handler must not be called")
	}
}

// Malformed JSON is rejected with 400 before the handler.
func TestMalformedJSONRejected(t *testing.T) {
	h, p := newTestHandler(t)
	rr := do(t, h, "POST", "/v1/enrollments", `{"operation":`, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
	})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	if p.total() != 0 {
		t.Fatal("handler must not be called")
	}
}

// A second JSON document after the first is rejected.
func TestSecondJSONDocumentRejected(t *testing.T) {
	h, p := newTestHandler(t)
	rr := do(t, h, "POST", "/v1/enrollments", validEnrollmentBody+` {}`, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
	})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	if p.total() != 0 {
		t.Fatal("handler must not be called")
	}
}

// Duplicate JSON member names are rejected (Protocol SP-13).
func TestDuplicateMemberRejected(t *testing.T) {
	h, p := newTestHandler(t)
	rr := do(t, h, "POST", "/v1/enrollments",
		`{"operation":"INITIAL","operation":"RENEWAL","certificate_usage":"PARTNER_AUTH"}`, map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
		})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rr.Code, rr.Body.String())
	}
	if p.total() != 0 {
		t.Fatal("handler must not be called")
	}
}

// Unknown fields on a closed request schema are rejected with 400.
func TestUnknownFieldRejected(t *testing.T) {
	h, p := newTestHandler(t)
	rr := do(t, h, "POST", "/v1/enrollments",
		`{"operation":"INITIAL","certificate_usage":"PARTNER_AUTH","extra":true}`, map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
		})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rr.Code, rr.Body.String())
	}
	if p.total() != 0 {
		t.Fatal("handler must not be called")
	}
	m := problemBody(t, rr)
	if m["error_code"] != "INVALID_REQUEST" {
		t.Fatalf("error_code = %v", m["error_code"])
	}
}

// A missing required body is rejected.
func TestMissingRequiredBodyRejected(t *testing.T) {
	h, p := newTestHandler(t)
	req := httptest.NewRequest("POST", "/v1/enrollments", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", validIdempotencyKey)
	req.Header.Set("Authorization", "Bearer "+m3TokenForRoute("POST", "/v1/enrollments"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rr.Code, rr.Body.String())
	}
	if p.total() != 0 {
		t.Fatal("handler must not be called")
	}
}

// A missing required header parameter is rejected before the handler.
func TestMissingRequiredHeaderParameterRejected(t *testing.T) {
	h, p := newTestHandler(t)
	rr := do(t, h, "POST", "/v1/enrollments", validEnrollmentBody, map[string]string{
		"Content-Type": "application/json",
		// Idempotency-Key intentionally absent.
	})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rr.Code, rr.Body.String())
	}
	if p.total() != 0 {
		t.Fatal("handler must not be called")
	}
}

// An Idempotency-Key that fails the contract pattern is rejected.
func TestInvalidIdempotencyKeyFormatRejected(t *testing.T) {
	h, p := newTestHandler(t)
	rr := do(t, h, "POST", "/v1/enrollments", validEnrollmentBody, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": "too-short",
	})

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rr.Code, rr.Body.String())
	}
	if p.total() != 0 {
		t.Fatal("handler must not be called")
	}
}

// Problem responses are RFC 9457-shaped and carry the correlation ID in both
// header and body.
func TestProblemResponseShape(t *testing.T) {
	h, _ := newTestHandler(t)
	rr := do(t, h, "POST", "/v1/enrollments", validEnrollmentBody, map[string]string{
		"Content-Type":    "text/plain",
		"Idempotency-Key": validIdempotencyKey,
	})

	if got := rr.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want application/problem+json", got)
	}
	m := problemBody(t, rr)
	for _, field := range []string{"type", "title", "status", "error_code", "correlation_id", "retryable"} {
		if _, ok := m[field]; !ok {
			t.Fatalf("problem body misses required field %q: %v", field, m)
		}
	}
	if m["status"] != float64(http.StatusUnsupportedMediaType) {
		t.Fatalf("status = %v", m["status"])
	}
	headerCorr := rr.Header().Get("X-Correlation-ID")
	if m["correlation_id"] != headerCorr {
		t.Fatalf("correlation_id = %v, header = %q", m["correlation_id"], headerCorr)
	}
}

// Paths outside the contract are left to the generated router (routing
// outcomes belong to it, not to contract enforcement).
func TestUnknownPathPassesThroughToRouter(t *testing.T) {
	h, p := newTestHandler(t)
	rr := do(t, h, "GET", "/v1/definitely/not/a/route", "", nil)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
	if p.total() != 0 {
		t.Fatal("handler must not be called")
	}
}
