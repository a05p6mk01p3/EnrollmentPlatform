package httpapi_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
)

// matrixCase is one authentication-policy matrix entry. The conditional
// branches of createEnrollment and completeEnrollment are separate cases of
// the same OpenAPI operation, exactly as the contract's authentication matrix
// describes them.
type matrixCase struct {
	name      string
	opID      string
	method    string
	path      string
	body      string
	headers   map[string]string
	want      []authpolicy.CredentialKind // nil means anonymous (security: [])
	disc      string                      // conditional discriminator property ("" if none)
	discValue string                      // conditional discriminator value for this case ("" if none)
	handler   string
	status    int
}

// matrixHeaders returns the shared base headers for a body-bearing operation
// plus any case-specific required headers (Idempotency-Key, If-Match).
func matrixHeaders(idempotent, ifMatch bool) map[string]string {
	h := map[string]string{"Content-Type": "application/json"}
	if idempotent {
		h["Idempotency-Key"] = validIdempotencyKey
	}
	if ifMatch {
		h["If-Match"] = `"4"`
	}
	return h
}

// authenticationMatrix is the explicit M4.6 expected matrix (§4). It is an
// independent parity oracle: the parity test cross-checks it against the
// compiled M4.1 policy.
func authenticationMatrix() []matrixCase {
	return []matrixCase{
		{
			name: "getMyAuthorizations", opID: "getMyAuthorizations",
			method: "GET", path: "/v1/me/authorizations",
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindHumanOIDC},
			handler: "GetMyAuthorizations", status: http.StatusOK,
		},
		{
			name: "createPreOnboardingRequest", opID: "createPreOnboardingRequest",
			method: "POST", path: "/v1/pre-onboarding-requests",
			body:    `{"partner_id":"P1","claimed_device":{"hostname":"PC-001"},"agent":{"version":"1.0.0","platform":"windows"}}`,
			headers: matrixHeaders(true, false),
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindHumanOIDC, authpolicy.CredentialKindTemporaryPrincipalToken},
			handler: "CreatePreOnboardingRequest", status: http.StatusCreated,
		},
		{
			name: "getPreOnboardingRequest", opID: "getPreOnboardingRequest",
			method: "GET", path: "/v1/pre-onboarding-requests/por-123",
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindHumanOIDC, authpolicy.CredentialKindRequestAccessToken},
			handler: "GetPreOnboardingRequest", status: http.StatusOK,
		},
		{
			name: "createEnrollment INITIAL", opID: "createEnrollment",
			method: "POST", path: "/v1/enrollments",
			body:    `{"operation":"INITIAL","certificate_usage":"PARTNER_AUTH"}`,
			headers: matrixHeaders(true, false),
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindRequestAccessToken},
			disc:    "operation", discValue: "INITIAL",
			handler: "CreateEnrollment", status: http.StatusCreated,
		},
		{
			name: "createEnrollment RENEWAL", opID: "createEnrollment",
			method: "POST", path: "/v1/enrollments",
			body:    `{"operation":"RENEWAL","certificate_usage":"PARTNER_AUTH"}`,
			headers: matrixHeaders(true, false),
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindDeviceMTLS},
			disc:    "operation", discValue: "RENEWAL",
			handler: "CreateEnrollment", status: http.StatusCreated,
		},
		{
			name: "createEnrollment REKEY", opID: "createEnrollment",
			method: "POST", path: "/v1/enrollments",
			body:    `{"operation":"REKEY","certificate_usage":"PARTNER_AUTH"}`,
			headers: matrixHeaders(true, false),
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindDeviceMTLS},
			disc:    "operation", discValue: "REKEY",
			handler: "CreateEnrollment", status: http.StatusCreated,
		},
		{
			name: "getEnrollment", opID: "getEnrollment",
			method: "GET", path: "/v1/enrollments/enr-123",
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindEnrollmentAccessToken},
			handler: "GetEnrollment", status: http.StatusOK,
		},
		{
			name: "submitEnrollmentEvidence", opID: "submitEnrollmentEvidence",
			method: "PUT", path: "/v1/enrollments/enr-123/evidence",
			body:    evidenceBody("TUlJQkNTUl9ERVI="),
			headers: map[string]string{"Content-Type": "application/json"},
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindEnrollmentAccessToken},
			handler: "SubmitEnrollmentEvidence", status: http.StatusAccepted,
		},
		{
			name: "refreshEnrollmentChallenge", opID: "refreshEnrollmentChallenge",
			method: "POST", path: "/v1/enrollments/enr-123/challenge:refresh",
			body:    `{"expected_challenge_version":1}`,
			headers: matrixHeaders(true, false),
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindEnrollmentAccessToken},
			handler: "RefreshEnrollmentChallenge", status: http.StatusOK,
		},
		{
			name: "getEnrollmentCertificate", opID: "getEnrollmentCertificate",
			method: "GET", path: "/v1/enrollments/enr-123/certificate",
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindEnrollmentAccessToken},
			handler: "GetEnrollmentCertificate", status: http.StatusOK,
		},
		{
			name: "completeEnrollment INSTALLED", opID: "completeEnrollment",
			method: "POST", path: "/v1/enrollments/enr-123/complete",
			body:    `{"installation_status":"INSTALLED"}`,
			headers: matrixHeaders(true, false),
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindDeviceMTLS},
			disc:    "installation_status", discValue: "INSTALLED",
			handler: "CompleteEnrollment", status: http.StatusOK,
		},
		{
			name: "completeEnrollment FAILED", opID: "completeEnrollment",
			method: "POST", path: "/v1/enrollments/enr-123/complete",
			body:    `{"installation_status":"FAILED","error_code":"AGENT_INSTALL_FAILED"}`,
			headers: matrixHeaders(true, false),
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindEnrollmentAccessToken},
			disc:    "installation_status", discValue: "FAILED",
			handler: "CompleteEnrollment", status: http.StatusOK,
		},
		{
			name: "getCurrentTrustBundle", opID: "getCurrentTrustBundle",
			method: "GET", path: "/v1/pki/trust-bundles/current",
			want:    nil, // anonymous: security: []
			handler: "GetCurrentTrustBundle", status: http.StatusOK,
		},
		{
			name: "adminListPreOnboardingRequests", opID: "adminListPreOnboardingRequests",
			method: "GET", path: "/v1/admin/pre-onboarding-requests",
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindAdminOIDC},
			handler: "AdminListPreOnboardingRequests", status: http.StatusOK,
		},
		{
			name: "adminGetPreOnboardingRequest", opID: "adminGetPreOnboardingRequest",
			method: "GET", path: "/v1/admin/pre-onboarding-requests/por-123",
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindAdminOIDC},
			handler: "AdminGetPreOnboardingRequest", status: http.StatusOK,
		},
		{
			name: "adminApprovePreOnboardingRequest", opID: "adminApprovePreOnboardingRequest",
			method: "POST", path: "/v1/admin/pre-onboarding-requests/por-123/approve",
			body:    `{"reason":"approved","expected_status":"PENDING_APPROVAL"}`,
			headers: matrixHeaders(true, true),
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindAdminOIDC},
			handler: "AdminApprovePreOnboardingRequest", status: http.StatusOK,
		},
		{
			name: "adminRejectPreOnboardingRequest", opID: "adminRejectPreOnboardingRequest",
			method: "POST", path: "/v1/admin/pre-onboarding-requests/por-123/reject",
			body:    `{"reason":"not approved","expected_status":"PENDING_APPROVAL"}`,
			headers: matrixHeaders(true, true),
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindAdminOIDC},
			handler: "AdminRejectPreOnboardingRequest", status: http.StatusOK,
		},
		{
			name: "adminCreateDeviceRebindRequest", opID: "adminCreateDeviceRebindRequest",
			method: "POST", path: "/v1/admin/devices/dev-123/rebind-requests",
			body:    `{"reason":"TPM_REPLACED"}`,
			headers: matrixHeaders(true, false),
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindAdminOIDC},
			handler: "AdminCreateDeviceRebindRequest", status: http.StatusCreated,
		},
		{
			name: "adminApproveDeviceRebindRequest", opID: "adminApproveDeviceRebindRequest",
			method: "POST", path: "/v1/admin/device-rebind-requests/rbr-123/approve",
			body:    `{"reason":"hardware replacement validated"}`,
			headers: matrixHeaders(true, true),
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindAdminOIDC},
			handler: "AdminApproveDeviceRebindRequest", status: http.StatusOK,
		},
		{
			name: "adminCreateRevocationRequest", opID: "adminCreateRevocationRequest",
			method: "POST", path: "/v1/admin/certificates/cert-123/revocations",
			body:    `{"reason":"KEY_COMPROMISE","scope":"KEY"}`,
			headers: matrixHeaders(true, false),
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindAdminOIDC},
			handler: "AdminCreateRevocationRequest", status: http.StatusAccepted,
		},
		{
			name: "adminCreateTemporaryPrincipal", opID: "adminCreateTemporaryPrincipal",
			method: "POST", path: "/v1/admin/temporary-principals",
			body:    `{"partner_id":"P1","expires_at":"2026-08-21T03:00:00Z","max_submissions":5,"reason":"contingency"}`,
			headers: matrixHeaders(true, false),
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindAdminOIDC},
			handler: "AdminCreateTemporaryPrincipal", status: http.StatusCreated,
		},
		{
			name: "adminDisableTemporaryPrincipal", opID: "adminDisableTemporaryPrincipal",
			method: "POST", path: "/v1/admin/temporary-principals/tp-123/disable",
			body:    `{"reason":"contingency ended"}`,
			headers: matrixHeaders(true, false),
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindAdminOIDC},
			handler: "AdminDisableTemporaryPrincipal", status: http.StatusOK,
		},
		{
			name: "adminGetRevocationRequest", opID: "adminGetRevocationRequest",
			method: "GET", path: "/v1/admin/revocation-requests/rev-123",
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindAdminOIDC},
			handler: "AdminGetRevocationRequest", status: http.StatusOK,
		},
		{
			name: "adminListRevocationCertificates", opID: "adminListRevocationCertificates",
			method: "GET", path: "/v1/admin/revocation-requests/rev-123/certificates",
			want:    []authpolicy.CredentialKind{authpolicy.CredentialKindAdminOIDC},
			handler: "AdminListRevocationCertificates", status: http.StatusOK,
		},
	}
}

// matrixRegistry accepts exactly one deterministic token per bearer kind and
// any device credential for DeviceMTLS, so a single bearer token can never
// authenticate as more than one kind.
func matrixRegistry(t *testing.T) *authruntime.Registry {
	t.Helper()
	return registry(t,
		acceptOnly(authpolicy.CredentialKindHumanOIDC, tokHuman),
		acceptOnly(authpolicy.CredentialKindAdminOIDC, tokAdmin),
		acceptOnly(authpolicy.CredentialKindTemporaryPrincipalToken, tokTemp),
		acceptOnly(authpolicy.CredentialKindRequestAccessToken, tokReq),
		acceptOnly(authpolicy.CredentialKindEnrollmentAccessToken, tokEnroll),
		acceptDeviceMTLS(),
	)
}

// matrixDeviceSource provides a device credential only when the request
// carries the test device marker. This keeps DeviceMTLS from silently
// authenticating bearer-required matrix cases while still allowing the
// DeviceMTLS branches to succeed.
const matrixDeviceHeader = "X-Test-Device"

func matrixDeviceSource() authruntime.DeviceMTLSSource {
	return authruntime.DeviceTestSource{Credential: func(r *http.Request) (*authruntime.DeviceCredential, error) {
		if r.Header.Get(matrixDeviceHeader) == "1" {
			return &authruntime.DeviceCredential{}, nil
		}
		return nil, nil
	}}
}

func matrixHandler(t *testing.T) (http.Handler, *probeSSI) {
	t.Helper()
	h, p := newAuthTestHandler(t, matrixRegistry(t), matrixDeviceSource())
	return h, &p.probeSSI
}

func matrixToken(kind authpolicy.CredentialKind) string {
	switch kind {
	case authpolicy.CredentialKindHumanOIDC:
		return tokHuman
	case authpolicy.CredentialKindAdminOIDC:
		return tokAdmin
	case authpolicy.CredentialKindTemporaryPrincipalToken:
		return tokTemp
	case authpolicy.CredentialKindRequestAccessToken:
		return tokReq
	case authpolicy.CredentialKindEnrollmentAccessToken:
		return tokEnroll
	default:
		return ""
	}
}

func matrixRequest(t *testing.T, h http.Handler, tc matrixCase, kind authpolicy.CredentialKind) *httptest.ResponseRecorder {
	t.Helper()
	headers := map[string]string{}
	for k, v := range tc.headers {
		headers[k] = v
	}
	switch kind {
	case authpolicy.CredentialKindDeviceMTLS:
		headers[matrixDeviceHeader] = "1"
	default:
		headers["Authorization"] = "Bearer " + matrixToken(kind)
	}
	return doAuth(t, h, tc.method, tc.path, tc.body, headers)
}

func wants(tc matrixCase, kind authpolicy.CredentialKind) bool {
	for _, k := range tc.want {
		if k == kind {
			return true
		}
	}
	return false
}

var allSixKinds = []authpolicy.CredentialKind{
	authpolicy.CredentialKindHumanOIDC,
	authpolicy.CredentialKindAdminOIDC,
	authpolicy.CredentialKindTemporaryPrincipalToken,
	authpolicy.CredentialKindRequestAccessToken,
	authpolicy.CredentialKindEnrollmentAccessToken,
	authpolicy.CredentialKindDeviceMTLS,
}

// TestAuthenticationMatrixPositive proves that every contracted operation (and
// every conditional branch) reaches its handler exactly when the correct
// credential kind is presented, through the real router/middleware pipeline.
func TestAuthenticationMatrixPositive(t *testing.T) {
	cases := authenticationMatrix()
	if len(cases) != 24 {
		t.Fatalf("matrix has %d cases; want 24 (21 operations with 3 createEnrollment + 2 completeEnrollment branches)", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.want == nil {
				// Anonymous operation: no credential of any kind is required.
				h, p := matrixHandler(t)
				rr := doAuth(t, h, tc.method, tc.path, tc.body, tc.headers)
				if rr.Code != tc.status {
					t.Fatalf("status = %d, want %d (body %s)", rr.Code, tc.status, rr.Body.String())
				}
				if p.count(tc.handler) != 1 {
					t.Fatalf("%s calls = %d, want 1", tc.handler, p.count(tc.handler))
				}
				return
			}
			for _, kind := range tc.want {
				t.Run(string(kind), func(t *testing.T) {
					h, p := matrixHandler(t)
					rr := matrixRequest(t, h, tc, kind)

					wantStatus, wantCalls := tc.status, 1
					switch {
					case tc.opID == "getMyAuthorizations":
						// M5.2 owns this operation: it is answered directly by the
						// partner authorization boundary and the inner handler is
						// never invoked.
						wantCalls = 0
					case tc.opID == "createPreOnboardingRequest" && kind == authpolicy.CredentialKindTemporaryPrincipalToken:
						// A synthetically authenticated Temporary Principal passes
						// authentication but is blocked by the M5.2 boundary before
						// the protected mutation: the later mandatory gates
						// (concrete production token verifier/bootstrap and
						// transactional max_submissions consumption) are
						// unavailable, so the boundary answers fail-closed.
						wantStatus, wantCalls = http.StatusServiceUnavailable, 0
					}
					if rr.Code != wantStatus {
						t.Fatalf("status = %d, want %d (body %s)", rr.Code, wantStatus, rr.Body.String())
					}
					if p.count(tc.handler) != wantCalls {
						t.Fatalf("%s calls = %d, want %d", tc.handler, p.count(tc.handler), wantCalls)
					}
					switch tc.opID {
					case "getMyAuthorizations":
						body := jsonBody(t, rr)
						if _, ok := body["principal_id"]; !ok {
							t.Fatalf("M5.2 response lacks principal_id: %v", body)
						}
						if _, ok := body["partners"]; !ok {
							t.Fatalf("M5.2 response lacks partners: %v", body)
						}
					case "createPreOnboardingRequest":
						if kind == authpolicy.CredentialKindTemporaryPrincipalToken {
							m := problemBody(t, rr)
							if m["error_code"] != "DEPENDENCY_UNAVAILABLE" {
								t.Fatalf("error_code = %v, want DEPENDENCY_UNAVAILABLE", m["error_code"])
							}
						}
					}
				})
			}
		})
	}
}

// TestAuthenticationMatrixNegative proves that every wrong credential kind
// fails closed (401) and never reaches the handler, across the complete
// cross-product of case x non-allowed kind.
func TestAuthenticationMatrixNegative(t *testing.T) {
	for _, tc := range authenticationMatrix() {
		if tc.want == nil {
			continue // anonymous operation has no wrong-kind pairing
		}
		for _, kind := range allSixKinds {
			if wants(tc, kind) {
				continue
			}
			t.Run(tc.name+"+"+string(kind), func(t *testing.T) {
				h, p := matrixHandler(t)
				rr := matrixRequest(t, h, tc, kind)
				assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
				assertNoHandlerCall(t, p)
			})
		}
	}
}

// TestAuthenticationMatrixParityWithCompiledPolicy cross-checks the explicit
// expected matrix against the compiled M4.1 policy (contract-drift oracle).
// A drift in the spec's security metadata, conditional mapping, or
// anonymous/protected classification fails here even if the HTTP assertions
// above would still pass against a stale expectation.
func TestAuthenticationMatrixParityWithCompiledPolicy(t *testing.T) {
	spec, err := openapi.GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := authpolicy.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.OperationCount() != 21 {
		t.Fatalf("compiled operation count = %d; want 21", compiled.OperationCount())
	}

	cases := authenticationMatrix()
	if len(cases) != 24 {
		t.Fatalf("matrix has %d cases; want 24", len(cases))
	}

	for _, tc := range cases {
		op, ok := compiled.Operation(tc.opID)
		if !ok {
			t.Errorf("case %q references operation %q not present in compiled policy", tc.name, tc.opID)
			continue
		}
		if tc.want == nil {
			if !op.NoApplicationCredential() {
				t.Errorf("case %q is anonymous in the matrix but compiled policy requires a credential: %s", tc.name, op)
			}
			continue
		}
		if tc.disc != "" {
			// Conditional branch: the compiled ConditionalSecurity case must
			// mandate exactly the matrix's single required kind.
			cond := op.Conditional()
			if cond == nil {
				t.Errorf("case %q expects discriminator %q but compiled policy has no conditional security", tc.name, tc.disc)
				continue
			}
			if cond.Discriminator() != tc.disc {
				t.Errorf("case %q discriminator = %q; want %q", tc.name, cond.Discriminator(), tc.disc)
			}
			req, ok := cond.RequirementFor(tc.discValue)
			if !ok {
				t.Errorf("case %q: compiled conditional has no case for discriminator value %q", tc.name, tc.discValue)
				continue
			}
			kinds := req.Kinds()
			if len(kinds) != 1 || kinds[0] != tc.want[0] {
				t.Errorf("case %q conditional %s=%q mandates %v; want %q", tc.name, tc.disc, tc.discValue, kinds, tc.want[0])
			}
			continue
		}
		// Non-conditional authenticated operation: the union of base
		// alternatives must equal the matrix's allowed set.
		got := map[authpolicy.CredentialKind]bool{}
		for _, alt := range op.Alternatives() {
			for _, k := range alt.Kinds() {
				got[k] = true
			}
		}
		if len(got) != len(tc.want) {
			t.Errorf("case %q base kinds = %v; want %v", tc.name, got, tc.want)
			continue
		}
		for _, k := range tc.want {
			if !got[k] {
				t.Errorf("case %q base kinds = %v; want %v", tc.name, got, tc.want)
				break
			}
		}
	}
}

// TestMixedAuthenticationConcurrencyIsolation runs concurrent requests that
// mix all six credential kinds, distinct resource IDs, and both successful and
// failing requests, then verifies that each recorded authentication context
// carries exactly its own kind and resource binding. It is the M4.6 §14
// cross-request isolation proof and is exercised by `go test -race`.
func TestMixedAuthenticationConcurrencyIsolation(t *testing.T) {
	h, p := newAuthTestHandler(t, matrixRegistry(t), matrixDeviceSource())

	const rounds = 6
	type role struct {
		name       string
		method     string
		path       string
		body       string
		headers    map[string]string
		wantStatus int
		wantCall   string
	}

	roles := []role{
		{
			// M5.2 owns GET /v1/me/authorizations: the HumanOIDC request
			// succeeds through the partner authorization boundary without
			// invoking the inner probe handler (wantCall is empty).
			name: "HumanOIDC", method: "GET", path: "/v1/me/authorizations",
			wantStatus: http.StatusOK, wantCall: "",
			headers: map[string]string{"Authorization": "Bearer " + tokHuman},
		},
		{
			name: "AdminOIDC", method: "GET", path: "/v1/admin/pre-onboarding-requests",
			wantStatus: http.StatusOK, wantCall: "AdminListPreOnboardingRequests",
			headers: map[string]string{"Authorization": "Bearer " + tokAdmin},
		},
		{
			name: "RequestAccessToken", method: "GET",
			path:       "/v1/pre-onboarding-requests/por-0",
			wantStatus: http.StatusOK, wantCall: "GetPreOnboardingRequest",
			headers: map[string]string{"Authorization": "Bearer " + tokReq},
		},
		{
			name: "EnrollmentAccessToken", method: "GET",
			path:       "/v1/enrollments/enr-0",
			wantStatus: http.StatusOK, wantCall: "GetEnrollment",
			headers: map[string]string{"Authorization": "Bearer " + tokEnroll},
		},
		{
			name: "DeviceMTLS", method: "POST",
			path: "/v1/enrollments/enr-0/complete",
			body: `{"installation_status":"INSTALLED"}`,
			headers: map[string]string{
				"Content-Type":     "application/json",
				"Idempotency-Key":  validIdempotencyKey,
				matrixDeviceHeader: "1",
			},
			wantStatus: http.StatusOK, wantCall: "CompleteEnrollment",
		},
		{
			name: "Failure", method: "GET", path: "/v1/me/authorizations",
			wantStatus: http.StatusUnauthorized, wantCall: "",
			headers: map[string]string{"Authorization": "Bearer " + tokAdmin},
		},
	}

	const workers = 24
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				role := &roles[w%len(roles)]
				path := role.path
				switch role.wantCall {
				case "GetPreOnboardingRequest":
					path = fmt.Sprintf("/v1/pre-onboarding-requests/por-%d", w)
				case "GetEnrollment":
					path = fmt.Sprintf("/v1/enrollments/enr-%d", w)
				case "CompleteEnrollment":
					path = fmt.Sprintf("/v1/enrollments/enr-%d/complete", w)
				}
				headers := map[string]string{}
				for k, v := range role.headers {
					headers[k] = v
				}
				rr := doAuth(t, h, role.method, path, role.body, headers)
				if rr.Code != role.wantStatus {
					errs <- fmt.Errorf("%s (worker %d): status = %d, want %d (body %s)", role.name, w, rr.Code, role.wantStatus, rr.Body.String())
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	// Failure role must never reach a handler; the M5.2-owned HumanOIDC role
	// succeeds through the M5.2 boundary without invoking the probe; every
	// other success worker invokes exactly one handler per round.
	expected := 0
	for w := 0; w < workers; w++ {
		if roles[w%len(roles)].wantCall != "" {
			expected += rounds
		}
	}
	if p.total() != expected {
		t.Fatalf("total handler calls = %d; want %d", p.total(), expected)
	}

	// Every recorded context carries exactly its own request's kind and a
	// resource binding derived from the real route (never the test fallback),
	// with no cross-request contamination. The HumanOIDC role is answered by
	// the M5.2 boundary and therefore records no probe context.
	for _, ac := range p.contextSnapshot() {
		if ac == nil {
			t.Fatal("handler observed a nil authentication context")
		}
		switch ac.OperationID() {
		case "getEnrollment":
			b, ok := ac.Binding(authpolicy.CredentialKindEnrollmentAccessToken)
			if !ok {
				t.Fatalf("getEnrollment context lacks EnrollmentAccessToken binding")
			}
			e, ok := b.EnrollmentAccess()
			if !ok || !strings.HasPrefix(e.EnrollmentID, "enr-") {
				t.Fatalf("getEnrollment binding EnrollmentID = %q; want route-derived enr-<n>", e.EnrollmentID)
			}
		case "completeEnrollment":
			b, ok := ac.Binding(authpolicy.CredentialKindDeviceMTLS)
			if !ok {
				t.Fatalf("completeEnrollment context lacks DeviceMTLS binding")
			}
			d, ok := b.DeviceMTLS()
			if !ok || !strings.HasPrefix(d.IssuedForEnrollmentID, "enr-") {
				t.Fatalf("completeEnrollment binding IssuedForEnrollmentID = %q; want route-derived enr-<n>", d.IssuedForEnrollmentID)
			}
		default:
			t.Fatalf("unexpected recorded operation %q", ac.OperationID())
		}
	}
}

// addSimCredential adds a single credential signal (bearer token for bearer
// kinds, the device marker for DeviceMTLS) to the request headers, so a
// request can carry a bearer credential and a device credential
// simultaneously.
func addSimCredential(headers map[string]string, kind authpolicy.CredentialKind) {
	if kind == authpolicy.CredentialKindDeviceMTLS {
		headers[matrixDeviceHeader] = "1"
		return
	}
	headers["Authorization"] = "Bearer " + matrixToken(kind)
}

// simHeaders builds the base JSON headers plus the given credential signals.
func simHeaders(kinds ...authpolicy.CredentialKind) map[string]string {
	h := map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
	}
	for _, k := range kinds {
		addSimCredential(h, k)
	}
	return h
}

// TestConditionalAuthenticationIgnoresIrrelevantSimultaneousCredential is the
// SOL-M4.6-002 proof. For every conditional branch it runs through the real
// router/middleware pipeline with the required credential alongside an
// irrelevant (but valid) credential — a positive control — and with only the
// irrelevant credential — a negative that must fail closed with zero handler
// invocation. A valid credential that the discriminator did not select can
// never rescue the request.
func TestConditionalAuthenticationIgnoresIrrelevantSimultaneousCredential(t *testing.T) {
	cases := []struct {
		name                 string
		method               string
		path                 string
		body                 string
		wantCall             string
		wantStatus           int
		required, irrelevant authpolicy.CredentialKind
	}{
		{
			name: "INITIAL", method: "POST", path: "/v1/enrollments",
			body:     `{"operation":"INITIAL","certificate_usage":"PARTNER_AUTH"}`,
			wantCall: "CreateEnrollment", wantStatus: http.StatusCreated,
			required:   authpolicy.CredentialKindRequestAccessToken,
			irrelevant: authpolicy.CredentialKindDeviceMTLS,
		},
		{
			name: "RENEWAL", method: "POST", path: "/v1/enrollments",
			body:     `{"operation":"RENEWAL","certificate_usage":"PARTNER_AUTH"}`,
			wantCall: "CreateEnrollment", wantStatus: http.StatusCreated,
			required:   authpolicy.CredentialKindDeviceMTLS,
			irrelevant: authpolicy.CredentialKindRequestAccessToken,
		},
		{
			name: "REKEY", method: "POST", path: "/v1/enrollments",
			body:     `{"operation":"REKEY","certificate_usage":"PARTNER_AUTH"}`,
			wantCall: "CreateEnrollment", wantStatus: http.StatusCreated,
			required:   authpolicy.CredentialKindDeviceMTLS,
			irrelevant: authpolicy.CredentialKindRequestAccessToken,
		},
		{
			name: "INSTALLED", method: "POST", path: "/v1/enrollments/enr-123/complete",
			body:     `{"installation_status":"INSTALLED"}`,
			wantCall: "CompleteEnrollment", wantStatus: http.StatusOK,
			required:   authpolicy.CredentialKindDeviceMTLS,
			irrelevant: authpolicy.CredentialKindEnrollmentAccessToken,
		},
		{
			name: "FAILED", method: "POST", path: "/v1/enrollments/enr-123/complete",
			body:     `{"installation_status":"FAILED","error_code":"AGENT_INSTALL_FAILED"}`,
			wantCall: "CompleteEnrollment", wantStatus: http.StatusOK,
			required:   authpolicy.CredentialKindEnrollmentAccessToken,
			irrelevant: authpolicy.CredentialKindDeviceMTLS,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name+"/positive-control-required-and-irrelevant-present", func(t *testing.T) {
			h, p := matrixHandler(t)
			rr := doAuth(t, h, tc.method, tc.path, tc.body, simHeaders(tc.required, tc.irrelevant))
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if p.count(tc.wantCall) != 1 {
				t.Fatalf("%s calls = %d, want 1", tc.wantCall, p.count(tc.wantCall))
			}
		})
		t.Run(tc.name+"/negative-irrelevant-only-cannot-rescue", func(t *testing.T) {
			h, p := matrixHandler(t)
			rr := doAuth(t, h, tc.method, tc.path, tc.body, simHeaders(tc.irrelevant))
			assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
			assertNoHandlerCall(t, p)
		})
	}
}
