package httpapi_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-chi/chi/v5"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi/middleware"
)

// newHandlerWithEnforcer wires the generated router with a custom enforcer,
// mirroring Server.Handler but allowing divergent specs in tests.
func newHandlerWithEnforcer(t testing.TB, spec *openapi3.T) (http.Handler, *probeSSI) {
	t.Helper()
	enforcer, err := middleware.NewEnforcer(spec, 262144, 4<<20)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	p := &probeSSI{calls: map[string]int{}}
	strictSI := openapi.NewStrictHandler(p, nil)
	router := openapi.HandlerWithOptions(strictSI, openapi.ChiServerOptions{
		Middlewares: []openapi.MiddlewareFunc{
			openapi.MiddlewareFunc(enforcer.OperationMiddleware()),
		},
	})
	return middleware.Correlation(router), p
}

// A. Fail-closed: when the generated router matches a route but the enforcer
// cannot map it to a contract operation, the handler must never run.
func TestEnforcementFailClosedWhenOperationUnknown(t *testing.T) {
	spec, err := openapi.GetSpec()
	if err != nil {
		t.Fatalf("GetSpec: %v", err)
	}
	spec.Paths = openapi3.NewPaths() // enforcer knows no operations

	h, p := newHandlerWithEnforcer(t, spec)
	rr := do(t, h, "GET", "/v1/pki/trust-bundles/current", "", nil)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (fail closed), body %s", rr.Code, rr.Body.String())
	}
	if p.total() != 0 {
		t.Fatal("handler ran without contract enforcement")
	}
	m := problemBody(t, rr)
	if m["error_code"] != "INTERNAL_ERROR" {
		t.Fatalf("error_code = %v, want INTERNAL_ERROR", m["error_code"])
	}
}

// Fail-closed is per operation: a route missing from the enforcer's spec
// fails, while operations still present continue to be enforced normally.
func TestEnforcementFailClosedPerOperation(t *testing.T) {
	spec, err := openapi.GetSpec()
	if err != nil {
		t.Fatalf("GetSpec: %v", err)
	}
	// Drop one operation from the enforcer's view only.
	data, merr := json.Marshal(spec)
	if merr != nil {
		t.Fatalf("marshal: %v", merr)
	}
	doc := map[string]any{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	delete(doc["paths"].(map[string]any), "/v1/pki/trust-bundles/current")
	reducedData, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal reduced: %v", err)
	}
	reduced, err := openapi3.NewLoader().LoadFromData(reducedData)
	if err != nil {
		t.Fatalf("load reduced: %v", err)
	}

	h, p := newHandlerWithEnforcer(t, reduced)

	rr := do(t, h, "GET", "/v1/pki/trust-bundles/current", "", nil)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("dropped operation: status = %d, want 500 (fail closed)", rr.Code)
	}
	if p.total() != 0 {
		t.Fatal("handler ran without contract enforcement")
	}

	rr2 := do(t, h, "GET", "/v1/me/authorizations", "", nil)
	if rr2.Code != http.StatusOK {
		t.Fatalf("kept operation: status = %d, want 200 (body %s)", rr2.Code, rr2.Body.String())
	}
	if p.count("GetMyAuthorizations") != 1 {
		t.Fatal("kept operation was not enforced and routed")
	}
}

// B. The handwritten enforcement layer does not hardcode the contract's
// route matrix; operations are derived from the spec.
func TestNoHandwrittenRouteTable(t *testing.T) {
	files := []string{
		"enforce.go",
		"jsonschema.go",
		"correlation.go",
		"jsonstrict.go",
	}
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join("middleware", f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if bytes.Contains(data, []byte(`"/v1/`)) {
			t.Errorf("%s hardcodes a contract route literal; routes must derive from the spec", f)
		}
	}
}

// C. Routes with dynamic path parameters are correctly identified and
// enforced by the generated router's matched pattern.
func TestDynamicPathParamOperationIdentified(t *testing.T) {
	h, p := newTestHandler(t)

	rr := do(t, h, "GET", "/v1/enrollments/enr-123", "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("GetEnrollment") != 1 {
		t.Fatalf("GetEnrollment calls = %d, want 1", p.count("GetEnrollment"))
	}

	rr2 := do(t, h, "POST", "/v1/enrollments/enr-123/complete",
		`{"installation_status":"INSTALLED"}`, map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
		})
	if rr2.Code != http.StatusOK {
		t.Fatalf("complete status = %d, want 200 (body %s)", rr2.Code, rr2.Body.String())
	}
	if p.count("CompleteEnrollment") != 1 {
		t.Fatalf("CompleteEnrollment calls = %d, want 1", p.count("CompleteEnrollment"))
	}
}

// D. The challenge:refresh path (literal colon segment) is identified
// correctly.
func TestChallengeRefreshOperationIdentified(t *testing.T) {
	h, p := newTestHandler(t)

	rr := do(t, h, "POST", "/v1/enrollments/enr-123/challenge:refresh",
		`{"expected_challenge_version":1}`, map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
		})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("RefreshEnrollmentChallenge") != 1 {
		t.Fatalf("RefreshEnrollmentChallenge calls = %d, want 1", p.count("RefreshEnrollmentChallenge"))
	}
}

// K. The If-Match header pattern (strong ETag, quoted) is enforced; invalid
// values are rejected before the handler and valid values pass.
func TestIfMatchPatternEnforced(t *testing.T) {
	valid := map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"If-Match":        testReq1ETag,
	}
	body := `{"reason":"approved","expected_status":"PENDING_APPROVAL"}`

	h, p := newTestHandler(t)
	rr := do(t, h, "POST", "/v1/admin/pre-onboarding-requests/req-1/approve", body, valid)
	if rr.Code != http.StatusOK {
		t.Fatalf("valid If-Match: status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("AdminApprovePreOnboardingRequest") != 0 {
		t.Fatal("AdminApprovePreOnboardingRequest must be answered by M5.5 boundary")
	}

	h2, p2 := newTestHandler(t)
	invalid := map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"If-Match":        "unquoted",
	}
	rr2 := do(t, h2, "POST", "/v1/admin/pre-onboarding-requests/req-1/approve", body, invalid)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("invalid If-Match: status = %d, want 400 (body %s)", rr2.Code, rr2.Body.String())
	}
	if p2.total() != 0 {
		t.Fatal("handler ran despite invalid If-Match")
	}
}

// SOL-005: behavioral proof that the routes actually registered by the
// generated chi router are exactly the operations of the canonical spec —
// both directions. This is the primary proof that no handwritten route matrix
// exists; TestNoHandwrittenRouteTable remains only as a cheap smoke check.
func TestGeneratedRoutesMatchSpecPaths(t *testing.T) {
	spec, err := openapi.GetSpec()
	if err != nil {
		t.Fatalf("GetSpec: %v", err)
	}

	p := &probeSSI{calls: map[string]int{}}
	r := chi.NewRouter()
	openapi.HandlerFromMux(openapi.NewStrictHandler(p, nil), r)

	routerRoutes := map[string]bool{}
	if err := chi.Walk(r, func(method, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		routerRoutes[method+" "+route] = true
		return nil
	}); err != nil {
		t.Fatalf("chi Walk: %v", err)
	}

	specOps := map[string]bool{}
	for path, pi := range spec.Paths.Map() {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			if pi.GetOperation(method) != nil {
				specOps[method+" "+path] = true
			}
		}
	}

	if len(specOps) != 21 || len(routerRoutes) != 21 {
		t.Fatalf("spec operations = %d, registered routes = %d, want 21 each", len(specOps), len(routerRoutes))
	}
	for k := range specOps {
		if !routerRoutes[k] {
			t.Errorf("spec operation %q is not registered by the generated router", k)
		}
	}
	for k := range routerRoutes {
		if !specOps[k] {
			t.Errorf("generated router route %q is not an operation of the spec", k)
		}
	}
}

// Routing edge characterization: percent-encoding, encoded slashes, trailing
// slashes, wrong methods and traversal attempts must not bypass enforcement
// (handler only runs for legitimately matched contract routes).
func TestRoutingEdgeNoBypass(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantCall   string
	}{
		{"trailing slash", "GET", "/v1/pki/trust-bundles/current/", 404, ""},
		{"wrong method", "DELETE", "/v1/pki/trust-bundles/current", 405, ""},
		{"dot-dot traversal", "GET", "/v1/enrollments/../me/authorizations", 404, ""},
		{"encoded slash in param value", "GET", "/v1/enrollments/enr%2F123", 200, "GetEnrollment"},
		{"percent-encoded literal segment", "GET", "/v1/pki%2Ftrust-bundles/current", 404, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, p := newTestHandler(t)
			rr := do(t, h, tc.method, tc.path, "", nil)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if tc.wantCall != "" && p.count(tc.wantCall) != 1 {
				t.Fatalf("%s calls = %d, want 1", tc.wantCall, p.count(tc.wantCall))
			}
			if tc.wantCall == "" && p.total() != 0 {
				t.Fatal("handler ran on a route that must not match")
			}
		})
	}
}

// N. Concurrent requests share the immutable precompiled validators safely.
func TestConcurrentRequests(t *testing.T) {
	h, p := newTestHandler(t)

	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := do(t, h, "POST", "/v1/enrollments", validEnrollmentBody, map[string]string{
				"Content-Type":    "application/json",
				"Idempotency-Key": validIdempotencyKey,
			})
			if rr.Code != http.StatusCreated {
				errs <- fmt.Errorf("status = %d (body %s)", rr.Code, rr.Body.String())
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := p.count("CreateEnrollment"); got != workers {
		t.Fatalf("CreateEnrollment calls = %d, want %d", got, workers)
	}
}
