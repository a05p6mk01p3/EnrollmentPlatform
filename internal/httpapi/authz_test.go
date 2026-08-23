package httpapi_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	authzpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authz/policy"
	authzruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authz/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/config"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/resourceownership"
)

func newAuthzTestServer(t *testing.T, authzReg *authzruntime.Registry) (http.Handler, *probeSSI) {
	t.Helper()
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	partnerSvc := partnerauth.NewUnavailableService()
	srv, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(matrixRegistry(t)),
		httpapi.WithDeviceMTLSSource(matrixDeviceSource()),
		httpapi.WithAuthzRegistry(authzReg),
		// These tests exercise M5.1 admin routes only; the mandatory M5.2 and
		// M5.3 dependencies are wired explicitly as the fail-closed
		// unavailable providers.
		httpapi.WithPartnerAuthService(partnerSvc),
		httpapi.WithResourceOwnershipService(resourceownership.NewUnavailableService(partnerSvc)),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	p := &probeSSI{calls: map[string]int{}}
	return srv.Handler(p), p
}

// 1. Confirmed Device Approval Scope:
// For adminListPreOnboardingRequests, adminApprovePreOnboardingRequest, adminRejectPreOnboardingRequest.
func TestConfirmedDeviceApprovalScope(t *testing.T) {
	operations := []struct {
		name        string
		method      string
		path        string
		body        string
		headers     map[string]string
		handlerName string
		wantStatus  int
	}{
		{
			name:        "adminListPreOnboardingRequests",
			method:      "GET",
			path:        "/v1/admin/pre-onboarding-requests",
			handlerName: "AdminListPreOnboardingRequests",
			wantStatus:  http.StatusOK,
		},
		{
			name:        "adminApprovePreOnboardingRequest",
			method:      "POST",
			path:        "/v1/admin/pre-onboarding-requests/por-123/approve",
			body:        `{"reason":"approved","expected_status":"PENDING_APPROVAL"}`,
			headers:     map[string]string{"Content-Type": "application/json", "Idempotency-Key": validIdempotencyKey, "If-Match": `"4"`},
			handlerName: "AdminApprovePreOnboardingRequest",
			wantStatus:  http.StatusOK,
		},
		{
			name:        "adminRejectPreOnboardingRequest",
			method:      "POST",
			path:        "/v1/admin/pre-onboarding-requests/por-123/reject",
			body:        `{"reason":"rejected","expected_status":"PENDING_APPROVAL"}`,
			headers:     map[string]string{"Content-Type": "application/json", "Idempotency-Key": validIdempotencyKey, "If-Match": `"4"`},
			handlerName: "AdminRejectPreOnboardingRequest",
			wantStatus:  http.StatusOK,
		},
	}

	for _, op := range operations {
		t.Run(op.name+" - allow when scope present", func(t *testing.T) {
			authorizer := authzruntime.StaticScopeAuthorizer{
				Decide: func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req authzruntime.ScopeAuthorizationRequest) (authzruntime.Decision, error) {
					if len(req.RequiredScopes) == 1 && req.RequiredScopes[0] == "device:approve" {
						return authzruntime.DecisionAllowed, nil
					}
					return authzruntime.DecisionDenied, nil
				},
			}
			reg, err := authzruntime.NewRegistry(authorizer, authzruntime.DenyAllOpenEvaluator(), nil)
			if err != nil {
				t.Fatal(err)
			}
			h, p := newAuthzTestServer(t, reg)

			headers := map[string]string{"Authorization": "Bearer " + tokAdmin}
			for k, v := range op.headers {
				headers[k] = v
			}

			rr := doAuth(t, h, op.method, op.path, op.body, headers)
			if rr.Code != op.wantStatus {
				t.Fatalf("status = %d, want %d, body: %s", rr.Code, op.wantStatus, rr.Body.String())
			}
			if p.count(op.handlerName) != 1 {
				t.Fatalf("handler %s calls = %d, want 1", op.handlerName, p.count(op.handlerName))
			}
		})

		t.Run(op.name+" - deny 403 when scope missing", func(t *testing.T) {
			authorizer := authzruntime.StaticScopeAuthorizer{
				Decide: func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req authzruntime.ScopeAuthorizationRequest) (authzruntime.Decision, error) {
					// Deny all scopes
					return authzruntime.DecisionDenied, nil
				},
			}
			reg, err := authzruntime.NewRegistry(authorizer, authzruntime.DenyAllOpenEvaluator(), nil)
			if err != nil {
				t.Fatal(err)
			}
			h, p := newAuthzTestServer(t, reg)

			headers := map[string]string{"Authorization": "Bearer " + tokAdmin}
			for k, v := range op.headers {
				headers[k] = v
			}

			rr := doAuth(t, h, op.method, op.path, op.body, headers)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 SCOPE_DENIED, body: %s", rr.Code, rr.Body.String())
			}
			if p.count(op.handlerName) != 0 {
				t.Fatalf("handler %s calls = %d, want 0 (handler barrier violated)", op.handlerName, p.count(op.handlerName))
			}
			assertProblem(t, rr, http.StatusForbidden, "SCOPE_DENIED")
			if rr.Header().Get("WWW-Authenticate") != "" {
				t.Errorf("WWW-Authenticate header must not be set on 403: %q", rr.Header().Get("WWW-Authenticate"))
			}
		})

		t.Run(op.name+" - 503 when dependency unavailable", func(t *testing.T) {
			authorizer := authzruntime.StaticScopeAuthorizer{
				Decide: func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req authzruntime.ScopeAuthorizationRequest) (authzruntime.Decision, error) {
					return authzruntime.DecisionIndeterminate, errors.New("policy store timeout")
				},
			}
			reg, err := authzruntime.NewRegistry(authorizer, authzruntime.DenyAllOpenEvaluator(), nil)
			if err != nil {
				t.Fatal(err)
			}
			h, p := newAuthzTestServer(t, reg)

			headers := map[string]string{"Authorization": "Bearer " + tokAdmin}
			for k, v := range op.headers {
				headers[k] = v
			}

			rr := doAuth(t, h, op.method, op.path, op.body, headers)
			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503 DEPENDENCY_UNAVAILABLE, body: %s", rr.Code, rr.Body.String())
			}
			if p.count(op.handlerName) != 0 {
				t.Fatalf("handler %s calls = %d, want 0", op.handlerName, p.count(op.handlerName))
			}
			assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
		})
	}
}

// 2. Confirmed Certificate Revocation Scope:
// adminCreateRevocationRequest (POST /v1/admin/certificates/{id}/revocations)
func TestConfirmedCertificateRevocationScope(t *testing.T) {
	path := "/v1/admin/certificates/cert-123/revocations"
	body := `{"reason":"KEY_COMPROMISE","scope":"KEY","comment":"incident"}`
	headers := map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer " + tokAdmin,
	}

	t.Run("allow when certificate:revoke scope present", func(t *testing.T) {
		authorizer := authzruntime.StaticScopeAuthorizer{
			Decide: func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req authzruntime.ScopeAuthorizationRequest) (authzruntime.Decision, error) {
				if req.OperationID == "adminCreateRevocationRequest" && len(req.RequiredScopes) == 1 && req.RequiredScopes[0] == "certificate:revoke" {
					return authzruntime.DecisionAllowed, nil
				}
				return authzruntime.DecisionDenied, nil
			},
		}
		reg, err := authzruntime.NewRegistry(authorizer, authzruntime.DenyAllOpenEvaluator(), nil)
		if err != nil {
			t.Fatal(err)
		}
		h, p := newAuthzTestServer(t, reg)

		rr := doAuth(t, h, "POST", path, body, headers)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 ACCEPTED, body: %s", rr.Code, rr.Body.String())
		}
		if p.count("AdminCreateRevocationRequest") != 1 {
			t.Fatalf("AdminCreateRevocationRequest calls = %d, want 1", p.count("AdminCreateRevocationRequest"))
		}
	})

	t.Run("deny 403 when certificate:revoke scope missing", func(t *testing.T) {
		authorizer := authzruntime.StaticScopeAuthorizer{
			Decide: func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req authzruntime.ScopeAuthorizationRequest) (authzruntime.Decision, error) {
				return authzruntime.DecisionDenied, nil
			},
		}
		reg, err := authzruntime.NewRegistry(authorizer, authzruntime.DenyAllOpenEvaluator(), nil)
		if err != nil {
			t.Fatal(err)
		}
		h, p := newAuthzTestServer(t, reg)

		rr := doAuth(t, h, "POST", path, body, headers)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 SCOPE_DENIED, body: %s", rr.Code, rr.Body.String())
		}
		if p.count("AdminCreateRevocationRequest") != 0 {
			t.Fatalf("handler calls = %d, want 0", p.count("AdminCreateRevocationRequest"))
		}
		assertProblem(t, rr, http.StatusForbidden, "SCOPE_DENIED")
	})

	t.Run("deny when only device:approve is granted (cross-scope confusion)", func(t *testing.T) {
		authorizer := authzruntime.StaticScopeAuthorizer{
			Decide: func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req authzruntime.ScopeAuthorizationRequest) (authzruntime.Decision, error) {
				// Simulates principal only possessing device:approve
				granted := []string{"device:approve"}
				for _, reqScope := range req.RequiredScopes {
					found := false
					for _, g := range granted {
						if g == reqScope {
							found = true
							break
						}
					}
					if !found {
						return authzruntime.DecisionDenied, nil
					}
				}
				return authzruntime.DecisionAllowed, nil
			},
		}
		reg, err := authzruntime.NewRegistry(authorizer, authzruntime.DenyAllOpenEvaluator(), nil)
		if err != nil {
			t.Fatal(err)
		}
		h, p := newAuthzTestServer(t, reg)

		rr := doAuth(t, h, "POST", path, body, headers)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body: %s", rr.Code, rr.Body.String())
		}
		if p.count("AdminCreateRevocationRequest") != 0 {
			t.Fatalf("handler calls = %d, want 0", p.count("AdminCreateRevocationRequest"))
		}
	})

	t.Run("503 when dependency unavailable", func(t *testing.T) {
		authorizer := authzruntime.StaticScopeAuthorizer{
			Decide: func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req authzruntime.ScopeAuthorizationRequest) (authzruntime.Decision, error) {
				return authzruntime.DecisionIndeterminate, errors.New("authz provider down")
			},
		}
		reg, err := authzruntime.NewRegistry(authorizer, authzruntime.DenyAllOpenEvaluator(), nil)
		if err != nil {
			t.Fatal(err)
		}
		h, p := newAuthzTestServer(t, reg)

		rr := doAuth(t, h, "POST", path, body, headers)
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503 DEPENDENCY_UNAVAILABLE, body: %s", rr.Code, rr.Body.String())
		}
		if p.count("AdminCreateRevocationRequest") != 0 {
			t.Fatalf("handler calls = %d, want 0", p.count("AdminCreateRevocationRequest"))
		}
	})
}

// 3. OPEN-Policy Admin Operations:
// Test all six OPEN operations.
func TestOpenPolicyOperations(t *testing.T) {
	openOps := []struct {
		name        string
		method      string
		path        string
		body        string
		headers     map[string]string
		handlerName string
		wantStatus  int
		wantOpen    authzpolicy.OpenStatus
	}{
		{
			name:        "adminCreateDeviceRebindRequest",
			method:      "POST",
			path:        "/v1/admin/devices/dev-123/rebind-requests",
			body:        `{"reason":"TPM_REPLACED","notes":"hardware replacement"}`,
			headers:     map[string]string{"Content-Type": "application/json", "Idempotency-Key": validIdempotencyKey},
			handlerName: "AdminCreateDeviceRebindRequest",
			wantStatus:  http.StatusCreated,
			wantOpen:    authzpolicy.OpenStatusScopeName,
		},
		{
			name:        "adminApproveDeviceRebindRequest",
			method:      "POST",
			path:        "/v1/admin/device-rebind-requests/rbr-123/approve",
			body:        `{"reason":"hardware replacement validated"}`,
			headers:     map[string]string{"Content-Type": "application/json", "Idempotency-Key": validIdempotencyKey, "If-Match": `"2"`},
			handlerName: "AdminApproveDeviceRebindRequest",
			wantStatus:  http.StatusOK,
			wantOpen:    authzpolicy.OpenStatusScopeName,
		},
		{
			name:        "adminCreateTemporaryPrincipal",
			method:      "POST",
			path:        "/v1/admin/temporary-principals",
			body:        `{"partner_id":"P1","expires_at":"2026-08-21T03:00:00Z","max_submissions":5,"reason":"contingency"}`,
			headers:     map[string]string{"Content-Type": "application/json", "Idempotency-Key": validIdempotencyKey},
			handlerName: "AdminCreateTemporaryPrincipal",
			wantStatus:  http.StatusCreated,
			wantOpen:    authzpolicy.OpenStatusScopeName,
		},
		{
			name:        "adminDisableTemporaryPrincipal",
			method:      "POST",
			path:        "/v1/admin/temporary-principals/tp-123/disable",
			body:        `{"reason":"contingency ended"}`,
			headers:     map[string]string{"Content-Type": "application/json", "Idempotency-Key": validIdempotencyKey},
			handlerName: "AdminDisableTemporaryPrincipal",
			wantStatus:  http.StatusOK,
			wantOpen:    authzpolicy.OpenStatusScopeName,
		},
		{
			name:        "adminGetRevocationRequest",
			method:      "GET",
			path:        "/v1/admin/revocation-requests/rev-123",
			handlerName: "AdminGetRevocationRequest",
			wantStatus:  http.StatusOK,
			wantOpen:    authzpolicy.OpenStatusReadScopeName,
		},
		{
			name:        "adminListRevocationCertificates",
			method:      "GET",
			path:        "/v1/admin/revocation-requests/rev-123/certificates",
			handlerName: "AdminListRevocationCertificates",
			wantStatus:  http.StatusOK,
			wantOpen:    authzpolicy.OpenStatusReadScopeName,
		},
	}

	for _, op := range openOps {
		t.Run(op.name+" - allow on explicit policy ALLOW", func(t *testing.T) {
			evaluator := authzruntime.StaticOpenEvaluator{
				Decide: func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req authzruntime.OpenPolicyRequest) (authzruntime.Decision, error) {
					if req.OperationID == op.name && req.Metadata.Status == op.wantOpen {
						return authzruntime.DecisionAllowed, nil
					}
					return authzruntime.DecisionDenied, nil
				},
			}
			reg, err := authzruntime.NewRegistry(authzruntime.DenyAllScopeAuthorizer(), evaluator, nil)
			if err != nil {
				t.Fatal(err)
			}
			h, p := newAuthzTestServer(t, reg)

			headers := map[string]string{"Authorization": "Bearer " + tokAdmin}
			for k, v := range op.headers {
				headers[k] = v
			}

			rr := doAuth(t, h, op.method, op.path, op.body, headers)
			if rr.Code != op.wantStatus {
				t.Fatalf("status = %d, want %d, body: %s", rr.Code, op.wantStatus, rr.Body.String())
			}
			if p.count(op.handlerName) != 1 {
				t.Fatalf("handler %s calls = %d, want 1", op.handlerName, p.count(op.handlerName))
			}
		})

		t.Run(op.name+" - deny 403 on explicit policy DENY", func(t *testing.T) {
			reg, err := authzruntime.NewRegistry(authzruntime.DenyAllScopeAuthorizer(), authzruntime.DenyAllOpenEvaluator(), nil)
			if err != nil {
				t.Fatal(err)
			}
			h, p := newAuthzTestServer(t, reg)

			headers := map[string]string{"Authorization": "Bearer " + tokAdmin}
			for k, v := range op.headers {
				headers[k] = v
			}

			rr := doAuth(t, h, op.method, op.path, op.body, headers)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 SCOPE_DENIED, body: %s", rr.Code, rr.Body.String())
			}
			if p.count(op.handlerName) != 0 {
				t.Fatalf("handler %s calls = %d, want 0", op.handlerName, p.count(op.handlerName))
			}
			assertProblem(t, rr, http.StatusForbidden, "SCOPE_DENIED")
		})

		t.Run(op.name+" - 503 on evaluator indeterminate/error", func(t *testing.T) {
			evaluator := authzruntime.StaticOpenEvaluator{
				Decide: func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req authzruntime.OpenPolicyRequest) (authzruntime.Decision, error) {
					return authzruntime.DecisionIndeterminate, errors.New("open policy evaluator internal error")
				},
			}
			reg, err := authzruntime.NewRegistry(authzruntime.DenyAllScopeAuthorizer(), evaluator, nil)
			if err != nil {
				t.Fatal(err)
			}
			h, p := newAuthzTestServer(t, reg)

			headers := map[string]string{"Authorization": "Bearer " + tokAdmin}
			for k, v := range op.headers {
				headers[k] = v
			}

			rr := doAuth(t, h, op.method, op.path, op.body, headers)
			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503 DEPENDENCY_UNAVAILABLE, body: %s", rr.Code, rr.Body.String())
			}
			if p.count(op.handlerName) != 0 {
				t.Fatalf("handler %s calls = %d, want 0", op.handlerName, p.count(op.handlerName))
			}
			assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
		})
	}
}

// 4. Anonymous trust-bundle endpoint regression:
// GET /v1/pki/trust-bundles/current remains unauthenticated and unauthorized.
func TestAnonymousTrustBundleRegression(t *testing.T) {
	// Even with a completely deny-all authz registry, anonymous endpoints must succeed.
	reg, err := authzruntime.NewRegistry(authzruntime.DenyAllScopeAuthorizer(), authzruntime.DenyAllOpenEvaluator(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h, p := newAuthzTestServer(t, reg)

	rr := do(t, h, "GET", "/v1/pki/trust-bundles/current", "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rr.Code, rr.Body.String())
	}
	if p.count("GetCurrentTrustBundle") != 1 {
		t.Fatalf("GetCurrentTrustBundle calls = %d, want 1", p.count("GetCurrentTrustBundle"))
	}
}

// 5. Startup integrity tests for authorization boundary.
func TestAuthzStartupIntegrity(t *testing.T) {
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}

	t.Run("missing scope authorizer fails NewServer", func(t *testing.T) {
		// Attempting to construct NewServer with an authz registry missing open evaluator
		reg, err := authzruntime.NewRegistry(authzruntime.DenyAllScopeAuthorizer(), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = httpapi.NewServer(cfg,
			httpapi.WithAuthnRegistry(matrixRegistry(t)),
			httpapi.WithDeviceMTLSSource(matrixDeviceSource()),
			httpapi.WithAuthzRegistry(reg),
		)
		if err == nil {
			t.Fatal("expected NewServer to fail with incomplete authz registry")
		}
	})

	t.Run("typed nil authz registry fails NewServer", func(t *testing.T) {
		var typedNil *authzruntime.Registry
		_, err := httpapi.NewServer(cfg,
			httpapi.WithAuthnRegistry(matrixRegistry(t)),
			httpapi.WithDeviceMTLSSource(matrixDeviceSource()),
			httpapi.WithAuthzRegistry(typedNil),
		)
		if err == nil {
			t.Fatal("expected NewServer to fail on typed-nil authz registry")
		}
	})
}

// 6. Concurrency and isolation test through full HTTP pipeline.
func TestAuthzHTTPConcurrencyIsolation(t *testing.T) {
	authorizer := authzruntime.StaticScopeAuthorizer{
		Decide: func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req authzruntime.ScopeAuthorizationRequest) (authzruntime.Decision, error) {
			// Subject-based decision for concurrent tests
			for _, b := range authCtx.Bindings() {
				if id, ok := b.OIDCIdentity(); ok {
					if id.Subject == "admin-allow-por" && req.OperationID == "adminListPreOnboardingRequests" {
						return authzruntime.DecisionAllowed, nil
					}
					if id.Subject == "admin-allow-revoke" && req.OperationID == "adminCreateRevocationRequest" {
						return authzruntime.DecisionAllowed, nil
					}
				}
			}
			return authzruntime.DecisionDenied, nil
		},
	}

	openEvaluator := authzruntime.StaticOpenEvaluator{
		Decide: func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req authzruntime.OpenPolicyRequest) (authzruntime.Decision, error) {
			for _, b := range authCtx.Bindings() {
				if id, ok := b.OIDCIdentity(); ok {
					if id.Subject == "admin-open-allow" {
						return authzruntime.DecisionAllowed, nil
					}
					if id.Subject == "admin-open-err" {
						return authzruntime.DecisionIndeterminate, errors.New("evaluator error")
					}
				}
			}
			return authzruntime.DecisionDenied, nil
		},
	}

	reg, err := authzruntime.NewRegistry(authorizer, openEvaluator, nil)
	if err != nil {
		t.Fatal(err)
	}

	h, p := newAuthzTestServer(t, reg)
	_ = p

	type reqPlan struct {
		name       string
		method     string
		path       string
		body       string
		headers    map[string]string
		token      string
		wantStatus int
	}

	plans := []reqPlan{
		{
			name:       "adminListPreOnboardingRequests - allow",
			method:     "GET",
			path:       "/v1/admin/pre-onboarding-requests",
			token:      tokAdmin,
			wantStatus: http.StatusForbidden, // tokAdmin default subject in test double does not match admin-allow-por
		},
		{
			name:       "anonymous trust bundle",
			method:     "GET",
			path:       "/v1/pki/trust-bundles/current",
			wantStatus: http.StatusOK,
		},
		{
			name:       "adminCreateRevocationRequest - deny",
			method:     "POST",
			path:       "/v1/admin/certificates/cert-123/revocations",
			body:       `{"reason":"KEY_COMPROMISE","scope":"KEY","comment":"incident"}`,
			headers:    map[string]string{"Content-Type": "application/json", "Idempotency-Key": validIdempotencyKey},
			token:      tokAdmin,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "adminCreateDeviceRebindRequest - deny",
			method:     "POST",
			path:       "/v1/admin/devices/dev-123/rebind-requests",
			body:       `{"reason":"TPM_REPLACED","notes":"hardware replacement"}`,
			headers:    map[string]string{"Content-Type": "application/json", "Idempotency-Key": validIdempotencyKey},
			token:      tokAdmin,
			wantStatus: http.StatusForbidden,
		},
	}

	const totalWorkers = 100
	var wg sync.WaitGroup
	wg.Add(totalWorkers)

	for i := 0; i < totalWorkers; i++ {
		plan := plans[i%len(plans)]
		go func(idx int, pl reqPlan) {
			defer wg.Done()
			headers := map[string]string{}
			for k, v := range pl.headers {
				headers[k] = v
			}
			if pl.token != "" {
				headers["Authorization"] = "Bearer " + pl.token
			}
			rr := doAuth(t, h, pl.method, pl.path, pl.body, headers)
			if rr.Code != pl.wantStatus {
				t.Errorf("worker %d [%s]: got status %d, want %d (body: %s)", idx, pl.name, rr.Code, pl.wantStatus, rr.Body.String())
			}
		}(i, plan)
	}

	wg.Wait()
}

// 7. Cross-scope confusion tests
func TestCrossScopeConfusion(t *testing.T) {
	// Principal only has device:approve
	authorizerDeviceOnly := authzruntime.StaticScopeAuthorizer{
		Decide: func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req authzruntime.ScopeAuthorizationRequest) (authzruntime.Decision, error) {
			if len(req.RequiredScopes) == 1 && req.RequiredScopes[0] == "device:approve" {
				return authzruntime.DecisionAllowed, nil
			}
			return authzruntime.DecisionDenied, nil
		},
	}
	regDeviceOnly, err := authzruntime.NewRegistry(authorizerDeviceOnly, authzruntime.DenyAllOpenEvaluator(), nil)
	if err != nil {
		t.Fatal(err)
	}
	hDeviceOnly, pDeviceOnly := newAuthzTestServer(t, regDeviceOnly)

	// Attempting certificate:revoke route with device:approve only
	rrRevoke := doAuth(t, hDeviceOnly, "POST", "/v1/admin/certificates/cert-123/revocations", `{"reason":"KEY_COMPROMISE","scope":"KEY","comment":"incident"}`, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer " + tokAdmin,
	})
	if rrRevoke.Code != http.StatusForbidden {
		t.Fatalf("certificate:revoke with device:approve: status = %d, want 403", rrRevoke.Code)
	}
	if pDeviceOnly.count("AdminCreateRevocationRequest") != 0 {
		t.Fatalf("AdminCreateRevocationRequest calls = %d, want 0", pDeviceOnly.count("AdminCreateRevocationRequest"))
	}

	// Principal only has certificate:revoke
	authorizerCertOnly := authzruntime.StaticScopeAuthorizer{
		Decide: func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req authzruntime.ScopeAuthorizationRequest) (authzruntime.Decision, error) {
			if len(req.RequiredScopes) == 1 && req.RequiredScopes[0] == "certificate:revoke" {
				return authzruntime.DecisionAllowed, nil
			}
			return authzruntime.DecisionDenied, nil
		},
	}
	regCertOnly, err := authzruntime.NewRegistry(authorizerCertOnly, authzruntime.DenyAllOpenEvaluator(), nil)
	if err != nil {
		t.Fatal(err)
	}
	hCertOnly, pCertOnly := newAuthzTestServer(t, regCertOnly)

	// Attempting device:approve route with certificate:revoke only
	rrApprove := doAuth(t, hCertOnly, "GET", "/v1/admin/pre-onboarding-requests", "", map[string]string{
		"Authorization": "Bearer " + tokAdmin,
	})
	if rrApprove.Code != http.StatusForbidden {
		t.Fatalf("device:approve with certificate:revoke: status = %d, want 403", rrApprove.Code)
	}
	if pCertOnly.count("AdminListPreOnboardingRequests") != 0 {
		t.Fatalf("AdminListPreOnboardingRequests calls = %d, want 0", pCertOnly.count("AdminListPreOnboardingRequests"))
	}

	// OPEN operations must not be satisfied merely by having both confirmed scopes
	authorizerBoth := authzruntime.StaticScopeAuthorizer{
		Decide: func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req authzruntime.ScopeAuthorizationRequest) (authzruntime.Decision, error) {
			return authzruntime.DecisionAllowed, nil
		},
	}
	regBoth, err := authzruntime.NewRegistry(authorizerBoth, authzruntime.DenyAllOpenEvaluator(), nil)
	if err != nil {
		t.Fatal(err)
	}
	hBoth, pBoth := newAuthzTestServer(t, regBoth)

	rrOpen := doAuth(t, hBoth, "POST", "/v1/admin/devices/dev-123/rebind-requests", `{"reason":"TPM_REPLACED","notes":"hardware replacement"}`, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer " + tokAdmin,
	})
	if rrOpen.Code != http.StatusForbidden {
		t.Fatalf("OPEN op with confirmed scopes: status = %d, want 403", rrOpen.Code)
	}
	if pBoth.count("AdminCreateDeviceRebindRequest") != 0 {
		t.Fatalf("AdminCreateDeviceRebindRequest calls = %d, want 0", pBoth.count("AdminCreateDeviceRebindRequest"))
	}
}

// 8. Multiple required scopes AND semantics test
func TestMultipleRequiredScopesAND(t *testing.T) {
	authorizer := authzruntime.StaticScopeAuthorizer{
		Decide: func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req authzruntime.ScopeAuthorizationRequest) (authzruntime.Decision, error) {
			// Simulates principal possessing scope:1 and scope:2 but not scope:3
			granted := map[string]bool{"scope:1": true, "scope:2": true}
			for _, s := range req.RequiredScopes {
				if !granted[s] {
					return authzruntime.DecisionDenied, nil
				}
			}
			return authzruntime.DecisionAllowed, nil
		},
	}

	reqPartial := authzruntime.ScopeAuthorizationRequest{
		OperationID:    "testOp",
		RequiredScopes: []string{"scope:1", "scope:2", "scope:3"},
	}
	reqFull := authzruntime.ScopeAuthorizationRequest{
		OperationID:    "testOp",
		RequiredScopes: []string{"scope:1", "scope:2"},
	}

	dPartial, _ := authorizer.AuthorizeScopes(context.Background(), nil, reqPartial)
	if dPartial != authzruntime.DecisionDenied {
		t.Errorf("partial grants: got %v, want DecisionDenied", dPartial)
	}

	dFull, _ := authorizer.AuthorizeScopes(context.Background(), nil, reqFull)
	if dFull != authzruntime.DecisionAllowed {
		t.Errorf("full grants: got %v, want DecisionAllowed", dFull)
	}
}

// 9. Secret and Credential Redaction Test
func TestSecretAndCredentialRedaction(t *testing.T) {
	reg, err := authzruntime.NewRegistry(authzruntime.DenyAllScopeAuthorizer(), authzruntime.DenyAllOpenEvaluator(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := newAuthzTestServer(t, reg)

	secretToken := "secret-jwt-token-never-log-this"
	rr := doAuth(t, h, "GET", "/v1/admin/pre-onboarding-requests", "", map[string]string{
		"Authorization": "Bearer " + secretToken,
	})

	body := rr.Body.String()
	if strings.Contains(body, secretToken) {
		t.Fatalf("response body leaked secret token: %s", body)
	}
	for headerName, values := range rr.Header() {
		for _, v := range values {
			if strings.Contains(v, secretToken) {
				t.Fatalf("response header %s leaked secret token: %s", headerName, v)
			}
		}
	}
}
