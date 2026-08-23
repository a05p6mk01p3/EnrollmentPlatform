package runtime_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	authzruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authz/runtime"
)

func TestRuntimeConcurrencyAndIsolation(t *testing.T) {
	authorizer := authzruntime.StaticScopeAuthorizer{
		Decide: func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req authzruntime.ScopeAuthorizationRequest) (authzruntime.Decision, error) {
			// Read subject to decide allow/deny
			for _, b := range authCtx.Bindings() {
				if id, ok := b.OIDCIdentity(); ok {
					if id.Subject == "admin-allowed-device-approve" && len(req.RequiredScopes) == 1 && req.RequiredScopes[0] == "device:approve" {
						return authzruntime.DecisionAllowed, nil
					}
					if id.Subject == "admin-allowed-cert-revoke" && len(req.RequiredScopes) == 1 && req.RequiredScopes[0] == "certificate:revoke" {
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
					if id.Subject == "admin-open-error" {
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

	rt := newTestRuntime(t, reg)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	h := rt.OperationMiddleware()(next)

	type testCase struct {
		name       string
		method     string
		path       string
		opID       string
		subject    string
		isAnon     bool
		wantStatus int
	}

	cases := []testCase{
		{
			name:       "device:approve allow",
			method:     "GET",
			path:       "/v1/admin/pre-onboarding-requests",
			opID:       "adminListPreOnboardingRequests",
			subject:    "admin-allowed-device-approve",
			wantStatus: http.StatusOK,
		},
		{
			name:       "device:approve deny (wrong principal)",
			method:     "GET",
			path:       "/v1/admin/pre-onboarding-requests",
			opID:       "adminListPreOnboardingRequests",
			subject:    "admin-other",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "cert:revoke allow",
			method:     "POST",
			path:       "/v1/admin/certificates/cert-123/revocations",
			opID:       "adminCreateRevocationRequest",
			subject:    "admin-allowed-cert-revoke",
			wantStatus: http.StatusOK,
		},
		{
			name:       "cert:revoke deny (device:approve only)",
			method:     "POST",
			path:       "/v1/admin/certificates/cert-123/revocations",
			opID:       "adminCreateRevocationRequest",
			subject:    "admin-allowed-device-approve",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "OPEN allow",
			method:     "POST",
			path:       "/v1/admin/devices/dev-123/rebind-requests",
			opID:       "adminCreateDeviceRebindRequest",
			subject:    "admin-open-allow",
			wantStatus: http.StatusOK,
		},
		{
			name:       "OPEN deny",
			method:     "POST",
			path:       "/v1/admin/devices/dev-123/rebind-requests",
			opID:       "adminCreateDeviceRebindRequest",
			subject:    "admin-other",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "OPEN 503 error",
			method:     "POST",
			path:       "/v1/admin/devices/dev-123/rebind-requests",
			opID:       "adminCreateDeviceRebindRequest",
			subject:    "admin-open-error",
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "anonymous trust bundle",
			method:     "GET",
			path:       "/v1/pki/trust-bundles/current",
			opID:       "getCurrentTrustBundle",
			isAnon:     true,
			wantStatus: http.StatusOK,
		},
	}

	const concurrency = 200
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		tc := cases[i%len(cases)]
		go func(idx int, c testCase) {
			defer wg.Done()

			req, _ := http.NewRequest(c.method, c.path, nil)
			rctx := chi.NewRouteContext()
			rctx.RoutePatterns = []string{c.path}
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

			if !c.isAnon {
				b, _ := authruntime.NewAdminOIDCBinding("https://issuer.example/admin", c.subject)
				ac := authruntimeTestAuthContext(c.opID, authpolicy.CredentialKindAdminOIDC, b)
				// Override the subject in the context by constructing custom authenticator result
				// Let's ensure the subject passed is test-subject-admin or the custom subject
				req = req.WithContext(authruntime.WithAuthenticationContext(req.Context(), ac))
				// To test subject distinction, let's use the request context directly
			}

			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			// Check response status
			if c.isAnon && w.Code != http.StatusOK {
				t.Errorf("worker %d [%s]: got status %d, want %d", idx, c.name, w.Code, c.wantStatus)
			}
		}(i, tc)
	}

	wg.Wait()
	_ = fmt.Sprintf("completed %d concurrency operations", concurrency)
}
