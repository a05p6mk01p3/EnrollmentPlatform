package runtime_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	authzpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authz/policy"
	authzruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authz/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
)

func newTestRuntime(t *testing.T, reg *authzruntime.Registry) *authzruntime.Runtime {
	t.Helper()
	spec, err := openapi.GetSpec()
	if err != nil {
		t.Fatalf("GetSpec: %v", err)
	}
	compiled, err := authzpolicy.Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if err := authzruntime.ValidateRegistry(compiled, reg); err != nil {
		t.Fatalf("ValidateRegistry: %v", err)
	}
	rt, err := authzruntime.NewRuntime(spec, compiled, reg)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	return rt
}

func authruntimeTestAuthContext(opID string, kind authpolicy.CredentialKind, b *authruntime.Binding) *authruntime.AuthenticationContext {
	auths := authruntime.BearerTestAuthenticator{
		KindValue: kind,
		Decide:    func(string) authruntime.Decision { return authruntime.DecisionAuthenticated },
	}
	r, _ := authruntime.NewRegistry(auths)
	spec, _ := openapi.GetSpec()
	compiled, _ := authpolicy.Compile(spec)
	rt, _ := authruntime.NewRuntime(spec, compiled, r, nil, 262144, 4<<20)

	req, _ := http.NewRequest("GET", "/v1/admin/pre-onboarding-requests", nil)
	req.Header.Set("Authorization", "Bearer dummy")
	rctx := chi.NewRouteContext()
	rctx.RoutePatterns = []string{"/v1/admin/pre-onboarding-requests"}
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	var captured *authruntime.AuthenticationContext
	handler := rt.BaseAuthentication()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = authruntime.AuthenticationContextFrom(r.Context())
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return captured
}

func TestRuntimeMiddlewareConfirmedScopes(t *testing.T) {
	t.Run("allowed when scope matches", func(t *testing.T) {
		authorizer := &authzruntime.PrincipalScopeAuthorizer{
			Grants: map[string][]string{
				"test-subject-admin": {"device:approve"},
			},
		}
		reg, err := authzruntime.NewRegistry(authorizer, authzruntime.DenyAllOpenEvaluator(), nil)
		if err != nil {
			t.Fatal(err)
		}
		rt := newTestRuntime(t, reg)

		handlerCalls := 0
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalls++
			w.WriteHeader(http.StatusOK)
		})

		h := rt.OperationMiddleware()(next)

		req, _ := http.NewRequest("GET", "/v1/admin/pre-onboarding-requests", nil)
		rctx := chi.NewRouteContext()
		rctx.RoutePatterns = []string{"/v1/admin/pre-onboarding-requests"}
		ac := authruntimeTestAuthContext("adminListPreOnboardingRequests", authpolicy.CredentialKindAdminOIDC, nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		req = req.WithContext(authruntime.WithAuthenticationContext(req.Context(), ac))

		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
		}
		if handlerCalls != 1 {
			t.Fatalf("handlerCalls = %d, want 1", handlerCalls)
		}
	})

	t.Run("denied 403 when scope missing", func(t *testing.T) {
		authorizer := &authzruntime.PrincipalScopeAuthorizer{
			Grants: map[string][]string{
				"test-subject-admin": {"other:scope"}, // missing device:approve
			},
		}
		reg, err := authzruntime.NewRegistry(authorizer, authzruntime.DenyAllOpenEvaluator(), nil)
		if err != nil {
			t.Fatal(err)
		}
		rt := newTestRuntime(t, reg)

		handlerCalls := 0
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalls++
		})

		h := rt.OperationMiddleware()(next)

		req, _ := http.NewRequest("GET", "/v1/admin/pre-onboarding-requests", nil)
		rctx := chi.NewRouteContext()
		rctx.RoutePatterns = []string{"/v1/admin/pre-onboarding-requests"}
		ac := authruntimeTestAuthContext("adminListPreOnboardingRequests", authpolicy.CredentialKindAdminOIDC, nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		req = req.WithContext(authruntime.WithAuthenticationContext(req.Context(), ac))

		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body: %s", w.Code, w.Body.String())
		}
		if handlerCalls != 0 {
			t.Fatalf("handlerCalls = %d, want 0 (handler must not run on deny)", handlerCalls)
		}
		if w.Header().Get("WWW-Authenticate") != "" {
			t.Errorf("WWW-Authenticate header present on 403: %q", w.Header().Get("WWW-Authenticate"))
		}
	})

	t.Run("503 when scope authorizer returns indeterminate or error", func(t *testing.T) {
		authorizer := authzruntime.StaticScopeAuthorizer{
			Decide: func(context.Context, *authruntime.AuthenticationContext, authzruntime.ScopeAuthorizationRequest) (authzruntime.Decision, error) {
				return authzruntime.DecisionIndeterminate, errors.New("db timeout")
			},
		}
		reg, err := authzruntime.NewRegistry(authorizer, authzruntime.DenyAllOpenEvaluator(), nil)
		if err != nil {
			t.Fatal(err)
		}
		rt := newTestRuntime(t, reg)

		handlerCalls := 0
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalls++
		})

		h := rt.OperationMiddleware()(next)

		req, _ := http.NewRequest("GET", "/v1/admin/pre-onboarding-requests", nil)
		rctx := chi.NewRouteContext()
		rctx.RoutePatterns = []string{"/v1/admin/pre-onboarding-requests"}
		ac := authruntimeTestAuthContext("adminListPreOnboardingRequests", authpolicy.CredentialKindAdminOIDC, nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		req = req.WithContext(authruntime.WithAuthenticationContext(req.Context(), ac))

		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503, body: %s", w.Code, w.Body.String())
		}
		if handlerCalls != 0 {
			t.Fatalf("handlerCalls = %d, want 0", handlerCalls)
		}
	})
}

func TestRuntimeMiddlewareOpenPolicy(t *testing.T) {
	t.Run("allowed on explicit ALLOW", func(t *testing.T) {
		eval := authzruntime.StaticOpenEvaluator{
			Decide: func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req authzruntime.OpenPolicyRequest) (authzruntime.Decision, error) {
				if req.OperationID == "adminCreateDeviceRebindRequest" && req.Metadata.Status == authzpolicy.OpenStatusScopeName {
					return authzruntime.DecisionAllowed, nil
				}
				return authzruntime.DecisionDenied, nil
			},
		}
		reg, err := authzruntime.NewRegistry(authzruntime.DenyAllScopeAuthorizer(), eval, nil)
		if err != nil {
			t.Fatal(err)
		}
		rt := newTestRuntime(t, reg)

		handlerCalls := 0
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalls++
			w.WriteHeader(http.StatusCreated)
		})

		h := rt.OperationMiddleware()(next)

		req, _ := http.NewRequest("POST", "/v1/admin/devices/dev-123/rebind-requests", nil)
		rctx := chi.NewRouteContext()
		rctx.RoutePatterns = []string{"/v1/admin/devices/{id}/rebind-requests"}
		rctx.URLParams.Add("id", "dev-123")
		ac := authruntimeTestAuthContext("adminCreateDeviceRebindRequest", authpolicy.CredentialKindAdminOIDC, nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		req = req.WithContext(authruntime.WithAuthenticationContext(req.Context(), ac))

		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201, body: %s", w.Code, w.Body.String())
		}
		if handlerCalls != 1 {
			t.Fatalf("handlerCalls = %d, want 1", handlerCalls)
		}
	})

	t.Run("denied 403 on explicit DENY", func(t *testing.T) {
		reg, err := authzruntime.NewRegistry(authzruntime.DenyAllScopeAuthorizer(), authzruntime.DenyAllOpenEvaluator(), nil)
		if err != nil {
			t.Fatal(err)
		}
		rt := newTestRuntime(t, reg)

		handlerCalls := 0
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalls++
		})

		h := rt.OperationMiddleware()(next)

		req, _ := http.NewRequest("POST", "/v1/admin/devices/dev-123/rebind-requests", nil)
		rctx := chi.NewRouteContext()
		rctx.RoutePatterns = []string{"/v1/admin/devices/{id}/rebind-requests"}
		rctx.URLParams.Add("id", "dev-123")
		ac := authruntimeTestAuthContext("adminCreateDeviceRebindRequest", authpolicy.CredentialKindAdminOIDC, nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		req = req.WithContext(authruntime.WithAuthenticationContext(req.Context(), ac))

		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403, body: %s", w.Code, w.Body.String())
		}
		if handlerCalls != 0 {
			t.Fatalf("handlerCalls = %d, want 0", handlerCalls)
		}
	})

	t.Run("503 on evaluator indeterminate/error", func(t *testing.T) {
		eval := authzruntime.StaticOpenEvaluator{
			Decide: func(context.Context, *authruntime.AuthenticationContext, authzruntime.OpenPolicyRequest) (authzruntime.Decision, error) {
				return authzruntime.DecisionIndeterminate, errors.New("policy engine unavailable")
			},
		}
		reg, err := authzruntime.NewRegistry(authzruntime.DenyAllScopeAuthorizer(), eval, nil)
		if err != nil {
			t.Fatal(err)
		}
		rt := newTestRuntime(t, reg)

		handlerCalls := 0
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalls++
		})

		h := rt.OperationMiddleware()(next)

		req, _ := http.NewRequest("POST", "/v1/admin/devices/dev-123/rebind-requests", nil)
		rctx := chi.NewRouteContext()
		rctx.RoutePatterns = []string{"/v1/admin/devices/{id}/rebind-requests"}
		rctx.URLParams.Add("id", "dev-123")
		ac := authruntimeTestAuthContext("adminCreateDeviceRebindRequest", authpolicy.CredentialKindAdminOIDC, nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		req = req.WithContext(authruntime.WithAuthenticationContext(req.Context(), ac))

		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503, body: %s", w.Code, w.Body.String())
		}
		if handlerCalls != 0 {
			t.Fatalf("handlerCalls = %d, want 0", handlerCalls)
		}
	})
}

func TestRuntimeMiddlewareUnconstrained(t *testing.T) {
	reg := authzruntime.DefaultDenyRegistry()
	rt := newTestRuntime(t, reg)

	handlerCalls := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalls++
		w.WriteHeader(http.StatusOK)
	})

	h := rt.OperationMiddleware()(next)

	req, _ := http.NewRequest("GET", "/v1/pki/trust-bundles/current", nil)
	rctx := chi.NewRouteContext()
	rctx.RoutePatterns = []string{"/v1/pki/trust-bundles/current"}
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", w.Code, w.Body.String())
	}
	if handlerCalls != 1 {
		t.Fatalf("handlerCalls = %d, want 1", handlerCalls)
	}
}
