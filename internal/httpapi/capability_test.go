package httpapi_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
)

// capabilityVerifier is the injected key material for capability tests.
var capabilityTestKey = []byte("capability-test-key-material")

// newCapabilityRegistry wires the two real capability authenticators, with
// reject-all doubles for the other bearer kinds and an accept-any device
// authenticator for DeviceMTLS.
func newCapabilityRegistry(t *testing.T, v capability.Verifier, store capability.Store, clock capability.Clock) *authruntime.Registry {
	t.Helper()
	return registry(t,
		capability.NewRequestAccessAuthenticator(v, store, clock),
		capability.NewEnrollmentAccessAuthenticator(v, store, clock),
		rejectAll(authpolicy.CredentialKindHumanOIDC),
		rejectAll(authpolicy.CredentialKindAdminOIDC),
		rejectAll(authpolicy.CredentialKindTemporaryPrincipalToken),
		acceptDeviceMTLS(),
	)
}

// newCapabilityHandler builds the full pipeline with capability authenticators
// and a nil device source (DeviceMTLS is not exercised by capability tests).
func newCapabilityHandler(t *testing.T, v capability.Verifier, store capability.Store, clock capability.Clock) (http.Handler, *probeSSI) {
	t.Helper()
	h, p := newAuthTestHandler(t, newCapabilityRegistry(t, v, store, clock), nil)
	return h, &p.probeSSI
}

func newCapabilityVerifier(t *testing.T) capability.Verifier {
	t.Helper()
	v, err := capability.NewHMACVerifier(capabilityTestKey)
	if err != nil {
		t.Fatalf("NewHMACVerifier: %v", err)
	}
	return v
}

func futureExpiry() time.Time { return time.Now().Add(24 * time.Hour) }

// failingCapabilityStore returns a generic error, simulating a verifier/store
// outage.
type failingCapabilityStore struct{}

func (failingCapabilityStore) LookupRequestAccess(context.Context, capability.VerifierKey) (*capability.RequestAccessRecord, error) {
	return nil, errors.New("backend unavailable")
}

func (failingCapabilityStore) LookupEnrollmentAccess(context.Context, capability.VerifierKey) (*capability.EnrollmentAccessRecord, error) {
	return nil, errors.New("backend unavailable")
}

// --- RequestAccessToken resource binding (§13, §14) ---

func TestRequestAccessResourceBinding(t *testing.T) {
	v := newCapabilityVerifier(t)
	store := capability.NewMemoryStore(v)
	if err := store.SeedRequestAccess("req-A-token", "por-A", futureExpiry(), capability.StateActive); err != nil {
		t.Fatal(err)
	}
	h, p := newCapabilityHandler(t, v, store, capability.SystemClock{})

	// Bound resource A used on URL A => pass.
	rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-A", "", map[string]string{
		"Authorization": "Bearer req-A-token",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("GetPreOnboardingRequest") != 1 {
		t.Fatal("GetPreOnboardingRequest was not reached")
	}

	// Bound resource A used on URL B => 401 (no resource oracle beyond 401).
	rr2 := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-B", "", map[string]string{
		"Authorization": "Bearer req-A-token",
	})
	assertProblem(t, rr2, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	if got := rr2.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q, want Bearer", got)
	}
}

// --- EnrollmentAccessToken resource binding ---

func TestEnrollmentAccessResourceBinding(t *testing.T) {
	v := newCapabilityVerifier(t)
	store := capability.NewMemoryStore(v)
	if err := store.SeedEnrollmentAccess("enr-A-token", "enr-A", futureExpiry()); err != nil {
		t.Fatal(err)
	}
	h, p := newCapabilityHandler(t, v, store, capability.SystemClock{})

	rr := doAuth(t, h, "GET", "/v1/enrollments/enr-A", "", map[string]string{
		"Authorization": "Bearer enr-A-token",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("GetEnrollment") != 1 {
		t.Fatal("GetEnrollment was not reached")
	}

	rr2 := doAuth(t, h, "GET", "/v1/enrollments/enr-B", "", map[string]string{
		"Authorization": "Bearer enr-A-token",
	})
	assertProblem(t, rr2, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	if got := rr2.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q, want Bearer", got)
	}
}

// --- createEnrollment INITIAL: binding simply available, no path id (§14) ---

func TestRequestAccessTokenAvailableForCreateEnrollment(t *testing.T) {
	v := newCapabilityVerifier(t)
	store := capability.NewMemoryStore(v)
	if err := store.SeedRequestAccess("req-init-token", "por-A", futureExpiry(), capability.StateActive); err != nil {
		t.Fatal(err)
	}
	h, p := newCapabilityHandler(t, v, store, capability.SystemClock{})

	rr := doAuth(t, h, "POST", "/v1/enrollments", validEnrollmentBody, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer req-init-token",
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("CreateEnrollment") != 1 {
		t.Fatal("CreateEnrollment was not reached")
	}
}

// --- consumed RequestAccessToken does not authenticate (§16) ---

func TestConsumedRequestAccessTokenRejectedAtHTTP(t *testing.T) {
	v := newCapabilityVerifier(t)
	store := capability.NewMemoryStore(v)
	if err := store.SeedRequestAccess("consumed-token", "por-A", futureExpiry(), capability.StateConsumed); err != nil {
		t.Fatal(err)
	}
	h, p := newCapabilityHandler(t, v, store, capability.SystemClock{})

	rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-A", "", map[string]string{
		"Authorization": "Bearer consumed-token",
	})
	assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	assertNoHandlerCall(t, p)
}

// --- error mapping: unknown vs dependency (§17) ---

func TestCapabilityErrorMapping(t *testing.T) {
	t.Run("unknown token -> 401 + Bearer", func(t *testing.T) {
		v := newCapabilityVerifier(t)
		store := capability.NewMemoryStore(v)
		_ = store.SeedRequestAccess("known-token", "por-A", futureExpiry(), capability.StateActive)
		h, p := newCapabilityHandler(t, v, store, capability.SystemClock{})

		rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-A", "", map[string]string{
			"Authorization": "Bearer unknown-token",
		})
		assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		if got := rr.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Fatalf("WWW-Authenticate = %q, want Bearer", got)
		}
		assertNoHandlerCall(t, p)
	})

	t.Run("store failure -> 503 DEPENDENCY_UNAVAILABLE", func(t *testing.T) {
		v := newCapabilityVerifier(t)
		h, p := newCapabilityHandler(t, v, failingCapabilityStore{}, capability.SystemClock{})
		rr := doAuth(t, h, "GET", "/v1/pre-onboarding-requests/por-A", "", map[string]string{
			"Authorization": "Bearer any-token",
		})
		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
		assertNoHandlerCall(t, p)
	})
}

// --- M4.2 regression: capability authenticators integrate with conditional
// security and do not disturb DeviceMTLS pairing. ---

func TestCapabilityAuthenticatorConditionalIntegration(t *testing.T) {
	v := newCapabilityVerifier(t)
	store := capability.NewMemoryStore(v)
	// EnrollmentAccessToken bound to enr-123 (the completeEnrollment path id).
	if err := store.SeedEnrollmentAccess("enr-token", "enr-123", futureExpiry()); err != nil {
		t.Fatal(err)
	}
	// RequestAccessToken for the createEnrollment INITIAL path.
	if err := store.SeedRequestAccess("req-token", "por-A", futureExpiry(), capability.StateActive); err != nil {
		t.Fatal(err)
	}

	// DeviceMTLS present so INSTALLED can authenticate via DeviceMTLS.
	h, p := newAuthTestHandler(t, newCapabilityRegistry(t, v, store, capability.SystemClock{}), presentDeviceSource())

	// FAILED requires EnrollmentAccessToken: matching enrollment id passes.
	rr := doAuth(t, h, "POST", "/v1/enrollments/enr-123/complete", `{"installation_status":"FAILED","error_code":"AGENT_INSTALL_FAILED"}`, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer enr-token",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("FAILED: status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}

	// INSTALLED requires DeviceMTLS; even though the enrollment token
	// authenticates, the pairing must be enforced by Phase B (no bearer
	// challenge shortcut).
	rr2 := doAuth(t, h, "POST", "/v1/enrollments/enr-123/complete", `{"installation_status":"INSTALLED"}`, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer enr-token",
	})
	if rr2.Code != http.StatusOK {
		t.Fatalf("INSTALLED: status = %d, want 200 (body %s)", rr2.Code, rr2.Body.String())
	}
	if p.count("CompleteEnrollment") != 2 {
		t.Fatalf("CompleteEnrollment calls = %d, want 2", p.count("CompleteEnrollment"))
	}
}

// --- SOL-M4.3-002: resource binding follows the effective policy ---

// TestConditionalResourceBindingIgnoresExtraCapability proves that an extra
// authenticated capability bound to a DIFFERENT resource never vetoes a valid
// alternative selected by the effective condition (INSTALLED -> DeviceMTLS).
func TestConditionalResourceBindingIgnoresExtraCapability(t *testing.T) {
	v := newCapabilityVerifier(t)
	store := capability.NewMemoryStore(v)
	// Extra EnrollmentAccessToken bound to enrollment B.
	if err := store.SeedEnrollmentAccess("enr-B-token", "enr-B", futureExpiry()); err != nil {
		t.Fatal(err)
	}
	h, p := newAuthTestHandler(t, newCapabilityRegistry(t, v, store, capability.SystemClock{}), presentDeviceSource())

	// INSTALLED requires DeviceMTLS, which authenticates; the extra
	// EnrollmentAccessToken bound to B must not cause a 401.
	rr := doAuth(t, h, "POST", "/v1/enrollments/enr-A/complete", `{"installation_status":"INSTALLED"}`, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer enr-B-token",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("INSTALLED: status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("CompleteEnrollment") != 1 {
		t.Fatal("CompleteEnrollment was not reached")
	}
}

// TestConditionalResourceBindingEnforcesRequiredKind proves that when the
// effective condition REQUIRES a capability, that capability's binding must
// match the route resource.
func TestConditionalResourceBindingEnforcesRequiredKind(t *testing.T) {
	v := newCapabilityVerifier(t)
	store := capability.NewMemoryStore(v)
	if err := store.SeedEnrollmentAccess("enr-B-token", "enr-B", futureExpiry()); err != nil {
		t.Fatal(err)
	}
	if err := store.SeedEnrollmentAccess("enr-A-token", "enr-A", futureExpiry()); err != nil {
		t.Fatal(err)
	}

	t.Run("FAILED bound to B on route A -> 401 Bearer", func(t *testing.T) {
		h, p := newAuthTestHandler(t, newCapabilityRegistry(t, v, store, capability.SystemClock{}), presentDeviceSource())
		rr := doAuth(t, h, "POST", "/v1/enrollments/enr-A/complete", `{"installation_status":"FAILED","error_code":"AGENT_INSTALL_FAILED"}`, map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
			"Authorization":   "Bearer enr-B-token",
		})
		assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		if got := rr.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Fatalf("WWW-Authenticate = %q, want Bearer", got)
		}
		assertNoHandlerCall(t, &p.probeSSI)
	})

	t.Run("FAILED bound to A on route A -> pass", func(t *testing.T) {
		h, p := newAuthTestHandler(t, newCapabilityRegistry(t, v, store, capability.SystemClock{}), presentDeviceSource())
		rr := doAuth(t, h, "POST", "/v1/enrollments/enr-A/complete", `{"installation_status":"FAILED","error_code":"AGENT_INSTALL_FAILED"}`, map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
			"Authorization":   "Bearer enr-A-token",
		})
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
		}
		if p.count("CompleteEnrollment") != 1 {
			t.Fatal("CompleteEnrollment was not reached")
		}
	})
}
