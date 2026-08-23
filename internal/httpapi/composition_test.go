package httpapi_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/composition"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/oidc"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/config"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/resourceownership"
)

// TestCompositionBuildWiresIntoServer proves the M4.6 composition root: the
// registry and device source produced by composition.Build (which validates
// them against the compiled canonical policy at startup) drive the real HTTP
// pipeline through NewServer. A genuinely seeded opaque RequestAccessToken is
// verified by the real M4.3 authenticator and reaches the handler.
func TestCompositionBuildWiresIntoServer(t *testing.T) {
	verifier, err := capability.NewHMACVerifier([]byte("composition-http-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	store := capability.NewMemoryStore(verifier)
	if err := store.SeedRequestAccess("req-abc-token", "por-123", time.Now().Add(time.Hour), capability.StateActive); err != nil {
		t.Fatal(err)
	}

	humanCfg, err := oidc.NewProviderConfig(authpolicy.CredentialKindHumanOIDC, "https://issuer.example/human", []string{"enrollment-api"}, []string{"RS256"}, oidc.StaticKeySetSource{}, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	adminCfg, err := oidc.NewProviderConfig(authpolicy.CredentialKindAdminOIDC, "https://issuer.example/admin", []string{"enrollment-api"}, []string{"RS256"}, oidc.StaticKeySetSource{}, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	registry, device, err := composition.Build(composition.Config{
		CapabilityVerifier: verifier,
		CapabilityStore:    store,
		HumanOIDC:          humanCfg,
		AdminOIDC:          adminCfg,
		// A present-but-empty device source satisfies the startup validation;
		// this test exercises the bearer RequestAccessToken branch only.
		DeviceMTLSSource: authruntime.DeviceTestSource{Credential: func(*http.Request) (*authruntime.DeviceCredential, error) {
			return nil, nil
		}},
	})
	if err != nil {
		t.Fatalf("composition.Build: %v", err)
	}

	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	partnerSvc := partnerauth.NewUnavailableService()
	srv, err := httpapi.NewServer(cfg,
		httpapi.WithAuthnRegistry(registry),
		httpapi.WithDeviceMTLSSource(device),
		// This test exercises the bearer RequestAccessToken enrollment branch
		// only; the mandatory M5.2 and M5.3 dependencies are wired explicitly
		// as the fail-closed unavailable providers.
		httpapi.WithPartnerAuthService(partnerSvc),
		httpapi.WithResourceOwnershipService(resourceownership.NewUnavailableService(partnerSvc)),
	)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	p := &probeSSI{calls: map[string]int{}}
	h := srv.Handler(p)

	rr := doAuth(t, h, "POST", "/v1/enrollments", validEnrollmentBody, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
		"Authorization":   "Bearer req-abc-token",
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("CreateEnrollment") != 1 {
		t.Fatalf("CreateEnrollment calls = %d, want 1", p.count("CreateEnrollment"))
	}
}
