package composition

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/oidc"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
)

var compositionTestKey = []byte("composition-test-key-material")

func newCapabilityVerifier(t *testing.T) capability.Verifier {
	t.Helper()
	v, err := capability.NewHMACVerifier(compositionTestKey)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func newOIDCConfig(t *testing.T, kind authpolicy.CredentialKind, issuer string) *oidc.ProviderConfig {
	t.Helper()
	cfg, err := oidc.NewProviderConfig(kind, issuer, []string{"enrollment-api"}, []string{"RS256"}, oidc.StaticKeySetSource{}, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func fullConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		CapabilityVerifier: newCapabilityVerifier(t),
		CapabilityStore:    capability.NewMemoryStore(newCapabilityVerifier(t)),
		HumanOIDC:          newOIDCConfig(t, authpolicy.CredentialKindHumanOIDC, "https://issuer.example/human"),
		AdminOIDC:          newOIDCConfig(t, authpolicy.CredentialKindAdminOIDC, "https://issuer.example/admin"),
		DeviceMTLSSource: authruntime.DeviceTestSource{Credential: func(*http.Request) (*authruntime.DeviceCredential, error) {
			return &authruntime.DeviceCredential{}, nil
		}},
	}
}

func TestRegistryAssemblesAllSixKinds(t *testing.T) {
	r, err := Registry(fullConfig(t))
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	for _, kind := range []authpolicy.CredentialKind{
		authpolicy.CredentialKindHumanOIDC,
		authpolicy.CredentialKindAdminOIDC,
		authpolicy.CredentialKindTemporaryPrincipalToken,
		authpolicy.CredentialKindRequestAccessToken,
		authpolicy.CredentialKindEnrollmentAccessToken,
		authpolicy.CredentialKindDeviceMTLS,
	} {
		if _, ok := r.Get(kind); !ok {
			t.Errorf("registry is missing kind %q", kind)
		}
	}
}

func TestBuildValidComposition(t *testing.T) {
	r, device, err := Build(fullConfig(t))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if r == nil {
		t.Fatal("registry is nil")
	}
	if device == nil {
		t.Fatal("device source is nil; canonical policy references DeviceMTLS")
	}
}

func TestBuildMissingDeviceSourceFails(t *testing.T) {
	cfg := fullConfig(t)
	cfg.DeviceMTLSSource = nil
	_, _, err := Build(cfg)
	var mae *authruntime.MissingAuthenticatorError
	if !errors.As(err, &mae) {
		t.Fatalf("err = %v, want MissingAuthenticatorError", err)
	}
	if mae.Kind != authpolicy.CredentialKindDeviceMTLS {
		t.Fatalf("MissingAuthenticatorError.Kind = %q; want DeviceMTLS", mae.Kind)
	}
}

func TestRegistryRejectsMissingRequiredPorts(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		field  string
	}{
		{"capability verifier", func(c *Config) { c.CapabilityVerifier = nil }, "capability_verifier"},
		{"capability store", func(c *Config) { c.CapabilityStore = nil }, "capability_store"},
		{"human oidc", func(c *Config) { c.HumanOIDC = nil }, "human_oidc"},
		{"admin oidc", func(c *Config) { c.AdminOIDC = nil }, "admin_oidc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fullConfig(t)
			tc.mutate(&cfg)
			_, err := Registry(cfg)
			var ce *ConfigError
			if !errors.As(err, &ce) {
				t.Fatalf("err = %v, want ConfigError", err)
			}
			if ce.Field != tc.field {
				t.Fatalf("ConfigError.Field = %q; want %q", ce.Field, tc.field)
			}
		})
	}
}

func TestTemporaryPrincipalDefaultAdapterFailsClosed(t *testing.T) {
	r, err := Registry(fullConfig(t))
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	a, ok := r.Get(authpolicy.CredentialKindTemporaryPrincipalToken)
	if !ok {
		t.Fatal("TemporaryPrincipalToken kind missing")
	}
	if got := a.Kind(); got != authpolicy.CredentialKindTemporaryPrincipalToken {
		t.Fatalf("Kind = %q", got)
	}
	res := a.Authenticate(context.Background(), &authruntime.Credential{BearerToken: "any-opaque-token"})
	if res.Decision != authruntime.DecisionRejected {
		t.Fatalf("Decision = %v; want Rejected", res.Decision)
	}
}

func TestTemporaryPrincipalOverrideIsUsed(t *testing.T) {
	cfg := fullConfig(t)
	cfg.TemporaryPrincipal = authruntime.BearerTestAuthenticator{
		KindValue: authpolicy.CredentialKindTemporaryPrincipalToken,
		Decide: func(string) authruntime.Decision {
			return authruntime.DecisionRejected
		},
	}
	r, err := Registry(cfg)
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	if _, ok := r.Get(authpolicy.CredentialKindTemporaryPrincipalToken); !ok {
		t.Fatal("TemporaryPrincipalToken override missing")
	}
}

func TestUnavailableTemporaryPrincipalNeverAuthenticates(t *testing.T) {
	a := NewUnavailableTemporaryPrincipal()
	if a.Kind() != authpolicy.CredentialKindTemporaryPrincipalToken {
		t.Fatalf("Kind = %q", a.Kind())
	}
	for _, token := range []string{"", "jwt-looking.token.value", "any-bearer"} {
		res := a.Authenticate(context.Background(), &authruntime.Credential{BearerToken: token})
		if res.Decision != authruntime.DecisionRejected {
			t.Fatalf("token %q: Decision = %v; want Rejected", token, res.Decision)
		}
	}
}
