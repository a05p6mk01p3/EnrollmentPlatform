package devicemtls

import (
	"context"
	"testing"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	runtime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
)

func TestAuthenticatorKind(t *testing.T) {
	if NewAuthenticator().Kind() != authpolicy.CredentialKindDeviceMTLS {
		t.Fatal("authenticator kind != DeviceMTLS")
	}
}

func TestAuthenticatorAuthenticate(t *testing.T) {
	a := NewAuthenticator()
	ctx := context.Background()

	t.Run("nil credential rejected", func(t *testing.T) {
		if res := a.Authenticate(ctx, nil); res.Decision != runtime.DecisionRejected {
			t.Fatalf("decision = %v, want rejected", res.Decision)
		}
	})

	t.Run("nil device rejected", func(t *testing.T) {
		if res := a.Authenticate(ctx, &runtime.Credential{}); res.Decision != runtime.DecisionRejected {
			t.Fatalf("decision = %v, want rejected", res.Decision)
		}
	})

	t.Run("valid device authenticated", func(t *testing.T) {
		cred := &runtime.Credential{Device: &runtime.DeviceCredential{
			DeviceID:              "dev-D",
			CertificateID:         "cert-A",
			IssuedForEnrollmentID: "enr-A",
		}}
		res := a.Authenticate(ctx, cred)
		if res.Decision != runtime.DecisionAuthenticated {
			t.Fatalf("decision = %v, want authenticated", res.Decision)
		}
		d, ok := res.Binding.DeviceMTLS()
		if !ok || d.DeviceID != "dev-D" || d.CertificateID != "cert-A" || d.IssuedForEnrollmentID != "enr-A" {
			t.Fatalf("binding = %+v (ok=%v)", d, ok)
		}
	})

	t.Run("incomplete device indeterminate", func(t *testing.T) {
		cred := &runtime.Credential{Device: &runtime.DeviceCredential{
			DeviceID:      "dev-D",
			CertificateID: "cert-A",
		}}
		res := a.Authenticate(ctx, cred)
		if res.Decision != runtime.DecisionIndeterminate {
			t.Fatalf("decision = %v, want indeterminate", res.Decision)
		}
	})
}
