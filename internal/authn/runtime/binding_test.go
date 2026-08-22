package runtime

import (
	"testing"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
)

// mustBinding unwraps a (binding, error) pair or panics on error.
func mustBinding(b *Binding, err error) *Binding {
	if err != nil {
		panic(err)
	}
	return b
}

// TestBindingVariantsMatchCredentialKinds proves every CredentialKind has its
// own typed binding variant, and only the matching accessor succeeds.
func TestBindingVariantsMatchCredentialKinds(t *testing.T) {
	human := mustBinding(NewHumanOIDCBinding("issuer-a", "subject-a"))
	if human.Kind() != authpolicy.CredentialKindHumanOIDC {
		t.Fatalf("kind = %q", human.Kind())
	}
	o, ok := human.OIDCIdentity()
	if !ok || o.Issuer != "issuer-a" || o.Subject != "subject-a" {
		t.Fatalf("OIDC identity = %+v (ok=%v)", o, ok)
	}
	if _, ok := human.RequestAccess(); ok {
		t.Fatal("HumanOIDC binding must not expose RequestAccess")
	}

	admin := mustBinding(NewAdminOIDCBinding("issuer-b", "subject-b"))
	if admin.Kind() != authpolicy.CredentialKindAdminOIDC {
		t.Fatalf("AdminOIDC kind = %q", admin.Kind())
	}
	if _, ok := admin.OIDCIdentity(); !ok {
		t.Fatal("AdminOIDC binding must expose OIDCIdentity")
	}

	req := mustBinding(NewRequestAccessBinding("por-123"))
	if req.Kind() != authpolicy.CredentialKindRequestAccessToken {
		t.Fatalf("kind = %q", req.Kind())
	}
	r, ok := req.RequestAccess()
	if !ok || r.PreOnboardingRequestID != "por-123" {
		t.Fatalf("request-access = %+v (ok=%v)", r, ok)
	}
	if _, ok := req.EnrollmentAccess(); ok {
		t.Fatal("RequestAccess binding must not expose EnrollmentAccess")
	}
	if _, ok := req.OIDCIdentity(); ok {
		t.Fatal("RequestAccess binding must not expose OIDCIdentity")
	}

	enr := mustBinding(NewEnrollmentAccessBinding("enr-123"))
	if enr.Kind() != authpolicy.CredentialKindEnrollmentAccessToken {
		t.Fatalf("kind = %q", enr.Kind())
	}
	e, ok := enr.EnrollmentAccess()
	if !ok || e.EnrollmentID != "enr-123" {
		t.Fatalf("enrollment-access = %+v (ok=%v)", e, ok)
	}

	tp := mustBinding(NewTemporaryPrincipalBinding("tp-123"))
	if tp.Kind() != authpolicy.CredentialKindTemporaryPrincipalToken {
		t.Fatalf("kind = %q", tp.Kind())
	}
	tt, ok := tp.TemporaryPrincipal()
	if !ok || tt.TemporaryPrincipalID != "tp-123" {
		t.Fatalf("temporary-principal = %+v (ok=%v)", tt, ok)
	}
	if _, ok := tp.OIDCIdentity(); ok {
		t.Fatal("TemporaryPrincipal binding must not expose OIDCIdentity")
	}

	dev := mustBinding(NewDeviceMTLSBinding("dev-123", "cert-456"))
	if dev.Kind() != authpolicy.CredentialKindDeviceMTLS {
		t.Fatalf("kind = %q", dev.Kind())
	}
	d, ok := dev.DeviceMTLS()
	if !ok || d.DeviceID != "dev-123" || d.CertificateID != "cert-456" {
		t.Fatalf("device-mTLS = %+v (ok=%v)", d, ok)
	}
	if _, ok := dev.TemporaryPrincipal(); ok {
		t.Fatal("DeviceMTLS binding must not expose TemporaryPrincipal")
	}
}

// TestBindingEmptyMandatoryFieldsFailConstruction proves every constructor
// rejects empty mandatory fields.
func TestBindingEmptyMandatoryFieldsFailConstruction(t *testing.T) {
	cases := []struct {
		name string
		fn   func() (*Binding, error)
	}{
		{"HumanOIDC empty issuer", func() (*Binding, error) { return NewHumanOIDCBinding("", "s") }},
		{"HumanOIDC empty subject", func() (*Binding, error) { return NewHumanOIDCBinding("i", "") }},
		{"AdminOIDC empty issuer", func() (*Binding, error) { return NewAdminOIDCBinding("", "s") }},
		{"AdminOIDC empty subject", func() (*Binding, error) { return NewAdminOIDCBinding("i", "") }},
		{"RequestAccess empty request ID", func() (*Binding, error) { return NewRequestAccessBinding("") }},
		{"EnrollmentAccess empty enrollment ID", func() (*Binding, error) { return NewEnrollmentAccessBinding("") }},
		{"TemporaryPrincipal empty ID", func() (*Binding, error) { return NewTemporaryPrincipalBinding("") }},
		{"DeviceMTLS empty device ID", func() (*Binding, error) { return NewDeviceMTLSBinding("", "cert") }},
		{"DeviceMTLS empty certificate ID", func() (*Binding, error) { return NewDeviceMTLSBinding("dev", "") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.fn(); err == nil {
				t.Fatal("empty mandatory field was accepted")
			}
		})
	}
}

// TestValidateBindingVariantIncompatibleWithKind proves the runtime fails
// closed when a Binding's kind disagrees with its populated variant (reachable
// only by manual construction within this package; the typed constructors
// couple them).
func TestValidateBindingVariantIncompatibleWithKind(t *testing.T) {
	humanWithDevice := &Binding{
		kind:       authpolicy.CredentialKindHumanOIDC,
		deviceMTLS: DeviceMTLSBinding{DeviceID: "d", CertificateID: "c"},
	}
	if err := validateBinding(authpolicy.CredentialKindHumanOIDC, humanWithDevice); err == nil {
		t.Fatal("HumanOIDC kind with DeviceMTLS variant was accepted")
	}

	requestWithEnrollment := &Binding{
		kind:             authpolicy.CredentialKindRequestAccessToken,
		enrollmentAccess: EnrollmentAccessBinding{EnrollmentID: "e"},
	}
	if err := validateBinding(authpolicy.CredentialKindRequestAccessToken, requestWithEnrollment); err == nil {
		t.Fatal("RequestAccessToken kind with EnrollmentAccess variant was accepted")
	}

	deviceEmpty := &Binding{kind: authpolicy.CredentialKindDeviceMTLS}
	if err := validateBinding(authpolicy.CredentialKindDeviceMTLS, deviceEmpty); err == nil {
		t.Fatal("DeviceMTLS binding with empty device/certificate IDs was accepted")
	}
}

// TestBindingWrongKindPairingFailsClosedAtRuntime proves the two exact
// examples from the finding fail closed through the runtime: a HumanOIDC
// authenticator returning a DeviceMTLS binding, and a RequestAccessToken
// authenticator returning an EnrollmentAccess binding.
func TestBindingWrongKindPairingFailsClosedAtRuntime(t *testing.T) {
	dev, err := NewDeviceMTLSBinding("dev-1", "cert-1")
	if err != nil {
		t.Fatal(err)
	}
	enr, err := NewEnrollmentAccessBinding("enr-1")
	if err != nil {
		t.Fatal(err)
	}

	// HumanOIDC authenticator + DeviceMTLS binding.
	spec, policy, op := compileSynthetic(t, orSpecYAML)
	reg, err := NewRegistry(
		resultAuthenticator{kind: authpolicy.CredentialKindHumanOIDC, result: AuthenticationResult{Decision: DecisionAuthenticated, Binding: dev}},
		acceptDevice(),
	)
	if err != nil {
		t.Fatal(err)
	}
	rt := newRT(t, spec, policy, reg, nil)
	if _, err := rt.authenticate(bearerRequest(t, "tok"), op); err == nil {
		t.Fatal("HumanOIDC authenticator with DeviceMTLS binding was accepted")
	} else {
		wantErrorKind(t, err, errorKindInvalidBinding)
	}

	// RequestAccessToken authenticator + EnrollmentAccess binding.
	reqSpec, reqPolicy, reqOp := compileSynthetic(t, `openapi: 3.1.0
info: {title: synthetic, version: '1'}
paths:
  /x:
    get:
      operationId: reqOp
      responses:
        '200': {description: ok}
      security:
        - RequestAccessToken: []
components:
  securitySchemes:
    RequestAccessToken: {type: http, scheme: bearer, bearerFormat: opaque}
`)
	reg2, err := NewRegistry(
		resultAuthenticator{kind: authpolicy.CredentialKindRequestAccessToken, result: AuthenticationResult{Decision: DecisionAuthenticated, Binding: enr}},
	)
	if err != nil {
		t.Fatal(err)
	}
	rt2 := newRT(t, reqSpec, reqPolicy, reg2, nil)
	if _, err := rt2.authenticate(bearerRequest(t, "tok"), reqOp); err == nil {
		t.Fatal("RequestAccessToken authenticator with EnrollmentAccess binding was accepted")
	} else {
		wantErrorKind(t, err, errorKindInvalidBinding)
	}
}
