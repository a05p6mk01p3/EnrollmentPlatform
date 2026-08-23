package runtime

import (
	"errors"
	"testing"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
)

func canonicalPolicy(t *testing.T) *authpolicy.Policy {
	t.Helper()
	spec, err := openapi.GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	p, err := authpolicy.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// fullRegistry builds a registry covering all six contractual credential
// kinds (reject-all bearer doubles plus an accept-any device authenticator),
// exercising the validation's success path without authenticating anything.
func fullRegistry(t *testing.T) *Registry {
	t.Helper()
	r, err := NewRegistry(
		rejectAllBearer(authpolicy.CredentialKindHumanOIDC),
		rejectAllBearer(authpolicy.CredentialKindAdminOIDC),
		rejectAllBearer(authpolicy.CredentialKindTemporaryPrincipalToken),
		rejectAllBearer(authpolicy.CredentialKindRequestAccessToken),
		rejectAllBearer(authpolicy.CredentialKindEnrollmentAccessToken),
		acceptDevice(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestValidateRegistryCanonicalSatisfied(t *testing.T) {
	if err := ValidateRegistry(canonicalPolicy(t), fullRegistry(t), presentDevice()); err != nil {
		t.Fatalf("ValidateRegistry = %v; want nil", err)
	}
}

func TestValidateRegistryMissingBearerKind(t *testing.T) {
	p := canonicalPolicy(t)

	// Every referenced bearer kind must be present; omit one at a time and
	// assert the error names exactly the missing kind.
	bearerKinds := []authpolicy.CredentialKind{
		authpolicy.CredentialKindHumanOIDC,
		authpolicy.CredentialKindAdminOIDC,
		authpolicy.CredentialKindTemporaryPrincipalToken,
		authpolicy.CredentialKindRequestAccessToken,
		authpolicy.CredentialKindEnrollmentAccessToken,
	}
	for _, missing := range bearerKinds {
		var auths []Authenticator
		for _, k := range bearerKinds {
			if k == missing {
				continue
			}
			auths = append(auths, rejectAllBearer(k))
		}
		auths = append(auths, acceptDevice())
		r, err := NewRegistry(auths...)
		if err != nil {
			t.Fatal(err)
		}

		err = ValidateRegistry(p, r, presentDevice())
		var mae *MissingAuthenticatorError
		if !errors.As(err, &mae) {
			t.Fatalf("ValidateRegistry missing %q: err = %v, want MissingAuthenticatorError", missing, err)
		}
		if mae.Kind != missing {
			t.Fatalf("MissingAuthenticatorError.Kind = %q; want %q", mae.Kind, missing)
		}
	}
}

func TestValidateRegistryMissingDeviceSource(t *testing.T) {
	// DeviceMTLS is referenced by the canonical policy (createEnrollment
	// RENEWAL/REKEY, completeEnrollment INSTALLED). A full registry but a nil
	// trusted-proxy source means the DeviceMTLS boundary is absent.
	err := ValidateRegistry(canonicalPolicy(t), fullRegistry(t), nil)
	var mae *MissingAuthenticatorError
	if !errors.As(err, &mae) {
		t.Fatalf("err = %v, want MissingAuthenticatorError", err)
	}
	if mae.Kind != authpolicy.CredentialKindDeviceMTLS {
		t.Fatalf("MissingAuthenticatorError.Kind = %q; want %q", mae.Kind, authpolicy.CredentialKindDeviceMTLS)
	}
}

func TestValidateRegistryMissingDeviceAuthenticator(t *testing.T) {
	// Omitting the DeviceMTLS authenticator (even with a present source) must
	// be reported as a missing DeviceMTLS component.
	r, err := NewRegistry(
		rejectAllBearer(authpolicy.CredentialKindHumanOIDC),
		rejectAllBearer(authpolicy.CredentialKindAdminOIDC),
		rejectAllBearer(authpolicy.CredentialKindTemporaryPrincipalToken),
		rejectAllBearer(authpolicy.CredentialKindRequestAccessToken),
		rejectAllBearer(authpolicy.CredentialKindEnrollmentAccessToken),
	)
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateRegistry(canonicalPolicy(t), r, presentDevice())
	var mae *MissingAuthenticatorError
	if !errors.As(err, &mae) {
		t.Fatalf("err = %v, want MissingAuthenticatorError", err)
	}
	if mae.Kind != authpolicy.CredentialKindDeviceMTLS {
		t.Fatalf("MissingAuthenticatorError.Kind = %q; want %q", mae.Kind, authpolicy.CredentialKindDeviceMTLS)
	}
}

func TestValidateRegistryRejectsNilInputs(t *testing.T) {
	if err := ValidateRegistry(nil, fullRegistry(t), presentDevice()); err == nil {
		t.Fatal("nil compiled policy: want error")
	}
	if err := ValidateRegistry(canonicalPolicy(t), nil, presentDevice()); err == nil {
		t.Fatal("nil registry: want error")
	}
}

func TestValidateRegistryRejectsTypedNilAuthenticator(t *testing.T) {
	// A registry that LOOKS complete but holds a typed-nil HumanOIDC
	// authenticator must be rejected by the startup boundary independently of
	// NewRegistry (SOL-M4.6-003). The registry is constructed directly to
	// model a caller that bypassed the fixed registry constructor.
	var ptr *pointerBearerAuthenticator
	reg := &Registry{byKind: map[authpolicy.CredentialKind]Authenticator{
		authpolicy.CredentialKindHumanOIDC:               ptr,
		authpolicy.CredentialKindAdminOIDC:               rejectAllBearer(authpolicy.CredentialKindAdminOIDC),
		authpolicy.CredentialKindTemporaryPrincipalToken: rejectAllBearer(authpolicy.CredentialKindTemporaryPrincipalToken),
		authpolicy.CredentialKindRequestAccessToken:      rejectAllBearer(authpolicy.CredentialKindRequestAccessToken),
		authpolicy.CredentialKindEnrollmentAccessToken:   rejectAllBearer(authpolicy.CredentialKindEnrollmentAccessToken),
		authpolicy.CredentialKindDeviceMTLS:              acceptDevice(),
	}}

	err := ValidateRegistry(canonicalPolicy(t), reg, presentDevice())
	var mae *MissingAuthenticatorError
	if !errors.As(err, &mae) || mae.Kind != authpolicy.CredentialKindHumanOIDC {
		t.Fatalf("err = %v, want MissingAuthenticatorError{HumanOIDC}", err)
	}
}

func TestValidateRegistryRejectsTypedNilDeviceSource(t *testing.T) {
	var ptr *pointerDeviceSource
	var src DeviceMTLSSource = ptr

	err := ValidateRegistry(canonicalPolicy(t), fullRegistry(t), src)
	var mae *MissingAuthenticatorError
	if !errors.As(err, &mae) || mae.Kind != authpolicy.CredentialKindDeviceMTLS {
		t.Fatalf("err = %v, want MissingAuthenticatorError{DeviceMTLS}", err)
	}
}

func TestReferencedKindsCanonicalAllSix(t *testing.T) {
	got := referencedKinds(canonicalPolicy(t))
	want := []authpolicy.CredentialKind{
		authpolicy.CredentialKindAdminOIDC,
		authpolicy.CredentialKindDeviceMTLS,
		authpolicy.CredentialKindEnrollmentAccessToken,
		authpolicy.CredentialKindHumanOIDC,
		authpolicy.CredentialKindRequestAccessToken,
		authpolicy.CredentialKindTemporaryPrincipalToken,
	}
	if len(got) != len(want) {
		t.Fatalf("referencedKinds = %v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("referencedKinds[%d] = %q; want %q (full %v)", i, got[i], want[i], got)
		}
	}
}
