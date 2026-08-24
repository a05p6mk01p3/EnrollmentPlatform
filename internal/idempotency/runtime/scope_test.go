package runtime_test

import (
	"reflect"
	"strings"
	"testing"

	authnpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
)

func TestEffectiveScopeExactEqualityAndSeparation(t *testing.T) {
	key := mustKey(t, "0123456789abcdef")
	cred := mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "issuer-a|subject-a")
	base := mustEffectiveScope(t, cred, "POST", "/v1/enrollments", key)

	same := mustEffectiveScope(t, cred, "POST", "/v1/enrollments", key)
	if !base.Equal(same) {
		t.Fatal("identical components must map to the same effective scope")
	}

	// Any exact component change maps to a different scope.
	differentCred := mustEffectiveScope(t,
		mustCredentialScope(t, authnpolicy.CredentialKindAdminOIDC, "issuer-a|subject-a"),
		"POST", "/v1/enrollments", key)
	differentMethod := mustEffectiveScope(t, cred, "PUT", "/v1/enrollments", key)
	differentRoute := mustEffectiveScope(t, cred, "POST", "/v1/enrollments/{id}/complete", key)
	differentKey := mustEffectiveScope(t, cred, "POST", "/v1/enrollments", mustKey(t, "0123456789abcdeg"))

	for name, other := range map[string]runtime.EffectiveScope{
		"credential": differentCred,
		"method":     differentMethod,
		"route":      differentRoute,
		"key":        differentKey,
	} {
		if base.Equal(other) {
			t.Errorf("scope differing only in %s must not be equal", name)
		}
	}
}

func TestCredentialScopeRejectsUnusableConstruction(t *testing.T) {
	if _, err := runtime.NewCredentialScope("", "binding"); err == nil {
		t.Fatal("unrecognized kind must be rejected")
	}
	if _, err := runtime.NewCredentialScope(authnpolicy.CredentialKindHumanOIDC, ""); err == nil {
		t.Fatal("empty binding must be rejected")
	}
}

func TestEffectiveScopeRejectsUnusableConstruction(t *testing.T) {
	cred := mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "subject-a")
	key := mustKey(t, "0123456789abcdef")

	if _, err := runtime.NewEffectiveScope(runtime.CredentialScope{}, "POST", "/v1/enrollments", key); err == nil {
		t.Fatal("zero credential scope must be rejected")
	}
	if _, err := runtime.NewEffectiveScope(cred, "post", "/v1/enrollments", key); err == nil {
		t.Fatal("non-canonical lowercase method must be rejected")
	}
	if _, err := runtime.NewEffectiveScope(cred, "POST", "", key); err == nil {
		t.Fatal("empty route must be rejected")
	}
	if _, err := runtime.NewEffectiveScope(cred, "POST", "/v1/enrollments", runtime.IdempotencyKey{}); err == nil {
		t.Fatal("zero key must be rejected")
	}
}

func TestScopeCarriesNoRawCredentialAuthority(t *testing.T) {
	deny := []string{"token", "authorization", "bearer", "partner", "certificate", "private", "secret", "header", "jwt"}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(runtime.CredentialScope{}),
		reflect.TypeOf(runtime.EffectiveScope{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			name := strings.ToLower(typ.Field(i).Name)
			for _, d := range deny {
				if strings.Contains(name, d) {
					t.Errorf("%s field %q carries raw credential authority marker %q", typ.Name(), typ.Field(i).Name, d)
				}
			}
		}
	}

	// The only discriminator is the closed M4 credential kind, plus an opaque
	// binding. A Replay Capsule cannot be turned into a credential scope.
	capsuleType := reflect.TypeOf(&runtime.ProtectedEnvelope{})
	for i := 0; i < capsuleType.NumMethod(); i++ {
		if strings.Contains(strings.ToLower(capsuleType.Method(i).Name), "credential") {
			t.Errorf("ProtectedEnvelope must not expose a credential-producing method")
		}
	}
}
