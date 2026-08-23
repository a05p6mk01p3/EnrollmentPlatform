package runtime

import (
	"context"
	"errors"
	"net/http"
	"testing"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
)

// pointerBearerAuthenticator is a pointer-backed Authenticator whose nil
// pointer, wrapped in an Authenticator interface, is the typed-nil case.
// Kind returns a constant when the receiver is nil so that a naive registry
// constructor (one that only compared the interface to nil) would have stored
// it; the fixed constructor detects the typed-nil before ever calling Kind.
type pointerBearerAuthenticator struct {
	kind authpolicy.CredentialKind
}

func (a *pointerBearerAuthenticator) Kind() authpolicy.CredentialKind {
	if a == nil {
		return authpolicy.CredentialKindHumanOIDC
	}
	return a.kind
}

func (a *pointerBearerAuthenticator) Authenticate(context.Context, *Credential) AuthenticationResult {
	return AuthenticationResult{Decision: DecisionRejected}
}

// pointerDeviceSource is a pointer-backed DeviceMTLSSource whose nil pointer
// is the typed-nil device-source case.
type pointerDeviceSource struct{}

func (*pointerDeviceSource) DeviceCredential(*http.Request) (*DeviceCredential, error) {
	return nil, nil
}

// valueAuthenticator is a concrete non-pointer Authenticator: isNilLike must
// not panic when the dynamic kind is non-nilable.
type valueAuthenticator struct{}

func (valueAuthenticator) Kind() authpolicy.CredentialKind {
	return authpolicy.CredentialKindHumanOIDC
}

func (valueAuthenticator) Authenticate(context.Context, *Credential) AuthenticationResult {
	return AuthenticationResult{Decision: DecisionRejected}
}

func TestNewRegistryRejectsLiteralNilAuthenticator(t *testing.T) {
	reg, err := NewRegistry(nil)
	if reg != nil {
		t.Fatal("registry must be nil when construction fails")
	}
	var ne *NilAuthenticatorError
	if !errors.As(err, &ne) {
		t.Fatalf("err = %v, want NilAuthenticatorError", err)
	}
}

func TestNewRegistryRejectsTypedNilAuthenticator(t *testing.T) {
	var ptr *pointerBearerAuthenticator
	var auth Authenticator = ptr
	reg, err := NewRegistry(auth, acceptDevice())
	if reg != nil {
		t.Fatal("registry must be nil when construction fails")
	}
	var ne *NilAuthenticatorError
	if !errors.As(err, &ne) {
		t.Fatalf("err = %v, want NilAuthenticatorError", err)
	}
}

func TestRegistryGetDoesNotExposeTypedNilAuthenticator(t *testing.T) {
	var ptr *pointerBearerAuthenticator
	reg := &Registry{byKind: map[authpolicy.CredentialKind]Authenticator{
		authpolicy.CredentialKindHumanOIDC: ptr,
	}}
	if _, ok := reg.Get(authpolicy.CredentialKindHumanOIDC); ok {
		t.Fatal("Get must not report a typed-nil authenticator as available")
	}
}

func TestIsNilLike(t *testing.T) {
	var ptr *pointerBearerAuthenticator
	var nilMap map[string]int
	var nilSlice []int
	var nilFunc func()
	var nilChan chan int

	cases := []struct {
		name string
		v    any
		want bool
	}{
		{"literal nil", nil, true},
		{"typed-nil pointer", ptr, true},
		{"typed-nil map", nilMap, true},
		{"typed-nil slice", nilSlice, true},
		{"typed-nil func", nilFunc, true},
		{"typed-nil channel", nilChan, true},
		{"non-nil pointer", &pointerBearerAuthenticator{kind: authpolicy.CredentialKindAdminOIDC}, false},
		{"value authenticator (non-nilable)", valueAuthenticator{}, false},
		{"string (non-nilable)", "x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNilLike(tc.v); got != tc.want {
				t.Fatalf("isNilLike(%T) = %v, want %v", tc.v, got, tc.want)
			}
		})
	}
}
