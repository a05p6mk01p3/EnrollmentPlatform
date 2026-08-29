package recovery

import (
	"context"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
)

type unavailableVerifier struct{}

func (unavailableVerifier) Derive(authpolicy.CredentialKind, string) (capability.VerifierKey, error) {
	return "", ErrDependencyUnavailable
}

type unavailableStore struct{}

func (unavailableStore) LookupRequestAccess(context.Context, capability.VerifierKey) (*capability.RequestAccessRecord, error) {
	return nil, ErrDependencyUnavailable
}
func (unavailableStore) LookupEnrollmentAccess(context.Context, capability.VerifierKey) (*capability.EnrollmentAccessRecord, error) {
	return nil, ErrDependencyUnavailable
}

// NewUnavailableRecognizer returns an explicit fail-closed recovery boundary
// for composition roots that do not have the retained capability store wired.
func NewUnavailableRecognizer() *Recognizer {
	r, err := NewRecognizer(unavailableVerifier{}, unavailableStore{})
	if err != nil {
		panic(err)
	}
	return r
}
