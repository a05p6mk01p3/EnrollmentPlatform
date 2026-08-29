package application

import (
	"context"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
)

// UnavailableUnitOfWorkManager is a structurally valid, fail-closed M5.7
// persistence boundary. It is used only by composition roots that intentionally
// have no enrollment persistence provider yet.
type UnavailableUnitOfWorkManager struct{}

func (UnavailableUnitOfWorkManager) Begin(context.Context) (UnitOfWork, error) {
	return nil, ErrDependencyUnavailable
}
func (UnavailableUnitOfWorkManager) Validate() error { return nil }

type unavailableIDGenerator struct{}

func (unavailableIDGenerator) NewEnrollmentID(context.Context) (string, error) {
	return "", ErrDependencyUnavailable
}

type unavailableChallengeGenerator struct{}

func (unavailableChallengeGenerator) NewChallengeNonce(context.Context) ([]byte, error) {
	return nil, ErrDependencyUnavailable
}

type unavailableTokenGenerator struct{}

func (unavailableTokenGenerator) NewEnrollmentAccessToken(context.Context) (string, error) {
	return "", ErrDependencyUnavailable
}

type unavailableVerifier struct{}

func (unavailableVerifier) Derive(authpolicy.CredentialKind, string) (capability.VerifierKey, error) {
	return "", ErrDependencyUnavailable
}

type unavailableProtector struct{}

func (unavailableProtector) Seal(context.Context, []byte, []byte) (*idempotencyruntime.ProtectedEnvelope, error) {
	return nil, ErrDependencyUnavailable
}
func (unavailableProtector) Open(context.Context, *idempotencyruntime.ProtectedEnvelope, []byte) ([]byte, error) {
	return nil, ErrDependencyUnavailable
}

// NewUnavailableService returns an explicitly wired fail-closed M5.7 service.
// It passes startup structural validation but every operation fails before any
// mutation because the UnitOfWork manager is unavailable.
func NewUnavailableService() *Service {
	svc, err := NewService(ServiceConfig{
		UOWManager:                    UnavailableUnitOfWorkManager{},
		Clock:                         SystemClock{},
		RetentionPolicy:               StaticIdempotencyRetentionPolicy{Duration: time.Hour},
		ReplayCapsulePolicy:           StaticReplayCapsuleRetentionPolicy{Duration: time.Hour},
		ChallengeLifetime:             StaticChallengeLifetimePolicy{Duration: time.Hour},
		EnrollmentAccessTokenLifetime: StaticEnrollmentAccessTokenLifetimePolicy{Duration: time.Hour},
		Create: &CreateDependencies{
			IDGenerator:        unavailableIDGenerator{},
			ChallengeGenerator: unavailableChallengeGenerator{},
			TokenGenerator:     unavailableTokenGenerator{},
			Verifier:           unavailableVerifier{},
			Protector:          unavailableProtector{},
		},
	})
	if err != nil {
		panic(err)
	}
	return svc
}
