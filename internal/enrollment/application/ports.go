package application

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	preonboardingdomain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
)

// Clock is the trusted server-controlled time source.
type Clock interface{ Now() time.Time }

type SystemClock struct{}

func (SystemClock) Now() time.Time  { return time.Now() }
func (SystemClock) Validate() error { return nil }

// PreOnboardingReader exposes the authoritative approved request inside the
// same logical UoW as RequestAccess consumption and enrollment publication.
type PreOnboardingReader interface {
	Get(ctx context.Context, id preonboardingdomain.ID) (*preonboardingdomain.PreOnboardingRequest, bool, error)
}

// RequestAccessCredential is a transaction-local view of the retained
// non-reversible RequestAccess verifier record. Key contains no plaintext.
type RequestAccessCredential struct {
	Key    capability.VerifierKey
	Record capability.RequestAccessRecord
}

// RequestAccessLifecycleStore is the write-side lifecycle boundary separated
// from frozen/read-only M4 authentication. Implementations MUST detect
// ambiguous duplicate records for one request and fail closed.
type RequestAccessLifecycleStore interface {
	GetByPreOnboardingRequestID(ctx context.Context, id string) (RequestAccessCredential, bool, error)
	Save(ctx context.Context, credential RequestAccessCredential) error
}

// EnrollmentRepository owns enrollment persistence used by the originator. Create
// is insertion-only; it must never overwrite an existing enrollment.
// GetEnrollment is used only to fail closed during committed response recovery
// when the idempotency result no longer has a matching authoritative resource.
type EnrollmentRepository interface {
	Create(ctx context.Context, record EnrollmentRecord) error
	GetEnrollment(ctx context.Context, id string) (EnrollmentRecord, bool, error)
}

// EnrollmentContinuationRepository is the shared consistency boundary for
// evidence acceptance and challenge refresh. Implementations must record the
// enrollment snapshot read by a UoW and validate the expected state,
// challenge_version and active challenge again at Commit. Neither operation
// may publish a partial write.
type EnrollmentContinuationRepository interface {
	GetEnrollment(ctx context.Context, id string) (EnrollmentRecord, bool, error)
	StageEvidenceAcceptance(ctx context.Context, write EvidenceAcceptanceWrite) error
	StageChallengeRefresh(ctx context.Context, write ChallengeRefreshWrite) error
}

type EvidenceAcceptanceWrite struct {
	EnrollmentID             string
	ExpectedChallengeVersion int
	Evidence                 AcceptedEvidence
	Material                 *EvaluationMaterial
	AcceptedAt               time.Time
}

type ChallengeRefreshWrite struct {
	EnrollmentID             string
	ExpectedChallengeVersion int
	Challenge                Challenge
	RefreshedAt              time.Time
}

// RefreshResultStore stores only the deterministic non-secret result needed
// for idempotent refresh replay. The challenge nonce is returned by the
// originating response but is not an authentication token.
type RefreshResultStore interface {
	SaveChallengeRefreshResult(ctx context.Context, loc idempotencyruntime.ResultLocator, result ChallengeRefreshResult) error
	GetChallengeRefreshResult(ctx context.Context, loc idempotencyruntime.ResultLocator) (ChallengeRefreshResult, bool, error)
}

// EnrollmentAccessWriter stages the non-reversible authentication verifier for
// the newly-originated EnrollmentAccessToken.
type EnrollmentAccessWriter interface {
	CreateEnrollmentAccess(ctx context.Context, key capability.VerifierKey, rec capability.EnrollmentAccessRecord) error
}

// ResultStore persists the non-secret original 201 snapshot used on replay.
type ResultStore interface {
	SaveCreateResult(ctx context.Context, loc idempotencyruntime.ResultLocator, res CreateResultSnapshot) error
	GetCreateResult(ctx context.Context, loc idempotencyruntime.ResultLocator) (CreateResultSnapshot, bool, error)
}

// InitialEligibilityChecker is transaction-bound so an adapter may track and
// revalidate the authoritative partner/device/profile eligibility read-set at
// commit without freezing the future PostgreSQL or external-policy mechanism.
type InitialEligibilityChecker interface {
	IsInitialEligible(ctx context.Context, partnerID, deviceID, certificateUsage string) (bool, error)
}

// EvidenceRequirementsProvider snapshots the current server-side evidence
// requirements for a NEW INITIAL exchange. REPLAY returns the original
// committed snapshot and never recomputes this response material.
type EvidenceRequirementsProvider interface {
	InitialEvidenceRequirements(ctx context.Context, partnerID, deviceID, certificateUsage string) (EvidenceRequirements, error)
}

// AuditWriter stages audit events; publication occurs only with outer commit.
type AuditWriter interface {
	StageEvent(ctx context.Context, event AuditEvent) error
}

// UnitOfWork coordinates every mutation owned by a NEW INITIAL exchange.
// Implementations must validate all fallible commit-time preconditions before
// publishing any staged state. In particular they must revalidate the tracked
// RequestAccess/pre-onboarding/policy read-set so a late collision cannot
// partially publish an exchange.
type UnitOfWork interface {
	PreOnboarding() PreOnboardingReader
	RequestAccess() RequestAccessLifecycleStore
	Enrollments() EnrollmentRepository
	EnrollmentAccess() EnrollmentAccessWriter
	Results() ResultStore
	Eligibility() InitialEligibilityChecker
	EvidenceRequirements() EvidenceRequirementsProvider
	Audit() AuditWriter
	IdempotencyStore() idempotencyruntime.Store
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

type UnitOfWorkManager interface {
	Begin(ctx context.Context) (UnitOfWork, error)
}

// ContinuationUnitOfWork is an optional extension of UnitOfWork used by M5.8.
// It is deliberately separate so existing M5.7 originator test doubles cannot
// accidentally claim the stronger evidence/refresh consistency contract.
type ContinuationUnitOfWork interface {
	EnrollmentContinuation() EnrollmentContinuationRepository
	RefreshResults() RefreshResultStore
	IdempotencyStore() idempotencyruntime.Store
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// IDGenerator, ChallengeGenerator and TokenGenerator are generation seams.
// Generated values carry no authority until the enclosing UnitOfWork commits.
type IDGenerator interface {
	NewEnrollmentID(context.Context) (string, error)
}
type ChallengeGenerator interface {
	NewChallengeNonce(context.Context) ([]byte, error)
}
type TokenGenerator interface {
	NewEnrollmentAccessToken(context.Context) (string, error)
}

type CryptoIDGenerator struct{}

func (CryptoIDGenerator) NewEnrollmentID(context.Context) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "enr-" + base64.RawURLEncoding.EncodeToString(b), nil
}

type CryptoChallengeGenerator struct{}

func (CryptoChallengeGenerator) NewChallengeNonce(context.Context) ([]byte, error) {
	b := make([]byte, 16) // Protocol requires at least 128 unpredictable bits.
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

type CryptoTokenGenerator struct{}

func (CryptoTokenGenerator) NewEnrollmentAccessToken(context.Context) (string, error) {
	b := make([]byte, 32) // Protocol requires at least 256 bits before encoding.
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Duration policies remain injected/configurable so M5.7 does not freeze
// OPEN/CG-003 quantitative values.
type IdempotencyRetentionPolicy interface{ ReservationDuration() time.Duration }
type ReplayCapsuleRetentionPolicy interface{ ReplayCapsuleLifetime() time.Duration }
type ChallengeLifetimePolicy interface{ ChallengeLifetime() time.Duration }
type EnrollmentAccessTokenLifetimePolicy interface{ EnrollmentAccessTokenLifetime() time.Duration }

type StaticIdempotencyRetentionPolicy struct{ Duration time.Duration }
type StaticReplayCapsuleRetentionPolicy struct{ Duration time.Duration }
type StaticChallengeLifetimePolicy struct{ Duration time.Duration }
type StaticEnrollmentAccessTokenLifetimePolicy struct{ Duration time.Duration }

func (p StaticIdempotencyRetentionPolicy) ReservationDuration() time.Duration     { return p.Duration }
func (p StaticReplayCapsuleRetentionPolicy) ReplayCapsuleLifetime() time.Duration { return p.Duration }
func (p StaticChallengeLifetimePolicy) ChallengeLifetime() time.Duration          { return p.Duration }
func (p StaticEnrollmentAccessTokenLifetimePolicy) EnrollmentAccessTokenLifetime() time.Duration {
	return p.Duration
}

func (p StaticIdempotencyRetentionPolicy) Validate() error {
	return positiveDuration("idempotency retention", p.Duration)
}
func (p StaticReplayCapsuleRetentionPolicy) Validate() error {
	return positiveDuration("replay capsule retention", p.Duration)
}
func (p StaticChallengeLifetimePolicy) Validate() error {
	return positiveDuration("challenge lifetime", p.Duration)
}
func (p StaticEnrollmentAccessTokenLifetimePolicy) Validate() error {
	return positiveDuration("enrollment access token lifetime", p.Duration)
}

func positiveDuration(name string, d time.Duration) error {
	if d <= 0 {
		return errors.New("enrollment application: " + name + " must be positive")
	}
	return nil
}

// CreateDependencies are the cryptographic/generation dependencies specific
// to the secret-originating createEnrollment path.
type CreateDependencies struct {
	IDGenerator        IDGenerator
	ChallengeGenerator ChallengeGenerator
	TokenGenerator     TokenGenerator
	Verifier           capability.Verifier
	Protector          idempotencyruntime.Protector
}
