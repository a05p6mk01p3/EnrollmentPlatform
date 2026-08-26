package application

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
)

// Clock provides the server-controlled time source used for all expiry and
// lifecycle decisions. Client time authority is never trusted.
type Clock interface {
	Now() time.Time
}

// SystemClock implements Clock using the system clock.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

func (SystemClock) Validate() error { return nil }

// Repository is the provider-neutral aggregate persistence port.
type Repository interface {
	Get(ctx context.Context, id domain.ID) (*domain.PreOnboardingRequest, bool, error)
	List(ctx context.Context, filter ListFilter) (ListResult, error)
	Save(ctx context.Context, req *domain.PreOnboardingRequest) error
}

// ListFilter specifies filtering and pagination criteria for pre-onboarding queries.
type ListFilter struct {
	AuthorizedPartners []string
	PartnerIDFilter    *string
	StatusFilter       *domain.State
	CreatedFrom        *time.Time
	CreatedTo          *time.Time
	PageSize           int
	PageToken          string
	Now                time.Time
}

// ListResult holds the outcome of a repository listing query.
type ListResult struct {
	Items         []*domain.PreOnboardingRequest
	NextPageToken string
	TotalCount    int
}

// ResultStore is the transaction-bound port for persisting and retrieving
// committed application result snapshots for idempotent replay.
type ResultStore interface {
	SaveCreateResult(ctx context.Context, loc runtime.ResultLocator, res PreOnboardingCreateResultSnapshot) error
	GetCreateResult(ctx context.Context, loc runtime.ResultLocator) (PreOnboardingCreateResultSnapshot, bool, error)
	SaveApprovalResult(ctx context.Context, loc runtime.ResultLocator, res ApprovalResultSnapshot) error
	GetApprovalResult(ctx context.Context, loc runtime.ResultLocator) (ApprovalResultSnapshot, bool, error)
	SaveRejectionResult(ctx context.Context, loc runtime.ResultLocator, res RejectionResultSnapshot) error
	GetRejectionResult(ctx context.Context, loc runtime.ResultLocator) (RejectionResultSnapshot, bool, error)
}

// RequestAccessWriter is the write-side complement to capability.Store. It is
// transaction-bound; authentication remains strictly read-only.
type RequestAccessWriter interface {
	CreateRequestAccess(ctx context.Context, key capability.VerifierKey, rec capability.RequestAccessRecord) error
}

// IDGenerator and TokenGenerator are pure generation seams. Their output is
// transient until the enclosing UoW commits it.
type IDGenerator interface {
	NewPreOnboardingRequestID(context.Context) (string, error)
}
type TokenGenerator interface {
	NewRequestAccessToken(context.Context) (string, error)
}

type CryptoIDGenerator struct{}

func (CryptoIDGenerator) NewPreOnboardingRequestID(context.Context) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "por-" + base64.RawURLEncoding.EncodeToString(b), nil
}

type CryptoTokenGenerator struct{}

func (CryptoTokenGenerator) NewRequestAccessToken(context.Context) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DeviceAllocator is the provider-neutral logical device identifier generator.
type DeviceAllocator interface {
	AllocateDeviceID(ctx context.Context, req *domain.PreOnboardingRequest) (string, error)
}

// AuditWriter is the transaction-bound audit staging port.
type AuditWriter interface {
	StageEvent(ctx context.Context, event AuditEvent) error
}

// AdminPrincipal represents an authenticated administrative caller.
type AdminPrincipal struct {
	Issuer  string
	Subject string
}

// PartnerAuthorityChecker determines whether an administrative principal
// possesses current server-side authority for a given partner.
type PartnerAuthorityChecker interface {
	HasPartnerAuthority(ctx context.Context, admin AdminPrincipal, partnerID string) (bool, error)
	GetAuthorizedPartners(ctx context.Context, admin AdminPrincipal) ([]string, error)
}

// PartnerEligibilityChecker evaluates whether a partner is currently eligible
// for device enrollment / pre-onboarding approval.
type PartnerEligibilityChecker interface {
	IsPartnerEligible(ctx context.Context, partnerID string) (bool, error)
}

// IdempotencyRetentionPolicy provides the reservation and replay retention
// durations for idempotent administrative decisions.
type IdempotencyRetentionPolicy interface {
	ReservationDuration() time.Duration
}

// RequestAccessTokenLifetime is deliberately distinct from idempotency retention.
type RequestAccessTokenLifetime interface{ RequestAccessTokenLifetime() time.Duration }
type StaticRequestAccessTokenLifetime struct{ Duration time.Duration }

func (p StaticRequestAccessTokenLifetime) RequestAccessTokenLifetime() time.Duration {
	return p.Duration
}
func (p StaticRequestAccessTokenLifetime) Validate() error {
	if p.Duration <= 0 {
		return errors.New("application: request access token lifetime must be positive")
	}
	return nil
}

// StaticIdempotencyRetentionPolicy is a simple duration-based retention policy.
type StaticIdempotencyRetentionPolicy struct {
	Duration time.Duration
}

func (p StaticIdempotencyRetentionPolicy) ReservationDuration() time.Duration {
	return p.Duration
}

func (p StaticIdempotencyRetentionPolicy) Validate() error {
	if p.Duration <= 0 {
		return errors.New("application: retention policy duration must be positive")
	}
	return nil
}

// ReplayCapsuleRetentionPolicy provides the lifetime of replay capsules.
type ReplayCapsuleRetentionPolicy interface {
	ReplayCapsuleLifetime() time.Duration
}

type StaticReplayCapsuleRetentionPolicy struct {
	Duration time.Duration
}

func (p StaticReplayCapsuleRetentionPolicy) ReplayCapsuleLifetime() time.Duration {
	return p.Duration
}

func (p StaticReplayCapsuleRetentionPolicy) Validate() error {
	if p.Duration <= 0 {
		return errors.New("application: replay capsule retention policy duration must be positive")
	}
	return nil
}

type TemporaryPrincipalStore interface {
	Get(ctx context.Context, id string) (*domain.TemporaryPrincipal, bool, error)
	Save(ctx context.Context, tp *domain.TemporaryPrincipal) error
}

// UnitOfWork coordinates idempotency reservation, aggregate mutation,
// result snapshot persistence, and audit event staging inside an atomic transaction.
type UnitOfWork interface {
	Repository() Repository
	ResultStore() ResultStore
	AuditWriter() AuditWriter
	IdempotencyStore() runtime.Store
	RequestAccessWriter() RequestAccessWriter
	TemporaryPrincipalStore() TemporaryPrincipalStore
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// UnitOfWorkManager manages UnitOfWork lifecycle.
type UnitOfWorkManager interface {
	Begin(ctx context.Context) (UnitOfWork, error)
}
