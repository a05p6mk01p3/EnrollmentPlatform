package application

import (
	"context"
	"errors"
	"time"

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
	SaveApprovalResult(ctx context.Context, loc runtime.ResultLocator, res ApprovalResultSnapshot) error
	GetApprovalResult(ctx context.Context, loc runtime.ResultLocator) (ApprovalResultSnapshot, bool, error)
	SaveRejectionResult(ctx context.Context, loc runtime.ResultLocator, res RejectionResultSnapshot) error
	GetRejectionResult(ctx context.Context, loc runtime.ResultLocator) (RejectionResultSnapshot, bool, error)
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

// UnitOfWork coordinates idempotency reservation, aggregate mutation,
// result snapshot persistence, and audit event staging inside an atomic transaction.
type UnitOfWork interface {
	Repository() Repository
	ResultStore() ResultStore
	AuditWriter() AuditWriter
	IdempotencyStore() runtime.Store
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// UnitOfWorkManager manages UnitOfWork lifecycle.
type UnitOfWorkManager interface {
	Begin(ctx context.Context) (UnitOfWork, error)
}
