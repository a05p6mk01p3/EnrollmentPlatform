package application

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
)

// failClosedNoSecretProtector satisfies M5.4 Protector for non-secret operations.
// Approve and reject are strictly non-secret operations: their execution never invokes
// secret protection methods.
type failClosedNoSecretProtector struct{}

func (failClosedNoSecretProtector) Seal(_ context.Context, _ []byte, _ []byte) (*idempotencyruntime.ProtectedEnvelope, error) {
	return nil, errors.New("idempotency: secret protection not supported for non-secret operations")
}

func (failClosedNoSecretProtector) Open(_ context.Context, _ *idempotencyruntime.ProtectedEnvelope, _ []byte) ([]byte, error) {
	return nil, errors.New("idempotency: secret recovery not supported for non-secret operations")
}

// isNilLike reports whether v is nil or holds a typed-nil value.
func isNilLike(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

// Service is the M5.5 Pre-Onboarding lifecycle application service.
type Service struct {
	uowManager         UnitOfWorkManager
	clock              Clock
	deviceAllocator    DeviceAllocator
	partnerAuth        PartnerAuthorityChecker
	partnerEligibility PartnerEligibilityChecker
	retentionPolicy    IdempotencyRetentionPolicy
}

// ServiceConfig carries mandatory dependencies for constructing a Service.
type ServiceConfig struct {
	UOWManager         UnitOfWorkManager
	Clock              Clock
	DeviceAllocator    DeviceAllocator
	PartnerAuth        PartnerAuthorityChecker
	PartnerEligibility PartnerEligibilityChecker
	RetentionPolicy    IdempotencyRetentionPolicy
}

type validator interface {
	Validate() error
}

func validateDependency(name string, dep any) error {
	if isNilLike(dep) {
		return fmt.Errorf("application: %s missing or typed-nil", name)
	}
	if v, ok := dep.(validator); ok {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("application: %s invalid: %w", name, err)
		}
	}
	return nil
}

// NewService constructs a Pre-Onboarding application service. All dependencies
// are mandatory and fail closed if missing, typed-nil, or structurally invalid.
func NewService(cfg ServiceConfig) (*Service, error) {
	s := &Service{
		uowManager:         cfg.UOWManager,
		clock:              cfg.Clock,
		deviceAllocator:    cfg.DeviceAllocator,
		partnerAuth:        cfg.PartnerAuth,
		partnerEligibility: cfg.PartnerEligibility,
		retentionPolicy:    cfg.RetentionPolicy,
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Validate checks the structural integrity of the Service.
func (s *Service) Validate() error {
	if s == nil {
		return errors.New("application: nil service")
	}
	if err := validateDependency("uow manager", s.uowManager); err != nil {
		return err
	}
	if err := validateDependency("clock", s.clock); err != nil {
		return err
	}
	if err := validateDependency("device allocator", s.deviceAllocator); err != nil {
		return err
	}
	if err := validateDependency("partner authority checker", s.partnerAuth); err != nil {
		return err
	}
	if err := validateDependency("partner eligibility checker", s.partnerEligibility); err != nil {
		return err
	}
	if err := validateDependency("retention policy", s.retentionPolicy); err != nil {
		return err
	}
	if s.retentionPolicy.ReservationDuration() <= 0 {
		return errors.New("application: retention policy must have positive reservation duration")
	}
	return nil
}

// CreateCommand carries data for creating a pre-onboarding proposal.
type CreateCommand struct {
	PartnerID     string
	ClaimedDevice domain.ClaimedDevice
	Agent         domain.Agent
}

// CreatePreOnboardingRequest handles proposal creation.
//
// In M5.5, mandatory secret-originator capabilities (RequestAccessToken issuer,
// non-reversible verifier, and encrypted Replay Capsule) are not implemented.
// Therefore, production execution MUST fail closed before any reservation,
// persistent ID allocation, persistence, or audit event generation occurs.
func (s *Service) CreatePreOnboardingRequest(ctx context.Context, cmd CreateCommand) (*domain.PreOnboardingRequest, error) {
	return nil, ErrDependencyUnavailable
}

// PublicGetResult holds the outcome of a public pre-onboarding read.
type PublicGetResult struct {
	Request         *domain.PreOnboardingRequest
	EffectiveStatus domain.State
	ETag            string
}

// GetPublic executes a public read of a pre-onboarding request.
// Effective EXPIRED status returns ErrResourceExpired (mapped to HTTP 410).
func (s *Service) GetPublic(ctx context.Context, id string) (PublicGetResult, error) {
	if err := s.Validate(); err != nil {
		return PublicGetResult{}, ErrDependencyUnavailable
	}
	uow, err := s.uowManager.Begin(ctx)
	if err != nil {
		return PublicGetResult{}, ErrDependencyUnavailable
	}
	defer uow.Rollback(ctx)

	req, ok, err := uow.Repository().Get(ctx, domain.ID(id))
	if err != nil {
		return PublicGetResult{}, ErrDependencyUnavailable
	}
	if !ok {
		return PublicGetResult{}, ErrNotFound
	}

	now := s.clock.Now()
	eff := req.EffectiveStatus(now)
	if eff == domain.StateExpired {
		return PublicGetResult{}, ErrResourceExpired
	}

	etag := domain.ComputeETag(req, now)
	return PublicGetResult{
		Request:         req,
		EffectiveStatus: eff,
		ETag:            etag,
	}, nil
}

// AdminListFilter specifies filtering for administrative list queries.
type AdminListFilter struct {
	PartnerID *string
	Status    *domain.State
	From      *time.Time
	To        *time.Time
	PageSize  int
	PageToken string
}

// AdminListResult holds the paginated outcome of an administrative list query.
type AdminListResult struct {
	Items         []AdminGetResult
	NextPageToken string
	TotalCount    int
}

// ListAdmin executes an administrative list query restricted strictly to
// partners for which the admin holds current server-side authority.
func (s *Service) ListAdmin(ctx context.Context, admin AdminPrincipal, filter AdminListFilter) (AdminListResult, error) {
	if err := s.Validate(); err != nil {
		return AdminListResult{}, ErrDependencyUnavailable
	}
	authorizedPartners, err := s.partnerAuth.GetAuthorizedPartners(ctx, admin)
	if err != nil {
		return AdminListResult{}, ErrDependencyUnavailable
	}
	if len(authorizedPartners) == 0 {
		return AdminListResult{Items: []AdminGetResult{}}, nil
	}

	if filter.PartnerID != nil && *filter.PartnerID != "" {
		targetPartner := *filter.PartnerID
		hasAuth := false
		for _, ap := range authorizedPartners {
			if ap == targetPartner {
				hasAuth = true
				break
			}
		}
		if !hasAuth {
			return AdminListResult{Items: []AdminGetResult{}}, nil
		}
	}

	uow, err := s.uowManager.Begin(ctx)
	if err != nil {
		return AdminListResult{}, ErrDependencyUnavailable
	}
	defer uow.Rollback(ctx)

	now := s.clock.Now()
	repoFilter := ListFilter{
		AuthorizedPartners: authorizedPartners,
		PartnerIDFilter:    filter.PartnerID,
		StatusFilter:       filter.Status,
		CreatedFrom:        filter.From,
		CreatedTo:          filter.To,
		PageSize:           filter.PageSize,
		PageToken:          filter.PageToken,
		Now:                now,
	}

	res, err := uow.Repository().List(ctx, repoFilter)
	if err != nil {
		return AdminListResult{}, ErrDependencyUnavailable
	}

	items := make([]AdminGetResult, 0, len(res.Items))
	for _, req := range res.Items {
		eff := req.EffectiveStatus(now)
		etag := domain.ComputeETag(req, now)
		items = append(items, AdminGetResult{
			Request:         req,
			EffectiveStatus: eff,
			ETag:            etag,
		})
	}

	return AdminListResult{
		Items:         items,
		NextPageToken: res.NextPageToken,
		TotalCount:    res.TotalCount,
	}, nil
}

// AdminGetResult holds the outcome of an administrative read-by-id.
type AdminGetResult struct {
	Request         *domain.PreOnboardingRequest
	EffectiveStatus domain.State
	ETag            string
}

// GetAdmin executes an administrative read of a pre-onboarding request.
// If the caller lacks current server-side authority for the resource's partner,
// the existence is concealed as ErrNotFound (HTTP 404; M5.5-DEC-002).
func (s *Service) GetAdmin(ctx context.Context, admin AdminPrincipal, id string) (AdminGetResult, error) {
	if err := s.Validate(); err != nil {
		return AdminGetResult{}, ErrDependencyUnavailable
	}
	uow, err := s.uowManager.Begin(ctx)
	if err != nil {
		return AdminGetResult{}, ErrDependencyUnavailable
	}
	defer uow.Rollback(ctx)

	req, ok, err := uow.Repository().Get(ctx, domain.ID(id))
	if err != nil {
		return AdminGetResult{}, ErrDependencyUnavailable
	}
	if !ok {
		return AdminGetResult{}, ErrNotFound
	}

	hasAuth, err := s.partnerAuth.HasPartnerAuthority(ctx, admin, string(req.PartnerID()))
	if err != nil {
		return AdminGetResult{}, ErrDependencyUnavailable
	}
	if !hasAuth {
		return AdminGetResult{}, ErrNotFound
	}

	now := s.clock.Now()
	eff := req.EffectiveStatus(now)
	etag := domain.ComputeETag(req, now)

	return AdminGetResult{
		Request:         req,
		EffectiveStatus: eff,
		ETag:            etag,
	}, nil
}

// ApproveCommand carries inputs for administrative approval.
type ApproveCommand struct {
	ID             string
	IfMatch        string
	IdempotencyKey string
	ExpectedStatus string
	Reason         string
	CorrelationID  string
}

// ApproveResult holds the outcome of an administrative approval.
type ApproveResult struct {
	PreOnboardingRequestID string
	Status                 domain.State
	DeviceID               string
	ResourceVersion        int
	ETag                   string
	IsReplay               bool
}

// Approve executes an atomic, idempotent administrative approval.
func (s *Service) Approve(ctx context.Context, admin AdminPrincipal, cmd ApproveCommand) (ApproveResult, error) {
	if err := s.Validate(); err != nil {
		return ApproveResult{}, ErrDependencyUnavailable
	}
	if strings.TrimSpace(cmd.ID) == "" {
		return ApproveResult{}, errors.New("application: request id must not be empty")
	}
	if strings.TrimSpace(cmd.IdempotencyKey) == "" {
		return ApproveResult{}, errors.New("application: idempotency key must not be empty")
	}

	// 1. Resolve authoritative partner and verify current admin partner authority BEFORE reservation.
	lookupUOW, err := s.uowManager.Begin(ctx)
	if err != nil {
		return ApproveResult{}, ErrDependencyUnavailable
	}
	existingReq, ok, err := lookupUOW.Repository().Get(ctx, domain.ID(cmd.ID))
	lookupUOW.Rollback(ctx)
	if err != nil {
		return ApproveResult{}, ErrDependencyUnavailable
	}
	if !ok {
		return ApproveResult{}, ErrNotFound
	}

	hasAuth, err := s.partnerAuth.HasPartnerAuthority(ctx, admin, string(existingReq.PartnerID()))
	if err != nil {
		return ApproveResult{}, ErrDependencyUnavailable
	}
	if !hasAuth {
		return ApproveResult{}, ErrPartnerNotAuthorized
	}

	// 2. Build EffectiveScope & Fingerprint.
	credScope, err := idempotencyruntime.NewCredentialScope(authpolicy.CredentialKindAdminOIDC, admin.Issuer+"#"+admin.Subject)
	if err != nil {
		return ApproveResult{}, fmt.Errorf("application: build credential scope: %w", err)
	}
	idemKey, err := idempotencyruntime.NewIdempotencyKey(cmd.IdempotencyKey)
	if err != nil {
		return ApproveResult{}, fmt.Errorf("application: invalid idempotency key: %w", err)
	}
	scope, err := idempotencyruntime.NewEffectiveScope(credScope, "POST", "/v1/admin/pre-onboarding-requests/{id}/approve", idemKey)
	if err != nil {
		return ApproveResult{}, fmt.Errorf("application: build effective scope: %w", err)
	}
	fp, err := ComputeDecisionFingerprint("adminApprovePreOnboardingRequest", "/v1/admin/pre-onboarding-requests/{id}/approve", cmd.ID, cmd.IfMatch, cmd.ExpectedStatus, cmd.Reason)
	if err != nil {
		return ApproveResult{}, fmt.Errorf("application: compute fingerprint: %w", err)
	}

	// 3. Begin atomic UnitOfWork.
	now := s.clock.Now()
	uow, err := s.uowManager.Begin(ctx)
	if err != nil {
		return ApproveResult{}, ErrDependencyUnavailable
	}
	defer uow.Rollback(ctx)

	// Construct M5.4 Service over the UoW's Store to enforce all M5.4 validation invariants.
	idemSvc, err := idempotencyruntime.NewService(
		uow.IdempotencyStore(),
		failClosedNoSecretProtector{},
		idempotencyruntime.WithClock(s.clock),
	)
	if err != nil {
		return ApproveResult{}, ErrDependencyUnavailable
	}

	res, err := idemSvc.Reserve(ctx, idempotencyruntime.ReserveRequest{
		Scope:       scope,
		Fingerprint: fp,
		Now:         now,
		ExpiresAt:   now.Add(s.retentionPolicy.ReservationDuration()),
	})
	if err != nil {
		return ApproveResult{}, ErrDependencyUnavailable
	}

	switch res.Status {
	case idempotencyruntime.ReservationReplay:
		snap, found, err := uow.ResultStore().GetApprovalResult(ctx, res.Result)
		if err != nil || !found || snap.PreOnboardingRequestID != cmd.ID {
			return ApproveResult{}, ErrDependencyUnavailable
		}
		return ApproveResult{
			PreOnboardingRequestID: snap.PreOnboardingRequestID,
			Status:                 domain.State(snap.Status),
			DeviceID:               snap.DeviceID,
			ResourceVersion:        snap.ResourceVersion,
			ETag:                   snap.ETag,
			IsReplay:               true,
		}, nil

	case idempotencyruntime.ReservationConflict:
		return ApproveResult{}, ErrIdempotencyConflict

	case idempotencyruntime.ReservationInProgress:
		return ApproveResult{}, ErrDependencyUnavailable

	case idempotencyruntime.ReservationNew:
		// Execute NEW approval within atomic UoW.
		req, ok, err := uow.Repository().Get(ctx, domain.ID(cmd.ID))
		if err != nil {
			return ApproveResult{}, ErrDependencyUnavailable
		}
		if !ok {
			return ApproveResult{}, ErrNotFound
		}

		eff := req.EffectiveStatus(now)
		currentETag := domain.ComputeETag(req, now)

		// Check expiry precedence & If-Match
		if eff == domain.StateExpired {
			if !domain.MatchETag(cmd.IfMatch, currentETag) {
				return ApproveResult{}, ErrPreconditionFailed
			}
			return ApproveResult{}, ErrStateConflict
		}

		if !domain.MatchETag(cmd.IfMatch, currentETag) {
			return ApproveResult{}, ErrPreconditionFailed
		}

		if req.Status() != domain.StatePendingApproval {
			return ApproveResult{}, ErrStateConflict
		}

		// Partner eligibility is checked ONLY for NEW approvals.
		eligible, err := s.partnerEligibility.IsPartnerEligible(ctx, string(req.PartnerID()))
		if err != nil {
			return ApproveResult{}, ErrDependencyUnavailable
		}
		if !eligible {
			return ApproveResult{}, ErrPartnerIneligible
		}

		// Allocate logical device_id if absent, or preserve existing without calling allocator.
		var devID string
		if req.DeviceID() != nil && *req.DeviceID() != "" {
			devID = *req.DeviceID()
		} else {
			devID, err = s.deviceAllocator.AllocateDeviceID(ctx, req)
			if err != nil {
				return ApproveResult{}, ErrDependencyUnavailable
			}
		}

		if err := req.Approve(now, devID); err != nil {
			return ApproveResult{}, ErrStateConflict
		}

		newETag := domain.ComputeETag(req, now)
		if err := uow.Repository().Save(ctx, req); err != nil {
			return ApproveResult{}, ErrDependencyUnavailable
		}

		// Stage audit event
		auditEvt := AuditEvent{
			Type:                   AuditEventApproved,
			ActorPrincipal:         admin.Issuer + "#" + admin.Subject,
			PreOnboardingRequestID: cmd.ID,
			PartnerID:              string(req.PartnerID()),
			DeviceID:               *req.DeviceID(),
			Reason:                 cmd.Reason,
			Timestamp:              now,
			CorrelationID:          cmd.CorrelationID,
		}
		if err := uow.AuditWriter().StageEvent(ctx, auditEvt); err != nil {
			return ApproveResult{}, ErrDependencyUnavailable
		}

		// Store result snapshot in ResultStore and commit opaque locator in M5.4
		resLoc, err := idempotencyruntime.NewResultLocator(fmt.Sprintf("loc-appr-%s-%d", cmd.ID, req.ResourceVersion()))
		if err != nil {
			return ApproveResult{}, ErrDependencyUnavailable
		}

		snap := ApprovalResultSnapshot{
			PreOnboardingRequestID: cmd.ID,
			Status:                 string(req.Status()),
			DeviceID:               *req.DeviceID(),
			ResourceVersion:        req.ResourceVersion(),
			ETag:                   newETag,
			CommittedAt:            now,
		}
		if err := uow.ResultStore().SaveApprovalResult(ctx, resLoc, snap); err != nil {
			return ApproveResult{}, ErrDependencyUnavailable
		}

		if _, err := idemSvc.Commit(ctx, idempotencyruntime.CommitRequest{
			Token:  res.Token,
			Scope:  scope,
			Result: resLoc,
		}); err != nil {
			return ApproveResult{}, ErrDependencyUnavailable
		}

		if err := uow.Commit(ctx); err != nil {
			if errors.Is(err, ErrPreconditionFailed) {
				return ApproveResult{}, ErrPreconditionFailed
			}
			return ApproveResult{}, ErrDependencyUnavailable
		}

		return ApproveResult{
			PreOnboardingRequestID: cmd.ID,
			Status:                 req.Status(),
			DeviceID:               *req.DeviceID(),
			ResourceVersion:        req.ResourceVersion(),
			ETag:                   newETag,
			IsReplay:               false,
		}, nil

	default:
		return ApproveResult{}, ErrDependencyUnavailable
	}
}

// RejectCommand carries inputs for administrative rejection.
type RejectCommand struct {
	ID             string
	IfMatch        string
	IdempotencyKey string
	ExpectedStatus string
	Reason         string
	CorrelationID  string
}

// RejectResult holds the outcome of an administrative rejection.
type RejectResult struct {
	Request         *domain.PreOnboardingRequest
	EffectiveStatus domain.State
	ETag            string
	IsReplay        bool
}

// Reject executes an atomic, idempotent administrative rejection.
// Rejection does NOT require partner eligibility and never allocates a device_id.
func (s *Service) Reject(ctx context.Context, admin AdminPrincipal, cmd RejectCommand) (RejectResult, error) {
	if err := s.Validate(); err != nil {
		return RejectResult{}, ErrDependencyUnavailable
	}
	if strings.TrimSpace(cmd.ID) == "" {
		return RejectResult{}, errors.New("application: request id must not be empty")
	}
	if strings.TrimSpace(cmd.IdempotencyKey) == "" {
		return RejectResult{}, errors.New("application: idempotency key must not be empty")
	}

	// 1. Resolve authoritative partner and verify current admin partner authority BEFORE reservation.
	lookupUOW, err := s.uowManager.Begin(ctx)
	if err != nil {
		return RejectResult{}, ErrDependencyUnavailable
	}
	existingReq, ok, err := lookupUOW.Repository().Get(ctx, domain.ID(cmd.ID))
	lookupUOW.Rollback(ctx)
	if err != nil {
		return RejectResult{}, ErrDependencyUnavailable
	}
	if !ok {
		return RejectResult{}, ErrNotFound
	}

	hasAuth, err := s.partnerAuth.HasPartnerAuthority(ctx, admin, string(existingReq.PartnerID()))
	if err != nil {
		return RejectResult{}, ErrDependencyUnavailable
	}
	if !hasAuth {
		return RejectResult{}, ErrPartnerNotAuthorized
	}

	// 2. Build EffectiveScope & Fingerprint.
	credScope, err := idempotencyruntime.NewCredentialScope(authpolicy.CredentialKindAdminOIDC, admin.Issuer+"#"+admin.Subject)
	if err != nil {
		return RejectResult{}, fmt.Errorf("application: build credential scope: %w", err)
	}
	idemKey, err := idempotencyruntime.NewIdempotencyKey(cmd.IdempotencyKey)
	if err != nil {
		return RejectResult{}, fmt.Errorf("application: invalid idempotency key: %w", err)
	}
	scope, err := idempotencyruntime.NewEffectiveScope(credScope, "POST", "/v1/admin/pre-onboarding-requests/{id}/reject", idemKey)
	if err != nil {
		return RejectResult{}, fmt.Errorf("application: build effective scope: %w", err)
	}
	fp, err := ComputeDecisionFingerprint("adminRejectPreOnboardingRequest", "/v1/admin/pre-onboarding-requests/{id}/reject", cmd.ID, cmd.IfMatch, cmd.ExpectedStatus, cmd.Reason)
	if err != nil {
		return RejectResult{}, fmt.Errorf("application: compute fingerprint: %w", err)
	}

	// 3. Begin atomic UnitOfWork.
	now := s.clock.Now()
	uow, err := s.uowManager.Begin(ctx)
	if err != nil {
		return RejectResult{}, ErrDependencyUnavailable
	}
	defer uow.Rollback(ctx)

	// Construct M5.4 Service over the UoW's Store to enforce all M5.4 validation invariants.
	idemSvc, err := idempotencyruntime.NewService(
		uow.IdempotencyStore(),
		failClosedNoSecretProtector{},
		idempotencyruntime.WithClock(s.clock),
	)
	if err != nil {
		return RejectResult{}, ErrDependencyUnavailable
	}

	res, err := idemSvc.Reserve(ctx, idempotencyruntime.ReserveRequest{
		Scope:       scope,
		Fingerprint: fp,
		Now:         now,
		ExpiresAt:   now.Add(s.retentionPolicy.ReservationDuration()),
	})
	if err != nil {
		return RejectResult{}, ErrDependencyUnavailable
	}

	switch res.Status {
	case idempotencyruntime.ReservationReplay:
		snap, found, err := uow.ResultStore().GetRejectionResult(ctx, res.Result)
		if err != nil || !found || snap.PreOnboardingRequestID != cmd.ID {
			return RejectResult{}, ErrDependencyUnavailable
		}
		restored, err := domain.RestoreRequest(
			domain.ID(snap.PreOnboardingRequestID),
			domain.PartnerID(snap.PartnerID),
			snap.ClaimedDevice,
			domain.Agent{},
			domain.State(snap.Status),
			snap.DeviceID,
			snap.CreatedAt,
			snap.ExpiresAt,
			snap.ResourceVersion,
		)
		if err != nil {
			return RejectResult{}, ErrDependencyUnavailable
		}
		return RejectResult{
			Request:         restored,
			EffectiveStatus: domain.StateRejected,
			ETag:            snap.ETag,
			IsReplay:        true,
		}, nil

	case idempotencyruntime.ReservationConflict:
		return RejectResult{}, ErrIdempotencyConflict

	case idempotencyruntime.ReservationInProgress:
		return RejectResult{}, ErrDependencyUnavailable

	case idempotencyruntime.ReservationNew:
		// Execute NEW rejection within atomic UoW.
		req, ok, err := uow.Repository().Get(ctx, domain.ID(cmd.ID))
		if err != nil {
			return RejectResult{}, ErrDependencyUnavailable
		}
		if !ok {
			return RejectResult{}, ErrNotFound
		}

		eff := req.EffectiveStatus(now)
		currentETag := domain.ComputeETag(req, now)

		// Check expiry precedence & If-Match
		if eff == domain.StateExpired {
			if !domain.MatchETag(cmd.IfMatch, currentETag) {
				return RejectResult{}, ErrPreconditionFailed
			}
			return RejectResult{}, ErrStateConflict
		}

		if !domain.MatchETag(cmd.IfMatch, currentETag) {
			return RejectResult{}, ErrPreconditionFailed
		}

		if req.Status() != domain.StatePendingApproval {
			return RejectResult{}, ErrStateConflict
		}

		// Rejection does NOT check partner eligibility.
		if err := req.Reject(now, cmd.Reason); err != nil {
			return RejectResult{}, ErrStateConflict
		}

		newETag := domain.ComputeETag(req, now)
		if err := uow.Repository().Save(ctx, req); err != nil {
			return RejectResult{}, ErrDependencyUnavailable
		}

		// Stage audit event
		auditEvt := AuditEvent{
			Type:                   AuditEventRejected,
			ActorPrincipal:         admin.Issuer + "#" + admin.Subject,
			PreOnboardingRequestID: cmd.ID,
			PartnerID:              string(req.PartnerID()),
			Reason:                 cmd.Reason,
			Timestamp:              now,
			CorrelationID:          cmd.CorrelationID,
		}
		if err := uow.AuditWriter().StageEvent(ctx, auditEvt); err != nil {
			return RejectResult{}, ErrDependencyUnavailable
		}

		// Store result snapshot in ResultStore and commit opaque locator in M5.4
		resLoc, err := idempotencyruntime.NewResultLocator(fmt.Sprintf("loc-rej-%s-%d", cmd.ID, req.ResourceVersion()))
		if err != nil {
			return RejectResult{}, ErrDependencyUnavailable
		}

		snap := RejectionResultSnapshot{
			PreOnboardingRequestID: cmd.ID,
			PartnerID:              string(req.PartnerID()),
			Status:                 string(req.Status()),
			DeviceID:               req.DeviceID(),
			ClaimedDevice:          req.ClaimedDevice(),
			CreatedAt:              req.CreatedAt(),
			ExpiresAt:              req.ExpiresAt(),
			ResourceVersion:        req.ResourceVersion(),
			ETag:                   newETag,
			CommittedAt:            now,
		}
		if err := uow.ResultStore().SaveRejectionResult(ctx, resLoc, snap); err != nil {
			return RejectResult{}, ErrDependencyUnavailable
		}

		if _, err := idemSvc.Commit(ctx, idempotencyruntime.CommitRequest{
			Token:  res.Token,
			Scope:  scope,
			Result: resLoc,
		}); err != nil {
			return RejectResult{}, ErrDependencyUnavailable
		}

		if err := uow.Commit(ctx); err != nil {
			if errors.Is(err, ErrPreconditionFailed) {
				return RejectResult{}, ErrPreconditionFailed
			}
			return RejectResult{}, ErrDependencyUnavailable
		}

		return RejectResult{
			Request:         req,
			EffectiveStatus: req.Status(),
			ETag:            newETag,
			IsReplay:        false,
		}, nil

	default:
		return RejectResult{}, ErrDependencyUnavailable
	}
}
