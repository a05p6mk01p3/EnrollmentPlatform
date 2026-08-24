package runtime

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
)

func cloneRequest(req *domain.PreOnboardingRequest) *domain.PreOnboardingRequest {
	if req == nil {
		return nil
	}
	res, _ := domain.RestoreRequest(
		req.ID(),
		req.PartnerID(),
		req.ClaimedDevice(),
		req.Agent(),
		req.Status(),
		req.DeviceID(),
		req.CreatedAt(),
		req.ExpiresAt(),
		req.ResourceVersion(),
	)
	return res
}

type idemActiveRecord struct {
	scope       idempotencyruntime.EffectiveScope
	fingerprint idempotencyruntime.Fingerprint
	token       idempotencyruntime.ReservationToken
	createdAt   time.Time
	expiresAt   time.Time
}

// MemoryStore is an in-memory transactional store for PreOnboarding aggregate roots,
// idempotency records, result snapshots, and audit events.
type MemoryStore struct {
	mu            sync.RWMutex
	requests      map[domain.ID]*domain.PreOnboardingRequest
	apprResults   map[string]application.ApprovalResultSnapshot
	rejResults    map[string]application.RejectionResultSnapshot
	idemActive    map[idempotencyruntime.EffectiveScope]*idemActiveRecord
	idemCommitted map[idempotencyruntime.EffectiveScope]*idempotencyruntime.Record
	auditRecorder *MemoryAuditRecorder
}

// NewMemoryStore constructs a MemoryStore.
func NewMemoryStore(recorder *MemoryAuditRecorder) *MemoryStore {
	return &MemoryStore{
		requests:      make(map[domain.ID]*domain.PreOnboardingRequest),
		apprResults:   make(map[string]application.ApprovalResultSnapshot),
		rejResults:    make(map[string]application.RejectionResultSnapshot),
		idemActive:    make(map[idempotencyruntime.EffectiveScope]*idemActiveRecord),
		idemCommitted: make(map[idempotencyruntime.EffectiveScope]*idempotencyruntime.Record),
		auditRecorder: recorder,
	}
}

// Validate checks the structural integrity of MemoryStore.
func (s *MemoryStore) Validate() error {
	if s == nil {
		return errors.New("runtime: nil memory store")
	}
	return nil
}

// SeedRequest inserts a pre-onboarding request directly into memory (for test fixture setup).
func (s *MemoryStore) SeedRequest(req *domain.PreOnboardingRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[req.ID()] = cloneRequest(req)
}

// GetRequest retrieves a request by ID.
func (s *MemoryStore) GetRequest(id domain.ID) (*domain.PreOnboardingRequest, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.requests[id]
	if !ok {
		return nil, false
	}
	return cloneRequest(req), true
}

// CountRequests returns the number of stored requests.
func (s *MemoryStore) CountRequests() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.requests)
}

// Begin initiates a new transactional UnitOfWork.
func (s *MemoryStore) Begin(ctx context.Context) (application.UnitOfWork, error) {
	return &memoryUOW{
		store:             s,
		stagedRequests:    make(map[domain.ID]*domain.PreOnboardingRequest),
		stagedApprRes:     make(map[string]application.ApprovalResultSnapshot),
		stagedRejRes:      make(map[string]application.RejectionResultSnapshot),
		stagedAudits:      make([]application.AuditEvent, 0),
		stagedIdemCommits: make(map[idempotencyruntime.EffectiveScope]*idempotencyruntime.Record),
		initialVersion:    make(map[domain.ID]int),
		activeTokens:      make(map[idempotencyruntime.ReservationToken]idempotencyruntime.EffectiveScope),
	}, nil
}

type memoryUOW struct {
	store             *MemoryStore
	stagedRequests    map[domain.ID]*domain.PreOnboardingRequest
	stagedApprRes     map[string]application.ApprovalResultSnapshot
	stagedRejRes      map[string]application.RejectionResultSnapshot
	stagedAudits      []application.AuditEvent
	stagedIdemCommits map[idempotencyruntime.EffectiveScope]*idempotencyruntime.Record
	initialVersion    map[domain.ID]int
	activeTokens      map[idempotencyruntime.ReservationToken]idempotencyruntime.EffectiveScope
	closed            bool
}

func (u *memoryUOW) Repository() application.Repository {
	return &memoryRepo{uow: u}
}

func (u *memoryUOW) ResultStore() application.ResultStore {
	return &memoryResultStore{uow: u}
}

func (u *memoryUOW) AuditWriter() application.AuditWriter {
	return &memoryAuditWriter{uow: u}
}

func (u *memoryUOW) IdempotencyStore() idempotencyruntime.Store {
	return &transactionalIdemStore{uow: u}
}

func (u *memoryUOW) rollbackLocked() {
	// Clean up any active reservations created in this transaction
	for _, scope := range u.activeTokens {
		delete(u.store.idemActive, scope)
	}

	// Clear staged mutations
	u.stagedRequests = nil
	u.stagedApprRes = nil
	u.stagedRejRes = nil
	u.stagedAudits = nil
	u.stagedIdemCommits = nil
}

func (u *memoryUOW) Commit(ctx context.Context) error {
	if u.closed {
		return errors.New("runtime: transaction already closed")
	}

	u.store.mu.Lock()
	defer u.store.mu.Unlock()

	// Optimistic locking verification: ensure no concurrently modified versions
	for id := range u.stagedRequests {
		if initialVer, tracked := u.initialVersion[id]; tracked {
			if existing, ok := u.store.requests[id]; ok {
				if existing.ResourceVersion() != initialVer {
					u.rollbackLocked()
					u.closed = true
					return application.ErrPreconditionFailed
				}
			}
		}
	}

	// Commit staged requests
	for id, req := range u.stagedRequests {
		u.store.requests[id] = cloneRequest(req)
	}

	// Commit staged approval results
	for loc, snap := range u.stagedApprRes {
		u.store.apprResults[loc] = snap
	}

	// Commit staged rejection results
	for loc, snap := range u.stagedRejRes {
		u.store.rejResults[loc] = snap
	}

	// Commit staged idempotency commits
	for scope, rec := range u.stagedIdemCommits {
		u.store.idemCommitted[scope] = rec
		delete(u.store.idemActive, scope)
	}

	// Commit staged audit events
	if u.store.auditRecorder != nil && len(u.stagedAudits) > 0 {
		u.store.auditRecorder.Record(u.stagedAudits)
	}

	u.closed = true
	return nil
}

func (u *memoryUOW) Rollback(ctx context.Context) error {
	if u.closed {
		return nil
	}
	u.closed = true

	u.store.mu.Lock()
	defer u.store.mu.Unlock()

	u.rollbackLocked()
	return nil
}

type memoryRepo struct {
	uow *memoryUOW
}

func (r *memoryRepo) Get(ctx context.Context, id domain.ID) (*domain.PreOnboardingRequest, bool, error) {
	if staged, ok := r.uow.stagedRequests[id]; ok {
		return cloneRequest(staged), true, nil
	}

	r.uow.store.mu.RLock()
	req, ok := r.uow.store.requests[id]
	r.uow.store.mu.RUnlock()

	if !ok {
		return nil, false, nil
	}

	// Record initial version for optimistic locking detection
	if _, tracked := r.uow.initialVersion[id]; !tracked {
		r.uow.initialVersion[id] = req.ResourceVersion()
	}

	cloned := cloneRequest(req)
	r.uow.stagedRequests[id] = cloned
	return cloned, true, nil
}

func (r *memoryRepo) List(ctx context.Context, filter application.ListFilter) (application.ListResult, error) {
	r.uow.store.mu.RLock()
	defer r.uow.store.mu.RUnlock()

	var matching []*domain.PreOnboardingRequest
	authMap := make(map[string]bool)
	for _, ap := range filter.AuthorizedPartners {
		authMap[ap] = true
	}

	for _, req := range r.uow.store.requests {
		if staged, ok := r.uow.stagedRequests[req.ID()]; ok {
			req = staged
		}

		pID := string(req.PartnerID())
		if !authMap[pID] {
			continue
		}

		if filter.PartnerIDFilter != nil && *filter.PartnerIDFilter != "" {
			if pID != *filter.PartnerIDFilter {
				continue
			}
		}

		eff := req.EffectiveStatus(filter.Now)
		if filter.StatusFilter != nil {
			if eff != *filter.StatusFilter {
				continue
			}
		}

		if filter.CreatedFrom != nil {
			if req.CreatedAt().Before(*filter.CreatedFrom) {
				continue
			}
		}
		if filter.CreatedTo != nil {
			if req.CreatedAt().After(*filter.CreatedTo) {
				continue
			}
		}

		matching = append(matching, cloneRequest(req))
	}

	sort.Slice(matching, func(i, j int) bool {
		return matching[i].ID() < matching[j].ID()
	})

	pageSize := filter.PageSize
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 50
	}

	startIndex := 0
	if filter.PageToken != "" {
		for i, req := range matching {
			if string(req.ID()) == filter.PageToken {
				startIndex = i + 1
				break
			}
		}
	}

	endIndex := startIndex + pageSize
	var nextToken string
	if endIndex < len(matching) {
		nextToken = string(matching[endIndex-1].ID())
	} else {
		endIndex = len(matching)
	}

	var page []*domain.PreOnboardingRequest
	if startIndex < len(matching) {
		page = matching[startIndex:endIndex]
	}

	return application.ListResult{
		Items:         page,
		NextPageToken: nextToken,
		TotalCount:    len(matching),
	}, nil
}

func (r *memoryRepo) Save(ctx context.Context, req *domain.PreOnboardingRequest) error {
	r.uow.stagedRequests[req.ID()] = cloneRequest(req)
	return nil
}

type memoryResultStore struct {
	uow *memoryUOW
}

func (s *memoryResultStore) SaveApprovalResult(ctx context.Context, loc idempotencyruntime.ResultLocator, res application.ApprovalResultSnapshot) error {
	s.uow.stagedApprRes[loc.String()] = res
	return nil
}

func (s *memoryResultStore) GetApprovalResult(ctx context.Context, loc idempotencyruntime.ResultLocator) (application.ApprovalResultSnapshot, bool, error) {
	if snap, ok := s.uow.stagedApprRes[loc.String()]; ok {
		return snap, true, nil
	}
	s.uow.store.mu.RLock()
	snap, ok := s.uow.store.apprResults[loc.String()]
	s.uow.store.mu.RUnlock()
	return snap, ok, nil
}

func (s *memoryResultStore) SaveRejectionResult(ctx context.Context, loc idempotencyruntime.ResultLocator, res application.RejectionResultSnapshot) error {
	s.uow.stagedRejRes[loc.String()] = res
	return nil
}

func (s *memoryResultStore) GetRejectionResult(ctx context.Context, loc idempotencyruntime.ResultLocator) (application.RejectionResultSnapshot, bool, error) {
	if snap, ok := s.uow.stagedRejRes[loc.String()]; ok {
		return snap, true, nil
	}
	s.uow.store.mu.RLock()
	snap, ok := s.uow.store.rejResults[loc.String()]
	s.uow.store.mu.RUnlock()
	return snap, ok, nil
}

type memoryAuditWriter struct {
	uow *memoryUOW
}

func (w *memoryAuditWriter) StageEvent(ctx context.Context, event application.AuditEvent) error {
	w.uow.stagedAudits = append(w.uow.stagedAudits, event)
	return nil
}

type transactionalIdemStore struct {
	uow *memoryUOW
}

func (s *transactionalIdemStore) Reserve(ctx context.Context, req idempotencyruntime.ReserveRequest) (idempotencyruntime.Reservation, error) {
	s.uow.store.mu.Lock()
	defer s.uow.store.mu.Unlock()

	// Check committed records in staged or durable store
	if rec, ok := s.uow.stagedIdemCommits[req.Scope]; ok {
		if rec.Fingerprint.Equal(req.Fingerprint) {
			return idempotencyruntime.Reservation{
				Scope:       req.Scope,
				Status:      idempotencyruntime.ReservationReplay,
				Result:      rec.Result,
				Fingerprint: rec.Fingerprint,
				ExpiresAt:   rec.ExpiresAt,
			}, nil
		}
		return idempotencyruntime.Reservation{
			Scope:       req.Scope,
			Status:      idempotencyruntime.ReservationConflict,
			Fingerprint: rec.Fingerprint,
			ExpiresAt:   rec.ExpiresAt,
		}, nil
	}

	if rec, ok := s.uow.store.idemCommitted[req.Scope]; ok {
		if rec.Fingerprint.Equal(req.Fingerprint) {
			return idempotencyruntime.Reservation{
				Scope:       req.Scope,
				Status:      idempotencyruntime.ReservationReplay,
				Result:      rec.Result,
				Fingerprint: rec.Fingerprint,
				ExpiresAt:   rec.ExpiresAt,
			}, nil
		}
		return idempotencyruntime.Reservation{
			Scope:       req.Scope,
			Status:      idempotencyruntime.ReservationConflict,
			Fingerprint: rec.Fingerprint,
			ExpiresAt:   rec.ExpiresAt,
		}, nil
	}

	// Check active reservations
	if active, ok := s.uow.store.idemActive[req.Scope]; ok {
		if req.Now.Before(active.expiresAt) {
			if active.fingerprint.Equal(req.Fingerprint) {
				return idempotencyruntime.Reservation{
					Scope:       req.Scope,
					Status:      idempotencyruntime.ReservationInProgress,
					Fingerprint: active.fingerprint,
					ExpiresAt:   active.expiresAt,
				}, nil
			}
			return idempotencyruntime.Reservation{
				Scope:       req.Scope,
				Status:      idempotencyruntime.ReservationConflict,
				Fingerprint: active.fingerprint,
				ExpiresAt:   active.expiresAt,
			}, nil
		}
		// Stale active reservation expired
		delete(s.uow.store.idemActive, req.Scope)
	}

	token, err := idempotencyruntime.NewReservationToken()
	if err != nil {
		return idempotencyruntime.Reservation{}, err
	}

	active := &idemActiveRecord{
		scope:       req.Scope,
		fingerprint: req.Fingerprint,
		token:       token,
		createdAt:   req.Now,
		expiresAt:   req.ExpiresAt,
	}

	s.uow.store.idemActive[req.Scope] = active
	s.uow.activeTokens[token] = req.Scope

	return idempotencyruntime.Reservation{
		Scope:       req.Scope,
		Status:      idempotencyruntime.ReservationNew,
		Token:       token,
		Fingerprint: req.Fingerprint,
		ExpiresAt:   req.ExpiresAt,
	}, nil
}

func (s *transactionalIdemStore) Commit(ctx context.Context, req idempotencyruntime.CommitRequest) (idempotencyruntime.Record, error) {
	s.uow.store.mu.Lock()
	defer s.uow.store.mu.Unlock()

	active, ok := s.uow.store.idemActive[req.Scope]
	if !ok {
		return idempotencyruntime.Record{}, errors.New("runtime: no active reservation found for commit")
	}
	if !active.token.Equal(req.Token) {
		return idempotencyruntime.Record{}, errors.New("runtime: reservation token mismatch")
	}

	record := idempotencyruntime.Record{
		Scope:       req.Scope,
		Fingerprint: active.fingerprint,
		Status:      idempotencyruntime.RecordCommitted,
		Result:      req.Result,
		CreatedAt:   active.createdAt,
		ExpiresAt:   active.expiresAt,
	}

	// Stage commit to be finalized when UoW.Commit executes
	s.uow.stagedIdemCommits[req.Scope] = &record

	return record, nil
}

func (s *transactionalIdemStore) Lookup(ctx context.Context, scope idempotencyruntime.EffectiveScope) (idempotencyruntime.Record, bool, error) {
	s.uow.store.mu.RLock()
	defer s.uow.store.mu.RUnlock()

	if rec, ok := s.uow.stagedIdemCommits[scope]; ok {
		return *rec, true, nil
	}
	if rec, ok := s.uow.store.idemCommitted[scope]; ok {
		return *rec, true, nil
	}
	return idempotencyruntime.Record{}, false, nil
}
