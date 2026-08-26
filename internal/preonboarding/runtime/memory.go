package runtime

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
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
	mu                  sync.RWMutex
	requests            map[domain.ID]*domain.PreOnboardingRequest
	apprResults         map[string]application.ApprovalResultSnapshot
	rejResults          map[string]application.RejectionResultSnapshot
	createResults       map[string]application.PreOnboardingCreateResultSnapshot
	requestAccess       map[capability.VerifierKey]capability.RequestAccessRecord
	idemActive          map[idempotencyruntime.EffectiveScope]*idemActiveRecord
	idemCommitted       map[idempotencyruntime.EffectiveScope]*idempotencyruntime.Record
	temporaryPrincipals map[string]domain.TemporaryPrincipal
	auditRecorder       *MemoryAuditRecorder
}

// NewMemoryStore constructs a MemoryStore.
func NewMemoryStore(recorder *MemoryAuditRecorder) *MemoryStore {
	return &MemoryStore{
		requests:            make(map[domain.ID]*domain.PreOnboardingRequest),
		apprResults:         make(map[string]application.ApprovalResultSnapshot),
		rejResults:          make(map[string]application.RejectionResultSnapshot),
		createResults:       make(map[string]application.PreOnboardingCreateResultSnapshot),
		requestAccess:       make(map[capability.VerifierKey]capability.RequestAccessRecord),
		idemActive:          make(map[idempotencyruntime.EffectiveScope]*idemActiveRecord),
		idemCommitted:       make(map[idempotencyruntime.EffectiveScope]*idempotencyruntime.Record),
		temporaryPrincipals: make(map[string]domain.TemporaryPrincipal),
		auditRecorder:       recorder,
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

// CountRequestAccess returns the number of request access records.
func (s *MemoryStore) CountRequestAccess() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.requestAccess)
}

// CountCreateResults returns the number of pre-onboarding create-result snapshots.
func (s *MemoryStore) CountCreateResults() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.createResults)
}

// CountIdemCommitted returns the number of committed idempotency records.
func (s *MemoryStore) CountIdemCommitted() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.idemCommitted)
}

// LookupRequestAccess is the frozen capability.Store read interface over the
// same committed map that the UoW writer stages into. Staged records are never
// observable here.
func (s *MemoryStore) LookupRequestAccess(_ context.Context, key capability.VerifierKey) (*capability.RequestAccessRecord, error) {
	s.mu.RLock()
	rec, ok := s.requestAccess[key]
	s.mu.RUnlock()
	if !ok {
		return nil, capability.ErrNotFound
	}
	cp := rec
	return &cp, nil
}
func (s *MemoryStore) LookupEnrollmentAccess(context.Context, capability.VerifierKey) (*capability.EnrollmentAccessRecord, error) {
	return nil, capability.ErrNotFound
}

// Begin initiates a new transactional UnitOfWork.
func (s *MemoryStore) Begin(ctx context.Context) (application.UnitOfWork, error) {
	return &memoryUOW{
		store:                     s,
		stagedRequests:            make(map[domain.ID]*domain.PreOnboardingRequest),
		stagedApprRes:             make(map[string]application.ApprovalResultSnapshot),
		stagedRejRes:              make(map[string]application.RejectionResultSnapshot),
		stagedCreateRes:           make(map[string]application.PreOnboardingCreateResultSnapshot),
		stagedRequestAccess:       make(map[capability.VerifierKey]capability.RequestAccessRecord),
		stagedAudits:              make([]application.AuditEvent, 0),
		stagedIdemCommits:         make(map[idempotencyruntime.EffectiveScope]*idempotencyruntime.Record),
		stagedTemporaryPrincipals: make(map[string]domain.TemporaryPrincipal),
		initialVersion:            make(map[domain.ID]int),
		initialTPSubmissions:      make(map[string]int),
		activeTokens:              make(map[idempotencyruntime.ReservationToken]idempotencyruntime.EffectiveScope),
	}, nil
}

type memoryUOW struct {
	store                     *MemoryStore
	stagedRequests            map[domain.ID]*domain.PreOnboardingRequest
	stagedApprRes             map[string]application.ApprovalResultSnapshot
	stagedRejRes              map[string]application.RejectionResultSnapshot
	stagedCreateRes           map[string]application.PreOnboardingCreateResultSnapshot
	stagedRequestAccess       map[capability.VerifierKey]capability.RequestAccessRecord
	stagedAudits              []application.AuditEvent
	stagedIdemCommits         map[idempotencyruntime.EffectiveScope]*idempotencyruntime.Record
	stagedTemporaryPrincipals map[string]domain.TemporaryPrincipal
	initialVersion            map[domain.ID]int
	initialTPSubmissions      map[string]int
	activeTokens              map[idempotencyruntime.ReservationToken]idempotencyruntime.EffectiveScope
	closed                    bool
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
func (u *memoryUOW) RequestAccessWriter() application.RequestAccessWriter {
	return &memoryRequestAccessWriter{uow: u}
}

func (u *memoryUOW) TemporaryPrincipalStore() application.TemporaryPrincipalStore {
	return &memoryTemporaryPrincipalStore{uow: u}
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
	u.stagedCreateRes = nil
	u.stagedRequestAccess = nil
	u.stagedAudits = nil
	u.stagedIdemCommits = nil
	u.stagedTemporaryPrincipals = nil
	u.initialTPSubmissions = nil
}

func (u *memoryUOW) Commit(ctx context.Context) error {
	if u.closed {
		return errors.New("runtime: transaction already closed")
	}

	u.store.mu.Lock()
	defer u.store.mu.Unlock()

	// PHASE 1 — validate every fallible condition before any committed-state
	// mutation. If anything fails, nothing is published.
	if err := u.validateLocked(ctx); err != nil {
		u.rollbackLocked()
		u.closed = true
		return err
	}

	// PHASE 2 — publish all staged concerns. Publication is non-fallible:
	// after the first committed-state mutation there is no remaining
	// validation/error branch.
	u.publishLocked()
	u.closed = true
	return nil
}

// validateLocked evaluates every commit-time precondition against committed
// state. It MUST NOT mutate any committed map/list/counter.
func (u *memoryUOW) validateLocked(ctx context.Context) error {
	// 1. Optimistic locking + NEW-resource ID uniqueness.
	for id := range u.stagedRequests {
		initialVer, tracked := u.initialVersion[id]
		existing, exists := u.store.requests[id]
		if tracked {
			if exists && existing.ResourceVersion() != initialVer {
				return application.ErrPreconditionFailed
			}
			continue
		}
		// A newly-staged resource must never silently overwrite an
		// authoritatively committed resource with the same ID.
		if exists {
			return application.ErrDependencyUnavailable
		}
	}

	// 2. Temporary Principal authoritative freshness / preconditions / quota.
	if len(u.stagedTemporaryPrincipals) > 0 {
		commitNow, ok := u.commitTime(ctx)
		if !ok {
			// A time-sensitive commit precondition cannot be evaluated
			// without a trusted server-controlled clock; fail closed.
			return application.ErrDependencyUnavailable
		}
		for id, stagedTP := range u.stagedTemporaryPrincipals {
			if err := u.validateTPLocked(id, stagedTP, commitNow); err != nil {
				return err
			}
		}
	}

	// 3. RequestAccess verifier key uniqueness.
	for key := range u.stagedRequestAccess {
		if _, exists := u.store.requestAccess[key]; exists {
			return application.ErrDependencyUnavailable
		}
	}

	// 4. Create-result snapshot identity integrity.
	for loc := range u.stagedCreateRes {
		if _, exists := u.store.createResults[loc]; exists {
			return application.ErrDependencyUnavailable
		}
	}

	// 5. Idempotency publication integrity.
	for scope := range u.stagedIdemCommits {
		if _, exists := u.store.idemCommitted[scope]; exists {
			return application.ErrDependencyUnavailable
		}
	}

	return nil
}

// validateTPLocked evaluates a single staged TemporaryPrincipal against its
// current authoritative committed record using the trusted commit-time clock.
func (u *memoryUOW) validateTPLocked(id string, stagedTP domain.TemporaryPrincipal, commitNow time.Time) error {
	initialSubs, tracked := u.initialTPSubmissions[id]
	if !tracked {
		return nil
	}
	existing, ok := u.store.temporaryPrincipals[id]
	if !ok {
		return nil
	}
	// 1. Status must still be ACTIVE.
	if existing.Status != domain.TPStatusActive {
		return application.ErrPartnerNotAuthorized
	}
	// 2. PartnerID must not have changed concurrently.
	if existing.PartnerID != stagedTP.PartnerID {
		return application.ErrPartnerNotAuthorized
	}
	// 3. Authoritative commit-time expiry freshness.
	if !commitNow.Before(existing.ExpiresAt) {
		return application.ErrPartnerNotAuthorized
	}
	// 4. Quota using the CURRENT authoritative MaxSubmissions.
	delta := stagedTP.CommittedSubmissions - initialSubs
	if existing.CommittedSubmissions+delta > existing.MaxSubmissions {
		return application.ErrPartnerNotAuthorized
	}
	return nil
}

// commitTime returns the trusted server-controlled commit-time clock carried
// in the commit context. ok is false when no clock was injected.
func (u *memoryUOW) commitTime(ctx context.Context) (time.Time, bool) {
	if c := application.CommitClockFromContext(ctx); c != nil {
		return c.Now(), true
	}
	return time.Time{}, false
}

// tpDelta computes the committed-submission delta a staged TemporaryPrincipal
// intends to apply, preserving the existing delta-only update semantics.
func (u *memoryUOW) tpDelta(id string, stagedTP domain.TemporaryPrincipal) int {
	return stagedTP.CommittedSubmissions - u.initialTPSubmissions[id]
}

// publishLocked publishes all staged concerns to the committed store. It must
// not fail: every fallible precondition has already passed validateLocked.
func (u *memoryUOW) publishLocked() {
	// Requests.
	for id, req := range u.stagedRequests {
		u.store.requests[id] = cloneRequest(req)
	}

	// TemporaryPrincipals (delta-only updates to avoid lost updates).
	for id, stagedTP := range u.stagedTemporaryPrincipals {
		if existing, ok := u.store.temporaryPrincipals[id]; ok {
			existing.CommittedSubmissions += u.tpDelta(id, stagedTP)
			u.store.temporaryPrincipals[id] = existing
		} else {
			u.store.temporaryPrincipals[id] = stagedTP
		}
	}

	// Approval results.
	for loc, snap := range u.stagedApprRes {
		u.store.apprResults[loc] = snap
	}

	// Rejection results.
	for loc, snap := range u.stagedRejRes {
		u.store.rejResults[loc] = snap
	}

	// Create-result snapshots.
	for loc, snap := range u.stagedCreateRes {
		u.store.createResults[loc] = snap
	}

	// RequestAccess verifiers.
	for key, rec := range u.stagedRequestAccess {
		u.store.requestAccess[key] = rec
	}

	// Idempotency commits.
	for scope, rec := range u.stagedIdemCommits {
		u.store.idemCommitted[scope] = rec
		delete(u.store.idemActive, scope)
	}

	// Audit events.
	if u.store.auditRecorder != nil && len(u.stagedAudits) > 0 {
		u.store.auditRecorder.Record(u.stagedAudits)
	}
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

func (s *memoryResultStore) SaveCreateResult(ctx context.Context, loc idempotencyruntime.ResultLocator, res application.PreOnboardingCreateResultSnapshot) error {
	s.uow.stagedCreateRes[loc.String()] = res
	return nil
}
func (s *memoryResultStore) GetCreateResult(ctx context.Context, loc idempotencyruntime.ResultLocator) (application.PreOnboardingCreateResultSnapshot, bool, error) {
	if r, ok := s.uow.stagedCreateRes[loc.String()]; ok {
		return r, true, nil
	}
	s.uow.store.mu.RLock()
	r, ok := s.uow.store.createResults[loc.String()]
	s.uow.store.mu.RUnlock()
	return r, ok, nil
}

type memoryRequestAccessWriter struct{ uow *memoryUOW }

func (w *memoryRequestAccessWriter) CreateRequestAccess(ctx context.Context, key capability.VerifierKey, rec capability.RequestAccessRecord) error {
	if key == "" || rec.PreOnboardingRequestID == "" || rec.State != capability.StateActive {
		return errors.New("runtime: invalid request access record")
	}
	if _, ok := w.uow.stagedRequestAccess[key]; ok {
		return capability.ErrDuplicate
	}
	w.uow.store.mu.RLock()
	_, exists := w.uow.store.requestAccess[key]
	w.uow.store.mu.RUnlock()
	if exists {
		return capability.ErrDuplicate
	}
	w.uow.stagedRequestAccess[key] = rec
	return nil
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
		Capsule:     req.Capsule,
	}
	if req.Capsule != nil {
		record.CapsuleExpiresAt = req.Capsule.ExpiresAt()
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

func (s *MemoryStore) SeedTemporaryPrincipal(tp *domain.TemporaryPrincipal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.temporaryPrincipals[tp.TemporaryPrincipalID] = *cloneTP(tp)
}

// SeedCommittedIdempotencyRecord injects a committed idempotency record into
// the durable store for test fixtures. It mirrors SeedRequest and
// SeedTemporaryPrincipal: a narrow fixture seam only, never called by
// production paths. The protected capsule is defensively copied.
func (s *MemoryStore) SeedCommittedIdempotencyRecord(scope idempotencyruntime.EffectiveScope, rec idempotencyruntime.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := rec
	if rec.Capsule != nil {
		env, err := idempotencyruntime.NewProtectedEnvelope(
			rec.Capsule.Ciphertext(), rec.Capsule.Nonce(), rec.Capsule.KeyID(),
			rec.Capsule.KeyVersion(), rec.Capsule.ExpiresAt(),
		)
		if err == nil {
			cp.Capsule = env
		} else {
			cp.Capsule = nil
		}
	}
	s.idemCommitted[scope] = &cp
}

func cloneTP(tp *domain.TemporaryPrincipal) *domain.TemporaryPrincipal {
	if tp == nil {
		return nil
	}
	return &domain.TemporaryPrincipal{
		TemporaryPrincipalID: tp.TemporaryPrincipalID,
		PartnerID:            tp.PartnerID,
		Status:               tp.Status,
		ExpiresAt:            tp.ExpiresAt,
		MaxSubmissions:       tp.MaxSubmissions,
		CommittedSubmissions: tp.CommittedSubmissions,
	}
}

type memoryTemporaryPrincipalStore struct {
	uow *memoryUOW
}

func (s *memoryTemporaryPrincipalStore) Get(ctx context.Context, id string) (*domain.TemporaryPrincipal, bool, error) {
	if staged, ok := s.uow.stagedTemporaryPrincipals[id]; ok {
		return cloneTP(&staged), true, nil
	}
	s.uow.store.mu.RLock()
	tp, ok := s.uow.store.temporaryPrincipals[id]
	s.uow.store.mu.RUnlock()
	if !ok {
		return nil, false, nil
	}
	cloned := cloneTP(&tp)
	s.uow.stagedTemporaryPrincipals[id] = *cloned
	if _, tracked := s.uow.initialTPSubmissions[id]; !tracked {
		s.uow.initialTPSubmissions[id] = tp.CommittedSubmissions
	}
	return cloned, true, nil
}

func (s *memoryTemporaryPrincipalStore) Save(ctx context.Context, tp *domain.TemporaryPrincipal) error {
	s.uow.stagedTemporaryPrincipals[tp.TemporaryPrincipalID] = *cloneTP(tp)
	return nil
}
