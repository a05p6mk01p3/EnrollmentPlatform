// Package runtime provides the M5.7 in-memory transactional adapter for the
// INITIAL createEnrollment exchange. It deliberately reuses the committed
// pre-onboarding MemoryStore as the RequestAccess/pre-onboarding authority,
// rather than maintaining a second copy of that security-sensitive state.
package runtime

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	domain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/domain/enrollment"
	application "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/application"
	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	preonboardingdomain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	preonboardingruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
)

type idemActiveRecord struct {
	scope       idempotencyruntime.EffectiveScope
	fingerprint idempotencyruntime.Fingerprint
	token       idempotencyruntime.ReservationToken
	createdAt   time.Time
	expiresAt   time.Time
}

type policyKey struct {
	partnerID        string
	deviceID         string
	certificateUsage string
}

type policyRecord struct {
	eligible     bool
	requirements application.EvidenceRequirements
	version      uint64
}

// MemoryStore is the in-memory persistence adapter for enrollment-owned state.
// RequestAccess and pre-onboarding authority remain in the supplied M5.6
// pre-onboarding MemoryStore and are revalidated/consumed through its narrow
// atomic enrollment-authority boundary.
type MemoryStore struct {
	mu sync.RWMutex

	authority *preonboardingruntime.MemoryStore

	enrollments      map[string]application.EnrollmentRecord
	enrollmentAccess map[capability.VerifierKey]capability.EnrollmentAccessRecord
	createResults    map[string]application.CreateResultSnapshot
	idemActive       map[idempotencyruntime.EffectiveScope]*idemActiveRecord
	idemCommitted    map[idempotencyruntime.EffectiveScope]*idempotencyruntime.Record
	policies         map[policyKey]policyRecord
	audits           []application.AuditEvent
	policyVersion    uint64
}

func NewMemoryStore(authority *preonboardingruntime.MemoryStore) (*MemoryStore, error) {
	if authority == nil || authority.Validate() != nil {
		return nil, errors.New("enrollment runtime: pre-onboarding authority unavailable")
	}
	return &MemoryStore{
		authority:        authority,
		enrollments:      make(map[string]application.EnrollmentRecord),
		enrollmentAccess: make(map[capability.VerifierKey]capability.EnrollmentAccessRecord),
		createResults:    make(map[string]application.CreateResultSnapshot),
		idemActive:       make(map[idempotencyruntime.EffectiveScope]*idemActiveRecord),
		idemCommitted:    make(map[idempotencyruntime.EffectiveScope]*idempotencyruntime.Record),
		policies:         make(map[policyKey]policyRecord),
		audits:           make([]application.AuditEvent, 0),
	}, nil
}

func (s *MemoryStore) Validate() error {
	if s == nil || s.authority == nil || s.authority.Validate() != nil {
		return errors.New("enrollment runtime: unusable memory store")
	}
	return nil
}

// SetInitialPolicy installs/replaces the current server-side INITIAL policy
// snapshot for one authoritative partner/device/usage tuple. Quantitative and
// TPM/assurance values remain injected configuration; this does not close an
// OPEN item.
func (s *MemoryStore) SetInitialPolicy(partnerID, deviceID, certificateUsage string, eligible bool, requirements application.EvidenceRequirements) error {
	if s == nil || partnerID == "" || deviceID == "" || certificateUsage == "" || requirements.Validate() != nil {
		return errors.New("enrollment runtime: invalid INITIAL policy")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policyVersion++
	s.policies[policyKey{partnerID: partnerID, deviceID: deviceID, certificateUsage: certificateUsage}] = policyRecord{
		eligible: eligible, requirements: requirements.Clone(), version: s.policyVersion,
	}
	return nil
}

func (s *MemoryStore) Begin(context.Context) (application.UnitOfWork, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &memoryUOW{
		store:                  s,
		stagedEnrollments:      make(map[string]application.EnrollmentRecord),
		stagedEnrollmentAccess: make(map[capability.VerifierKey]capability.EnrollmentAccessRecord),
		stagedCreateResults:    make(map[string]application.CreateResultSnapshot),
		stagedIdemCommits:      make(map[idempotencyruntime.EffectiveScope]*idempotencyruntime.Record),
		stagedAudits:           make([]application.AuditEvent, 0),
		activeTokens:           make(map[idempotencyruntime.ReservationToken]idempotencyruntime.EffectiveScope),
		policyReads:            make(map[policyKey]policyRecord),
	}, nil
}

// Capability Store: RequestAccess lookups delegate to the M5.6 authoritative
// map; EnrollmentAccess lookups use only committed enrollment state. Staged
// verifier records are never visible to authentication.
func (s *MemoryStore) LookupRequestAccess(ctx context.Context, key capability.VerifierKey) (*capability.RequestAccessRecord, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s.authority.LookupRequestAccess(ctx, key)
}

func (s *MemoryStore) LookupEnrollmentAccess(_ context.Context, key capability.VerifierKey) (*capability.EnrollmentAccessRecord, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	rec, ok := s.enrollmentAccess[key]
	s.mu.RUnlock()
	if !ok {
		return nil, capability.ErrNotFound
	}
	cp := rec
	return &cp, nil
}

func (s *MemoryStore) CountEnrollments() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.enrollments)
}
func (s *MemoryStore) CountEnrollmentAccess() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.enrollmentAccess)
}
func (s *MemoryStore) CountCreateResults() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.createResults)
}
func (s *MemoryStore) CountIdemCommitted() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.idemCommitted)
}
func (s *MemoryStore) CountIdemActive() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.idemActive)
}

func (s *MemoryStore) GetEnrollment(id string) (application.EnrollmentRecord, bool) {
	s.mu.RLock()
	rec, ok := s.enrollments[id]
	s.mu.RUnlock()
	if !ok {
		return application.EnrollmentRecord{}, false
	}
	return cloneEnrollmentRecord(rec), true
}

func (s *MemoryStore) AuditEvents() []application.AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]application.AuditEvent, len(s.audits))
	copy(out, s.audits)
	return out
}

type memoryUOW struct {
	store *MemoryStore

	authoritySnapshot *preonboardingruntime.EnrollmentAuthoritySnapshot
	stagedRequest     *application.RequestAccessCredential

	stagedEnrollments      map[string]application.EnrollmentRecord
	stagedEnrollmentAccess map[capability.VerifierKey]capability.EnrollmentAccessRecord
	stagedCreateResults    map[string]application.CreateResultSnapshot
	stagedIdemCommits      map[idempotencyruntime.EffectiveScope]*idempotencyruntime.Record
	stagedAudits           []application.AuditEvent
	activeTokens           map[idempotencyruntime.ReservationToken]idempotencyruntime.EffectiveScope
	policyReads            map[policyKey]policyRecord
	closed                 bool
}

func (u *memoryUOW) PreOnboarding() application.PreOnboardingReader {
	return &memoryPreOnboardingReader{uow: u}
}
func (u *memoryUOW) RequestAccess() application.RequestAccessLifecycleStore {
	return &memoryRequestAccessStore{uow: u}
}
func (u *memoryUOW) Enrollments() application.EnrollmentRepository {
	return &memoryEnrollmentRepository{uow: u}
}
func (u *memoryUOW) EnrollmentAccess() application.EnrollmentAccessWriter {
	return &memoryEnrollmentAccessWriter{uow: u}
}
func (u *memoryUOW) Results() application.ResultStore { return &memoryResultStore{uow: u} }
func (u *memoryUOW) Eligibility() application.InitialEligibilityChecker {
	return &memoryPolicyReader{uow: u}
}
func (u *memoryUOW) EvidenceRequirements() application.EvidenceRequirementsProvider {
	return &memoryPolicyReader{uow: u}
}
func (u *memoryUOW) Audit() application.AuditWriter { return &memoryAuditWriter{uow: u} }
func (u *memoryUOW) IdempotencyStore() idempotencyruntime.Store {
	return &transactionalIdemStore{uow: u}
}

func (u *memoryUOW) ensureAuthority(requestID string) (preonboardingruntime.EnrollmentAuthoritySnapshot, bool, error) {
	if u.closed || requestID == "" {
		return preonboardingruntime.EnrollmentAuthoritySnapshot{}, false, errors.New("enrollment runtime: transaction closed or invalid request id")
	}
	if u.authoritySnapshot != nil {
		if u.authoritySnapshot.Request == nil || string(u.authoritySnapshot.Request.ID()) != requestID {
			return preonboardingruntime.EnrollmentAuthoritySnapshot{}, false, errors.New("enrollment runtime: transaction already bound to another request")
		}
		return cloneAuthoritySnapshot(*u.authoritySnapshot), true, nil
	}
	snap, found, err := u.store.authority.LoadEnrollmentAuthority(requestID)
	if err != nil || !found {
		return preonboardingruntime.EnrollmentAuthoritySnapshot{}, found, err
	}
	cp := cloneAuthoritySnapshot(snap)
	u.authoritySnapshot = &cp
	return cloneAuthoritySnapshot(cp), true, nil
}

func (u *memoryUOW) Commit(ctx context.Context) error {
	if u.closed {
		return errors.New("enrollment runtime: transaction already closed")
	}
	u.store.mu.Lock()
	defer u.store.mu.Unlock()

	commitNow, ok := u.commitTime(ctx)
	if !ok {
		u.rollbackLocked()
		u.closed = true
		return application.ErrDependencyUnavailable
	}
	if err := u.validateLocked(commitNow); err != nil {
		u.rollbackLocked()
		u.closed = true
		return err
	}

	// The authority transition is the first committed-state mutation and keeps
	// the M5.6 authority lock held while the already-prevalidated local write-set
	// is published. The callback cannot fail, so observers can never see
	// RequestAccess=CONSUMED without the corresponding enrollment/result state.
	if err := u.commitAuthorityAndPublish(commitNow); err != nil {
		u.rollbackLocked()
		u.closed = true
		return err
	}
	u.closed = true
	return nil
}

func (u *memoryUOW) Rollback(context.Context) error {
	if u.closed {
		return nil
	}
	u.store.mu.Lock()
	defer u.store.mu.Unlock()
	u.rollbackLocked()
	u.closed = true
	return nil
}

func (u *memoryUOW) commitTime(ctx context.Context) (time.Time, bool) {
	clock := application.CommitClockFromContext(ctx)
	if clock == nil {
		return time.Time{}, false
	}
	now := clock.Now()
	return now, !now.IsZero()
}

func (u *memoryUOW) validateLocked(now time.Time) error {
	if err := u.validateWriteSetLocked(now); err != nil {
		return err
	}
	if u.authoritySnapshot == nil || u.stagedRequest == nil {
		return application.ErrDependencyUnavailable
	}
	if err := u.store.authority.ValidateEnrollmentAuthority(*u.authoritySnapshot, now); err != nil {
		return mapAuthorityError(err)
	}
	for key, observed := range u.policyReads {
		current, ok := u.store.policies[key]
		if !ok || current.version != observed.version || !current.eligible || current.requirements.Validate() != nil {
			return application.ErrNotAuthorized
		}
	}
	return nil
}

func (u *memoryUOW) validateWriteSetLocked(now time.Time) error {
	// M5.7 INITIAL is exactly one atomic exchange. A partial or oversized staged
	// write-set is an adapter defect and must fail before RequestAccess is
	// consumed.
	if len(u.stagedEnrollments) != 1 || len(u.stagedEnrollmentAccess) != 1 || len(u.stagedCreateResults) != 1 ||
		len(u.stagedIdemCommits) != 1 || len(u.stagedAudits) != 1 || len(u.policyReads) != 1 {
		return application.ErrDependencyUnavailable
	}
	if u.stagedRequest.Record.State != capability.StateConsumed || u.authoritySnapshot.RequestAccess.State != capability.StateActive ||
		u.stagedRequest.Key != u.authoritySnapshot.RequestAccessKey ||
		u.stagedRequest.Record.PreOnboardingRequestID != u.authoritySnapshot.RequestAccess.PreOnboardingRequestID ||
		!u.stagedRequest.Record.ExpiresAt.Equal(u.authoritySnapshot.RequestAccess.ExpiresAt) {
		return application.ErrDependencyUnavailable
	}

	var enrollmentID string
	var enrollment application.EnrollmentRecord
	for id, rec := range u.stagedEnrollments {
		enrollmentID, enrollment = id, rec
	}
	if enrollment.Validate() != nil || enrollmentID != string(enrollment.Aggregate.ID()) || !enrollment.Challenge.ExpiresAt.After(now) {
		return application.ErrDependencyUnavailable
	}
	if _, exists := u.store.enrollments[enrollmentID]; exists {
		return application.ErrDependencyUnavailable
	}

	var access capability.EnrollmentAccessRecord
	for key, rec := range u.stagedEnrollmentAccess {
		if key == "" {
			return application.ErrDependencyUnavailable
		}
		if _, exists := u.store.enrollmentAccess[key]; exists {
			return application.ErrDependencyUnavailable
		}
		access = rec
	}
	if access.EnrollmentID != enrollmentID || !access.ExpiresAt.After(now) {
		return application.ErrDependencyUnavailable
	}

	var resultLocator string
	var result application.CreateResultSnapshot
	for loc, snap := range u.stagedCreateResults {
		resultLocator, result = loc, snap
	}
	if result.Validate() != nil || result.EnrollmentID != enrollmentID || result.Location != enrollmentLocation(enrollment) {
		return application.ErrDependencyUnavailable
	}
	if _, exists := u.store.createResults[resultLocator]; exists {
		return application.ErrDependencyUnavailable
	}

	var idem *idempotencyruntime.Record
	for scope, rec := range u.stagedIdemCommits {
		if rec == nil || rec.Scope != scope || rec.Status != idempotencyruntime.RecordCommitted || rec.Result.String() != resultLocator ||
			scope.Credential().Kind() != authpolicy.CredentialKindRequestAccessToken ||
			scope.Credential().Binding() != u.stagedRequest.Record.PreOnboardingRequestID ||
			scope.Method() != "POST" || scope.Route() != "/v1/enrollments" || !now.Before(rec.ExpiresAt) || rec.Capsule == nil {
			return application.ErrDependencyUnavailable
		}
		if _, exists := u.store.idemCommitted[scope]; exists {
			return application.ErrDependencyUnavailable
		}
		active, ok := u.store.idemActive[scope]
		if !ok || active == nil || !active.fingerprint.Equal(rec.Fingerprint) || !u.ownsActiveReservation(scope, active.token) {
			return application.ErrDependencyUnavailable
		}
		if rec.CapsuleExpiresAt.IsZero() || !now.Before(rec.CapsuleExpiresAt) || !now.Before(rec.Capsule.ExpiresAt()) {
			return application.ErrDependencyUnavailable
		}
		idem = rec
	}
	if idem == nil {
		return application.ErrDependencyUnavailable
	}

	event := u.stagedAudits[0]
	if event.Type != application.AuditEventEnrollmentCreated || event.EnrollmentID != enrollmentID || event.DeviceID != enrollment.DeviceID ||
		event.Operation != application.OperationInitial || event.CertificateUsage != enrollment.CertificateUsage || event.IdempotencyRef != resultLocator {
		return application.ErrDependencyUnavailable
	}
	return nil
}

func enrollmentLocation(r application.EnrollmentRecord) string {
	if r.Aggregate == nil {
		return ""
	}
	return "/v1/enrollments/" + string(r.Aggregate.ID())
}

func (u *memoryUOW) commitAuthorityAndPublish(now time.Time) error {
	if u.authoritySnapshot == nil || u.stagedRequest == nil {
		return application.ErrDependencyUnavailable
	}
	return mapAuthorityError(u.store.authority.CommitEnrollmentAuthority(*u.authoritySnapshot, now, u.publishLocked))
}

func mapAuthorityError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, preonboardingruntime.ErrEnrollmentAuthorityConsumed):
		return application.ErrAuthenticationRequired
	case errors.Is(err, preonboardingruntime.ErrEnrollmentAuthorityExpired):
		return application.ErrResourceExpired
	case errors.Is(err, preonboardingruntime.ErrEnrollmentAuthorityNotAuthorized):
		return application.ErrNotAuthorized
	default:
		return application.ErrDependencyUnavailable
	}
}

func (u *memoryUOW) ownsActiveReservation(scope idempotencyruntime.EffectiveScope, activeToken idempotencyruntime.ReservationToken) bool {
	for token, ownedScope := range u.activeTokens {
		if ownedScope.Equal(scope) && token.Equal(activeToken) {
			return true
		}
	}
	return false
}

func (u *memoryUOW) publishLocked() {
	for id, rec := range u.stagedEnrollments {
		u.store.enrollments[id] = cloneEnrollmentRecord(rec)
	}
	for key, rec := range u.stagedEnrollmentAccess {
		u.store.enrollmentAccess[key] = rec
	}
	for loc, snap := range u.stagedCreateResults {
		u.store.createResults[loc] = snap.Clone()
	}
	for scope, rec := range u.stagedIdemCommits {
		u.store.idemCommitted[scope] = cloneIdemRecord(rec)
		delete(u.store.idemActive, scope)
	}
	u.store.audits = append(u.store.audits, u.stagedAudits...)
}

func (u *memoryUOW) rollbackLocked() {
	for token, scope := range u.activeTokens {
		if active, ok := u.store.idemActive[scope]; ok && active != nil && active.token.Equal(token) {
			delete(u.store.idemActive, scope)
		}
	}
	u.stagedRequest = nil
	u.stagedEnrollments = nil
	u.stagedEnrollmentAccess = nil
	u.stagedCreateResults = nil
	u.stagedIdemCommits = nil
	u.stagedAudits = nil
	u.policyReads = nil
}

type memoryPreOnboardingReader struct{ uow *memoryUOW }

func (r *memoryPreOnboardingReader) Get(_ context.Context, id preonboardingdomain.ID) (*preonboardingdomain.PreOnboardingRequest, bool, error) {
	snap, found, err := r.uow.ensureAuthority(string(id))
	if err != nil || !found {
		return nil, found, err
	}
	return clonePreOnboardingRequest(snap.Request), true, nil
}

type memoryRequestAccessStore struct{ uow *memoryUOW }

func (s *memoryRequestAccessStore) GetByPreOnboardingRequestID(_ context.Context, id string) (application.RequestAccessCredential, bool, error) {
	snap, found, err := s.uow.ensureAuthority(id)
	if err != nil || !found {
		return application.RequestAccessCredential{}, found, err
	}
	return application.RequestAccessCredential{Key: snap.RequestAccessKey, Record: snap.RequestAccess}, true, nil
}

func (s *memoryRequestAccessStore) Save(_ context.Context, credential application.RequestAccessCredential) error {
	if s.uow.closed || s.uow.authoritySnapshot == nil || s.uow.stagedRequest != nil {
		return errors.New("enrollment runtime: invalid request access lifecycle save")
	}
	initial := s.uow.authoritySnapshot
	if initial.RequestAccess.State != capability.StateActive || credential.Record.State != capability.StateConsumed ||
		credential.Key != initial.RequestAccessKey || credential.Record.PreOnboardingRequestID != initial.RequestAccess.PreOnboardingRequestID ||
		!credential.Record.ExpiresAt.Equal(initial.RequestAccess.ExpiresAt) {
		return errors.New("enrollment runtime: only exact ACTIVE to CONSUMED transition may be staged")
	}
	cp := credential
	s.uow.stagedRequest = &cp
	return nil
}

type memoryEnrollmentRepository struct{ uow *memoryUOW }

func (r *memoryEnrollmentRepository) Create(_ context.Context, record application.EnrollmentRecord) error {
	if r.uow.closed || record.Validate() != nil {
		return errors.New("enrollment runtime: invalid enrollment record")
	}
	id := string(record.Aggregate.ID())
	if _, exists := r.uow.stagedEnrollments[id]; exists {
		return errors.New("enrollment runtime: duplicate staged enrollment")
	}
	r.uow.store.mu.RLock()
	_, exists := r.uow.store.enrollments[id]
	r.uow.store.mu.RUnlock()
	if exists {
		return errors.New("enrollment runtime: duplicate enrollment")
	}
	r.uow.stagedEnrollments[id] = cloneEnrollmentRecord(record)
	return nil
}

func (r *memoryEnrollmentRepository) GetEnrollment(_ context.Context, id string) (application.EnrollmentRecord, bool, error) {
	if r.uow.closed || id == "" {
		return application.EnrollmentRecord{}, false, errors.New("enrollment runtime: invalid enrollment lookup")
	}
	if rec, ok := r.uow.stagedEnrollments[id]; ok {
		return cloneEnrollmentRecord(rec), true, nil
	}
	r.uow.store.mu.RLock()
	rec, ok := r.uow.store.enrollments[id]
	r.uow.store.mu.RUnlock()
	if !ok {
		return application.EnrollmentRecord{}, false, nil
	}
	return cloneEnrollmentRecord(rec), true, nil
}

type memoryEnrollmentAccessWriter struct{ uow *memoryUOW }

func (w *memoryEnrollmentAccessWriter) CreateEnrollmentAccess(_ context.Context, key capability.VerifierKey, rec capability.EnrollmentAccessRecord) error {
	if w.uow.closed || key == "" || rec.EnrollmentID == "" || rec.ExpiresAt.IsZero() {
		return errors.New("enrollment runtime: invalid enrollment access verifier")
	}
	if _, exists := w.uow.stagedEnrollmentAccess[key]; exists {
		return capability.ErrDuplicate
	}
	w.uow.store.mu.RLock()
	_, exists := w.uow.store.enrollmentAccess[key]
	w.uow.store.mu.RUnlock()
	if exists {
		return capability.ErrDuplicate
	}
	w.uow.stagedEnrollmentAccess[key] = rec
	return nil
}

type memoryResultStore struct{ uow *memoryUOW }

func (s *memoryResultStore) SaveCreateResult(_ context.Context, loc idempotencyruntime.ResultLocator, res application.CreateResultSnapshot) error {
	if s.uow.closed || loc.IsZero() || res.Validate() != nil {
		return errors.New("enrollment runtime: invalid create result")
	}
	if _, exists := s.uow.stagedCreateResults[loc.String()]; exists {
		return errors.New("enrollment runtime: duplicate staged create result")
	}
	s.uow.store.mu.RLock()
	_, exists := s.uow.store.createResults[loc.String()]
	s.uow.store.mu.RUnlock()
	if exists {
		return errors.New("enrollment runtime: duplicate create result")
	}
	s.uow.stagedCreateResults[loc.String()] = res.Clone()
	return nil
}

func (s *memoryResultStore) GetCreateResult(_ context.Context, loc idempotencyruntime.ResultLocator) (application.CreateResultSnapshot, bool, error) {
	if snap, ok := s.uow.stagedCreateResults[loc.String()]; ok {
		return snap.Clone(), true, nil
	}
	s.uow.store.mu.RLock()
	snap, ok := s.uow.store.createResults[loc.String()]
	s.uow.store.mu.RUnlock()
	return snap.Clone(), ok, nil
}

type memoryPolicyReader struct{ uow *memoryUOW }

func (r *memoryPolicyReader) read(partnerID, deviceID, usage string) (policyRecord, error) {
	key := policyKey{partnerID: partnerID, deviceID: deviceID, certificateUsage: usage}
	if observed, ok := r.uow.policyReads[key]; ok {
		return observed, nil
	}
	r.uow.store.mu.RLock()
	policy, ok := r.uow.store.policies[key]
	r.uow.store.mu.RUnlock()
	if !ok {
		return policyRecord{}, errors.New("enrollment runtime: INITIAL policy unavailable")
	}
	policy.requirements = policy.requirements.Clone()
	r.uow.policyReads[key] = policy
	return policy, nil
}

func (r *memoryPolicyReader) IsInitialEligible(_ context.Context, partnerID, deviceID, usage string) (bool, error) {
	policy, err := r.read(partnerID, deviceID, usage)
	if err != nil {
		return false, err
	}
	return policy.eligible, nil
}

func (r *memoryPolicyReader) InitialEvidenceRequirements(_ context.Context, partnerID, deviceID, usage string) (application.EvidenceRequirements, error) {
	policy, err := r.read(partnerID, deviceID, usage)
	if err != nil {
		return application.EvidenceRequirements{}, err
	}
	return policy.requirements.Clone(), nil
}

type memoryAuditWriter struct{ uow *memoryUOW }

func (w *memoryAuditWriter) StageEvent(_ context.Context, event application.AuditEvent) error {
	if w.uow.closed || event.Type != application.AuditEventEnrollmentCreated || event.EnrollmentID == "" || event.DeviceID == "" || event.IdempotencyRef == "" || event.Timestamp.IsZero() {
		return errors.New("enrollment runtime: invalid audit event")
	}
	w.uow.stagedAudits = append(w.uow.stagedAudits, event)
	return nil
}

type transactionalIdemStore struct{ uow *memoryUOW }

func (s *transactionalIdemStore) Reserve(_ context.Context, req idempotencyruntime.ReserveRequest) (idempotencyruntime.Reservation, error) {
	if s.uow.closed {
		return idempotencyruntime.Reservation{}, errors.New("enrollment runtime: transaction closed")
	}
	s.uow.store.mu.Lock()
	defer s.uow.store.mu.Unlock()

	if rec, ok := s.uow.stagedIdemCommits[req.Scope]; ok {
		return classifyCommitted(req, rec), nil
	}
	if rec, ok := s.uow.store.idemCommitted[req.Scope]; ok {
		return classifyCommitted(req, rec), nil
	}
	if active, ok := s.uow.store.idemActive[req.Scope]; ok {
		if req.Now.Before(active.expiresAt) {
			status := idempotencyruntime.ReservationConflict
			if active.fingerprint.Equal(req.Fingerprint) {
				status = idempotencyruntime.ReservationInProgress
			}
			return idempotencyruntime.Reservation{Scope: req.Scope, Status: status, Fingerprint: active.fingerprint, ExpiresAt: active.expiresAt}, nil
		}
		delete(s.uow.store.idemActive, req.Scope)
	}
	token, err := idempotencyruntime.NewReservationToken()
	if err != nil {
		return idempotencyruntime.Reservation{}, err
	}
	active := &idemActiveRecord{scope: req.Scope, fingerprint: req.Fingerprint, token: token, createdAt: req.Now, expiresAt: req.ExpiresAt}
	s.uow.store.idemActive[req.Scope] = active
	s.uow.activeTokens[token] = req.Scope
	return idempotencyruntime.Reservation{Scope: req.Scope, Status: idempotencyruntime.ReservationNew, Token: token, Fingerprint: req.Fingerprint, ExpiresAt: req.ExpiresAt}, nil
}

func classifyCommitted(req idempotencyruntime.ReserveRequest, rec *idempotencyruntime.Record) idempotencyruntime.Reservation {
	if rec != nil && rec.Fingerprint.Equal(req.Fingerprint) {
		return idempotencyruntime.Reservation{Scope: req.Scope, Status: idempotencyruntime.ReservationReplay, Result: rec.Result, Fingerprint: rec.Fingerprint, ExpiresAt: rec.ExpiresAt}
	}
	var fp idempotencyruntime.Fingerprint
	var exp time.Time
	if rec != nil {
		fp, exp = rec.Fingerprint, rec.ExpiresAt
	}
	return idempotencyruntime.Reservation{Scope: req.Scope, Status: idempotencyruntime.ReservationConflict, Fingerprint: fp, ExpiresAt: exp}
}

func (s *transactionalIdemStore) Commit(_ context.Context, req idempotencyruntime.CommitRequest) (idempotencyruntime.Record, error) {
	if s.uow.closed {
		return idempotencyruntime.Record{}, errors.New("enrollment runtime: transaction closed")
	}
	s.uow.store.mu.Lock()
	defer s.uow.store.mu.Unlock()
	active, ok := s.uow.store.idemActive[req.Scope]
	if !ok || active == nil || !active.token.Equal(req.Token) {
		return idempotencyruntime.Record{}, errors.New("enrollment runtime: active reservation ownership mismatch")
	}
	if _, exists := s.uow.stagedIdemCommits[req.Scope]; exists {
		return idempotencyruntime.Record{}, errors.New("enrollment runtime: duplicate staged idempotency commit")
	}
	record := &idempotencyruntime.Record{
		Scope: req.Scope, Fingerprint: active.fingerprint, Status: idempotencyruntime.RecordCommitted,
		Result: req.Result, CreatedAt: active.createdAt, ExpiresAt: active.expiresAt,
	}
	if req.Capsule != nil {
		record.Capsule = cloneEnvelope(req.Capsule)
		if record.Capsule == nil {
			return idempotencyruntime.Record{}, errors.New("enrollment runtime: malformed replay capsule")
		}
		record.CapsuleExpiresAt = record.Capsule.ExpiresAt()
	}
	s.uow.stagedIdemCommits[req.Scope] = record
	return *cloneIdemRecord(record), nil
}

func (s *transactionalIdemStore) Lookup(_ context.Context, scope idempotencyruntime.EffectiveScope) (idempotencyruntime.Record, bool, error) {
	if rec, ok := s.uow.stagedIdemCommits[scope]; ok {
		return *cloneIdemRecord(rec), true, nil
	}
	s.uow.store.mu.RLock()
	rec, ok := s.uow.store.idemCommitted[scope]
	s.uow.store.mu.RUnlock()
	if !ok {
		return idempotencyruntime.Record{}, false, nil
	}
	return *cloneIdemRecord(rec), true, nil
}

func cloneAuthoritySnapshot(in preonboardingruntime.EnrollmentAuthoritySnapshot) preonboardingruntime.EnrollmentAuthoritySnapshot {
	return preonboardingruntime.EnrollmentAuthoritySnapshot{
		Request: clonePreOnboardingRequest(in.Request), RequestAccessKey: in.RequestAccessKey, RequestAccess: in.RequestAccess,
	}
}

func clonePreOnboardingRequest(req *preonboardingdomain.PreOnboardingRequest) *preonboardingdomain.PreOnboardingRequest {
	if req == nil {
		return nil
	}
	out, err := preonboardingdomain.RestoreRequest(req.ID(), req.PartnerID(), req.ClaimedDevice(), req.Agent(), req.Status(), req.DeviceID(), req.CreatedAt(), req.ExpiresAt(), req.ResourceVersion())
	if err != nil {
		return nil
	}
	return out
}

func cloneEnrollmentRecord(rec application.EnrollmentRecord) application.EnrollmentRecord {
	out := rec
	out.EvidenceRequirements = rec.EvidenceRequirements.Clone()
	if rec.Aggregate != nil {
		agg, err := domain.RestoreEnrollment(rec.Aggregate.ID(), rec.Aggregate.State())
		if err == nil {
			out.Aggregate = agg
		} else {
			out.Aggregate = nil
		}
	}
	return out
}

func cloneEnvelope(in *idempotencyruntime.ProtectedEnvelope) *idempotencyruntime.ProtectedEnvelope {
	if in == nil {
		return nil
	}
	out, err := idempotencyruntime.NewProtectedEnvelope(in.Ciphertext(), in.Nonce(), in.KeyID(), in.KeyVersion(), in.ExpiresAt())
	if err != nil {
		return nil
	}
	return out
}

func cloneIdemRecord(in *idempotencyruntime.Record) *idempotencyruntime.Record {
	if in == nil {
		return nil
	}
	out := *in
	out.Capsule = cloneEnvelope(in.Capsule)
	return &out
}

// Compile-time contracts.
var _ application.UnitOfWorkManager = (*MemoryStore)(nil)
var _ capability.Store = (*MemoryStore)(nil)
var _ application.UnitOfWork = (*memoryUOW)(nil)
