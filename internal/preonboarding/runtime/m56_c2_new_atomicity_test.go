package runtime_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/replaycapsule"
)

// trackingTokenGenerator records the last generated token so a test can prove a
// generated-but-uncommitted token does not authenticate after rollback.
type trackingTokenGenerator struct {
	calls int
	last  string
	err   error
}

func (g *trackingTokenGenerator) NewRequestAccessToken(context.Context) (string, error) {
	if g.err != nil {
		return "", g.err
	}
	g.calls++
	g.last = fmt.Sprintf("c2-token-%d", g.calls)
	return g.last, nil
}

type failingIDGenerator struct{}

func (failingIDGenerator) NewPreOnboardingRequestID(context.Context) (string, error) {
	return "", errors.New("injected id generation failure")
}

type c2FaultKind int

const (
	c2NoFault c2FaultKind = iota
	c2FaultRequestAccessWrite
	c2FaultRepositorySave
	c2FaultResultSnapshotSave
	c2FaultAuditStage
	c2FaultIdemCommit
	c2FaultOuterCommit
)

type c2FaultUOWManager struct {
	real  application.UnitOfWorkManager
	fault c2FaultKind
	err   error
}

func (m *c2FaultUOWManager) Begin(ctx context.Context) (application.UnitOfWork, error) {
	uow, err := m.real.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &c2FaultUOW{UnitOfWork: uow, fault: m.fault, err: m.err}, nil
}

type c2FaultUOW struct {
	application.UnitOfWork
	fault c2FaultKind
	err   error
}

func (u *c2FaultUOW) RequestAccessWriter() application.RequestAccessWriter {
	if u.fault == c2FaultRequestAccessWrite {
		return &faultRequestAccessWriter{RequestAccessWriter: u.UnitOfWork.RequestAccessWriter(), err: u.err}
	}
	return u.UnitOfWork.RequestAccessWriter()
}

func (u *c2FaultUOW) Repository() application.Repository {
	if u.fault == c2FaultRepositorySave {
		return &faultRepository{Repository: u.UnitOfWork.Repository(), err: u.err}
	}
	return u.UnitOfWork.Repository()
}

func (u *c2FaultUOW) ResultStore() application.ResultStore {
	if u.fault == c2FaultResultSnapshotSave {
		return &faultResultStore{ResultStore: u.UnitOfWork.ResultStore(), err: u.err}
	}
	return u.UnitOfWork.ResultStore()
}

func (u *c2FaultUOW) AuditWriter() application.AuditWriter {
	if u.fault == c2FaultAuditStage {
		return &faultAuditWriter{AuditWriter: u.UnitOfWork.AuditWriter(), err: u.err}
	}
	return u.UnitOfWork.AuditWriter()
}

func (u *c2FaultUOW) IdempotencyStore() idempotencyruntime.Store {
	if u.fault == c2FaultIdemCommit {
		return &faultIdemStore{Store: u.UnitOfWork.IdempotencyStore(), err: u.err}
	}
	return u.UnitOfWork.IdempotencyStore()
}

func (u *c2FaultUOW) Commit(ctx context.Context) error {
	if u.fault == c2FaultOuterCommit {
		return u.err
	}
	return u.UnitOfWork.Commit(ctx)
}

type faultRequestAccessWriter struct {
	application.RequestAccessWriter
	err error
}

func (w *faultRequestAccessWriter) CreateRequestAccess(ctx context.Context, key capability.VerifierKey, rec capability.RequestAccessRecord) error {
	return w.err
}

type faultRepository struct {
	application.Repository
	err error
}

func (r *faultRepository) Save(ctx context.Context, req *domain.PreOnboardingRequest) error {
	return r.err
}

type faultResultStore struct {
	application.ResultStore
	err error
}

func (s *faultResultStore) SaveCreateResult(ctx context.Context, loc idempotencyruntime.ResultLocator, res application.PreOnboardingCreateResultSnapshot) error {
	return s.err
}

type faultAuditWriter struct {
	application.AuditWriter
	err error
}

func (w *faultAuditWriter) StageEvent(ctx context.Context, event application.AuditEvent) error {
	return w.err
}

type faultIdemStore struct {
	idempotencyruntime.Store
	err error
}

func (s *faultIdemStore) Commit(ctx context.Context, req idempotencyruntime.CommitRequest) (idempotencyruntime.Record, error) {
	return idempotencyruntime.Record{}, s.err
}

type sealFaultProtector struct {
	real idempotencyruntime.Protector
}

func (p *sealFaultProtector) Seal(ctx context.Context, plaintext, aad []byte) (*idempotencyruntime.ProtectedEnvelope, error) {
	return nil, errors.New("injected seal failure")
}

func (p *sealFaultProtector) Open(ctx context.Context, env *idempotencyruntime.ProtectedEnvelope, aad []byte) ([]byte, error) {
	return p.real.Open(ctx, env, aad)
}

type c2Harness struct {
	store    *runtime.MemoryStore
	recorder *runtime.MemoryAuditRecorder
	clock    *runtime.MockClock
	verifier capability.Verifier
	tokens   *trackingTokenGenerator
	svc      *application.Service
}

// newC2Harness wires a Service over the given store (and uowMgr wrapping that
// same store). The harness shares the exact store/recorder instances the
// Service writes to, so assertions inspect the real durable state.
func newC2Harness(t *testing.T, now time.Time, store *runtime.MemoryStore, recorder *runtime.MemoryAuditRecorder, uowMgr application.UnitOfWorkManager, idGen application.IDGenerator, tokenGen application.TokenGenerator, protector idempotencyruntime.Protector, tokens *trackingTokenGenerator, partnerAuth application.PartnerAuthorityChecker) *c2Harness {
	t.Helper()
	clock := runtime.NewMockClock(now)
	verifier, err := capability.NewHMACVerifier([]byte("capability-verifier-key-m56a-32bytes!"))
	if err != nil {
		t.Fatal(err)
	}
	if partnerAuth == nil {
		partnerAuth = runtime.NewMemoryPartnerAuthorityChecker()
	}
	svc, err := application.NewService(application.ServiceConfig{
		UOWManager:                 uowMgr,
		Clock:                      clock,
		DeviceAllocator:            runtime.DefaultDeviceAllocator{},
		PartnerAuth:                partnerAuth,
		PartnerEligibility:         runtime.NewMemoryPartnerEligibilityChecker(),
		RetentionPolicy:            application.StaticIdempotencyRetentionPolicy{Duration: 24 * time.Hour},
		ReplayCapsulePolicy:        application.StaticReplayCapsuleRetentionPolicy{Duration: time.Hour},
		RequestAccessTokenLifetime: application.StaticRequestAccessTokenLifetime{Duration: 30 * time.Minute},
		Create: &application.CreateDependencies{
			IDGenerator:    idGen,
			TokenGenerator: tokenGen,
			Verifier:       verifier,
			Protector:      protector,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &c2Harness{store: store, recorder: recorder, clock: clock, verifier: verifier, tokens: tokens, svc: svc}
}

func (h *c2Harness) assertZeroPartialState(t *testing.T) {
	t.Helper()
	if h.store.CountRequests() != 0 {
		t.Fatalf("requests = %d, want 0", h.store.CountRequests())
	}
	if h.store.CountRequestAccess() != 0 {
		t.Fatalf("request access verifiers = %d, want 0", h.store.CountRequestAccess())
	}
	if h.store.CountCreateResults() != 0 {
		t.Fatalf("create-result snapshots = %d, want 0", h.store.CountCreateResults())
	}
	if h.store.CountIdemCommitted() != 0 {
		t.Fatalf("committed idempotency operations = %d, want 0", h.store.CountIdemCommitted())
	}
	if h.recorder.CountByType(application.AuditEventSubmitted) != 0 {
		t.Fatalf("PREONBOARD_SUBMITTED = %d, want 0", h.recorder.CountByType(application.AuditEventSubmitted))
	}
}

func (h *c2Harness) assertGeneratedTokenRejected(t *testing.T) {
	t.Helper()
	if h.tokens.last == "" {
		t.Fatal("no token was generated")
	}
	a := capability.NewRequestAccessAuthenticator(h.verifier, h.store, h.clock)
	got := a.Authenticate(context.Background(), &authruntime.Credential{BearerToken: h.tokens.last})
	if got.Decision == authruntime.DecisionAuthenticated {
		t.Fatalf("generated-but-uncommitted token %q authenticated after rollback", h.tokens.last)
	}
}

func checkGeneratedTokenRejected(t *testing.T, h *c2Harness) { h.assertGeneratedTokenRejected(t) }

func c2RealProtector(t *testing.T, now time.Time) idempotencyruntime.Protector {
	t.Helper()
	p, err := replaycapsule.NewAEADProtector([]byte("replay-capsule-protector-key-32!"), "m56a", func() time.Time { return now.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestM56_C2_NewFailureAtomicity proves that every fallible NEW stage after
// ReservationNew publishes zero partial durable state and that no generated
// plaintext token authenticates after rollback.
func TestM56_C2_NewFailureAtomicity(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	injected := errors.New("injected failure")

	cases := []struct {
		name  string
		setup func(t *testing.T) (*application.Service, *c2Harness)
		check func(t *testing.T, h *c2Harness)
	}{
		{
			name: "id_generation",
			setup: func(t *testing.T) (*application.Service, *c2Harness) {
				recorder := runtime.NewMemoryAuditRecorder()
				store := runtime.NewMemoryStore(recorder)
				tokens := &trackingTokenGenerator{}
				h := newC2Harness(t, now, store, recorder, store, failingIDGenerator{}, tokens, c2RealProtector(t, now), tokens, nil)
				return h.svc, h
			},
		},
		{
			name: "token_generation",
			setup: func(t *testing.T) (*application.Service, *c2Harness) {
				recorder := runtime.NewMemoryAuditRecorder()
				store := runtime.NewMemoryStore(recorder)
				tokens := &trackingTokenGenerator{err: injected}
				h := newC2Harness(t, now, store, recorder, store, &seqID{}, tokens, c2RealProtector(t, now), tokens, nil)
				return h.svc, h
			},
		},
		{
			name: "request_access_write",
			setup: func(t *testing.T) (*application.Service, *c2Harness) {
				recorder := runtime.NewMemoryAuditRecorder()
				store := runtime.NewMemoryStore(recorder)
				tokens := &trackingTokenGenerator{}
				mgr := &c2FaultUOWManager{real: store, fault: c2FaultRequestAccessWrite, err: injected}
				h := newC2Harness(t, now, store, recorder, mgr, &seqID{}, tokens, c2RealProtector(t, now), tokens, nil)
				return h.svc, h
			},
			check: func(t *testing.T, h *c2Harness) { h.assertGeneratedTokenRejected(t) },
		},
		{
			name: "repository_save",
			setup: func(t *testing.T) (*application.Service, *c2Harness) {
				recorder := runtime.NewMemoryAuditRecorder()
				store := runtime.NewMemoryStore(recorder)
				tokens := &trackingTokenGenerator{}
				mgr := &c2FaultUOWManager{real: store, fault: c2FaultRepositorySave, err: injected}
				h := newC2Harness(t, now, store, recorder, mgr, &seqID{}, tokens, c2RealProtector(t, now), tokens, nil)
				return h.svc, h
			},
			check: checkGeneratedTokenRejected,
		},
		{
			name: "result_snapshot_save",
			setup: func(t *testing.T) (*application.Service, *c2Harness) {
				recorder := runtime.NewMemoryAuditRecorder()
				store := runtime.NewMemoryStore(recorder)
				tokens := &trackingTokenGenerator{}
				mgr := &c2FaultUOWManager{real: store, fault: c2FaultResultSnapshotSave, err: injected}
				h := newC2Harness(t, now, store, recorder, mgr, &seqID{}, tokens, c2RealProtector(t, now), tokens, nil)
				return h.svc, h
			},
			check: checkGeneratedTokenRejected,
		},
		{
			name: "audit_stage",
			setup: func(t *testing.T) (*application.Service, *c2Harness) {
				recorder := runtime.NewMemoryAuditRecorder()
				store := runtime.NewMemoryStore(recorder)
				tokens := &trackingTokenGenerator{}
				mgr := &c2FaultUOWManager{real: store, fault: c2FaultAuditStage, err: injected}
				h := newC2Harness(t, now, store, recorder, mgr, &seqID{}, tokens, c2RealProtector(t, now), tokens, nil)
				return h.svc, h
			},
			check: checkGeneratedTokenRejected,
		},
		{
			name: "idem_commit",
			setup: func(t *testing.T) (*application.Service, *c2Harness) {
				recorder := runtime.NewMemoryAuditRecorder()
				store := runtime.NewMemoryStore(recorder)
				tokens := &trackingTokenGenerator{}
				mgr := &c2FaultUOWManager{real: store, fault: c2FaultIdemCommit, err: injected}
				h := newC2Harness(t, now, store, recorder, mgr, &seqID{}, tokens, c2RealProtector(t, now), tokens, nil)
				return h.svc, h
			},
			check: checkGeneratedTokenRejected,
		},
		{
			name: "seal",
			setup: func(t *testing.T) (*application.Service, *c2Harness) {
				recorder := runtime.NewMemoryAuditRecorder()
				store := runtime.NewMemoryStore(recorder)
				tokens := &trackingTokenGenerator{}
				prot := &sealFaultProtector{real: c2RealProtector(t, now)}
				h := newC2Harness(t, now, store, recorder, store, &seqID{}, tokens, prot, tokens, nil)
				return h.svc, h
			},
			check: checkGeneratedTokenRejected,
		},
		{
			name: "outer_commit",
			setup: func(t *testing.T) (*application.Service, *c2Harness) {
				recorder := runtime.NewMemoryAuditRecorder()
				store := runtime.NewMemoryStore(recorder)
				tokens := &trackingTokenGenerator{}
				mgr := &c2FaultUOWManager{real: store, fault: c2FaultOuterCommit, err: injected}
				h := newC2Harness(t, now, store, recorder, mgr, &seqID{}, tokens, c2RealProtector(t, now), tokens, nil)
				return h.svc, h
			},
			check: checkGeneratedTokenRejected,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, h := tc.setup(t)
			cmd := humanCmd("idem-c2-atomicity-" + tc.name)
			if _, err := svc.CreateOriginator(ctx, cmd); err == nil {
				t.Fatal("expected NEW failure, got success")
			}
			h.assertZeroPartialState(t)
			if tc.check != nil {
				tc.check(t, h)
			}
		})
	}
}

// TestM56_C2_TPQuotaRollbackOnDownstreamFailure proves the TemporaryPrincipal
// submission quota is rolled back for every downstream NEW failure after quota
// staging.
func TestM56_C2_TPQuotaRollbackOnDownstreamFailure(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	tpID := "tp-c2-atomicity"
	injected := errors.New("injected failure")

	cases := []struct {
		name      string
		fault     c2FaultKind
		seal      bool
		failID    bool
		failToken bool
	}{
		{"id_generation", c2NoFault, false, true, false},
		{"token_generation", c2NoFault, false, false, true},
		{"request_access_write", c2FaultRequestAccessWrite, false, false, false},
		{"repository_save", c2FaultRepositorySave, false, false, false},
		{"result_snapshot_save", c2FaultResultSnapshotSave, false, false, false},
		{"audit_stage", c2FaultAuditStage, false, false, false},
		{"idem_commit", c2FaultIdemCommit, false, false, false},
		{"outer_commit", c2FaultOuterCommit, false, false, false},
		{"seal", c2NoFault, true, false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := runtime.NewMemoryAuditRecorder()
			store := runtime.NewMemoryStore(recorder)
			store.SeedTemporaryPrincipal(&domain.TemporaryPrincipal{
				TemporaryPrincipalID: tpID,
				PartnerID:            "P1",
				Status:               domain.TPStatusActive,
				ExpiresAt:            now.Add(time.Hour),
				MaxSubmissions:       5,
				CommittedSubmissions: 0,
			})
			tokens := &trackingTokenGenerator{}
			var uowMgr application.UnitOfWorkManager = store
			var protector idempotencyruntime.Protector = c2RealProtector(t, now)
			var idGen application.IDGenerator = &seqID{}
			if tc.failID {
				idGen = failingIDGenerator{}
			}
			if tc.failToken {
				tokens.err = injected
			}
			if tc.seal {
				protector = &sealFaultProtector{real: protector}
			} else if tc.fault != c2NoFault {
				uowMgr = &c2FaultUOWManager{real: store, fault: tc.fault, err: injected}
			}
			h := newC2Harness(t, now, store, recorder, uowMgr, idGen, tokens, protector, tokens, nil)

			cmd := tpCmd("idem-c2-tp-quota-"+tc.name, tpID)
			if _, err := h.svc.CreateOriginator(ctx, cmd); err == nil {
				t.Fatal("expected NEW failure, got success")
			}

			uow, _ := store.Begin(ctx)
			tpRec, ok, _ := uow.TemporaryPrincipalStore().Get(ctx, tpID)
			uow.Rollback(ctx)
			if !ok {
				t.Fatal("TP record missing")
			}
			if tpRec.CommittedSubmissions != 0 {
				t.Fatalf("CommittedSubmissions = %d, want 0 (quota rolled back)", tpRec.CommittedSubmissions)
			}
			h.assertZeroPartialState(t)
			if tc.failID {
				if tokens.calls != 0 {
					t.Fatalf("token generator called %d times despite ID failure, want 0", tokens.calls)
				}
			}
			if tc.failID || tc.failToken {
				if tokens.last != "" {
					t.Fatalf("a token was generated despite failure: %q", tokens.last)
				}
			}
		})
	}
}

// TestM56_C2_HumanOIDCFailureLeavesTPUntouched proves a failed HumanOIDC NEW
// never alters Temporary Principal storage.
func TestM56_C2_HumanOIDCFailureLeavesTPUntouched(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	recorder := runtime.NewMemoryAuditRecorder()
	store := runtime.NewMemoryStore(recorder)
	store.SeedTemporaryPrincipal(&domain.TemporaryPrincipal{
		TemporaryPrincipalID: "tp-c2-human",
		PartnerID:            "P1",
		Status:               domain.TPStatusActive,
		ExpiresAt:            now.Add(time.Hour),
		MaxSubmissions:       5,
		CommittedSubmissions: 0,
	})
	tokens := &trackingTokenGenerator{}
	prot := &sealFaultProtector{real: c2RealProtector(t, now)}
	h := newC2Harness(t, now, store, recorder, store, &seqID{}, tokens, prot, tokens, nil)

	cmd := humanCmd("idem-c2-human-fail")
	if _, err := h.svc.CreateOriginator(ctx, cmd); err == nil {
		t.Fatal("expected NEW failure, got success")
	}

	uow, _ := store.Begin(ctx)
	tpRec, ok, _ := uow.TemporaryPrincipalStore().Get(ctx, "tp-c2-human")
	uow.Rollback(ctx)
	if !ok {
		t.Fatal("TP record missing")
	}
	if tpRec.CommittedSubmissions != 0 {
		t.Fatalf("HumanOIDC failure altered TP quota: CommittedSubmissions = %d, want 0", tpRec.CommittedSubmissions)
	}
	h.assertZeroPartialState(t)
}
