package runtime_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	domain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/domain/enrollment"
	application "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/application"
	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
)

func createContinuationEnrollment(t *testing.T, h *harness, id, requestID, token string) application.CreateInitialResult {
	t.Helper()
	h.seedReady(t, requestID, "partner-cont", "device-cont", token, h.clock.Now().Add(time.Hour))
	svc := h.service(t, h.store, id, tokenOf(0x91), 0x11)
	result, err := svc.CreateInitial(h.ctx, createCmd(requestID, "idem-create-"+id))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func evidenceFingerprint(t *testing.T, body string) idempotencyruntime.Fingerprint {
	t.Helper()
	fp, err := idempotencyruntime.FingerprintRequest(idempotencyruntime.FingerprintVersion1, "PUT", "/v1/enrollments/{id}/evidence", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

func continuationCommand(id string, fp idempotencyruntime.Fingerprint, body string) application.EvidenceAcceptanceCommand {
	return application.EvidenceAcceptanceCommand{
		EnrollmentID: id, ExpectedChallengeVersion: 1, Fingerprint: fp, Representation: []byte(body),
	}
}

func TestContinuationGetReturnsImmutableSnapshotWithoutMutation(t *testing.T) {
	h := newHarness(t)
	created := createContinuationEnrollment(t, h, "enr-get", "por-get", "request-get")
	svc := h.service(t, h.store, "unused", tokenOf(0x92), 0x22)
	got, err := svc.GetEnrollment(h.ctx, application.GetEnrollmentCommand{EnrollmentID: created.Snapshot.EnrollmentID})
	if err != nil {
		t.Fatal(err)
	}
	if got.Snapshot.State != domain.StateChallengeIssued || got.Snapshot.UpdatedAt != created.Snapshot.CommittedAt {
		t.Fatalf("snapshot = %#v", got.Snapshot)
	}
	got.Snapshot.EvidenceRequirements.TPMEvidenceProtocolVersions[0] = "mutated"
	got.Snapshot.Challenge.Nonce = "mutated"
	again, err := svc.GetEnrollment(h.ctx, application.GetEnrollmentCommand{EnrollmentID: created.Snapshot.EnrollmentID})
	if err != nil {
		t.Fatal(err)
	}
	if again.Snapshot.EvidenceRequirements.TPMEvidenceProtocolVersions[0] == "mutated" || again.Snapshot.Challenge.Nonce == "mutated" {
		t.Fatal("GET exposed mutable persisted state")
	}
	if h.store.CountEnrollments() != 1 || len(h.store.AuditEvents()) != 1 {
		t.Fatal("GET mutated enrollment or event state")
	}
}

func TestContinuationGetRepositoryFailureFailsClosed(t *testing.T) {
	h := newHarness(t)
	svc := h.service(t, failingEnrollmentManager{inner: h.store}, "unused", tokenOf(0x93), 0x23)
	if _, err := svc.GetEnrollment(h.ctx, application.GetEnrollmentCommand{EnrollmentID: "enr-repository-failure"}); !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("repository failure = %v, want ErrDependencyUnavailable", err)
	}

	svc = h.service(t, h.store, "unused", tokenOf(0x94), 0x24)
	if _, err := svc.GetEnrollment(h.ctx, application.GetEnrollmentCommand{EnrollmentID: "missing"}); !errors.Is(err, application.ErrEnrollmentNotFound) {
		t.Fatalf("error = %v, want ErrEnrollmentNotFound", err)
	}
}

func TestEvidenceAcceptanceRetryConflictAndExpiry(t *testing.T) {
	h := newHarness(t)
	created := createContinuationEnrollment(t, h, "enr-evidence", "por-evidence", "request-evidence")
	svc := h.service(t, h.store, "unused", tokenOf(0x94), 0x24)
	fp := evidenceFingerprint(t, "evidence-one")
	cmd := continuationCommand(created.Snapshot.EnrollmentID, fp, "evidence-one")
	first, err := svc.AcceptEvidence(h.ctx, cmd)
	if err != nil || first.State != domain.StateEvidenceReceived || first.Replay {
		t.Fatalf("first acceptance = %#v, error = %v", first, err)
	}
	retry, err := svc.AcceptEvidence(h.ctx, cmd)
	if err != nil || !retry.Replay {
		t.Fatalf("retry = %#v, error = %v", retry, err)
	}
	if h.store.CountEnrollments() != 1 || len(h.store.AuditEvents()) != 2 {
		t.Fatalf("retry duplicated state/effect: enrollments=%d events=%d", h.store.CountEnrollments(), len(h.store.AuditEvents()))
	}
	if _, err := svc.AcceptEvidence(h.ctx, continuationCommand(created.Snapshot.EnrollmentID, evidenceFingerprint(t, "evidence-two"), "evidence-two")); !errors.Is(err, application.ErrEvidenceConflict) {
		t.Fatalf("conflict = %v, want ErrEvidenceConflict", err)
	}

	h2 := newHarness(t)
	created2 := createContinuationEnrollment(t, h2, "enr-expiry", "por-expiry", "request-expiry")
	h2.clock.Set(created2.Snapshot.Challenge.ExpiresAt)
	if _, err := h2.service(t, h2.store, "unused", tokenOf(0x95), 0x25).AcceptEvidence(h2.ctx, continuationCommand(created2.Snapshot.EnrollmentID, evidenceFingerprint(t, "late"), "late")); !errors.Is(err, application.ErrResourceExpired) {
		t.Fatalf("expired first submission = %v, want ErrResourceExpired", err)
	}
}

func TestAcceptedEvidenceRetrySurvivesClockAdvance(t *testing.T) {
	h := newHarness(t)
	created := createContinuationEnrollment(t, h, "enr-retry-clock", "por-retry-clock", "request-retry-clock")
	svc := h.service(t, h.store, "unused", tokenOf(0x96), 0x26)
	cmd := continuationCommand(created.Snapshot.EnrollmentID, evidenceFingerprint(t, "stable"), "stable")
	if _, err := svc.AcceptEvidence(h.ctx, cmd); err != nil {
		t.Fatal(err)
	}
	h.clock.Set(created.Snapshot.Challenge.ExpiresAt.Add(time.Hour))
	if result, err := svc.AcceptEvidence(h.ctx, cmd); err != nil || !result.Replay {
		t.Fatalf("post-expiry retry = %#v, error = %v", result, err)
	}
}

func TestChallengeRefreshVersionNonceAndIdempotency(t *testing.T) {
	h := newHarness(t)
	created := createContinuationEnrollment(t, h, "enr-refresh", "por-refresh", "request-refresh")
	svc := h.service(t, h.store, "unused", tokenOf(0x97), 0x22)
	cmd := application.RefreshChallengeCommand{EnrollmentID: created.Snapshot.EnrollmentID, CredentialBinding: "binding-refresh", IdempotencyKey: "refresh-key-0001", ExpectedChallengeVersion: 1}
	first, err := svc.RefreshChallenge(h.ctx, cmd)
	if err != nil || first.Challenge.ChallengeVersion != 2 || first.Challenge.Nonce == created.Snapshot.Challenge.Nonce {
		t.Fatalf("refresh = %#v, error = %v", first, err)
	}
	replay, err := svc.RefreshChallenge(h.ctx, cmd)
	if err != nil || replay.Challenge != first.Challenge {
		t.Fatalf("refresh replay = %#v, error = %v", replay, err)
	}
	changed := cmd
	changed.ExpectedChallengeVersion = 2
	if _, err := svc.RefreshChallenge(h.ctx, changed); !errors.Is(err, application.ErrIdempotencyConflict) {
		t.Fatalf("changed refresh fingerprint = %v, want ErrIdempotencyConflict", err)
	}
	if h.store.CountRefreshResults() != 1 || h.store.CountIdemCommitted() != 2 {
		t.Fatalf("refresh replay/commit counts = results %d idem %d", h.store.CountRefreshResults(), h.store.CountIdemCommitted())
	}
	current, ok := h.store.GetEnrollment(created.Snapshot.EnrollmentID)
	if !ok || current.Challenge.ChallengeVersion != 2 || current.AcceptedEvidence != nil {
		t.Fatalf("current enrollment = %#v", current)
	}

	if _, err := svc.AcceptEvidence(h.ctx, continuationCommand(created.Snapshot.EnrollmentID, evidenceFingerprint(t, "old"), "old")); !errors.Is(err, application.ErrStateConflict) {
		t.Fatalf("old challenge evidence = %v, want ErrStateConflict", err)
	}
}

func TestEvidenceStaleChallengeVersionConflicts(t *testing.T) {
	h := newHarness(t)
	created := createContinuationEnrollment(t, h, "enr-stale", "por-stale", "request-stale")
	cmd := continuationCommand(created.Snapshot.EnrollmentID, evidenceFingerprint(t, "stale"), "stale")
	cmd.ExpectedChallengeVersion = 2
	if _, err := h.service(t, h.store, "unused", tokenOf(0x9A), 0x2A).AcceptEvidence(h.ctx, cmd); !errors.Is(err, application.ErrStateConflict) {
		t.Fatalf("stale challenge version = %v, want ErrStateConflict", err)
	}
}

func TestEvidenceAndRefreshCompeteAtOneCommitBoundary(t *testing.T) {
	h := newHarness(t)
	created := createContinuationEnrollment(t, h, "enr-race-cont", "por-race-cont", "request-race-cont")
	evidenceSvc := h.service(t, h.store, "unused-evidence", tokenOf(0x98), 0x31)
	refreshSvc := h.service(t, h.store, "unused-refresh", tokenOf(0x99), 0x32)
	evidenceCmd := continuationCommand(created.Snapshot.EnrollmentID, evidenceFingerprint(t, "race-evidence"), "race-evidence")
	refreshCmd := application.RefreshChallengeCommand{EnrollmentID: created.Snapshot.EnrollmentID, CredentialBinding: "binding-race", IdempotencyKey: "refresh-race-0001", ExpectedChallengeVersion: 1}
	type outcome struct {
		evidence bool
		refresh  bool
		err      error
	}
	out := make(chan outcome, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := evidenceSvc.AcceptEvidence(h.ctx, evidenceCmd)
		out <- outcome{evidence: err == nil, err: err}
	}()
	go func() {
		defer wg.Done()
		_, err := refreshSvc.RefreshChallenge(h.ctx, refreshCmd)
		out <- outcome{refresh: err == nil, err: err}
	}()
	wg.Wait()
	close(out)
	wins := 0
	for result := range out {
		if result.evidence || result.refresh {
			wins++
		} else if !errors.Is(result.err, application.ErrStateConflict) {
			t.Fatalf("loser error = %v, want ErrStateConflict", result.err)
		}
	}
	if wins != 1 {
		t.Fatalf("successful competitors = %d, want 1", wins)
	}
	current, ok := h.store.GetEnrollment(created.Snapshot.EnrollmentID)
	if !ok || (current.Aggregate.State() != domain.StateEvidenceReceived && current.Challenge.ChallengeVersion != 2) {
		t.Fatalf("inconsistent final state = %#v", current)
	}
	if current.Aggregate.State() == domain.StateEvidenceReceived && current.AcceptedEvidence == nil {
		t.Fatal("evidence winner did not persist accepted evidence")
	}
	if current.Aggregate.State() == domain.StateChallengeIssued && current.Challenge.ChallengeVersion != 2 {
		t.Fatal("refresh winner did not advance challenge")
	}
}

func TestConcurrentRefreshesOnlyOneCommits(t *testing.T) {
	h := newHarness(t)
	created := createContinuationEnrollment(t, h, "enr-refresh-race", "por-refresh-race", "request-refresh-race")
	svcA := h.service(t, h.store, "unused-a", tokenOf(0xA1), 0x41)
	svcB := h.service(t, h.store, "unused-b", tokenOf(0xA2), 0x42)
	cmdA := application.RefreshChallengeCommand{EnrollmentID: created.Snapshot.EnrollmentID, CredentialBinding: "binding-a", IdempotencyKey: "refresh-a-000001", ExpectedChallengeVersion: 1}
	cmdB := application.RefreshChallengeCommand{EnrollmentID: created.Snapshot.EnrollmentID, CredentialBinding: "binding-b", IdempotencyKey: "refresh-b-000001", ExpectedChallengeVersion: 1}
	results := make(chan error, 2)
	go func() { _, err := svcA.RefreshChallenge(h.ctx, cmdA); results <- err }()
	go func() { _, err := svcB.RefreshChallenge(h.ctx, cmdB); results <- err }()
	first, second := <-results, <-results
	if (first == nil) == (second == nil) || (!errors.Is(first, application.ErrStateConflict) && !errors.Is(second, application.ErrStateConflict)) {
		t.Fatalf("refresh race errors = %v, %v", first, second)
	}
	current, ok := h.store.GetEnrollment(created.Snapshot.EnrollmentID)
	if !ok || current.Challenge.ChallengeVersion != 2 || h.store.CountRefreshResults() != 1 {
		t.Fatalf("refresh race final state = %#v results=%d", current, h.store.CountRefreshResults())
	}
}

type advanceCommitManager struct {
	inner application.UnitOfWorkManager
	clock *mutableClock
	at    time.Time
}

func (m advanceCommitManager) Begin(ctx context.Context) (application.UnitOfWork, error) {
	uow, err := m.inner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &advanceCommitUOW{UnitOfWork: uow, clock: m.clock, at: m.at}, nil
}

type advanceCommitUOW struct {
	application.UnitOfWork
	clock *mutableClock
	at    time.Time
}

func (u *advanceCommitUOW) EnrollmentContinuation() application.EnrollmentContinuationRepository {
	return u.UnitOfWork.(application.ContinuationUnitOfWork).EnrollmentContinuation()
}

func (u *advanceCommitUOW) RefreshResults() application.RefreshResultStore {
	return u.UnitOfWork.(application.ContinuationUnitOfWork).RefreshResults()
}

func (u *advanceCommitUOW) Commit(ctx context.Context) error {
	u.clock.Set(u.at)
	return u.UnitOfWork.Commit(ctx)
}

func TestCommitFreshnessFailureRollsBackEvidence(t *testing.T) {
	h := newHarness(t)
	created := createContinuationEnrollment(t, h, "enr-rollback", "por-rollback", "request-rollback")
	commitAt := created.Snapshot.Challenge.ExpiresAt
	manager := advanceCommitManager{inner: h.store, clock: h.clock, at: commitAt}
	svc := h.service(t, manager, "unused", tokenOf(0xA3), 0x33)
	_, err := svc.AcceptEvidence(h.ctx, continuationCommand(created.Snapshot.EnrollmentID, evidenceFingerprint(t, "rollback"), "rollback"))
	if !errors.Is(err, application.ErrStateConflict) && !errors.Is(err, application.ErrResourceExpired) {
		t.Fatalf("commit freshness error = %v", err)
	}
	current, ok := h.store.GetEnrollment(created.Snapshot.EnrollmentID)
	if !ok || current.Aggregate.State() != domain.StateChallengeIssued || current.AcceptedEvidence != nil || h.store.CountIdemActive() != 0 {
		t.Fatalf("rollback left partial evidence state = %#v active-idem=%d", current, h.store.CountIdemActive())
	}
}

type failingEnrollmentManager struct{ inner application.UnitOfWorkManager }

func (m failingEnrollmentManager) Begin(ctx context.Context) (application.UnitOfWork, error) {
	uow, err := m.inner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &failingEnrollmentUOW{UnitOfWork: uow}, nil
}

type failingEnrollmentUOW struct{ application.UnitOfWork }

func (u *failingEnrollmentUOW) Enrollments() application.EnrollmentRepository {
	return failingEnrollmentRepository{}
}

type failingEnrollmentRepository struct{}

func (failingEnrollmentRepository) Create(context.Context, application.EnrollmentRecord) error {
	return errors.New("injected enrollment repository failure")
}

func (failingEnrollmentRepository) GetEnrollment(context.Context, string) (application.EnrollmentRecord, bool, error) {
	return application.EnrollmentRecord{}, false, errors.New("injected enrollment repository failure")
}

var _ application.UnitOfWorkManager = advanceCommitManager{}

// corruptEvidenceManager is a test-only adapter that simulates a missing or
// corrupt persisted accepted-evidence identity: reads return the committed
// record with its AcceptedEvidence identity material cleared, which must
// classify as 503 DEPENDENCY_UNAVAILABLE (SOL-M5.8-AUDIT-006 H).
type corruptEvidenceManager struct {
	inner   application.UnitOfWorkManager
	corrupt *atomic.Bool
}

func (m corruptEvidenceManager) Begin(ctx context.Context) (application.UnitOfWork, error) {
	uow, err := m.inner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &corruptEvidenceUOW{UnitOfWork: uow, m: m}, nil
}

type corruptEvidenceUOW struct {
	application.UnitOfWork
	m corruptEvidenceManager
}

func (u *corruptEvidenceUOW) EnrollmentContinuation() application.EnrollmentContinuationRepository {
	return corruptEvidenceRepo{inner: u.UnitOfWork.(application.ContinuationUnitOfWork).EnrollmentContinuation(), corrupt: u.m.corrupt}
}

type corruptEvidenceRepo struct {
	inner   application.EnrollmentContinuationRepository
	corrupt *atomic.Bool
}

func (r corruptEvidenceRepo) GetEnrollment(ctx context.Context, id string) (application.EnrollmentRecord, bool, error) {
	rec, found, err := r.inner.GetEnrollment(ctx, id)
	if err != nil || !found || rec.AcceptedEvidence == nil || !r.corrupt.Load() {
		return rec, found, err
	}
	corrupt := rec.AcceptedEvidence.Clone()
	corrupt.Representation = nil
	rec.AcceptedEvidence = &corrupt
	return rec, found, nil
}

func (r corruptEvidenceRepo) StageEvidenceAcceptance(ctx context.Context, write application.EvidenceAcceptanceWrite) error {
	return r.inner.StageEvidenceAcceptance(ctx, write)
}

func (r corruptEvidenceRepo) StageChallengeRefresh(ctx context.Context, write application.ChallengeRefreshWrite) error {
	return r.inner.StageChallengeRefresh(ctx, write)
}

var _ application.UnitOfWorkManager = corruptEvidenceManager{}

func TestAcceptedEvidenceCorruptPersistedIdentityMaps503(t *testing.T) {
	h := newHarness(t)
	created := createContinuationEnrollment(t, h, "enr-corrupt-evidence", "por-corrupt-evidence", "request-corrupt-evidence")
	svc := h.service(t, h.store, "unused", tokenOf(0x95), 0x25)
	fp := evidenceFingerprint(t, "corrupt-evidence")
	cmd := continuationCommand(created.Snapshot.EnrollmentID, fp, "corrupt-evidence")
	if _, err := svc.AcceptEvidence(h.ctx, cmd); err != nil {
		t.Fatalf("first acceptance = %v, want nil", err)
	}

	// The same trusted identity resubmitted while the persisted identity
	// material is missing/corrupt must fail as dependency-unavailable (503),
	// never as a fabricated accepted replay.
	corrupt := &atomic.Bool{}
	corrupt.Store(true)
	svcCorrupt := h.service(t, corruptEvidenceManager{inner: h.store, corrupt: corrupt}, "unused", tokenOf(0x96), 0x26)
	if _, err := svcCorrupt.AcceptEvidence(h.ctx, cmd); !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("corrupt persisted identity error = %v, want ErrDependencyUnavailable", err)
	}
}
