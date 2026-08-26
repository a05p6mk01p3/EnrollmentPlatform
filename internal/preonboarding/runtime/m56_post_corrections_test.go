package runtime_test

// M5.6 post-implementation review correction evidence.
//
// M56-POST-001 (BLOCKER): memoryUOW.Commit must never partially publish
// committed state before a later commit-time collision failure. The UoW now
// runs a non-mutating validateLocked phase (resource-ID uniqueness, TP
// authoritative preconditions, RequestAccess verifier uniqueness, create-result
// and idempotency publication integrity) before the non-fallible publishLocked
// phase. The tests below prove a commit-time collision publishes NOTHING —
// including concerns that would otherwise be published first.
//
// M56-POST-002 (HIGH): Temporary Principal expiry must be re-evaluated at the
// atomic NEW commit boundary against the trusted server-controlled clock. The
// tests below prove expiry crossed between staging and commit fails closed
// with zero publication, and that a missing trusted clock fails closed.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
)

// stageFullNewConcernSet stages one representative concern of every type the
// NEW path publishes (TP quota delta, resource, RequestAccess verifier,
// create-result snapshot, audit event) into the given UoW. It exists so a
// commit-time validation failure can prove zero partial publication across
// every concern type — including the request, which publishLocked would
// publish first.
func stageFullNewConcernSet(t *testing.T, uow application.UnitOfWork, now time.Time, id, tpID string, key capability.VerifierKey) {
	t.Helper()
	ctx := context.Background()

	// Temporary Principal quota staging (Get records the initial committed
	// submissions so the commit-time delta is tracked).
	tpRec, ok, err := uow.TemporaryPrincipalStore().Get(ctx, tpID)
	if err != nil || !ok {
		t.Fatalf("TP get failed: ok=%v err=%v", ok, err)
	}
	tpRec.CommittedSubmissions++
	if err := uow.TemporaryPrincipalStore().Save(ctx, tpRec); err != nil {
		t.Fatal(err)
	}

	// New pre-onboarding resource, staged without a prior read (untracked):
	// exercises the NEW-resource ID collision validation path.
	req, err := domain.NewRequest(domain.ID(id), domain.PartnerID("P1"),
		domain.ClaimedDevice{Hostname: "h-post"}, domain.Agent{Platform: "linux", Version: "1"},
		now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.Repository().Save(ctx, req); err != nil {
		t.Fatal(err)
	}

	// RequestAccess verifier.
	if err := uow.RequestAccessWriter().CreateRequestAccess(ctx, key, capability.RequestAccessRecord{
		PreOnboardingRequestID: id,
		ExpiresAt:              now.Add(time.Hour),
		State:                  capability.StateActive,
	}); err != nil {
		t.Fatal(err)
	}

	// Create-result snapshot.
	loc, err := idempotencyruntime.NewResultLocator("preonboarding-create:" + id)
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.ResultStore().SaveCreateResult(ctx, loc, application.PreOnboardingCreateResultSnapshot{
		PreOnboardingRequestID: id,
		PartnerID:              "P1",
		ExpiresAt:              now.Add(time.Hour),
		Status:                 string(domain.StatePendingApproval),
		ETag:                   "etag-post",
		Location:               "/v1/pre-onboarding-requests/" + id,
		CommittedAt:            now,
	}); err != nil {
		t.Fatal(err)
	}

	// Audit staging.
	if err := uow.AuditWriter().StageEvent(ctx, application.AuditEvent{
		Type:                   application.AuditEventSubmitted,
		PreOnboardingRequestID: id,
		PartnerID:              "P1",
		Timestamp:              now,
	}); err != nil {
		t.Fatal(err)
	}
}

// assertTPCommittedSubmissions asserts the authoritative committed
// TemporaryPrincipal record kept its original committed-submission count.
func assertTPCommittedSubmissions(t *testing.T, store *runtime.MemoryStore, tpID string, want int) {
	t.Helper()
	uow, err := store.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer uow.Rollback(context.Background())
	tpRec, ok, err := uow.TemporaryPrincipalStore().Get(context.Background(), tpID)
	if err != nil || !ok {
		t.Fatalf("TP %q missing after failed commit", tpID)
	}
	if tpRec.CommittedSubmissions != want {
		t.Fatalf("CommittedSubmissions = %d, want %d (no partial publication)", tpRec.CommittedSubmissions, want)
	}
}

func TestM56_POST001_CommitResourceIDCollisionPublishesNothing(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	rec := runtime.NewMemoryAuditRecorder()
	store := runtime.NewMemoryStore(rec)

	store.SeedTemporaryPrincipal(&domain.TemporaryPrincipal{
		TemporaryPrincipalID: "tp-post-resid",
		PartnerID:            "P1",
		Status:               domain.TPStatusActive,
		ExpiresAt:            now.Add(time.Hour),
		MaxSubmissions:       5,
		CommittedSubmissions: 0,
	})

	// A committed resource whose ID the staged NEW flow will collide with.
	seeded, err := domain.NewRequest(domain.ID("por-collide"), domain.PartnerID("P1"),
		domain.ClaimedDevice{Hostname: "committed"}, domain.Agent{Platform: "linux", Version: "1"},
		now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	store.SeedRequest(seeded)

	uow, err := store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer uow.Rollback(ctx)
	stageFullNewConcernSet(t, uow, now, "por-collide", "tp-post-resid", capability.VerifierKey("post-key-resid"))

	// The generated resource ID already exists in committed state. The commit
	// must detect the collision in the validation phase and publish nothing.
	err = uow.Commit(application.ContextWithCommitClock(ctx, runtime.NewMockClock(now)))
	if !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("expected ErrDependencyUnavailable on resource-ID collision, got: %v", err)
	}

	// The committed resource must remain untouched (no silent overwrite).
	got, ok := store.GetRequest("por-collide")
	if !ok {
		t.Fatal("committed resource missing after failed commit")
	}
	if got.ResourceVersion() != seeded.ResourceVersion() {
		t.Fatalf("committed resource version changed: %d -> %d", seeded.ResourceVersion(), got.ResourceVersion())
	}
	if store.CountRequests() != 1 {
		t.Fatalf("requests = %d, want 1 (only the seeded committed resource)", store.CountRequests())
	}
	if store.CountRequestAccess() != 0 {
		t.Fatalf("request access verifiers = %d, want 0", store.CountRequestAccess())
	}
	if store.CountCreateResults() != 0 {
		t.Fatalf("create-result snapshots = %d, want 0", store.CountCreateResults())
	}
	if store.CountIdemCommitted() != 0 {
		t.Fatalf("committed idempotency operations = %d, want 0", store.CountIdemCommitted())
	}
	if rec.Count() != 0 {
		t.Fatalf("committed audit events = %d, want 0", rec.Count())
	}
	assertTPCommittedSubmissions(t, store, "tp-post-resid", 0)
}

func TestM56_POST001_CommitVerifierCollisionPublishesNothing(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	rec := runtime.NewMemoryAuditRecorder()
	store := runtime.NewMemoryStore(rec)

	store.SeedTemporaryPrincipal(&domain.TemporaryPrincipal{
		TemporaryPrincipalID: "tp-post-verif",
		PartnerID:            "P1",
		Status:               domain.TPStatusActive,
		ExpiresAt:            now.Add(time.Hour),
		MaxSubmissions:       5,
		CommittedSubmissions: 0,
	})

	key := capability.VerifierKey("post-key-collide")

	// Transaction 1 stages the full NEW concern set while the verifier key is
	// still free.
	uow1, err := store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer uow1.Rollback(ctx)
	stageFullNewConcernSet(t, uow1, now, "por-vcol", "tp-post-verif", key)

	// A concurrent transaction commits the SAME verifier key after transaction
	// 1 staged it. This is exactly the commit-time race the review flagged.
	uow2, err := store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := uow2.RequestAccessWriter().CreateRequestAccess(ctx, key, capability.RequestAccessRecord{
		PreOnboardingRequestID: "por-other",
		ExpiresAt:              now.Add(time.Hour),
		State:                  capability.StateActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := uow2.Commit(application.ContextWithCommitClock(ctx, runtime.NewMockClock(now))); err != nil {
		t.Fatalf("concurrent commit failed: %v", err)
	}

	// Transaction 1 must detect the verifier collision in the validation phase
	// and publish NOTHING — in particular not the staged request, which the
	// old interleaved commit would have published before the collision check.
	err = uow1.Commit(application.ContextWithCommitClock(ctx, runtime.NewMockClock(now)))
	if !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("expected ErrDependencyUnavailable on verifier collision, got: %v", err)
	}

	if store.CountRequests() != 0 {
		t.Fatalf("requests = %d, want 0 (staged request must not be partially published)", store.CountRequests())
	}
	if store.CountRequestAccess() != 1 {
		t.Fatalf("request access verifiers = %d, want 1 (only the concurrent committed record)", store.CountRequestAccess())
	}
	if store.CountCreateResults() != 0 {
		t.Fatalf("create-result snapshots = %d, want 0", store.CountCreateResults())
	}
	if store.CountIdemCommitted() != 0 {
		t.Fatalf("committed idempotency operations = %d, want 0", store.CountIdemCommitted())
	}
	if rec.Count() != 0 {
		t.Fatalf("committed audit events = %d, want 0", rec.Count())
	}
	assertTPCommittedSubmissions(t, store, "tp-post-verif", 0)
}

func TestM56_POST002_TPExpiryReevaluatedAtCommitBoundary(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	rec := runtime.NewMemoryAuditRecorder()
	store := runtime.NewMemoryStore(rec)

	store.SeedTemporaryPrincipal(&domain.TemporaryPrincipal{
		TemporaryPrincipalID: "tp-post-expiry",
		PartnerID:            "P1",
		Status:               domain.TPStatusActive,
		ExpiresAt:            now.Add(30 * time.Minute),
		MaxSubmissions:       5,
		CommittedSubmissions: 0,
	})

	uow, err := store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer uow.Rollback(ctx)
	stageFullNewConcernSet(t, uow, now, "por-expiry", "tp-post-expiry", capability.VerifierKey("post-key-expiry"))

	// The TP was unexpired when the concerns were staged, but the trusted
	// server clock has now crossed the authoritative ExpiresAt. The atomic
	// commit boundary must re-evaluate expiry and fail without publishing.
	commitClock := runtime.NewMockClock(now.Add(31 * time.Minute))
	err = uow.Commit(application.ContextWithCommitClock(ctx, commitClock))
	if !errors.Is(err, application.ErrPartnerNotAuthorized) {
		t.Fatalf("expected ErrPartnerNotAuthorized on commit-boundary expiry, got: %v", err)
	}

	if store.CountRequests() != 0 {
		t.Fatalf("requests = %d, want 0", store.CountRequests())
	}
	if store.CountRequestAccess() != 0 {
		t.Fatalf("request access verifiers = %d, want 0", store.CountRequestAccess())
	}
	if store.CountCreateResults() != 0 {
		t.Fatalf("create-result snapshots = %d, want 0", store.CountCreateResults())
	}
	if store.CountIdemCommitted() != 0 {
		t.Fatalf("committed idempotency operations = %d, want 0", store.CountIdemCommitted())
	}
	if rec.Count() != 0 {
		t.Fatalf("committed audit events = %d, want 0", rec.Count())
	}
	assertTPCommittedSubmissions(t, store, "tp-post-expiry", 0)
}

func TestM56_POST002_TPCommitWithoutTrustedClockFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	rec := runtime.NewMemoryAuditRecorder()
	store := runtime.NewMemoryStore(rec)

	store.SeedTemporaryPrincipal(&domain.TemporaryPrincipal{
		TemporaryPrincipalID: "tp-post-noclock",
		PartnerID:            "P1",
		Status:               domain.TPStatusActive,
		ExpiresAt:            now.Add(time.Hour),
		MaxSubmissions:       5,
		CommittedSubmissions: 0,
	})

	uow, err := store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer uow.Rollback(ctx)
	stageFullNewConcernSet(t, uow, now, "por-noclock", "tp-post-noclock", capability.VerifierKey("post-key-noclock"))

	// Commit WITHOUT the trusted server-controlled clock: the time-sensitive
	// commit precondition cannot be evaluated, so the commit must fail closed
	// and publish nothing rather than substitute uncontrolled wall-clock time.
	err = uow.Commit(ctx)
	if !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("expected ErrDependencyUnavailable when the trusted commit clock is missing, got: %v", err)
	}

	if store.CountRequests() != 0 {
		t.Fatalf("requests = %d, want 0", store.CountRequests())
	}
	if store.CountRequestAccess() != 0 {
		t.Fatalf("request access verifiers = %d, want 0", store.CountRequestAccess())
	}
	if store.CountCreateResults() != 0 {
		t.Fatalf("create-result snapshots = %d, want 0", store.CountCreateResults())
	}
	if store.CountIdemCommitted() != 0 {
		t.Fatalf("committed idempotency operations = %d, want 0", store.CountIdemCommitted())
	}
	if rec.Count() != 0 {
		t.Fatalf("committed audit events = %d, want 0", rec.Count())
	}
	assertTPCommittedSubmissions(t, store, "tp-post-noclock", 0)
}
