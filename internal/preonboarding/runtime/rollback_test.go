package runtime_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
)

// InjectedFailureStore wraps MemoryStore to inject failure points in UoW operations.
type InjectedFailureStore struct {
	*runtime.MemoryStore
	injectCommitErr error
}

func (s *InjectedFailureStore) Begin(ctx context.Context) (application.UnitOfWork, error) {
	uow, err := s.MemoryStore.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &injectedFailureUOW{UnitOfWork: uow, store: s}, nil
}

type injectedFailureUOW struct {
	application.UnitOfWork
	store *InjectedFailureStore
}

func (u *injectedFailureUOW) Commit(ctx context.Context) error {
	if u.store.injectCommitErr != nil {
		return u.store.injectCommitErr
	}
	return u.UnitOfWork.Commit(ctx)
}

// failingAllocator fails on device allocation.
type failingAllocator struct{}

func (failingAllocator) AllocateDeviceID(ctx context.Context, req *domain.PreOnboardingRequest) (string, error) {
	return "", errors.New("allocator failure: pool exhausted")
}

func TestAtomicRollbackOnInjectedFailures(t *testing.T) {
	now := time.Now()
	ctx := context.Background()
	admin := application.AdminPrincipal{Issuer: "https://auth.example", Subject: "admin-1"}

	t.Run("FailureOnUOWCommitLeavesZeroPartialEffectsAndAllowsCleanRetry", func(t *testing.T) {
		rec := runtime.NewMemoryAuditRecorder()
		baseStore := runtime.NewMemoryStore(rec)
		injStore := &InjectedFailureStore{MemoryStore: baseStore}
		clk := runtime.NewMockClock(now)
		auth := runtime.NewMemoryPartnerAuthorityChecker()
		elig := runtime.NewMemoryPartnerEligibilityChecker()
		auth.GrantPartnerAuthority(admin, "P1")

		svc, err := application.NewService(application.ServiceConfig{
			UOWManager:         injStore,
			Clock:              clk,
			DeviceAllocator:    runtime.DefaultDeviceAllocator{},
			PartnerAuth:        auth,
			PartnerEligibility: elig,
			RetentionPolicy:    application.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
		})
		if err != nil {
			t.Fatalf("NewService failed: %v", err)
		}

		req, _ := domain.NewRequest("por-rb-1", "P1", domain.ClaimedDevice{Hostname: "h1"}, domain.Agent{}, now, now.Add(time.Hour))
		injStore.SeedRequest(req)
		etag := domain.ComputeETag(req, now)

		// Inject commit error
		injStore.injectCommitErr = errors.New("injected database commit error")

		_, err = svc.Approve(ctx, admin, application.ApproveCommand{
			ID:             "por-rb-1",
			IfMatch:        etag,
			IdempotencyKey: "idem-key-atomic-001",
			ExpectedStatus: "PENDING_APPROVAL",
			Reason:         "attempt 1",
		})
		if err == nil {
			t.Fatal("expected failure on injected commit error")
		}

		// Verify zero partial state left:
		// 1. Stored request untouched in PENDING_APPROVAL with resourceVersion = 1
		reqAfter, _ := injStore.GetRequest("por-rb-1")
		if reqAfter.Status() != domain.StatePendingApproval {
			t.Errorf("status = %s, want PENDING_APPROVAL", reqAfter.Status())
		}
		if reqAfter.ResourceVersion() != 1 {
			t.Errorf("resourceVersion = %d, want 1", reqAfter.ResourceVersion())
		}
		if reqAfter.DeviceID() != nil {
			t.Errorf("deviceID = %v, want nil", reqAfter.DeviceID())
		}

		// 2. Audit events untouched (0 recorded)
		if rec.Count() != 0 {
			t.Errorf("recorded audit events = %d, want 0", rec.Count())
		}

		// 3. Clear injected error -> immediate retry with SAME idempotency key succeeds cleanly
		injStore.injectCommitErr = nil
		resRetry, err := svc.Approve(ctx, admin, application.ApproveCommand{
			ID:             "por-rb-1",
			IfMatch:        etag,
			IdempotencyKey: "idem-key-atomic-001",
			ExpectedStatus: "PENDING_APPROVAL",
			Reason:         "attempt 1",
		})
		if err != nil {
			t.Fatalf("retry after rollback failed: %v", err)
		}
		if resRetry.Status != domain.StateEnrollmentReady {
			t.Errorf("status = %s, want ENROLLMENT_READY", resRetry.Status)
		}
		if resRetry.IsReplay {
			t.Fatal("resRetry.IsReplay = true, want false (clean retry should be NEW)")
		}
		if rec.CountByType(application.AuditEventApproved) != 1 {
			t.Errorf("audit events after retry = %d, want 1", rec.CountByType(application.AuditEventApproved))
		}
	})

	t.Run("FailureOnDeviceAllocatorLeavesZeroPartialEffects", func(t *testing.T) {
		rec := runtime.NewMemoryAuditRecorder()
		store := runtime.NewMemoryStore(rec)
		clk := runtime.NewMockClock(now)
		auth := runtime.NewMemoryPartnerAuthorityChecker()
		elig := runtime.NewMemoryPartnerEligibilityChecker()
		auth.GrantPartnerAuthority(admin, "P1")

		svc, err := application.NewService(application.ServiceConfig{
			UOWManager:         store,
			Clock:              clk,
			DeviceAllocator:    failingAllocator{},
			PartnerAuth:        auth,
			PartnerEligibility: elig,
			RetentionPolicy:    application.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
		})
		if err != nil {
			t.Fatalf("NewService failed: %v", err)
		}

		req, _ := domain.NewRequest("por-rb-2", "P1", domain.ClaimedDevice{Hostname: "h2"}, domain.Agent{}, now, now.Add(time.Hour))
		store.SeedRequest(req)
		etag := domain.ComputeETag(req, now)

		_, err = svc.Approve(ctx, admin, application.ApproveCommand{
			ID:             "por-rb-2",
			IfMatch:        etag,
			IdempotencyKey: "idem-key-alloc-fail",
			ExpectedStatus: "PENDING_APPROVAL",
			Reason:         "attempt alloc",
		})
		if err == nil {
			t.Fatal("expected failure on failing allocator")
		}

		// Verify zero partial state left
		reqAfter, _ := store.GetRequest("por-rb-2")
		if reqAfter.Status() != domain.StatePendingApproval {
			t.Errorf("status = %s, want PENDING_APPROVAL", reqAfter.Status())
		}
		if reqAfter.DeviceID() != nil {
			t.Errorf("deviceID = %v, want nil", reqAfter.DeviceID())
		}
		if rec.Count() != 0 {
			t.Errorf("audit events = %d, want 0", rec.Count())
		}
	})
}

// hookableUOWManager allows intercepting Commit to simulate deterministic interleavings.
type hookableUOWManager struct {
	baseStore        *runtime.MemoryStore
	beforeCommitHook func()
}

func (m *hookableUOWManager) Begin(ctx context.Context) (application.UnitOfWork, error) {
	uow, err := m.baseStore.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &hookableUOW{UnitOfWork: uow, hook: m.beforeCommitHook}, nil
}

type hookableUOW struct {
	application.UnitOfWork
	hook func()
}

func (u *hookableUOW) Commit(ctx context.Context) error {
	if u.hook != nil {
		u.hook()
	}
	return u.UnitOfWork.Commit(ctx)
}

func TestDeterministicOptimisticConflictRollback(t *testing.T) {
	now := time.Now()
	ctx := context.Background()
	admin := application.AdminPrincipal{Issuer: "https://auth.example", Subject: "admin-1"}

	rec := runtime.NewMemoryAuditRecorder()
	store := runtime.NewMemoryStore(rec)
	clk := runtime.NewMockClock(now)
	auth := runtime.NewMemoryPartnerAuthorityChecker()
	elig := runtime.NewMemoryPartnerEligibilityChecker()
	auth.GrantPartnerAuthority(admin, "P1")

	// Seed resource at version 1 with strong ETag E
	req, _ := domain.NewRequest("por-determ-1", "P1", domain.ClaimedDevice{Hostname: "h-determ"}, domain.Agent{Platform: "windows", Version: "1.0"}, now, now.Add(time.Hour))
	store.SeedRequest(req)
	strongETag := domain.ComputeETag(req, now)

	// SvcA is standard service (Request A)
	svcA, err := application.NewService(application.ServiceConfig{
		UOWManager:         store,
		Clock:              clk,
		DeviceAllocator:    runtime.DefaultDeviceAllocator{},
		PartnerAuth:        auth,
		PartnerEligibility: elig,
		RetentionPolicy:    application.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
	})
	if err != nil {
		t.Fatalf("NewService svcA failed: %v", err)
	}

	// SvcB uses hookable UoW manager (Request B)
	hookMgr := &hookableUOWManager{baseStore: store}
	svcB, err := application.NewService(application.ServiceConfig{
		UOWManager:         hookMgr,
		Clock:              clk,
		DeviceAllocator:    runtime.DefaultDeviceAllocator{},
		PartnerAuth:        auth,
		PartnerEligibility: elig,
		RetentionPolicy:    application.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
	})
	if err != nil {
		t.Fatalf("NewService svcB failed: %v", err)
	}

	// Set hook on B: right before B commits, execute A to completion!
	var resA application.ApproveResult
	var errA error
	hookMgr.beforeCommitHook = func() {
		// A executes with Idempotency-Key A and If-Match E
		resA, errA = svcA.Approve(ctx, admin, application.ApproveCommand{
			ID:             "por-determ-1",
			IfMatch:        strongETag,
			IdempotencyKey: "idem-key-winner-A",
			ExpectedStatus: "PENDING_APPROVAL",
			Reason:         "winner A",
		})
	}

	// B executes with Idempotency-Key B and the same initial If-Match E
	resB, errB := svcB.Approve(ctx, admin, application.ApproveCommand{
		ID:             "por-determ-1",
		IfMatch:        strongETag,
		IdempotencyKey: "idem-key-loser-B",
		ExpectedStatus: "PENDING_APPROVAL",
		Reason:         "loser B",
	})

	// 1. A succeeded
	if errA != nil {
		t.Fatalf("Winner A failed: %v", errA)
	}
	if resA.Status != domain.StateEnrollmentReady {
		t.Fatalf("Winner A status = %v, want ENROLLMENT_READY", resA.Status)
	}

	// 2. B lost optimistic check and returned exactly ErrPreconditionFailed (412)
	if !errors.Is(errB, application.ErrPreconditionFailed) {
		t.Fatalf("Loser B error = %v, want ErrPreconditionFailed (412)", errB)
	}
	if resB.Status != "" {
		t.Fatalf("Loser B returned non-empty status: %v", resB.Status)
	}

	// 3. Verify B's ACTIVE reservation is completely gone (rolled back)
	reqMutated, ok := store.GetRequest("por-determ-1")
	if !ok {
		t.Fatal("mutated request not found")
	}
	newETag := domain.ComputeETag(reqMutated, now)

	// Retry using Key B and refreshed newETag:
	// Because request is already ENROLLMENT_READY, Approve returns ErrStateConflict (409).
	// It does NOT return IN_PROGRESS or a conflict on the token!
	_, errBRetry := svcA.Approve(ctx, admin, application.ApproveCommand{
		ID:             "por-determ-1",
		IfMatch:        newETag,
		IdempotencyKey: "idem-key-loser-B",
		ExpectedStatus: "PENDING_APPROVAL",
		Reason:         "retry B",
	})
	if !errors.Is(errBRetry, application.ErrStateConflict) {
		t.Fatalf("B retry error = %v, want ErrStateConflict (409)", errBRetry)
	}

	// 4. Verify no partial artifacts from B:
	// Exactly 1 audit event from A, 0 from B
	if rec.Count() != 1 {
		t.Fatalf("audit event count = %d, want 1", rec.Count())
	}
	if rec.CountByType(application.AuditEventApproved) != 1 {
		t.Fatalf("AuditEventApproved count = %d, want 1", rec.CountByType(application.AuditEventApproved))
	}
}
