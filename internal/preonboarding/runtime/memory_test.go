package runtime_test

import (
	"context"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
)

func TestMemoryStoreSeedAndGet(t *testing.T) {
	recorder := runtime.NewMemoryAuditRecorder()
	store := runtime.NewMemoryStore(recorder)
	now := time.Now()

	req, _ := domain.NewRequest("por-1", "P1", domain.ClaimedDevice{Hostname: "host-1"}, domain.Agent{}, now, now.Add(time.Hour))
	store.SeedRequest(req)

	got, ok := store.GetRequest("por-1")
	if !ok {
		t.Fatal("expected request to be found")
	}
	if got.ID() != "por-1" {
		t.Errorf("ID = %s, want por-1", got.ID())
	}
	if store.CountRequests() != 1 {
		t.Errorf("CountRequests = %d, want 1", store.CountRequests())
	}
}

func TestMemoryUnitOfWorkCommit(t *testing.T) {
	recorder := runtime.NewMemoryAuditRecorder()
	store := runtime.NewMemoryStore(recorder)
	ctx := context.Background()
	now := time.Now()

	uow, err := store.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}

	req, _ := domain.NewRequest("por-10", "P1", domain.ClaimedDevice{Hostname: "host-10"}, domain.Agent{}, now, now.Add(time.Hour))
	if err := uow.Repository().Save(ctx, req); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if err := uow.AuditWriter().StageEvent(ctx, application.AuditEvent{
		Type:                   application.AuditEventApproved,
		ActorPrincipal:         "admin-1",
		PreOnboardingRequestID: "por-10",
		PartnerID:              "P1",
		Timestamp:              now,
	}); err != nil {
		t.Fatalf("StageEvent failed: %v", err)
	}

	// Before commit: unobservable in store or recorder
	if _, ok := store.GetRequest("por-10"); ok {
		t.Error("uncommitted request should not be visible in store")
	}
	if recorder.Count() != 0 {
		t.Errorf("uncommitted audit events = %d, want 0", recorder.Count())
	}

	// Commit
	if err := uow.Commit(ctx); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// After commit: visible
	if _, ok := store.GetRequest("por-10"); !ok {
		t.Error("committed request must be visible in store")
	}
	if recorder.Count() != 1 {
		t.Errorf("committed audit events = %d, want 1", recorder.Count())
	}
}

func TestMemoryUnitOfWorkRollback(t *testing.T) {
	recorder := runtime.NewMemoryAuditRecorder()
	store := runtime.NewMemoryStore(recorder)
	ctx := context.Background()
	now := time.Now()

	uow, err := store.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin failed: %v", err)
	}

	req, _ := domain.NewRequest("por-20", "P1", domain.ClaimedDevice{Hostname: "host-20"}, domain.Agent{}, now, now.Add(time.Hour))
	_ = uow.Repository().Save(ctx, req)
	_ = uow.AuditWriter().StageEvent(ctx, application.AuditEvent{
		Type:                   application.AuditEventApproved,
		ActorPrincipal:         "admin-1",
		PreOnboardingRequestID: "por-20",
		PartnerID:              "P1",
		Timestamp:              now,
	})

	// Rollback
	if err := uow.Rollback(ctx); err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	// Discarded completely
	if _, ok := store.GetRequest("por-20"); ok {
		t.Error("rolled back request must not exist in store")
	}
	if recorder.Count() != 0 {
		t.Errorf("audit events after rollback = %d, want 0", recorder.Count())
	}
}
