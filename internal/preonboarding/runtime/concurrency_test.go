package runtime_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
)

func TestHighContentionConcurrentApprovals(t *testing.T) {
	now := time.Now()
	ctx := context.Background()
	admin := application.AdminPrincipal{Issuer: "https://auth.example", Subject: "admin-1"}

	rec := runtime.NewMemoryAuditRecorder()
	st := runtime.NewMemoryStore(rec)
	clk := runtime.NewMockClock(now)
	auth := runtime.NewMemoryPartnerAuthorityChecker()
	elig := runtime.NewMemoryPartnerEligibilityChecker()
	auth.GrantPartnerAuthority(admin, "P1")

	svc, err := application.NewService(application.ServiceConfig{
		UOWManager:         st,
		Clock:              clk,
		DeviceAllocator:    runtime.DefaultDeviceAllocator{},
		PartnerAuth:        auth,
		PartnerEligibility: elig,
		RetentionPolicy:    application.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
	})
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	req, _ := domain.NewRequest("por-conc-1", "P1", domain.ClaimedDevice{Hostname: "h1"}, domain.Agent{}, now, now.Add(time.Hour))
	st.SeedRequest(req)
	etag := domain.ComputeETag(req, now)

	concurrency := 20
	var wg sync.WaitGroup
	var successCount int64
	var preconditionFailedCount int64
	var stateConflictCount int64
	var otherErrCount int64

	startSignal := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		key := fmt.Sprintf("idem-key-approve-%03d", i)
		go func(k string) {
			defer wg.Done()
			<-startSignal
			res, err := svc.Approve(ctx, admin, application.ApproveCommand{
				ID:             "por-conc-1",
				IfMatch:        etag,
				IdempotencyKey: k,
				ExpectedStatus: "PENDING_APPROVAL",
				Reason:         "concurrent test",
			})
			if err == nil && res.Status == domain.StateEnrollmentReady {
				atomic.AddInt64(&successCount, 1)
			} else if errors.Is(err, application.ErrPreconditionFailed) {
				atomic.AddInt64(&preconditionFailedCount, 1)
			} else if errors.Is(err, application.ErrStateConflict) {
				atomic.AddInt64(&stateConflictCount, 1)
			} else {
				atomic.AddInt64(&otherErrCount, 1)
			}
		}(key)
	}

	close(startSignal)
	wg.Wait()

	if successCount != 1 {
		t.Fatalf("successCount = %d, want exactly 1 winner", successCount)
	}
	if preconditionFailedCount+stateConflictCount != int64(concurrency-1) {
		t.Errorf("preconditionFailed (%d) + stateConflict (%d) = %d, want %d losers",
			preconditionFailedCount, stateConflictCount, preconditionFailedCount+stateConflictCount, concurrency-1)
	}
	if otherErrCount != 0 {
		t.Errorf("otherErrCount = %d, want 0", otherErrCount)
	}

	// Verify authoritative aggregate status and exactly 1 audit event
	finalReq, _ := st.GetRequest("por-conc-1")
	if finalReq.Status() != domain.StateEnrollmentReady {
		t.Errorf("final status = %s, want ENROLLMENT_READY", finalReq.Status())
	}
	if finalReq.ResourceVersion() != 2 {
		t.Errorf("final resourceVersion = %d, want 2", finalReq.ResourceVersion())
	}
	if rec.CountByType(application.AuditEventApproved) != 1 {
		t.Errorf("AuditEventApproved count = %d, want 1", rec.CountByType(application.AuditEventApproved))
	}
}

func TestHighContentionConcurrentDifferentKeyApproveVsReject(t *testing.T) {
	now := time.Now()
	ctx := context.Background()
	admin := application.AdminPrincipal{Issuer: "https://auth.example", Subject: "admin-1"}

	rec := runtime.NewMemoryAuditRecorder()
	st := runtime.NewMemoryStore(rec)
	clk := runtime.NewMockClock(now)
	auth := runtime.NewMemoryPartnerAuthorityChecker()
	elig := runtime.NewMemoryPartnerEligibilityChecker()
	auth.GrantPartnerAuthority(admin, "P1")

	svc, err := application.NewService(application.ServiceConfig{
		UOWManager:         st,
		Clock:              clk,
		DeviceAllocator:    runtime.DefaultDeviceAllocator{},
		PartnerAuth:        auth,
		PartnerEligibility: elig,
		RetentionPolicy:    application.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
	})
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	req, _ := domain.NewRequest("por-conc-race", "P1", domain.ClaimedDevice{Hostname: "h1"}, domain.Agent{}, now, now.Add(time.Hour))
	st.SeedRequest(req)
	etag := domain.ComputeETag(req, now)

	concurrency := 20
	var wg sync.WaitGroup
	var approveSuccess int64
	var rejectSuccess int64
	var loserCount int64

	startSignal := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		idx := i
		key := fmt.Sprintf("idem-key-race-%03d", idx)
		go func(k string, isApprove bool) {
			defer wg.Done()
			<-startSignal
			if isApprove {
				res, err := svc.Approve(ctx, admin, application.ApproveCommand{
					ID:             "por-conc-race",
					IfMatch:        etag,
					IdempotencyKey: k,
					ExpectedStatus: "PENDING_APPROVAL",
					Reason:         "race approve",
				})
				if err == nil && res.Status == domain.StateEnrollmentReady {
					atomic.AddInt64(&approveSuccess, 1)
				} else if errors.Is(err, application.ErrPreconditionFailed) || errors.Is(err, application.ErrStateConflict) {
					atomic.AddInt64(&loserCount, 1)
				}
			} else {
				res, err := svc.Reject(ctx, admin, application.RejectCommand{
					ID:             "por-conc-race",
					IfMatch:        etag,
					IdempotencyKey: k,
					ExpectedStatus: "PENDING_APPROVAL",
					Reason:         "race reject",
				})
				if err == nil && res.Request.Status() == domain.StateRejected {
					atomic.AddInt64(&rejectSuccess, 1)
				} else if errors.Is(err, application.ErrPreconditionFailed) || errors.Is(err, application.ErrStateConflict) {
					atomic.AddInt64(&loserCount, 1)
				}
			}
		}(key, idx%2 == 0)
	}

	close(startSignal)
	wg.Wait()

	totalWinners := approveSuccess + rejectSuccess
	if totalWinners != 1 {
		t.Fatalf("total winners = %d (approve=%d, reject=%d), want exactly 1", totalWinners, approveSuccess, rejectSuccess)
	}
	if loserCount != int64(concurrency-1) {
		t.Errorf("loserCount = %d, want %d", loserCount, concurrency-1)
	}
}

func TestHighContentionSameKeyConcurrentReplay(t *testing.T) {
	now := time.Now()
	ctx := context.Background()
	admin := application.AdminPrincipal{Issuer: "https://auth.example", Subject: "admin-1"}

	rec := runtime.NewMemoryAuditRecorder()
	st := runtime.NewMemoryStore(rec)
	clk := runtime.NewMockClock(now)
	auth := runtime.NewMemoryPartnerAuthorityChecker()
	elig := runtime.NewMemoryPartnerEligibilityChecker()
	auth.GrantPartnerAuthority(admin, "P1")

	svc, err := application.NewService(application.ServiceConfig{
		UOWManager:         st,
		Clock:              clk,
		DeviceAllocator:    runtime.DefaultDeviceAllocator{},
		PartnerAuth:        auth,
		PartnerEligibility: elig,
		RetentionPolicy:    application.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
	})
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	req, _ := domain.NewRequest("por-same-key", "P1", domain.ClaimedDevice{Hostname: "h1"}, domain.Agent{}, now, now.Add(time.Hour))
	st.SeedRequest(req)
	etag := domain.ComputeETag(req, now)

	// First execution executes NEW
	sameKey := "idem-key-same-replay-001"
	res1, err := svc.Approve(ctx, admin, application.ApproveCommand{
		ID:             "por-same-key",
		IfMatch:        etag,
		IdempotencyKey: sameKey,
		ExpectedStatus: "PENDING_APPROVAL",
		Reason:         "initial",
	})
	if err != nil || res1.IsReplay {
		t.Fatalf("initial approve failed or was replay: err=%v, res=%+v", err, res1)
	}

	// 20 concurrent goroutines with SAME key race to replay
	concurrency := 20
	var wg sync.WaitGroup
	var replaySuccess int64

	startSignal := make(chan struct{})
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startSignal
			res, err := svc.Approve(ctx, admin, application.ApproveCommand{
				ID:             "por-same-key",
				IfMatch:        etag,
				IdempotencyKey: sameKey,
				ExpectedStatus: "PENDING_APPROVAL",
				Reason:         "initial",
			})
			if err == nil && res.IsReplay && res.DeviceID == res1.DeviceID && res.ETag == res1.ETag {
				atomic.AddInt64(&replaySuccess, 1)
			}
		}()
	}

	close(startSignal)
	wg.Wait()

	if replaySuccess != int64(concurrency) {
		t.Fatalf("replaySuccess = %d, want %d", replaySuccess, concurrency)
	}
	if rec.CountByType(application.AuditEventApproved) != 1 {
		t.Errorf("AuditEventApproved count = %d, want 1", rec.CountByType(application.AuditEventApproved))
	}
}
