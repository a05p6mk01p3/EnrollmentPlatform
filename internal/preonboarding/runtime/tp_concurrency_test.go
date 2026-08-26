package runtime_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/replaycapsule"
)

type syncUOW struct {
	application.UnitOfWork
	beforeCommit func()
}

func (s *syncUOW) Commit(ctx context.Context) error {
	if s.beforeCommit != nil {
		s.beforeCommit()
	}
	return s.UnitOfWork.Commit(ctx)
}

type syncUOWManager struct {
	application.UnitOfWorkManager
	onBegin func(application.UnitOfWork) application.UnitOfWork
}

func (m *syncUOWManager) Begin(ctx context.Context) (application.UnitOfWork, error) {
	uow, err := m.UnitOfWorkManager.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if m.onBegin != nil {
		return m.onBegin(uow), nil
	}
	return uow, nil
}

func TestTP_B2_LifecycleReplay(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	store := runtime.NewMemoryStore(runtime.NewMemoryAuditRecorder())
	clock := runtime.NewMockClock(now)
	verifier, err := capability.NewHMACVerifier([]byte("capability-verifier-key-m56a-32bytes!"))
	if err != nil {
		t.Fatal(err)
	}
	protector, err := replaycapsule.NewAEADProtector([]byte("replay-capsule-protector-key-32!"), "m56a", func() time.Time { return now.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	tokens := &lifecycleCountedToken{}
	ids := &seqID{}

	svc, err := application.NewService(application.ServiceConfig{
		UOWManager:                 store,
		Clock:                      clock,
		DeviceAllocator:            runtime.DefaultDeviceAllocator{},
		PartnerAuth:                runtime.NewMemoryPartnerAuthorityChecker(),
		PartnerEligibility:         runtime.NewMemoryPartnerEligibilityChecker(),
		RetentionPolicy:            application.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
		RequestAccessTokenLifetime: application.StaticRequestAccessTokenLifetime{Duration: 30 * time.Minute},
		ReplayCapsulePolicy:        application.StaticReplayCapsuleRetentionPolicy{Duration: time.Hour},
		Create: &application.CreateDependencies{
			IDGenerator:    ids,
			TokenGenerator: tokens,
			Verifier:       verifier,
			Protector:      protector,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Seed TP
	tpID := "tp-replay-zero"
	tp := &domain.TemporaryPrincipal{
		TemporaryPrincipalID: tpID,
		PartnerID:            "P1",
		Status:               domain.TPStatusActive,
		ExpiresAt:            now.Add(time.Hour),
		MaxSubmissions:       1,
		CommittedSubmissions: 0,
	}
	store.SeedTemporaryPrincipal(tp)

	cmd1 := application.CreateOriginatorCommand{
		CreateCommand: application.CreateCommand{
			PartnerID:     "P1",
			ClaimedDevice: domain.ClaimedDevice{Hostname: "h-replay-1"},
			Agent:         domain.Agent{Platform: "linux", Version: "1"},
		},
		CredentialKind:    authpolicy.CredentialKindTemporaryPrincipalToken,
		CredentialBinding: tpID,
		IdempotencyKey:    "idem-tp-replay-zero-key",
		CorrelationID:     "corr-replay-1",
	}

	// 1. Issue NEW
	res1, err := svc.CreateOriginator(context.Background(), cmd1)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}

	// Check CommittedSubmissions is 1
	uow, _ := store.Begin(context.Background())
	tpRec, _, _ := uow.TemporaryPrincipalStore().Get(context.Background(), tpID)
	uow.Rollback(context.Background())
	if tpRec.CommittedSubmissions != 1 {
		t.Fatalf("expected CommittedSubmissions to be 1, got %d", tpRec.CommittedSubmissions)
	}

	// 2. Replay with zero quota remaining
	cmd2 := cmd1
	cmd2.CorrelationID = "corr-replay-2"
	res2, err := svc.CreateOriginator(context.Background(), cmd2)
	if err != nil {
		t.Fatalf("replay failed: %v", err)
	}
	if !res2.Replay {
		t.Fatal("expected REPLAY, got NEW")
	}
	if res2.RequestAccessToken != res1.RequestAccessToken {
		t.Fatal("token mismatch on replay")
	}

	// Verify quota remains 1
	uow, _ = store.Begin(context.Background())
	tpRec, _, _ = uow.TemporaryPrincipalStore().Get(context.Background(), tpID)
	uow.Rollback(context.Background())
	if tpRec.CommittedSubmissions != 1 {
		t.Fatalf("expected CommittedSubmissions to remain 1, got %d", tpRec.CommittedSubmissions)
	}

	// 3. Disabled TP cannot use prior replay
	tp.Status = domain.TPStatusDisabled
	store.SeedTemporaryPrincipal(tp)

	_, err = svc.CreateOriginator(context.Background(), cmd2)
	if !errors.Is(err, application.ErrPartnerNotAuthorized) {
		t.Fatalf("expected ErrPartnerNotAuthorized on disabled TP replay, got: %v", err)
	}

	// 4. Expired TP cannot use prior replay
	tp.Status = domain.TPStatusActive
	tp.ExpiresAt = now.Add(-time.Hour)
	store.SeedTemporaryPrincipal(tp)

	_, err = svc.CreateOriginator(context.Background(), cmd2)
	if !errors.Is(err, application.ErrPartnerNotAuthorized) {
		t.Fatalf("expected ErrPartnerNotAuthorized on expired TP replay, got: %v", err)
	}
}

func TestTP_B2_IdentityIsolation(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	store := runtime.NewMemoryStore(runtime.NewMemoryAuditRecorder())
	clock := runtime.NewMockClock(now)
	verifier, err := capability.NewHMACVerifier([]byte("capability-verifier-key-m56a-32bytes!"))
	if err != nil {
		t.Fatal(err)
	}
	protector, err := replaycapsule.NewAEADProtector([]byte("replay-capsule-protector-key-32!"), "m56a", func() time.Time { return now.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	tokens := &lifecycleCountedToken{}
	ids := &seqID{}

	svc, err := application.NewService(application.ServiceConfig{
		UOWManager:                 store,
		Clock:                      clock,
		DeviceAllocator:            runtime.DefaultDeviceAllocator{},
		PartnerAuth:                runtime.NewMemoryPartnerAuthorityChecker(),
		PartnerEligibility:         runtime.NewMemoryPartnerEligibilityChecker(),
		RetentionPolicy:            application.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
		RequestAccessTokenLifetime: application.StaticRequestAccessTokenLifetime{Duration: 30 * time.Minute},
		ReplayCapsulePolicy:        application.StaticReplayCapsuleRetentionPolicy{Duration: time.Hour},
		Create: &application.CreateDependencies{
			IDGenerator:    ids,
			TokenGenerator: tokens,
			Verifier:       verifier,
			Protector:      protector,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Seed TP-A and TP-B
	tpA := &domain.TemporaryPrincipal{
		TemporaryPrincipalID: "tp-A",
		PartnerID:            "P1",
		Status:               domain.TPStatusActive,
		ExpiresAt:            now.Add(time.Hour),
		MaxSubmissions:       1,
		CommittedSubmissions: 0,
	}
	store.SeedTemporaryPrincipal(tpA)

	tpB := &domain.TemporaryPrincipal{
		TemporaryPrincipalID: "tp-B",
		PartnerID:            "P1",
		Status:               domain.TPStatusActive,
		ExpiresAt:            now.Add(time.Hour),
		MaxSubmissions:       1,
		CommittedSubmissions: 0,
	}
	store.SeedTemporaryPrincipal(tpB)

	// TP-A NEW
	cmdA := application.CreateOriginatorCommand{
		CreateCommand: application.CreateCommand{
			PartnerID:     "P1",
			ClaimedDevice: domain.ClaimedDevice{Hostname: "h-iso"},
			Agent:         domain.Agent{Platform: "linux", Version: "1"},
		},
		CredentialKind:    authpolicy.CredentialKindTemporaryPrincipalToken,
		CredentialBinding: "tp-A",
		IdempotencyKey:    "idem-cross-replay-key",
		CorrelationID:     "corr-tp-A",
	}

	resA, err := svc.CreateOriginator(context.Background(), cmdA)
	if err != nil {
		t.Fatal(err)
	}

	// TP-B NEW (with same key and body)
	cmdB := cmdA
	cmdB.CredentialBinding = "tp-B"
	cmdB.CorrelationID = "corr-tp-B"

	resB, err := svc.CreateOriginator(context.Background(), cmdB)
	if err != nil {
		t.Fatal(err)
	}

	if resB.Replay {
		t.Fatal("expected TP-B request to be NEW, not replay")
	}
	if resB.Snapshot.PreOnboardingRequestID == resA.Snapshot.PreOnboardingRequestID {
		t.Fatal("expected different request IDs")
	}

	// HumanOIDC with same key and body
	cmdHuman := cmdA
	cmdHuman.CredentialKind = authpolicy.CredentialKindHumanOIDC
	cmdHuman.CredentialBinding = "issuer|subject"
	cmdHuman.CorrelationID = "corr-human"

	resHuman, err := svc.CreateOriginator(context.Background(), cmdHuman)
	if err != nil {
		t.Fatal(err)
	}

	if resHuman.Replay {
		t.Fatal("expected HumanOIDC request to be NEW, not replay")
	}
}

func TestTP_B2_Conflict_and_InProgress(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	store := runtime.NewMemoryStore(runtime.NewMemoryAuditRecorder())
	clock := runtime.NewMockClock(now)
	verifier, err := capability.NewHMACVerifier([]byte("capability-verifier-key-m56a-32bytes!"))
	if err != nil {
		t.Fatal(err)
	}
	protector, err := replaycapsule.NewAEADProtector([]byte("replay-capsule-protector-key-32!"), "m56a", func() time.Time { return now.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	tokens := &lifecycleCountedToken{}
	ids := &seqID{}

	svc, err := application.NewService(application.ServiceConfig{
		UOWManager:                 store,
		Clock:                      clock,
		DeviceAllocator:            runtime.DefaultDeviceAllocator{},
		PartnerAuth:                runtime.NewMemoryPartnerAuthorityChecker(),
		PartnerEligibility:         runtime.NewMemoryPartnerEligibilityChecker(),
		RetentionPolicy:            application.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
		RequestAccessTokenLifetime: application.StaticRequestAccessTokenLifetime{Duration: 30 * time.Minute},
		ReplayCapsulePolicy:        application.StaticReplayCapsuleRetentionPolicy{Duration: time.Hour},
		Create: &application.CreateDependencies{
			IDGenerator:    ids,
			TokenGenerator: tokens,
			Verifier:       verifier,
			Protector:      protector,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	tpID := "tp-conflict"
	tp := &domain.TemporaryPrincipal{
		TemporaryPrincipalID: tpID,
		PartnerID:            "P1",
		Status:               domain.TPStatusActive,
		ExpiresAt:            now.Add(time.Hour),
		MaxSubmissions:       2,
		CommittedSubmissions: 0,
	}
	store.SeedTemporaryPrincipal(tp)

	cmd := application.CreateOriginatorCommand{
		CreateCommand: application.CreateCommand{
			PartnerID:     "P1",
			ClaimedDevice: domain.ClaimedDevice{Hostname: "h-conf-1"},
			Agent:         domain.Agent{Platform: "linux", Version: "1"},
		},
		CredentialKind:    authpolicy.CredentialKindTemporaryPrincipalToken,
		CredentialBinding: tpID,
		IdempotencyKey:    "idem-tp-conflict-key",
		CorrelationID:     "corr-1",
	}

	// 1. Success NEW
	_, err = svc.CreateOriginator(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Conflict (different fingerprint)
	cmd2 := cmd
	cmd2.ClaimedDevice.Hostname = "h-conf-2"
	_, err = svc.CreateOriginator(context.Background(), cmd2)
	if !errors.Is(err, application.ErrIdempotencyConflict) {
		t.Fatalf("expected ErrIdempotencyConflict, got: %v", err)
	}

	// Quota remains 1
	uow, _ := store.Begin(context.Background())
	tpRec, _, _ := uow.TemporaryPrincipalStore().Get(context.Background(), tpID)
	uow.Rollback(context.Background())
	if tpRec.CommittedSubmissions != 1 {
		t.Fatalf("expected CommittedSubmissions to remain 1, got %d", tpRec.CommittedSubmissions)
	}

	// 3. In Progress
	// We can run two concurrent requests with the same key.
	// SinceChi route matching is not used here, we block in UoW commit to keep one active.
	blockCommit := make(chan struct{})
	doneCommit := make(chan struct{})

	go func() {
		uowMgr := &syncUOWManager{
			UnitOfWorkManager: store,
			onBegin: func(uow application.UnitOfWork) application.UnitOfWork {
				return &syncUOW{
					UnitOfWork: uow,
					beforeCommit: func() {
						close(doneCommit)
						<-blockCommit
					},
				}
			},
		}
		syncSvc, _ := application.NewService(application.ServiceConfig{
			UOWManager:                 uowMgr,
			Clock:                      clock,
			DeviceAllocator:            runtime.DefaultDeviceAllocator{},
			PartnerAuth:                runtime.NewMemoryPartnerAuthorityChecker(),
			PartnerEligibility:         runtime.NewMemoryPartnerEligibilityChecker(),
			RetentionPolicy:            application.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
			RequestAccessTokenLifetime: application.StaticRequestAccessTokenLifetime{Duration: 30 * time.Minute},
			ReplayCapsulePolicy:        application.StaticReplayCapsuleRetentionPolicy{Duration: time.Hour},
			Create: &application.CreateDependencies{
				IDGenerator:    ids,
				TokenGenerator: tokens,
				Verifier:       verifier,
				Protector:      protector,
			},
		})
		cmd3 := cmd
		cmd3.IdempotencyKey = "idem-tp-in-progress"
		syncSvc.CreateOriginator(context.Background(), cmd3)
	}()

	<-doneCommit

	// Now try to run another request with the same key
	cmd4 := cmd
	cmd4.IdempotencyKey = "idem-tp-in-progress"
	_, err = svc.CreateOriginator(context.Background(), cmd4)
	if err == nil || err.Error() != "application: operation in progress: create reservation active" {
		t.Fatalf("expected InProgressError, got: %v", err)
	}

	close(blockCommit)

	// Quota remains 2 (1 from successful cmd, 1 from cmd3 that commits)
	time.Sleep(50 * time.Millisecond) // let sync goroutine finish commit
	uow, _ = store.Begin(context.Background())
	tpRec, _, _ = uow.TemporaryPrincipalStore().Get(context.Background(), tpID)
	uow.Rollback(context.Background())
	if tpRec.CommittedSubmissions != 2 {
		t.Fatalf("expected CommittedSubmissions to be 2, got %d", tpRec.CommittedSubmissions)
	}
}

func TestTP_B2_Concurrency_FinalSlot(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	recorder := runtime.NewMemoryAuditRecorder()
	store := runtime.NewMemoryStore(recorder)
	clock := runtime.NewMockClock(now)
	verifier, err := capability.NewHMACVerifier([]byte("capability-verifier-key-m56a-32bytes!"))
	if err != nil {
		t.Fatal(err)
	}
	protector, err := replaycapsule.NewAEADProtector([]byte("replay-capsule-protector-key-32!"), "m56a", func() time.Time { return now.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	tokens := &lifecycleCountedToken{}
	ids := &seqID{}

	tpID := "tp-final-slot"
	tp := &domain.TemporaryPrincipal{
		TemporaryPrincipalID: tpID,
		PartnerID:            "P1",
		Status:               domain.TPStatusActive,
		ExpiresAt:            now.Add(time.Hour),
		MaxSubmissions:       1,
		CommittedSubmissions: 0,
	}
	store.SeedTemporaryPrincipal(tp)

	t1Staged := make(chan struct{})
	t2Staged := make(chan struct{})
	allowCommit := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(2)

	var err1 error
	go func() {
		defer wg.Done()
		uowMgr := &syncUOWManager{
			UnitOfWorkManager: store,
			onBegin: func(uow application.UnitOfWork) application.UnitOfWork {
				return &syncUOW{
					UnitOfWork: uow,
					beforeCommit: func() {
						close(t1Staged)
						<-allowCommit
					},
				}
			},
		}
		svc, _ := application.NewService(application.ServiceConfig{
			UOWManager:                 uowMgr,
			Clock:                      clock,
			DeviceAllocator:            runtime.DefaultDeviceAllocator{},
			PartnerAuth:                runtime.NewMemoryPartnerAuthorityChecker(),
			PartnerEligibility:         runtime.NewMemoryPartnerEligibilityChecker(),
			RetentionPolicy:            application.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
			RequestAccessTokenLifetime: application.StaticRequestAccessTokenLifetime{Duration: 30 * time.Minute},
			ReplayCapsulePolicy:        application.StaticReplayCapsuleRetentionPolicy{Duration: time.Hour},
			Create: &application.CreateDependencies{
				IDGenerator:    ids,
				TokenGenerator: tokens,
				Verifier:       verifier,
				Protector:      protector,
			},
		})
		cmd := application.CreateOriginatorCommand{
			CreateCommand: application.CreateCommand{
				PartnerID:     "P1",
				ClaimedDevice: domain.ClaimedDevice{Hostname: "h-race-1"},
				Agent:         domain.Agent{Platform: "linux", Version: "1"},
			},
			CredentialKind:    authpolicy.CredentialKindTemporaryPrincipalToken,
			CredentialBinding: tpID,
			IdempotencyKey:    "idem-tp-race-final-1",
			CorrelationID:     "corr-tp-race-1",
		}
		_, err1 = svc.CreateOriginator(context.Background(), cmd)
	}()

	var err2 error
	go func() {
		defer wg.Done()
		uowMgr := &syncUOWManager{
			UnitOfWorkManager: store,
			onBegin: func(uow application.UnitOfWork) application.UnitOfWork {
				return &syncUOW{
					UnitOfWork: uow,
					beforeCommit: func() {
						close(t2Staged)
						<-allowCommit
					},
				}
			},
		}
		svc, _ := application.NewService(application.ServiceConfig{
			UOWManager:                 uowMgr,
			Clock:                      clock,
			DeviceAllocator:            runtime.DefaultDeviceAllocator{},
			PartnerAuth:                runtime.NewMemoryPartnerAuthorityChecker(),
			PartnerEligibility:         runtime.NewMemoryPartnerEligibilityChecker(),
			RetentionPolicy:            application.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
			RequestAccessTokenLifetime: application.StaticRequestAccessTokenLifetime{Duration: 30 * time.Minute},
			ReplayCapsulePolicy:        application.StaticReplayCapsuleRetentionPolicy{Duration: time.Hour},
			Create: &application.CreateDependencies{
				IDGenerator:    ids,
				TokenGenerator: tokens,
				Verifier:       verifier,
				Protector:      protector,
			},
		})
		cmd := application.CreateOriginatorCommand{
			CreateCommand: application.CreateCommand{
				PartnerID:     "P1",
				ClaimedDevice: domain.ClaimedDevice{Hostname: "h-race-2"},
				Agent:         domain.Agent{Platform: "linux", Version: "1"},
			},
			CredentialKind:    authpolicy.CredentialKindTemporaryPrincipalToken,
			CredentialBinding: tpID,
			IdempotencyKey:    "idem-tp-race-final-2",
			CorrelationID:     "corr-tp-race-2",
		}
		_, err2 = svc.CreateOriginator(context.Background(), cmd)
	}()

	<-t1Staged
	<-t2Staged
	close(allowCommit)

	wg.Wait()

	// Assert exactly one succeeded and one failed
	var successCount, failureCount int
	var failErr error
	if err1 == nil {
		successCount++
	} else {
		failureCount++
		failErr = err1
	}
	if err2 == nil {
		successCount++
	} else {
		failureCount++
		failErr = err2
	}

	if successCount != 1 || failureCount != 1 {
		t.Fatalf("expected exactly 1 success and 1 failure, got %d successes and %d failures (err1=%v, err2=%v)", successCount, failureCount, err1, err2)
	}

	if !errors.Is(failErr, application.ErrPartnerNotAuthorized) {
		t.Fatalf("expected loser to fail with ErrPartnerNotAuthorized, got: %v", failErr)
	}

	// Assert CommittedSubmissions == 1
	uow, _ := store.Begin(context.Background())
	tpRec, _, _ := uow.TemporaryPrincipalStore().Get(context.Background(), tpID)
	uow.Rollback(context.Background())
	if tpRec.CommittedSubmissions != 1 {
		t.Fatalf("expected quota consumed to be 1, got %d", tpRec.CommittedSubmissions)
	}

	// Verify only 1 pre-onboarding request committed
	uow, _ = store.Begin(context.Background())
	defer uow.Rollback(context.Background())
	requests, _ := uow.Repository().List(context.Background(), application.ListFilter{AuthorizedPartners: []string{"P1"}})
	if len(requests.Items) != 1 {
		t.Fatalf("expected exactly 1 committed pre-onboarding request, got %d", len(requests.Items))
	}

	// Assert RequestAccess verifier count is exactly 1 (loser contributed 0)
	if count := store.CountRequestAccess(); count != 1 {
		t.Fatalf("expected exactly 1 request access record, got %d", count)
	}

	// Assert create-result snapshot count is exactly 1 (loser contributed 0)
	if count := store.CountCreateResults(); count != 1 {
		t.Fatalf("expected exactly 1 create result snapshot, got %d", count)
	}

	// Assert committed idempotency records count is exactly 1 (loser contributed 0)
	if count := store.CountIdemCommitted(); count != 1 {
		t.Fatalf("expected exactly 1 committed idempotency record, got %d", count)
	}

	// Assert committed audit events count is exactly 1 (loser contributed 0)
	if count := recorder.Count(); count != 1 {
		t.Fatalf("expected exactly 1 committed audit event, got %d", count)
	}
}

func TestTP_B2_Concurrency_MultiSlot(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	recorder := runtime.NewMemoryAuditRecorder()
	store := runtime.NewMemoryStore(recorder)
	clock := runtime.NewMockClock(now)
	verifier, err := capability.NewHMACVerifier([]byte("capability-verifier-key-m56a-32bytes!"))
	if err != nil {
		t.Fatal(err)
	}
	protector, err := replaycapsule.NewAEADProtector([]byte("replay-capsule-protector-key-32!"), "m56a", func() time.Time { return now.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	tokens := &lifecycleCountedToken{}
	ids := &seqID{}

	tpID := "tp-multi-slot"
	tp := &domain.TemporaryPrincipal{
		TemporaryPrincipalID: tpID,
		PartnerID:            "P1",
		Status:               domain.TPStatusActive,
		ExpiresAt:            now.Add(time.Hour),
		MaxSubmissions:       3,
		CommittedSubmissions: 0,
	}
	store.SeedTemporaryPrincipal(tp)

	svc, err := application.NewService(application.ServiceConfig{
		UOWManager:                 store,
		Clock:                      clock,
		DeviceAllocator:            runtime.DefaultDeviceAllocator{},
		PartnerAuth:                runtime.NewMemoryPartnerAuthorityChecker(),
		PartnerEligibility:         runtime.NewMemoryPartnerEligibilityChecker(),
		RetentionPolicy:            application.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
		RequestAccessTokenLifetime: application.StaticRequestAccessTokenLifetime{Duration: 30 * time.Minute},
		ReplayCapsulePolicy:        application.StaticReplayCapsuleRetentionPolicy{Duration: time.Hour},
		Create: &application.CreateDependencies{
			IDGenerator:    ids,
			TokenGenerator: tokens,
			Verifier:       verifier,
			Protector:      protector,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	results := make([]error, 6)

	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cmd := application.CreateOriginatorCommand{
				CreateCommand: application.CreateCommand{
					PartnerID:     "P1",
					ClaimedDevice: domain.ClaimedDevice{Hostname: fmt.Sprintf("h-multi-%d", idx)},
					Agent:         domain.Agent{Platform: "linux", Version: "1"},
				},
				CredentialKind:    authpolicy.CredentialKindTemporaryPrincipalToken,
				CredentialBinding: tpID,
				IdempotencyKey:    fmt.Sprintf("idem-multi-slot-key-%d", idx),
				CorrelationID:     fmt.Sprintf("corr-multi-%d", idx),
			}
			_, results[idx] = svc.CreateOriginator(context.Background(), cmd)
		}(i)
	}

	wg.Wait()

	var successCount, failureCount int
	for _, res := range results {
		if res == nil {
			successCount++
		} else {
			failureCount++
		}
	}

	if successCount != 3 || failureCount != 3 {
		t.Fatalf("expected exactly 3 successes and 3 failures, got %d successes and %d failures", successCount, failureCount)
	}

	// Verify quota is exactly 3
	uow, _ := store.Begin(context.Background())
	tpRec, _, _ := uow.TemporaryPrincipalStore().Get(context.Background(), tpID)
	uow.Rollback(context.Background())
	if tpRec.CommittedSubmissions != 3 {
		t.Fatalf("expected CommittedSubmissions to be 3, got %d", tpRec.CommittedSubmissions)
	}

	// Verify only 3 pre-onboarding requests committed
	uow, _ = store.Begin(context.Background())
	defer uow.Rollback(context.Background())
	requests, _ := uow.Repository().List(context.Background(), application.ListFilter{AuthorizedPartners: []string{"P1"}})
	if len(requests.Items) != 3 {
		t.Fatalf("expected exactly 3 committed pre-onboarding requests, got %d", len(requests.Items))
	}

	// Assert RequestAccess verifier count is exactly 3
	if count := store.CountRequestAccess(); count != 3 {
		t.Fatalf("expected exactly 3 request access records, got %d", count)
	}

	// Assert create-result snapshot count is exactly 3
	if count := store.CountCreateResults(); count != 3 {
		t.Fatalf("expected exactly 3 create result snapshots, got %d", count)
	}

	// Assert committed idempotency records count is exactly 3
	if count := store.CountIdemCommitted(); count != 3 {
		t.Fatalf("expected exactly 3 committed idempotency records, got %d", count)
	}

	// Assert committed audit events count is exactly 3
	if count := recorder.Count(); count != 3 {
		t.Fatalf("expected exactly 3 committed audit events, got %d", count)
	}
}

func TestTP_B2_LifecycleLostUpdateProtection(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	store := runtime.NewMemoryStore(runtime.NewMemoryAuditRecorder())
	commitCtx := application.ContextWithCommitClock(ctx, runtime.NewMockClock(now))

	tpID := "tp-lost-update"
	tp := &domain.TemporaryPrincipal{
		TemporaryPrincipalID: tpID,
		PartnerID:            "P1",
		Status:               domain.TPStatusActive,
		ExpiresAt:            now.Add(time.Hour),
		MaxSubmissions:       3,
		CommittedSubmissions: 0,
	}
	store.SeedTemporaryPrincipal(tp)

	// 1. Begin transaction uow1 and observe/stage TP quota consumption
	uow1, err := store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer uow1.Rollback(ctx)

	tpRec1, ok, err := uow1.TemporaryPrincipalStore().Get(ctx, tpID)
	if err != nil || !ok {
		t.Fatalf("failed to get TP in uow1: %v", err)
	}

	tpRec1.CommittedSubmissions++
	if err := uow1.TemporaryPrincipalStore().Save(ctx, tpRec1); err != nil {
		t.Fatal(err)
	}

	// 2. Before uow1 commits, mutate/commit a newer authoritative TP lifecycle state (DISABLED)
	tpNewer := &domain.TemporaryPrincipal{
		TemporaryPrincipalID: tpID,
		PartnerID:            "P1",
		Status:               domain.TPStatusDisabled,
		ExpiresAt:            now.Add(time.Hour),
		MaxSubmissions:       3,
		CommittedSubmissions: 0,
	}
	store.SeedTemporaryPrincipal(tpNewer)

	// 3. Attempt to commit uow1, which should fail because Status changed to DISABLED
	err = uow1.Commit(commitCtx)
	if !errors.Is(err, application.ErrPartnerNotAuthorized) {
		t.Fatalf("expected ErrPartnerNotAuthorized due to status change, got: %v", err)
	}

	// Prove Status is still DISABLED (not overwritten or resurrected)
	uowVerify, _ := store.Begin(ctx)
	tpVal, _, _ := uowVerify.TemporaryPrincipalStore().Get(ctx, tpID)
	uowVerify.Rollback(ctx)
	if tpVal.Status != domain.TPStatusDisabled {
		t.Fatalf("expected status to remain DISABLED, got %v", tpVal.Status)
	}

	// 4. Test concurrent MaxSubmissions change
	// Reset to active and seed
	tp.Status = domain.TPStatusActive
	tp.CommittedSubmissions = 0
	store.SeedTemporaryPrincipal(tp)

	uow2, err := store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer uow2.Rollback(ctx)

	tpRec2, _, _ := uow2.TemporaryPrincipalStore().Get(ctx, tpID)
	tpRec2.CommittedSubmissions++
	uow2.TemporaryPrincipalStore().Save(ctx, tpRec2)

	// Concurrently change MaxSubmissions to 0 (which means quota is exhausted)
	tpExhausted := &domain.TemporaryPrincipal{
		TemporaryPrincipalID: tpID,
		PartnerID:            "P1",
		Status:               domain.TPStatusActive,
		ExpiresAt:            now.Add(time.Hour),
		MaxSubmissions:       0,
		CommittedSubmissions: 0,
	}
	store.SeedTemporaryPrincipal(tpExhausted)

	// Commit should fail because 1 > 0
	err = uow2.Commit(commitCtx)
	if !errors.Is(err, application.ErrPartnerNotAuthorized) {
		t.Fatalf("expected ErrPartnerNotAuthorized due to max submissions decrease, got: %v", err)
	}

	// Prove MaxSubmissions is still 0 (not overwritten back to 3)
	uowVerify2, _ := store.Begin(ctx)
	tpVal2, _, _ := uowVerify2.TemporaryPrincipalStore().Get(ctx, tpID)
	uowVerify2.Rollback(ctx)
	if tpVal2.MaxSubmissions != 0 {
		t.Fatalf("expected MaxSubmissions to remain 0, got %d", tpVal2.MaxSubmissions)
	}
}
