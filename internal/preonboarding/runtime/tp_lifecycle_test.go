package runtime_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/replaycapsule"
	"sync"
)

type seqID struct {
	mu      sync.Mutex
	counter int
}

func (s *seqID) NewPreOnboardingRequestID(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counter++
	return fmt.Sprintf("por-%d", s.counter), nil
}

type lifecycleCountedToken struct {
	mu    sync.Mutex
	calls int
}

func (g *lifecycleCountedToken) NewRequestAccessToken(context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	return fmt.Sprintf("token-%d", g.calls), nil
}

func (g *lifecycleCountedToken) GetCalls() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

type faultyProtector struct {
	failSeal bool
	real     idempotencyruntime.Protector
}

func (f *faultyProtector) Seal(ctx context.Context, p []byte, a []byte) (*idempotencyruntime.ProtectedEnvelope, error) {
	if f.failSeal {
		return nil, errors.New("injected seal failure")
	}
	return f.real.Seal(ctx, p, a)
}

func (f *faultyProtector) Open(ctx context.Context, e *idempotencyruntime.ProtectedEnvelope, a []byte) ([]byte, error) {
	return f.real.Open(ctx, e, a)
}

func TestTP_B1_Lifecycle(t *testing.T) {
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
	faultyProt := &faultyProtector{real: protector}
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
			Protector:      faultyProt,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("1. active + correct partner + unexpired + quota 1 -> NEW succeeds", func(t *testing.T) {
		tp := &domain.TemporaryPrincipal{
			TemporaryPrincipalID: "tp-1",
			PartnerID:            "P1",
			Status:               domain.TPStatusActive,
			ExpiresAt:            now.Add(time.Hour),
			MaxSubmissions:       1,
			CommittedSubmissions: 0,
		}
		store.SeedTemporaryPrincipal(tp)

		cmd := application.CreateOriginatorCommand{
			CreateCommand: application.CreateCommand{
				PartnerID:     "P1",
				ClaimedDevice: domain.ClaimedDevice{Hostname: "h1"},
				Agent:         domain.Agent{Platform: "linux", Version: "1"},
			},
			CredentialKind:    authpolicy.CredentialKindTemporaryPrincipalToken,
			CredentialBinding: "tp-1",
			IdempotencyKey:    "idem-tp-1-must-be-long",
			CorrelationID:     "corr-tp-1",
		}

		res, err := svc.CreateOriginator(context.Background(), cmd)
		if err != nil {
			t.Fatalf("expected success, got err: %v", err)
		}
		if res.Replay {
			t.Fatal("expected NEW, got replay")
		}
		if res.Snapshot.PartnerID != "P1" {
			t.Fatalf("expected partner P1, got %v", res.Snapshot.PartnerID)
		}

		t.Run("2. committed NEW consumes exactly one", func(t *testing.T) {
			uow, _ := store.Begin(context.Background())
			defer uow.Rollback(context.Background())
			tpRec, ok, _ := uow.TemporaryPrincipalStore().Get(context.Background(), "tp-1")
			if !ok {
				t.Fatal("expected to find tp-1")
			}
			if tpRec.CommittedSubmissions != 1 {
				t.Fatalf("expected CommittedSubmissions to be 1, got %d", tpRec.CommittedSubmissions)
			}
		})
	})

	t.Run("3. quota 2 permits exactly two sequential different-key NEW operations", func(t *testing.T) {
		tp := &domain.TemporaryPrincipal{
			TemporaryPrincipalID: "tp-3",
			PartnerID:            "P1",
			Status:               domain.TPStatusActive,
			ExpiresAt:            now.Add(time.Hour),
			MaxSubmissions:       2,
			CommittedSubmissions: 0,
		}
		store.SeedTemporaryPrincipal(tp)

		cmd1 := application.CreateOriginatorCommand{
			CreateCommand: application.CreateCommand{
				PartnerID:     "P1",
				ClaimedDevice: domain.ClaimedDevice{Hostname: "h3-1"},
				Agent:         domain.Agent{Platform: "linux", Version: "1"},
			},
			CredentialKind:    authpolicy.CredentialKindTemporaryPrincipalToken,
			CredentialBinding: "tp-3",
			IdempotencyKey:    "idem-tp-3-1-must-be-long",
			CorrelationID:     "corr-tp-3-1",
		}
		_, err := svc.CreateOriginator(context.Background(), cmd1)
		if err != nil {
			t.Fatalf("first request failed: %v", err)
		}

		cmd2 := application.CreateOriginatorCommand{
			CreateCommand: application.CreateCommand{
				PartnerID:     "P1",
				ClaimedDevice: domain.ClaimedDevice{Hostname: "h3-2"},
				Agent:         domain.Agent{Platform: "linux", Version: "1"},
			},
			CredentialKind:    authpolicy.CredentialKindTemporaryPrincipalToken,
			CredentialBinding: "tp-3",
			IdempotencyKey:    "idem-tp-3-2-must-be-long",
			CorrelationID:     "corr-tp-3-2",
		}
		_, err = svc.CreateOriginator(context.Background(), cmd2)
		if err != nil {
			t.Fatalf("second request failed: %v", err)
		}

		uow, _ := store.Begin(context.Background())
		defer uow.Rollback(context.Background())
		tpRec, _, _ := uow.TemporaryPrincipalStore().Get(context.Background(), "tp-3")
		if tpRec.CommittedSubmissions != 2 {
			t.Fatalf("expected CommittedSubmissions to be 2, got %d", tpRec.CommittedSubmissions)
		}

		t.Run("5. third operation after quota 2 exhausted rejects", func(t *testing.T) {
			cmd3 := application.CreateOriginatorCommand{
				CreateCommand: application.CreateCommand{
					PartnerID:     "P1",
					ClaimedDevice: domain.ClaimedDevice{Hostname: "h3-3"},
					Agent:         domain.Agent{Platform: "linux", Version: "1"},
				},
				CredentialKind:    authpolicy.CredentialKindTemporaryPrincipalToken,
				CredentialBinding: "tp-3",
				IdempotencyKey:    "idem-tp-3-3-must-be-long",
				CorrelationID:     "corr-tp-3-3",
			}
			_, err = svc.CreateOriginator(context.Background(), cmd3)
			if !errors.Is(err, application.ErrPartnerNotAuthorized) {
				t.Fatalf("expected ErrPartnerNotAuthorized, got: %v", err)
			}

			// Verify quota remains 2 and no request committed
			tpRec, _, _ := uow.TemporaryPrincipalStore().Get(context.Background(), "tp-3")
			if tpRec.CommittedSubmissions != 2 {
				t.Fatalf("expected CommittedSubmissions to remain 2, got %d", tpRec.CommittedSubmissions)
			}
		})
	})

	t.Run("4. quota 0 rejects NEW", func(t *testing.T) {
		tp := &domain.TemporaryPrincipal{
			TemporaryPrincipalID: "tp-4",
			PartnerID:            "P1",
			Status:               domain.TPStatusActive,
			ExpiresAt:            now.Add(time.Hour),
			MaxSubmissions:       0,
			CommittedSubmissions: 0,
		}
		store.SeedTemporaryPrincipal(tp)

		cmd := application.CreateOriginatorCommand{
			CreateCommand: application.CreateCommand{
				PartnerID:     "P1",
				ClaimedDevice: domain.ClaimedDevice{Hostname: "h4"},
				Agent:         domain.Agent{Platform: "linux", Version: "1"},
			},
			CredentialKind:    authpolicy.CredentialKindTemporaryPrincipalToken,
			CredentialBinding: "tp-4",
			IdempotencyKey:    "idem-tp-4-must-be-long",
			CorrelationID:     "corr-tp-4",
		}
		_, err := svc.CreateOriginator(context.Background(), cmd)
		if !errors.Is(err, application.ErrPartnerNotAuthorized) {
			t.Fatalf("expected ErrPartnerNotAuthorized, got: %v", err)
		}

		uow, _ := store.Begin(context.Background())
		defer uow.Rollback(context.Background())
		tpRec, _, _ := uow.TemporaryPrincipalStore().Get(context.Background(), "tp-4")
		if tpRec.CommittedSubmissions != 0 {
			t.Fatalf("expected CommittedSubmissions to be 0, got %d", tpRec.CommittedSubmissions)
		}
	})

	t.Run("6. wrong partner rejects with quota unchanged", func(t *testing.T) {
		tp := &domain.TemporaryPrincipal{
			TemporaryPrincipalID: "tp-6",
			PartnerID:            "P1",
			Status:               domain.TPStatusActive,
			ExpiresAt:            now.Add(time.Hour),
			MaxSubmissions:       1,
			CommittedSubmissions: 0,
		}
		store.SeedTemporaryPrincipal(tp)

		cmd := application.CreateOriginatorCommand{
			CreateCommand: application.CreateCommand{
				PartnerID:     "P2", // mismatched partner
				ClaimedDevice: domain.ClaimedDevice{Hostname: "h6"},
				Agent:         domain.Agent{Platform: "linux", Version: "1"},
			},
			CredentialKind:    authpolicy.CredentialKindTemporaryPrincipalToken,
			CredentialBinding: "tp-6",
			IdempotencyKey:    "idem-tp-6-must-be-long",
			CorrelationID:     "corr-tp-6",
		}
		_, err := svc.CreateOriginator(context.Background(), cmd)
		if !errors.Is(err, application.ErrPartnerNotAuthorized) {
			t.Fatalf("expected ErrPartnerNotAuthorized, got: %v", err)
		}

		uow, _ := store.Begin(context.Background())
		defer uow.Rollback(context.Background())
		tpRec, _, _ := uow.TemporaryPrincipalStore().Get(context.Background(), "tp-6")
		if tpRec.CommittedSubmissions != 0 {
			t.Fatalf("expected CommittedSubmissions to be 0, got %d", tpRec.CommittedSubmissions)
		}
	})

	t.Run("7. disabled TP rejects with quota unchanged", func(t *testing.T) {
		tp := &domain.TemporaryPrincipal{
			TemporaryPrincipalID: "tp-7",
			PartnerID:            "P1",
			Status:               domain.TPStatusDisabled,
			ExpiresAt:            now.Add(time.Hour),
			MaxSubmissions:       1,
			CommittedSubmissions: 0,
		}
		store.SeedTemporaryPrincipal(tp)

		cmd := application.CreateOriginatorCommand{
			CreateCommand: application.CreateCommand{
				PartnerID:     "P1",
				ClaimedDevice: domain.ClaimedDevice{Hostname: "h7"},
				Agent:         domain.Agent{Platform: "linux", Version: "1"},
			},
			CredentialKind:    authpolicy.CredentialKindTemporaryPrincipalToken,
			CredentialBinding: "tp-7",
			IdempotencyKey:    "idem-tp-7-must-be-long",
			CorrelationID:     "corr-tp-7",
		}
		_, err := svc.CreateOriginator(context.Background(), cmd)
		if !errors.Is(err, application.ErrPartnerNotAuthorized) {
			t.Fatalf("expected ErrPartnerNotAuthorized, got: %v", err)
		}

		uow, _ := store.Begin(context.Background())
		defer uow.Rollback(context.Background())
		tpRec, _, _ := uow.TemporaryPrincipalStore().Get(context.Background(), "tp-7")
		if tpRec.CommittedSubmissions != 0 {
			t.Fatalf("expected CommittedSubmissions to be 0, got %d", tpRec.CommittedSubmissions)
		}
	})

	t.Run("8. expired TP rejects with quota unchanged", func(t *testing.T) {
		tp := &domain.TemporaryPrincipal{
			TemporaryPrincipalID: "tp-8",
			PartnerID:            "P1",
			Status:               domain.TPStatusActive,
			ExpiresAt:            now.Add(-time.Hour), // expired
			MaxSubmissions:       1,
			CommittedSubmissions: 0,
		}
		store.SeedTemporaryPrincipal(tp)

		cmd := application.CreateOriginatorCommand{
			CreateCommand: application.CreateCommand{
				PartnerID:     "P1",
				ClaimedDevice: domain.ClaimedDevice{Hostname: "h8"},
				Agent:         domain.Agent{Platform: "linux", Version: "1"},
			},
			CredentialKind:    authpolicy.CredentialKindTemporaryPrincipalToken,
			CredentialBinding: "tp-8",
			IdempotencyKey:    "idem-tp-8-must-be-long",
			CorrelationID:     "corr-tp-8",
		}
		_, err := svc.CreateOriginator(context.Background(), cmd)
		if !errors.Is(err, application.ErrPartnerNotAuthorized) {
			t.Fatalf("expected ErrPartnerNotAuthorized, got: %v", err)
		}

		uow, _ := store.Begin(context.Background())
		defer uow.Rollback(context.Background())
		tpRec, _, _ := uow.TemporaryPrincipalStore().Get(context.Background(), "tp-8")
		if tpRec.CommittedSubmissions != 0 {
			t.Fatalf("expected CommittedSubmissions to be 0, got %d", tpRec.CommittedSubmissions)
		}
	})

	t.Run("9. Seal failure after quota staging rolls everything back", func(t *testing.T) {
		tp := &domain.TemporaryPrincipal{
			TemporaryPrincipalID: "tp-9",
			PartnerID:            "P1",
			Status:               domain.TPStatusActive,
			ExpiresAt:            now.Add(time.Hour),
			MaxSubmissions:       1,
			CommittedSubmissions: 0,
		}
		store.SeedTemporaryPrincipal(tp)
		faultyProt.failSeal = true
		defer func() { faultyProt.failSeal = false }()

		cmd := application.CreateOriginatorCommand{
			CreateCommand: application.CreateCommand{
				PartnerID:     "P1",
				ClaimedDevice: domain.ClaimedDevice{Hostname: "h9"},
				Agent:         domain.Agent{Platform: "linux", Version: "1"},
			},
			CredentialKind:    authpolicy.CredentialKindTemporaryPrincipalToken,
			CredentialBinding: "tp-9",
			IdempotencyKey:    "idem-tp-9-must-be-long",
			CorrelationID:     "corr-tp-9",
		}
		_, err := svc.CreateOriginator(context.Background(), cmd)
		if err == nil {
			t.Fatal("expected failure on seal error, got nil")
		}

		uow, _ := store.Begin(context.Background())
		defer uow.Rollback(context.Background())
		tpRec, _, _ := uow.TemporaryPrincipalStore().Get(context.Background(), "tp-9")
		if tpRec.CommittedSubmissions != 0 {
			t.Fatalf("expected CommittedSubmissions to remain 0, got %d", tpRec.CommittedSubmissions)
		}

		// Verify no request was stored
		_, found, _ := uow.Repository().Get(context.Background(), domain.ID("por-4")) // ids.counter will be 4
		if found {
			t.Fatal("pre-onboarding request should not have been committed")
		}
	})

	t.Run("10. outer UoW failure after quota staging rolls everything back", func(t *testing.T) {
		tp := &domain.TemporaryPrincipal{
			TemporaryPrincipalID: "tp-10",
			PartnerID:            "P1",
			Status:               domain.TPStatusActive,
			ExpiresAt:            now.Add(time.Hour),
			MaxSubmissions:       1,
			CommittedSubmissions: 0,
		}
		store.SeedTemporaryPrincipal(tp)

		// Create a separate service using the failure store
		failStore := &InjectedFailureStore{MemoryStore: store, injectCommitErr: errors.New("commit failed")}
		failSvc, err := application.NewService(application.ServiceConfig{
			UOWManager:                 failStore,
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
				Protector:      faultyProt,
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		cmd := application.CreateOriginatorCommand{
			CreateCommand: application.CreateCommand{
				PartnerID:     "P1",
				ClaimedDevice: domain.ClaimedDevice{Hostname: "h10"},
				Agent:         domain.Agent{Platform: "linux", Version: "1"},
			},
			CredentialKind:    authpolicy.CredentialKindTemporaryPrincipalToken,
			CredentialBinding: "tp-10",
			IdempotencyKey:    "idem-tp-10-must-be-long",
			CorrelationID:     "corr-tp-10",
		}
		_, err = failSvc.CreateOriginator(context.Background(), cmd)
		if err == nil {
			t.Fatal("expected failure on commit error, got nil")
		}

		uow, _ := store.Begin(context.Background())
		defer uow.Rollback(context.Background())
		tpRec, _, _ := uow.TemporaryPrincipalStore().Get(context.Background(), "tp-10")
		if tpRec.CommittedSubmissions != 0 {
			t.Fatalf("expected CommittedSubmissions to remain 0, got %d", tpRec.CommittedSubmissions)
		}
	})

	t.Run("11. HumanOIDC NEW/REPLAY leaves TP storage untouched", func(t *testing.T) {
		tp := &domain.TemporaryPrincipal{
			TemporaryPrincipalID: "tp-11",
			PartnerID:            "P1",
			Status:               domain.TPStatusActive,
			ExpiresAt:            now.Add(time.Hour),
			MaxSubmissions:       1,
			CommittedSubmissions: 0,
		}
		store.SeedTemporaryPrincipal(tp)

		cmd := application.CreateOriginatorCommand{
			CreateCommand: application.CreateCommand{
				PartnerID:     "P1",
				ClaimedDevice: domain.ClaimedDevice{Hostname: "h11"},
				Agent:         domain.Agent{Platform: "linux", Version: "1"},
			},
			CredentialKind:    authpolicy.CredentialKindHumanOIDC,
			CredentialBinding: "issuer|subject",
			IdempotencyKey:    "idem-tp-11-must-be-long",
			CorrelationID:     "corr-tp-11",
		}
		_, err := svc.CreateOriginator(context.Background(), cmd)
		if err != nil {
			t.Fatalf("HumanOIDC request failed: %v", err)
		}

		uow, _ := store.Begin(context.Background())
		defer uow.Rollback(context.Background())
		tpRec, _, _ := uow.TemporaryPrincipalStore().Get(context.Background(), "tp-11")
		if tpRec.CommittedSubmissions != 0 {
			t.Fatalf("expected tp-11 CommittedSubmissions to remain 0, got %d", tpRec.CommittedSubmissions)
		}
	})

	t.Run("12. production UnavailableTemporaryPrincipal remains fail-closed", func(t *testing.T) {
		resolver := partnerauth.UnavailableTemporaryPrincipalResolver{}
		_, err := resolver.ResolveTemporaryPrincipal(context.Background(), "tp-12")
		if !errors.Is(err, partnerauth.ErrDependencyUnavailable) {
			t.Fatalf("expected ErrDependencyUnavailable, got: %v", err)
		}

		// UnavailableService
		unSvc := application.NewUnavailableService()
		cmd := application.CreateOriginatorCommand{
			CreateCommand: application.CreateCommand{
				PartnerID:     "P1",
				ClaimedDevice: domain.ClaimedDevice{Hostname: "h12"},
				Agent:         domain.Agent{Platform: "linux", Version: "1"},
			},
			CredentialKind:    authpolicy.CredentialKindTemporaryPrincipalToken,
			CredentialBinding: "tp-12",
			IdempotencyKey:    "idem-tp-12-must-be-long",
			CorrelationID:     "corr-tp-12",
		}
		_, err = unSvc.CreateOriginator(context.Background(), cmd)
		if !errors.Is(err, application.ErrDependencyUnavailable) {
			t.Fatalf("expected ErrDependencyUnavailable, got: %v", err)
		}
	})
}
