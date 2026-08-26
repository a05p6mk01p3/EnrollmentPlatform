package runtime_test

import (
	"context"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/replaycapsule"
)

type fixedID struct{}

func (fixedID) NewPreOnboardingRequestID(context.Context) (string, error) { return "por-m56a", nil }

type countedToken struct{ calls int }

func (g *countedToken) NewRequestAccessToken(context.Context) (string, error) {
	g.calls++
	return "m56a-request-token-0123456789abcdef", nil
}

func TestM56ACreateCommitsVerifierToCapabilityReadStoreAndReplayDoesNotMint(t *testing.T) {
	now := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
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
	tokens := &countedToken{}
	svc, err := application.NewService(application.ServiceConfig{UOWManager: store, Clock: clock, DeviceAllocator: runtime.DefaultDeviceAllocator{}, PartnerAuth: runtime.NewMemoryPartnerAuthorityChecker(), PartnerEligibility: runtime.NewMemoryPartnerEligibilityChecker(), RetentionPolicy: application.StaticIdempotencyRetentionPolicy{Duration: time.Hour}, ReplayCapsulePolicy: application.StaticReplayCapsuleRetentionPolicy{Duration: time.Hour}, RequestAccessTokenLifetime: application.StaticRequestAccessTokenLifetime{Duration: 30 * time.Minute}, Create: &application.CreateDependencies{IDGenerator: fixedID{}, TokenGenerator: tokens, Verifier: verifier, Protector: protector}})
	if err != nil {
		t.Fatal(err)
	}
	cmd := application.CreateOriginatorCommand{CreateCommand: application.CreateCommand{PartnerID: "P1", ClaimedDevice: domain.ClaimedDevice{Hostname: "h"}, Agent: domain.Agent{Platform: "windows", Version: "1"}}, CredentialKind: authpolicy.CredentialKindHumanOIDC, CredentialBinding: "issuer|subject", IdempotencyKey: "m56a-idempotency-key-0001", CorrelationID: "first"}
	first, err := svc.CreateOriginator(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	a := capability.NewRequestAccessAuthenticator(verifier, store, clock)
	got := a.Authenticate(context.Background(), &authruntime.Credential{BearerToken: first.RequestAccessToken})
	if got.Decision != authruntime.DecisionAuthenticated {
		t.Fatalf("decision=%v", got.Decision)
	}
	b, ok := got.Binding.RequestAccess()
	if !ok || b.PreOnboardingRequestID != "por-m56a" {
		t.Fatalf("binding=%+v", b)
	}
	cmd.CorrelationID = "retry"
	second, err := svc.CreateOriginator(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replay || second.RequestAccessToken != first.RequestAccessToken || tokens.calls != 1 {
		t.Fatalf("replay=%v calls=%d", second.Replay, tokens.calls)
	}
}

func TestM56AVerifierVisibilityFollowsUOWCommitAndRollback(t *testing.T) {
	store := runtime.NewMemoryStore(nil)
	verifier, err := capability.NewHMACVerifier([]byte("capability-verifier-key-m56a-32bytes!"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := verifier.Derive(authpolicy.CredentialKindRequestAccessToken, "uncommitted-token")
	if err != nil {
		t.Fatal(err)
	}
	uow, err := store.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rec := capability.RequestAccessRecord{PreOnboardingRequestID: "por-visible", ExpiresAt: time.Now().Add(time.Hour), State: capability.StateActive}
	if err := uow.RequestAccessWriter().CreateRequestAccess(context.Background(), key, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupRequestAccess(context.Background(), key); err == nil {
		t.Fatal("staged verifier visible before commit")
	}
	if err := uow.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := store.LookupRequestAccess(context.Background(), key)
	if err != nil || got.PreOnboardingRequestID != "por-visible" || got.State != capability.StateActive {
		t.Fatalf("committed verifier=%+v err=%v", got, err)
	}
	key2, err := verifier.Derive(authpolicy.CredentialKindRequestAccessToken, "rolled-back-token")
	if err != nil {
		t.Fatal(err)
	}
	uow, err = store.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.RequestAccessWriter().CreateRequestAccess(context.Background(), key2, rec); err != nil {
		t.Fatal(err)
	}
	if err := uow.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupRequestAccess(context.Background(), key2); err == nil {
		t.Fatal("rolled-back verifier visible")
	}
}
