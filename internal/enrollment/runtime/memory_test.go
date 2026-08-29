package runtime_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	application "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/recovery"
	enrollmentruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/runtime"
	preonboardingdomain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	preonboardingruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/replaycapsule"
)

type mutableClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (c *mutableClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}
func (c *mutableClock) Set(t time.Time) {
	c.mu.Lock()
	c.now = t
	c.mu.Unlock()
}
func (c *mutableClock) Validate() error { return nil }

type fixedID string

func (g fixedID) NewEnrollmentID(context.Context) (string, error) { return string(g), nil }

type fixedChallenge byte

func (g fixedChallenge) NewChallengeNonce(context.Context) ([]byte, error) {
	return bytes.Repeat([]byte{byte(g)}, 16), nil
}

type fixedToken string

func (g fixedToken) NewEnrollmentAccessToken(context.Context) (string, error) { return string(g), nil }

type barrierManager struct {
	inner   application.UnitOfWorkManager
	entered chan struct{}
	release chan struct{}
}

func newBarrierManager(inner application.UnitOfWorkManager) *barrierManager {
	return &barrierManager{inner: inner, entered: make(chan struct{}, 1), release: make(chan struct{})}
}

func (m *barrierManager) Begin(ctx context.Context) (application.UnitOfWork, error) {
	uow, err := m.inner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &barrierUOW{UnitOfWork: uow, entered: m.entered, release: m.release}, nil
}

type barrierUOW struct {
	application.UnitOfWork
	entered chan struct{}
	release chan struct{}
}

func (u *barrierUOW) Commit(ctx context.Context) error {
	u.entered <- struct{}{}
	select {
	case <-u.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return u.UnitOfWork.Commit(ctx)
}

type harness struct {
	ctx       context.Context
	clock     *mutableClock
	verifier  capability.Verifier
	authority *preonboardingruntime.MemoryStore
	store     *enrollmentruntime.MemoryStore
	protector *replaycapsule.AEADProtector
	reqs      application.EvidenceRequirements
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 8, 28, 18, 0, 0, 0, time.UTC)
	clock := &mutableClock{now: now}
	verifier, err := capability.NewHMACVerifier([]byte("m57-runtime-verifier-key-material"))
	if err != nil {
		t.Fatal(err)
	}
	authority := preonboardingruntime.NewMemoryStore(nil)
	store, err := enrollmentruntime.NewMemoryStore(authority)
	if err != nil {
		t.Fatal(err)
	}
	protector, err := replaycapsule.NewAEADProtector(bytes.Repeat([]byte{0x42}, 32), "m57-test-key", func() time.Time {
		return clock.Now().Add(time.Hour)
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{
		ctx: ctx, clock: clock, verifier: verifier, authority: authority, store: store, protector: protector,
		reqs: application.EvidenceRequirements{
			TPMEvidenceProtocolVersions: []string{"test-v1"},
			MinimumAssurance:            "A1",
			AllowedKeyProfiles:          []string{"test-profile"},
		},
	}
}

func (h *harness) seedReady(t *testing.T, requestID, partnerID, deviceID, requestToken string, tokenExpiresAt time.Time) capability.VerifierKey {
	t.Helper()
	return h.seedReadyWithRequestExpiry(t, requestID, partnerID, deviceID, requestToken, h.clock.Now().Add(2*time.Hour), tokenExpiresAt)
}

func (h *harness) seedReadyWithRequestExpiry(t *testing.T, requestID, partnerID, deviceID, requestToken string, requestExpiresAt, tokenExpiresAt time.Time) capability.VerifierKey {
	t.Helper()
	now := h.clock.Now()
	req, err := preonboardingdomain.RestoreRequest(
		preonboardingdomain.ID(requestID), preonboardingdomain.PartnerID(partnerID),
		preonboardingdomain.ClaimedDevice{}, preonboardingdomain.Agent{},
		preonboardingdomain.StateEnrollmentReady, &deviceID,
		now.Add(-time.Hour), requestExpiresAt, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	h.authority.SeedRequest(req)
	key, err := h.verifier.Derive(authpolicy.CredentialKindRequestAccessToken, requestToken)
	if err != nil {
		t.Fatal(err)
	}
	uow, err := h.authority.Begin(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.RequestAccessWriter().CreateRequestAccess(h.ctx, key, capability.RequestAccessRecord{
		PreOnboardingRequestID: requestID, ExpiresAt: tokenExpiresAt, State: capability.StateActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := uow.Commit(h.ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.store.SetInitialPolicy(partnerID, deviceID, "PARTNER_AUTH", true, h.reqs); err != nil {
		t.Fatal(err)
	}
	return key
}

func tokenOf(b byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

func (h *harness) service(t *testing.T, manager application.UnitOfWorkManager, enrollmentID, token string, challengeByte byte) *application.Service {
	t.Helper()
	svc, err := application.NewService(application.ServiceConfig{
		UOWManager:                    manager,
		Clock:                         h.clock,
		RetentionPolicy:               application.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
		ReplayCapsulePolicy:           application.StaticReplayCapsuleRetentionPolicy{Duration: 45 * time.Minute},
		ChallengeLifetime:             application.StaticChallengeLifetimePolicy{Duration: 30 * time.Minute},
		EnrollmentAccessTokenLifetime: application.StaticEnrollmentAccessTokenLifetimePolicy{Duration: time.Hour},
		Create: &application.CreateDependencies{
			IDGenerator: fixedID(enrollmentID), ChallengeGenerator: fixedChallenge(challengeByte),
			TokenGenerator: fixedToken(token), Verifier: h.verifier, Protector: h.protector,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func createCmd(requestID, key string) application.CreateInitialCommand {
	return application.CreateInitialCommand{
		PreOnboardingRequestID: requestID, CertificateUsage: "PARTNER_AUTH", IdempotencyKey: key, CorrelationID: "corr-test",
	}
}

func TestDifferentKeyRace_FullWriteSetsStage_OnlyOneConsumesAndPublishes(t *testing.T) {
	h := newHarness(t)
	requestKey := h.seedReady(t, "por-race", "partner-A", "device-A", "request-token-race", h.clock.Now().Add(time.Hour))

	managerA := newBarrierManager(h.store)
	managerB := newBarrierManager(h.store)
	svcA := h.service(t, managerA, "enr-race-A", tokenOf(0xA1), 0x11)
	svcB := h.service(t, managerB, "enr-race-B", tokenOf(0xB2), 0x22)

	type outcome struct {
		result application.CreateInitialResult
		err    error
	}
	outA := make(chan outcome, 1)
	outB := make(chan outcome, 1)
	go func() {
		r, err := svcA.CreateInitial(h.ctx, createCmd("por-race", "idem-race-A-123456"))
		outA <- outcome{r, err}
	}()
	go func() {
		r, err := svcB.CreateInitial(h.ctx, createCmd("por-race", "idem-race-B-123456"))
		outB <- outcome{r, err}
	}()

	<-managerA.entered
	<-managerB.entered // both operations reached Commit only after staging the full write-set

	close(managerA.release)
	a := <-outA
	if a.err != nil {
		t.Fatalf("winner error = %v", a.err)
	}
	close(managerB.release)
	b := <-outB
	if !errors.Is(b.err, application.ErrAuthenticationRequired) {
		t.Fatalf("loser error = %v, want ErrAuthenticationRequired", b.err)
	}

	if h.store.CountEnrollments() != 1 || h.store.CountEnrollmentAccess() != 1 || h.store.CountCreateResults() != 1 || h.store.CountIdemCommitted() != 1 {
		t.Fatalf("partial/duplicate publication: enrollments=%d access=%d results=%d idem=%d",
			h.store.CountEnrollments(), h.store.CountEnrollmentAccess(), h.store.CountCreateResults(), h.store.CountIdemCommitted())
	}
	if h.store.CountIdemActive() != 0 {
		t.Fatalf("active idempotency reservations leaked: %d", h.store.CountIdemActive())
	}
	if got := h.store.AuditEvents(); len(got) != 1 || got[0].EnrollmentID != "enr-race-A" {
		t.Fatalf("audit events = %#v, want one winner event", got)
	}
	rec, err := h.authority.LookupRequestAccess(h.ctx, requestKey)
	if err != nil || rec.State != capability.StateConsumed {
		t.Fatalf("request access = %#v, err=%v, want CONSUMED", rec, err)
	}
	if _, ok := h.store.GetEnrollment("enr-race-B"); ok {
		t.Fatal("loser enrollment was published")
	}
	loserVerifier, err := h.verifier.Derive(authpolicy.CredentialKindEnrollmentAccessToken, tokenOf(0xB2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.LookupEnrollmentAccess(h.ctx, loserVerifier); !errors.Is(err, capability.ErrNotFound) {
		t.Fatalf("loser token verifier lookup error = %v, want not found", err)
	}
}

func TestLateEnrollmentIDCollision_RollsBackBeforeCapabilityConsumption(t *testing.T) {
	h := newHarness(t)
	keyA := h.seedReady(t, "por-collision-A", "partner-A", "device-A", "request-token-A", h.clock.Now().Add(time.Hour))
	keyB := h.seedReady(t, "por-collision-B", "partner-B", "device-B", "request-token-B", h.clock.Now().Add(time.Hour))

	blocked := newBarrierManager(h.store)
	svcA := h.service(t, blocked, "enr-shared", tokenOf(0x31), 0x31)
	svcB := h.service(t, h.store, "enr-shared", tokenOf(0x32), 0x32)

	errA := make(chan error, 1)
	go func() {
		_, err := svcA.CreateInitial(h.ctx, createCmd("por-collision-A", "idem-collision-A-123456"))
		errA <- err
	}()
	<-blocked.entered

	if _, err := svcB.CreateInitial(h.ctx, createCmd("por-collision-B", "idem-collision-B-123456")); err != nil {
		t.Fatalf("collision winner error = %v", err)
	}
	close(blocked.release)
	if err := <-errA; !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("late-collision loser error = %v, want ErrDependencyUnavailable", err)
	}

	recA, _ := h.authority.LookupRequestAccess(h.ctx, keyA)
	recB, _ := h.authority.LookupRequestAccess(h.ctx, keyB)
	if recA.State != capability.StateActive {
		t.Fatalf("loser capability state = %v, want ACTIVE", recA.State)
	}
	if recB.State != capability.StateConsumed {
		t.Fatalf("winner capability state = %v, want CONSUMED", recB.State)
	}
	if h.store.CountEnrollments() != 1 || h.store.CountEnrollmentAccess() != 1 || h.store.CountCreateResults() != 1 || h.store.CountIdemCommitted() != 1 || len(h.store.AuditEvents()) != 1 {
		t.Fatal("late enrollment-ID collision leaked a partial loser write-set")
	}
	if h.store.CountIdemActive() != 0 {
		t.Fatal("late enrollment-ID collision leaked active idempotency reservation")
	}
}

func TestLateEnrollmentAccessVerifierCollision_RollsBackBeforeCapabilityConsumption(t *testing.T) {
	h := newHarness(t)
	keyA := h.seedReady(t, "por-verifier-A", "partner-A", "device-A", "request-token-A", h.clock.Now().Add(time.Hour))
	keyB := h.seedReady(t, "por-verifier-B", "partner-B", "device-B", "request-token-B", h.clock.Now().Add(time.Hour))
	sharedToken := tokenOf(0x55)

	blocked := newBarrierManager(h.store)
	svcA := h.service(t, blocked, "enr-verifier-A", sharedToken, 0x41)
	svcB := h.service(t, h.store, "enr-verifier-B", sharedToken, 0x42)

	errA := make(chan error, 1)
	go func() {
		_, err := svcA.CreateInitial(h.ctx, createCmd("por-verifier-A", "idem-verifier-A-123456"))
		errA <- err
	}()
	<-blocked.entered
	if _, err := svcB.CreateInitial(h.ctx, createCmd("por-verifier-B", "idem-verifier-B-123456")); err != nil {
		t.Fatalf("verifier-collision winner error = %v", err)
	}
	close(blocked.release)
	if err := <-errA; !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("late verifier-collision loser error = %v, want ErrDependencyUnavailable", err)
	}

	recA, _ := h.authority.LookupRequestAccess(h.ctx, keyA)
	recB, _ := h.authority.LookupRequestAccess(h.ctx, keyB)
	if recA.State != capability.StateActive || recB.State != capability.StateConsumed {
		t.Fatalf("capability states loser=%v winner=%v, want ACTIVE/CONSUMED", recA.State, recB.State)
	}
	if h.store.CountEnrollments() != 1 || h.store.CountEnrollmentAccess() != 1 || h.store.CountCreateResults() != 1 || h.store.CountIdemCommitted() != 1 || len(h.store.AuditEvents()) != 1 {
		t.Fatal("late verifier collision leaked a partial loser write-set")
	}
}

func TestCommitTimePolicyDrift_FailsBeforeConsumption(t *testing.T) {
	h := newHarness(t)
	requestKey := h.seedReady(t, "por-policy", "partner-A", "device-A", "request-token-policy", h.clock.Now().Add(time.Hour))
	blocked := newBarrierManager(h.store)
	svc := h.service(t, blocked, "enr-policy", tokenOf(0x66), 0x66)

	errCh := make(chan error, 1)
	go func() {
		_, err := svc.CreateInitial(h.ctx, createCmd("por-policy", "idem-policy-123456"))
		errCh <- err
	}()
	<-blocked.entered
	if err := h.store.SetInitialPolicy("partner-A", "device-A", "PARTNER_AUTH", false, h.reqs); err != nil {
		t.Fatal(err)
	}
	close(blocked.release)
	if err := <-errCh; !errors.Is(err, application.ErrNotAuthorized) {
		t.Fatalf("policy drift error = %v, want ErrNotAuthorized", err)
	}
	rec, _ := h.authority.LookupRequestAccess(h.ctx, requestKey)
	if rec.State != capability.StateActive {
		t.Fatalf("request access state = %v, want ACTIVE after rejected commit", rec.State)
	}
	if h.store.CountEnrollments()+h.store.CountEnrollmentAccess()+h.store.CountCreateResults()+h.store.CountIdemCommitted()+len(h.store.AuditEvents()) != 0 {
		t.Fatal("policy drift published partial state")
	}
	if h.store.CountIdemActive() != 0 {
		t.Fatal("policy drift leaked active idempotency reservation")
	}
}

func TestCommitTimeRequestAccessExpiry_FailsBeforeConsumption(t *testing.T) {
	h := newHarness(t)
	requestKey := h.seedReady(t, "por-expiry", "partner-A", "device-A", "request-token-expiry", h.clock.Now().Add(10*time.Second))
	blocked := newBarrierManager(h.store)
	svc := h.service(t, blocked, "enr-expiry", tokenOf(0x77), 0x77)

	errCh := make(chan error, 1)
	go func() {
		_, err := svc.CreateInitial(h.ctx, createCmd("por-expiry", "idem-expiry-123456"))
		errCh <- err
	}()
	<-blocked.entered
	h.clock.Set(h.clock.Now().Add(20 * time.Second))
	close(blocked.release)
	if err := <-errCh; !errors.Is(err, application.ErrResourceExpired) {
		t.Fatalf("commit-time expiry error = %v, want ErrResourceExpired", err)
	}
	rec, _ := h.authority.LookupRequestAccess(h.ctx, requestKey)
	if rec.State != capability.StateActive {
		t.Fatalf("request access state = %v, want ACTIVE after expiry rollback", rec.State)
	}
	if h.store.CountEnrollments()+h.store.CountEnrollmentAccess()+h.store.CountCreateResults()+h.store.CountIdemCommitted()+len(h.store.AuditEvents()) != 0 {
		t.Fatal("commit-time expiry published partial state")
	}
}

func TestCommittedReplay_ReturnsExactSecretWithoutSecondMutation(t *testing.T) {
	h := newHarness(t)
	requestKey := h.seedReady(t, "por-replay", "partner-A", "device-A", "request-token-replay", h.clock.Now().Add(time.Hour))
	originalToken := tokenOf(0x88)
	svc := h.service(t, h.store, "enr-replay", originalToken, 0x18)
	cmd := createCmd("por-replay", "idem-replay-123456")

	first, err := svc.CreateInitial(h.ctx, cmd)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateInitial(h.ctx, cmd); !errors.Is(err, application.ErrAuthenticationRequired) {
		t.Fatalf("ordinary consumed retry error = %v, want ErrAuthenticationRequired", err)
	}
	recognizer, err := recovery.NewRecognizer(h.verifier, h.store)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := recognizer.Recognize(h.ctx, "request-token-replay")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.RecoverInitial(h.ctx, proof, application.RecoverInitialCommand{
		CertificateUsage: cmd.CertificateUsage, IdempotencyKey: cmd.IdempotencyKey, CorrelationID: cmd.CorrelationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Replay || !second.Replay {
		t.Fatalf("replay flags first=%v second=%v", first.Replay, second.Replay)
	}
	if first.EnrollmentAccessToken != originalToken || second.EnrollmentAccessToken != originalToken {
		t.Fatal("exact original EnrollmentAccessToken was not recovered")
	}
	if first.Snapshot.EnrollmentID != second.Snapshot.EnrollmentID || second.Snapshot.EnrollmentID != "enr-replay" {
		t.Fatal("replay did not return the original committed enrollment")
	}
	rec, _ := h.authority.LookupRequestAccess(h.ctx, requestKey)
	if rec.State != capability.StateConsumed {
		t.Fatalf("request access state = %v, want permanently CONSUMED", rec.State)
	}
	if h.store.CountEnrollments() != 1 || h.store.CountEnrollmentAccess() != 1 || h.store.CountCreateResults() != 1 || h.store.CountIdemCommitted() != 1 || len(h.store.AuditEvents()) != 1 {
		t.Fatal("replay produced a second mutation/audit")
	}
}

func TestCapabilityStoreIntegration_OrdinaryAuthRejectsConsumedAndEnrollmentAccessAuthenticates(t *testing.T) {
	h := newHarness(t)
	h.seedReady(t, "por-auth-integration", "partner-A", "device-A", "request-token-auth-integration", h.clock.Now().Add(time.Hour))
	eat := tokenOf(0x99)
	svc := h.service(t, h.store, "enr-auth-integration", eat, 0x29)

	requestAuth := capability.NewRequestAccessAuthenticator(h.verifier, h.store, h.clock)
	before := requestAuth.Authenticate(h.ctx, &authruntime.Credential{BearerToken: "request-token-auth-integration"})
	if before.Decision != authruntime.DecisionAuthenticated || before.Binding == nil {
		t.Fatalf("request access before exchange = %#v, want authenticated", before)
	}
	requestBinding, ok := before.Binding.RequestAccess()
	if !ok || requestBinding.PreOnboardingRequestID != "por-auth-integration" {
		t.Fatalf("request binding = %#v ok=%v", requestBinding, ok)
	}

	created, err := svc.CreateInitial(h.ctx, createCmd("por-auth-integration", "idem-auth-integration-123456"))
	if err != nil {
		t.Fatal(err)
	}
	if created.EnrollmentAccessToken != eat {
		t.Fatal("originator did not return expected EnrollmentAccessToken")
	}

	after := requestAuth.Authenticate(h.ctx, &authruntime.Credential{BearerToken: "request-token-auth-integration"})
	if after.Decision != authruntime.DecisionRejected {
		t.Fatalf("ordinary request access after exchange decision = %v, want rejected", after.Decision)
	}

	recognizer, err := recovery.NewRecognizer(h.verifier, h.store)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := recognizer.Recognize(h.ctx, "request-token-auth-integration")
	if err != nil || proof.RequestID() != "por-auth-integration" {
		t.Fatalf("consumed recovery proof request=%q err=%v", proof.RequestID(), err)
	}

	enrollmentAuth := capability.NewEnrollmentAccessAuthenticator(h.verifier, h.store, h.clock)
	eatResult := enrollmentAuth.Authenticate(h.ctx, &authruntime.Credential{BearerToken: eat})
	if eatResult.Decision != authruntime.DecisionAuthenticated || eatResult.Binding == nil {
		t.Fatalf("enrollment access auth = %#v, want authenticated", eatResult)
	}
	enrollmentBinding, ok := eatResult.Binding.EnrollmentAccess()
	if !ok || enrollmentBinding.EnrollmentID != "enr-auth-integration" {
		t.Fatalf("enrollment binding = %#v ok=%v", enrollmentBinding, ok)
	}
}

func TestSameKeyRace_OneNewOtherInProgressThenExactRecovery(t *testing.T) {
	h := newHarness(t)
	requestKey := h.seedReady(t, "por-same-key", "partner-A", "device-A", "request-token-same-key", h.clock.Now().Add(time.Hour))
	winnerManager := newBarrierManager(h.store)
	winnerSvc := h.service(t, winnerManager, "enr-same-key", tokenOf(0xA4), 0x44)
	peerSvc := h.service(t, h.store, "enr-same-key-peer", tokenOf(0xB4), 0x45)
	cmd := createCmd("por-same-key", "idem-same-key-123456")

	type outcome struct {
		result application.CreateInitialResult
		err    error
	}
	winnerCh := make(chan outcome, 1)
	go func() {
		result, err := winnerSvc.CreateInitial(h.ctx, cmd)
		winnerCh <- outcome{result: result, err: err}
	}()
	<-winnerManager.entered // winner owns the reservation and has staged the complete write-set

	_, peerErr := peerSvc.CreateInitial(h.ctx, cmd)
	var inProgress *application.InProgressError
	if !errors.As(peerErr, &inProgress) {
		t.Fatalf("same-key peer error = %v, want InProgressError", peerErr)
	}
	if h.store.CountIdemActive() != 1 {
		t.Fatalf("same-key race active reservations = %d, want exactly winner reservation", h.store.CountIdemActive())
	}
	rec, err := h.authority.LookupRequestAccess(h.ctx, requestKey)
	if err != nil || rec.State != capability.StateActive {
		t.Fatalf("capability before winner commit = %#v err=%v, want ACTIVE", rec, err)
	}
	if h.store.CountEnrollments()+h.store.CountEnrollmentAccess()+h.store.CountCreateResults()+h.store.CountIdemCommitted()+len(h.store.AuditEvents()) != 0 {
		t.Fatal("same-key IN_PROGRESS peer observed/published committed originator state before winner commit")
	}

	close(winnerManager.release)
	winner := <-winnerCh
	if winner.err != nil {
		t.Fatalf("same-key winner error = %v", winner.err)
	}
	if h.store.CountEnrollments() != 1 || h.store.CountEnrollmentAccess() != 1 || h.store.CountCreateResults() != 1 || h.store.CountIdemCommitted() != 1 || len(h.store.AuditEvents()) != 1 || h.store.CountIdemActive() != 0 {
		t.Fatal("same-key winner did not publish exactly one complete originator write-set")
	}

	rec, err = h.authority.LookupRequestAccess(h.ctx, requestKey)
	if err != nil || rec.State != capability.StateConsumed {
		t.Fatalf("capability after winner commit = %#v err=%v, want CONSUMED", rec, err)
	}
	recognizer, err := recovery.NewRecognizer(h.verifier, h.store)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := recognizer.Recognize(h.ctx, "request-token-same-key")
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := peerSvc.RecoverInitial(h.ctx, proof, application.RecoverInitialCommand{
		CertificateUsage: cmd.CertificateUsage, IdempotencyKey: cmd.IdempotencyKey, CorrelationID: "corr-recovery",
	})
	if err != nil {
		t.Fatalf("same-key committed recovery error = %v", err)
	}
	if !replayed.Replay || replayed.Snapshot.EnrollmentID != winner.result.Snapshot.EnrollmentID || replayed.EnrollmentAccessToken != winner.result.EnrollmentAccessToken {
		t.Fatalf("same-key committed recovery changed result: winner=%#v replay=%#v", winner.result, replayed)
	}
	if h.store.CountEnrollments() != 1 || h.store.CountEnrollmentAccess() != 1 || h.store.CountCreateResults() != 1 || h.store.CountIdemCommitted() != 1 || len(h.store.AuditEvents()) != 1 {
		t.Fatal("same-key recovery produced a second mutation")
	}
}

func TestCommittedReplay_RequiresCurrentEligibilityButPreservesOriginalSnapshot(t *testing.T) {
	h := newHarness(t)
	requestKey := h.seedReady(t, "por-replay-policy", "partner-A", "device-A", "request-token-replay-policy", h.clock.Now().Add(time.Hour))
	svc := h.service(t, h.store, "enr-replay-policy", tokenOf(0xA5), 0x46)
	cmd := createCmd("por-replay-policy", "idem-replay-policy-123456")
	first, err := svc.CreateInitial(h.ctx, cmd)
	if err != nil {
		t.Fatal(err)
	}
	recognizer, err := recovery.NewRecognizer(h.verifier, h.store)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := recognizer.Recognize(h.ctx, "request-token-replay-policy")
	if err != nil {
		t.Fatal(err)
	}

	if err := h.store.SetInitialPolicy("partner-A", "device-A", "PARTNER_AUTH", false, h.reqs); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RecoverInitial(h.ctx, proof, application.RecoverInitialCommand{
		CertificateUsage: cmd.CertificateUsage, IdempotencyKey: cmd.IdempotencyKey,
	}); !errors.Is(err, application.ErrNotAuthorized) {
		t.Fatalf("ineligible committed replay error = %v, want ErrNotAuthorized", err)
	}
	if h.store.CountEnrollments() != 1 || h.store.CountEnrollmentAccess() != 1 || h.store.CountCreateResults() != 1 || h.store.CountIdemCommitted() != 1 || len(h.store.AuditEvents()) != 1 {
		t.Fatal("denied replay mutated committed originator state")
	}
	rec, _ := h.authority.LookupRequestAccess(h.ctx, requestKey)
	if rec.State != capability.StateConsumed {
		t.Fatalf("denied replay changed capability state = %v", rec.State)
	}

	changed := application.EvidenceRequirements{
		TPMEvidenceProtocolVersions: []string{"test-v2"}, MinimumAssurance: "A3", AllowedKeyProfiles: []string{"future-profile"},
	}
	if err := h.store.SetInitialPolicy("partner-A", "device-A", "PARTNER_AUTH", true, changed); err != nil {
		t.Fatal(err)
	}
	replayed, err := svc.RecoverInitial(h.ctx, proof, application.RecoverInitialCommand{
		CertificateUsage: cmd.CertificateUsage, IdempotencyKey: cmd.IdempotencyKey,
	})
	if err != nil {
		t.Fatalf("eligible replay after policy update error = %v", err)
	}
	if !replayed.Replay || replayed.EnrollmentAccessToken != first.EnrollmentAccessToken || replayed.Snapshot.EvidenceRequirements.MinimumAssurance != first.Snapshot.EvidenceRequirements.MinimumAssurance || replayed.Snapshot.EvidenceRequirements.MinimumAssurance == changed.MinimumAssurance {
		t.Fatalf("replay recomputed or changed original response snapshot: first=%#v replay=%#v", first.Snapshot.EvidenceRequirements, replayed.Snapshot.EvidenceRequirements)
	}
}

func TestCommitTimeChallengeExpiry_FailsBeforeCapabilityConsumption(t *testing.T) {
	h := newHarness(t)
	requestKey := h.seedReady(t, "por-challenge-expiry", "partner-A", "device-A", "request-token-challenge-expiry", h.clock.Now().Add(time.Hour))
	blocked := newBarrierManager(h.store)
	svc := h.service(t, blocked, "enr-challenge-expiry", tokenOf(0xA6), 0x47)

	errCh := make(chan error, 1)
	go func() {
		_, err := svc.CreateInitial(h.ctx, createCmd("por-challenge-expiry", "idem-challenge-expiry-123456"))
		errCh <- err
	}()
	<-blocked.entered
	h.clock.Set(h.clock.Now().Add(31 * time.Minute)) // challenge expired; request/token/idem/EAT remain fresh
	close(blocked.release)
	if err := <-errCh; !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("challenge-expiry commit error = %v, want ErrDependencyUnavailable", err)
	}
	rec, _ := h.authority.LookupRequestAccess(h.ctx, requestKey)
	if rec.State != capability.StateActive {
		t.Fatalf("challenge-expiry rollback capability = %v, want ACTIVE", rec.State)
	}
	if h.store.CountEnrollments()+h.store.CountEnrollmentAccess()+h.store.CountCreateResults()+h.store.CountIdemCommitted()+len(h.store.AuditEvents()) != 0 || h.store.CountIdemActive() != 0 {
		t.Fatal("challenge expiry crossing commit leaked partial originator state")
	}
}

func TestCommitTimePreOnboardingExpiry_FailsBeforeCapabilityConsumption(t *testing.T) {
	h := newHarness(t)
	requestKey := h.seedReadyWithRequestExpiry(
		t, "por-request-expiry", "partner-A", "device-A", "request-token-request-expiry",
		h.clock.Now().Add(10*time.Minute), h.clock.Now().Add(time.Hour),
	)
	blocked := newBarrierManager(h.store)
	svc := h.service(t, blocked, "enr-request-expiry", tokenOf(0xA7), 0x48)

	errCh := make(chan error, 1)
	go func() {
		_, err := svc.CreateInitial(h.ctx, createCmd("por-request-expiry", "idem-request-expiry-123456"))
		errCh <- err
	}()
	<-blocked.entered
	h.clock.Set(h.clock.Now().Add(11 * time.Minute)) // request expired; token/challenge/idem/EAT remain fresh
	close(blocked.release)
	if err := <-errCh; !errors.Is(err, application.ErrResourceExpired) {
		t.Fatalf("pre-onboarding expiry commit error = %v, want ErrResourceExpired", err)
	}
	rec, _ := h.authority.LookupRequestAccess(h.ctx, requestKey)
	if rec.State != capability.StateActive {
		t.Fatalf("pre-onboarding expiry rollback capability = %v, want ACTIVE", rec.State)
	}
	if h.store.CountEnrollments()+h.store.CountEnrollmentAccess()+h.store.CountCreateResults()+h.store.CountIdemCommitted()+len(h.store.AuditEvents()) != 0 || h.store.CountIdemActive() != 0 {
		t.Fatal("pre-onboarding expiry crossing commit leaked partial originator state")
	}
}
