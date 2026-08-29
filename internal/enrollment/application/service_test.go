package application_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	domain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/domain/enrollment"
	application "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/recovery"
	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	preonboardingdomain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/replaycapsule"
)

type fixedClock struct{ now time.Time }

func (c *fixedClock) Now() time.Time  { return c.now }
func (c *fixedClock) Validate() error { return nil }

type fixedIDGenerator struct {
	value string
	calls int
}

func (g *fixedIDGenerator) NewEnrollmentID(context.Context) (string, error) {
	g.calls++
	return g.value, nil
}

type fixedChallengeGenerator struct {
	value []byte
	calls int
}

func (g *fixedChallengeGenerator) NewChallengeNonce(context.Context) ([]byte, error) {
	g.calls++
	return append([]byte(nil), g.value...), nil
}

type fixedTokenGenerator struct {
	value string
	calls int
}

func (g *fixedTokenGenerator) NewEnrollmentAccessToken(context.Context) (string, error) {
	g.calls++
	return g.value, nil
}

type fakeState struct {
	request          *preonboardingdomain.PreOnboardingRequest
	requestAccessKey capability.VerifierKey
	requestAccess    capability.RequestAccessRecord
	enrollments      map[string]application.EnrollmentRecord
	enrollmentAccess map[capability.VerifierKey]capability.EnrollmentAccessRecord
	results          map[string]application.CreateResultSnapshot
	idem             map[idempotencyruntime.EffectiveScope]idempotencyruntime.Record
	audits           []application.AuditEvent
}

func newFakeState(req *preonboardingdomain.PreOnboardingRequest, key capability.VerifierKey, access capability.RequestAccessRecord) *fakeState {
	return &fakeState{
		request:          req,
		requestAccessKey: key,
		requestAccess:    access,
		enrollments:      map[string]application.EnrollmentRecord{},
		enrollmentAccess: map[capability.VerifierKey]capability.EnrollmentAccessRecord{},
		results:          map[string]application.CreateResultSnapshot{},
		idem:             map[idempotencyruntime.EffectiveScope]idempotencyruntime.Record{},
	}
}

type fakeCapabilityStore struct{ state *fakeState }

func (s *fakeCapabilityStore) LookupRequestAccess(_ context.Context, key capability.VerifierKey) (*capability.RequestAccessRecord, error) {
	if s == nil || s.state == nil || key != s.state.requestAccessKey {
		return nil, capability.ErrNotFound
	}
	cp := s.state.requestAccess
	return &cp, nil
}

func (s *fakeCapabilityStore) LookupEnrollmentAccess(_ context.Context, key capability.VerifierKey) (*capability.EnrollmentAccessRecord, error) {
	if s == nil || s.state == nil {
		return nil, capability.ErrNotFound
	}
	rec, ok := s.state.enrollmentAccess[key]
	if !ok {
		return nil, capability.ErrNotFound
	}
	cp := rec
	return &cp, nil
}

func recognizeConsumed(t *testing.T, state *fakeState, bearer string) recovery.Proof {
	t.Helper()
	verifier, err := capability.NewHMACVerifier([]byte("m57-capability-verifier-key-32bytes"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := recovery.NewRecognizer(verifier, &fakeCapabilityStore{state: state})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := r.Recognize(context.Background(), bearer)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func recoveryCommand(cmd application.CreateInitialCommand) application.RecoverInitialCommand {
	return application.RecoverInitialCommand{
		CertificateUsage: cmd.CertificateUsage,
		IdempotencyKey:   cmd.IdempotencyKey,
		CorrelationID:    cmd.CorrelationID,
	}
}

type fakeUOWManager struct {
	state        *fakeState
	eligible     bool
	requirements application.EvidenceRequirements
	commitErr    error
}

func (m *fakeUOWManager) Validate() error {
	if m == nil || m.state == nil {
		return errors.New("fake uow manager unavailable")
	}
	return nil
}

func (m *fakeUOWManager) Begin(context.Context) (application.UnitOfWork, error) {
	return &fakeUOW{
		manager:                m,
		stagedEnrollments:      map[string]application.EnrollmentRecord{},
		stagedEnrollmentAccess: map[capability.VerifierKey]capability.EnrollmentAccessRecord{},
		stagedResults:          map[string]application.CreateResultSnapshot{},
	}, nil
}

type fakeUOW struct {
	manager *fakeUOWManager

	stagedRequestAccess    *application.RequestAccessCredential
	stagedEnrollments      map[string]application.EnrollmentRecord
	stagedEnrollmentAccess map[capability.VerifierKey]capability.EnrollmentAccessRecord
	stagedResults          map[string]application.CreateResultSnapshot
	stagedAudits           []application.AuditEvent
	reserveReq             *idempotencyruntime.ReserveRequest
	reserveToken           idempotencyruntime.ReservationToken
	stagedIdem             *idempotencyruntime.Record
	closed                 bool
}

func (u *fakeUOW) PreOnboarding() application.PreOnboardingReader                 { return u }
func (u *fakeUOW) RequestAccess() application.RequestAccessLifecycleStore         { return u }
func (u *fakeUOW) Enrollments() application.EnrollmentRepository                  { return u }
func (u *fakeUOW) EnrollmentAccess() application.EnrollmentAccessWriter           { return u }
func (u *fakeUOW) Results() application.ResultStore                               { return u }
func (u *fakeUOW) Eligibility() application.InitialEligibilityChecker             { return u }
func (u *fakeUOW) EvidenceRequirements() application.EvidenceRequirementsProvider { return u }
func (u *fakeUOW) Audit() application.AuditWriter                                 { return u }
func (u *fakeUOW) IdempotencyStore() idempotencyruntime.Store                     { return fakeIdemStore{u: u} }

func (u *fakeUOW) Get(_ context.Context, id preonboardingdomain.ID) (*preonboardingdomain.PreOnboardingRequest, bool, error) {
	if u.manager.state.request == nil || u.manager.state.request.ID() != id {
		return nil, false, nil
	}
	return u.manager.state.request, true, nil
}

func (u *fakeUOW) GetByPreOnboardingRequestID(_ context.Context, id string) (application.RequestAccessCredential, bool, error) {
	if u.manager.state.requestAccess.PreOnboardingRequestID != id {
		return application.RequestAccessCredential{}, false, nil
	}
	return application.RequestAccessCredential{Key: u.manager.state.requestAccessKey, Record: u.manager.state.requestAccess}, true, nil
}

func (u *fakeUOW) Save(_ context.Context, credential application.RequestAccessCredential) error {
	cp := credential
	u.stagedRequestAccess = &cp
	return nil
}

func (u *fakeUOW) Create(_ context.Context, record application.EnrollmentRecord) error {
	id := string(record.Aggregate.ID())
	if _, exists := u.manager.state.enrollments[id]; exists {
		return errors.New("duplicate enrollment")
	}
	u.stagedEnrollments[id] = record
	return nil
}

func (u *fakeUOW) GetEnrollment(_ context.Context, id string) (application.EnrollmentRecord, bool, error) {
	if rec, ok := u.stagedEnrollments[id]; ok {
		return rec, true, nil
	}
	rec, ok := u.manager.state.enrollments[id]
	return rec, ok, nil
}

func (u *fakeUOW) CreateEnrollmentAccess(_ context.Context, key capability.VerifierKey, rec capability.EnrollmentAccessRecord) error {
	if _, exists := u.manager.state.enrollmentAccess[key]; exists {
		return errors.New("duplicate enrollment access verifier")
	}
	u.stagedEnrollmentAccess[key] = rec
	return nil
}

func (u *fakeUOW) SaveCreateResult(_ context.Context, loc idempotencyruntime.ResultLocator, res application.CreateResultSnapshot) error {
	if _, exists := u.manager.state.results[loc.String()]; exists {
		return errors.New("duplicate result")
	}
	u.stagedResults[loc.String()] = res.Clone()
	return nil
}

func (u *fakeUOW) GetCreateResult(_ context.Context, loc idempotencyruntime.ResultLocator) (application.CreateResultSnapshot, bool, error) {
	res, ok := u.manager.state.results[loc.String()]
	return res.Clone(), ok, nil
}

func (u *fakeUOW) IsInitialEligible(context.Context, string, string, string) (bool, error) {
	return u.manager.eligible, nil
}

func (u *fakeUOW) InitialEvidenceRequirements(context.Context, string, string, string) (application.EvidenceRequirements, error) {
	return u.manager.requirements.Clone(), nil
}

func (u *fakeUOW) StageEvent(_ context.Context, event application.AuditEvent) error {
	u.stagedAudits = append(u.stagedAudits, event)
	return nil
}

func (u *fakeUOW) Reserve(_ context.Context, req idempotencyruntime.ReserveRequest) (idempotencyruntime.Reservation, error) {
	if rec, ok := u.manager.state.idem[req.Scope]; ok {
		if rec.Fingerprint.Equal(req.Fingerprint) {
			return idempotencyruntime.Reservation{
				Scope: req.Scope, Status: idempotencyruntime.ReservationReplay,
				Result: rec.Result, Fingerprint: rec.Fingerprint, ExpiresAt: rec.ExpiresAt,
			}, nil
		}
		return idempotencyruntime.Reservation{
			Scope: req.Scope, Status: idempotencyruntime.ReservationConflict,
			Fingerprint: rec.Fingerprint, ExpiresAt: rec.ExpiresAt,
		}, nil
	}
	token, err := idempotencyruntime.ReservationTokenFromString("m57-test-reservation")
	if err != nil {
		return idempotencyruntime.Reservation{}, err
	}
	u.reserveReq = &req
	u.reserveToken = token
	return idempotencyruntime.Reservation{
		Scope: req.Scope, Status: idempotencyruntime.ReservationNew,
		Token: token, Fingerprint: req.Fingerprint, ExpiresAt: req.ExpiresAt,
	}, nil
}

func (u *fakeUOW) Lookup(_ context.Context, scope idempotencyruntime.EffectiveScope) (idempotencyruntime.Record, bool, error) {
	if u.stagedIdem != nil && u.stagedIdem.Scope.Equal(scope) {
		return *u.stagedIdem, true, nil
	}
	rec, ok := u.manager.state.idem[scope]
	return rec, ok, nil
}

func (u *fakeUOW) Commit(ctx context.Context) error {
	if u.manager.commitErr != nil {
		u.closed = true
		return u.manager.commitErr
	}
	if u.stagedRequestAccess != nil {
		u.manager.state.requestAccessKey = u.stagedRequestAccess.Key
		u.manager.state.requestAccess = u.stagedRequestAccess.Record
	}
	for id, rec := range u.stagedEnrollments {
		u.manager.state.enrollments[id] = rec
	}
	for key, rec := range u.stagedEnrollmentAccess {
		u.manager.state.enrollmentAccess[key] = rec
	}
	for loc, res := range u.stagedResults {
		u.manager.state.results[loc] = res.Clone()
	}
	if u.stagedIdem != nil {
		u.manager.state.idem[u.stagedIdem.Scope] = *u.stagedIdem
	}
	u.manager.state.audits = append(u.manager.state.audits, u.stagedAudits...)
	u.closed = true
	return nil
}

func (u *fakeUOW) Rollback(context.Context) error {
	u.closed = true
	return nil
}

// fakeIdemStore resolves the Go method-name collision between Store.Commit and
// UnitOfWork.Commit while sharing the same transaction staging state.
type fakeIdemStore struct{ u *fakeUOW }

func (s fakeIdemStore) Reserve(ctx context.Context, req idempotencyruntime.ReserveRequest) (idempotencyruntime.Reservation, error) {
	return s.u.Reserve(ctx, req)
}

func (s fakeIdemStore) Commit(_ context.Context, req idempotencyruntime.CommitRequest) (idempotencyruntime.Record, error) {
	u := s.u
	if u.reserveReq == nil || !u.reserveToken.Equal(req.Token) || !u.reserveReq.Scope.Equal(req.Scope) {
		return idempotencyruntime.Record{}, errors.New("invalid reservation owner")
	}
	rec := idempotencyruntime.Record{
		Scope:       req.Scope,
		Fingerprint: u.reserveReq.Fingerprint,
		Status:      idempotencyruntime.RecordCommitted,
		Result:      req.Result,
		Capsule:     req.Capsule,
		CreatedAt:   u.reserveReq.Now,
		ExpiresAt:   u.reserveReq.ExpiresAt,
	}
	if req.Capsule != nil {
		rec.CapsuleExpiresAt = req.Capsule.ExpiresAt()
	}
	u.stagedIdem = &rec
	return rec, nil
}

func (s fakeIdemStore) Lookup(ctx context.Context, scope idempotencyruntime.EffectiveScope) (idempotencyruntime.Record, bool, error) {
	return s.u.Lookup(ctx, scope)
}

func buildHarness(t *testing.T, accessState capability.State) (*application.Service, *fakeState, *fixedIDGenerator, *fixedChallengeGenerator, *fixedTokenGenerator, *fixedClock, *fakeUOWManager) {
	t.Helper()
	now := time.Date(2026, 8, 28, 18, 0, 0, 0, time.UTC)
	clock := &fixedClock{now: now}

	req, err := preonboardingdomain.NewRequest(
		preonboardingdomain.ID("por-m57"), preonboardingdomain.PartnerID("P1"),
		preonboardingdomain.ClaimedDevice{Hostname: "PC-001"},
		preonboardingdomain.Agent{Platform: "windows", Version: "1.0"},
		now.Add(-time.Hour), now.Add(2*time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Approve(now.Add(-30*time.Minute), "dev-m57"); err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACVerifier([]byte("m57-capability-verifier-key-32bytes"))
	if err != nil {
		t.Fatal(err)
	}
	rqKey, err := verifier.Derive(authpolicy.CredentialKindRequestAccessToken, "request-access-secret")
	if err != nil {
		t.Fatal(err)
	}
	state := newFakeState(req, rqKey, capability.RequestAccessRecord{
		PreOnboardingRequestID: "por-m57",
		ExpiresAt:              now.Add(30 * time.Minute),
		State:                  accessState,
	})
	manager := &fakeUOWManager{
		state:    state,
		eligible: true,
		requirements: application.EvidenceRequirements{
			TPMEvidenceProtocolVersions: []string{"1"},
			MinimumAssurance:            "A2",
			AllowedKeyProfiles:          []string{"ECDSA_P256"},
		},
	}
	idGen := &fixedIDGenerator{value: "enr-m57"}
	challengeGen := &fixedChallengeGenerator{value: []byte("0123456789abcdef")}
	tokenGen := &fixedTokenGenerator{value: "enrollment-access-secret-original"}
	protector, err := replaycapsule.NewAEADProtector(
		[]byte("replay-capsule-protector-key-32!"), "m57", func() time.Time { return now.Add(time.Hour) },
	)
	if err != nil {
		t.Fatal(err)
	}

	svc, err := application.NewService(application.ServiceConfig{
		UOWManager:                    manager,
		Clock:                         clock,
		RetentionPolicy:               application.StaticIdempotencyRetentionPolicy{Duration: 24 * time.Hour},
		ReplayCapsulePolicy:           application.StaticReplayCapsuleRetentionPolicy{Duration: time.Hour},
		ChallengeLifetime:             application.StaticChallengeLifetimePolicy{Duration: 10 * time.Minute},
		EnrollmentAccessTokenLifetime: application.StaticEnrollmentAccessTokenLifetimePolicy{Duration: 2 * time.Hour},
		Create: &application.CreateDependencies{
			IDGenerator:        idGen,
			ChallengeGenerator: challengeGen,
			TokenGenerator:     tokenGen,
			Verifier:           verifier,
			Protector:          protector,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, state, idGen, challengeGen, tokenGen, clock, manager
}

type replayOpenErrorProtector struct{ err error }

func (p replayOpenErrorProtector) Seal(context.Context, []byte, []byte) (*idempotencyruntime.ProtectedEnvelope, error) {
	return nil, errors.New("replay test protector: unexpected Seal call")
}

func (p replayOpenErrorProtector) Open(context.Context, *idempotencyruntime.ProtectedEnvelope, []byte) ([]byte, error) {
	return nil, p.err
}

func buildRecoveryOnlyService(
	t *testing.T,
	manager *fakeUOWManager,
	clock *fixedClock,
	protector idempotencyruntime.Protector,
) (*application.Service, *fixedIDGenerator, *fixedChallengeGenerator, *fixedTokenGenerator) {
	t.Helper()
	verifier, err := capability.NewHMACVerifier([]byte("m57-capability-verifier-key-32bytes"))
	if err != nil {
		t.Fatal(err)
	}
	idGen := &fixedIDGenerator{value: "must-not-remint-enrollment"}
	challengeGen := &fixedChallengeGenerator{value: []byte("must-not-remint-challenge")}
	tokenGen := &fixedTokenGenerator{value: "must-not-remint-token"}
	svc, err := application.NewService(application.ServiceConfig{
		UOWManager:                    manager,
		Clock:                         clock,
		RetentionPolicy:               application.StaticIdempotencyRetentionPolicy{Duration: 24 * time.Hour},
		ReplayCapsulePolicy:           application.StaticReplayCapsuleRetentionPolicy{Duration: time.Hour},
		ChallengeLifetime:             application.StaticChallengeLifetimePolicy{Duration: 10 * time.Minute},
		EnrollmentAccessTokenLifetime: application.StaticEnrollmentAccessTokenLifetimePolicy{Duration: 2 * time.Hour},
		Create: &application.CreateDependencies{
			IDGenerator:        idGen,
			ChallengeGenerator: challengeGen,
			TokenGenerator:     tokenGen,
			Verifier:           verifier,
			Protector:          protector,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, idGen, challengeGen, tokenGen
}

func TestCreateInitial_NewCommitsSingleAtomicOriginatorResult(t *testing.T) {
	svc, state, idGen, challengeGen, tokenGen, _, _ := buildHarness(t, capability.StateActive)
	cmd := application.CreateInitialCommand{
		PreOnboardingRequestID: "por-m57",
		CertificateUsage:       "PARTNER_AUTH",
		IdempotencyKey:         "idem-m57-00000001",
		CorrelationID:          "corr-new",
	}
	got, err := svc.CreateInitial(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	if got.Replay {
		t.Fatal("NEW returned Replay=true")
	}
	if got.EnrollmentAccessToken != "enrollment-access-secret-original" {
		t.Fatalf("token = %q", got.EnrollmentAccessToken)
	}
	if got.Snapshot.State != domain.StateChallengeIssued || got.Snapshot.Operation != application.OperationInitial {
		t.Fatalf("snapshot = %#v", got.Snapshot)
	}
	if state.requestAccess.State != capability.StateConsumed {
		t.Fatalf("request access state = %v, want CONSUMED", state.requestAccess.State)
	}
	if len(state.enrollments) != 1 || len(state.enrollmentAccess) != 1 || len(state.results) != 1 || len(state.idem) != 1 {
		t.Fatalf("committed counts enrollments=%d enrollmentAccess=%d results=%d idem=%d", len(state.enrollments), len(state.enrollmentAccess), len(state.results), len(state.idem))
	}
	if len(state.audits) != 1 || state.audits[0].Type != application.AuditEventEnrollmentCreated {
		t.Fatalf("audits = %#v", state.audits)
	}
	if idGen.calls != 1 || challengeGen.calls != 1 || tokenGen.calls != 1 {
		t.Fatalf("generator calls id=%d challenge=%d token=%d", idGen.calls, challengeGen.calls, tokenGen.calls)
	}
	for _, rec := range state.enrollmentAccess {
		if rec.EnrollmentID != "enr-m57" {
			t.Fatalf("enrollment access binding = %q", rec.EnrollmentID)
		}
	}
}

func TestCreateInitial_ReplayReturnsExactSecretWithoutMutation(t *testing.T) {
	svc, state, idGen, challengeGen, tokenGen, _, _ := buildHarness(t, capability.StateActive)
	cmd := application.CreateInitialCommand{
		PreOnboardingRequestID: "por-m57",
		CertificateUsage:       "PARTNER_AUTH",
		IdempotencyKey:         "idem-m57-00000002",
		CorrelationID:          "corr-first",
	}
	first, err := svc.CreateInitial(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	cmd.CorrelationID = "corr-retry"
	if _, err := svc.CreateInitial(context.Background(), cmd); !errors.Is(err, application.ErrAuthenticationRequired) {
		t.Fatalf("ordinary consumed retry error = %v, want ErrAuthenticationRequired", err)
	}
	proof := recognizeConsumed(t, state, "request-access-secret")
	second, err := svc.RecoverInitial(context.Background(), proof, recoveryCommand(cmd))
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replay {
		t.Fatal("retry did not classify as replay")
	}
	if second.EnrollmentAccessToken != first.EnrollmentAccessToken {
		t.Fatalf("replay secret changed: first=%q second=%q", first.EnrollmentAccessToken, second.EnrollmentAccessToken)
	}
	if !reflect.DeepEqual(second.Snapshot, first.Snapshot) {
		t.Fatalf("replay snapshot changed: first=%#v second=%#v", first.Snapshot, second.Snapshot)
	}
	if len(state.enrollments) != 1 || len(state.enrollmentAccess) != 1 || len(state.results) != 1 || len(state.audits) != 1 {
		t.Fatalf("replay mutated state: enrollments=%d access=%d results=%d audits=%d", len(state.enrollments), len(state.enrollmentAccess), len(state.results), len(state.audits))
	}
	if idGen.calls != 1 || challengeGen.calls != 1 || tokenGen.calls != 1 {
		t.Fatalf("replay reran generators id=%d challenge=%d token=%d", idGen.calls, challengeGen.calls, tokenGen.calls)
	}
}

func TestCreateInitial_ConsumedDifferentKeyCannotCreateSecondEnrollment(t *testing.T) {
	svc, state, idGen, challengeGen, tokenGen, _, _ := buildHarness(t, capability.StateActive)
	firstCmd := application.CreateInitialCommand{PreOnboardingRequestID: "por-m57", CertificateUsage: "PARTNER_AUTH", IdempotencyKey: "idem-m57-00000003"}
	if _, err := svc.CreateInitial(context.Background(), firstCmd); err != nil {
		t.Fatal(err)
	}
	secondCmd := firstCmd
	secondCmd.IdempotencyKey = "idem-m57-00000004"
	_, err := svc.CreateInitial(context.Background(), secondCmd)
	if !errors.Is(err, application.ErrAuthenticationRequired) {
		t.Fatalf("different-key consumed attempt error = %v, want ErrAuthenticationRequired", err)
	}
	proof := recognizeConsumed(t, state, "request-access-secret")
	_, err = svc.RecoverInitial(context.Background(), proof, recoveryCommand(secondCmd))
	if !errors.Is(err, application.ErrAuthenticationRequired) {
		t.Fatalf("different-key recovery error = %v, want ErrAuthenticationRequired", err)
	}
	if len(state.enrollments) != 1 || len(state.enrollmentAccess) != 1 || len(state.audits) != 1 {
		t.Fatalf("different-key attempt created state: enrollments=%d access=%d audits=%d", len(state.enrollments), len(state.enrollmentAccess), len(state.audits))
	}
	if idGen.calls != 1 || challengeGen.calls != 1 || tokenGen.calls != 1 {
		t.Fatal("different-key consumed attempt reran originator generators")
	}
}

func TestCreateInitial_ReplaySurvivesClockAdvancementWithoutReactivation(t *testing.T) {
	svc, state, _, _, _, clock, _ := buildHarness(t, capability.StateActive)
	cmd := application.CreateInitialCommand{PreOnboardingRequestID: "por-m57", CertificateUsage: "PARTNER_AUTH", IdempotencyKey: "idem-m57-00000005"}
	first, err := svc.CreateInitial(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	clock.now = clock.now.Add(45 * time.Minute) // RequestAccessToken is now expired; capsule/idem still valid.
	if _, err := svc.CreateInitial(context.Background(), cmd); !errors.Is(err, application.ErrAuthenticationRequired) {
		t.Fatalf("ordinary late consumed retry error = %v, want ErrAuthenticationRequired", err)
	}
	proof := recognizeConsumed(t, state, "request-access-secret")
	second, err := svc.RecoverInitial(context.Background(), proof, recoveryCommand(cmd))
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replay || second.EnrollmentAccessToken != first.EnrollmentAccessToken {
		t.Fatalf("late replay = %#v, first token=%q", second, first.EnrollmentAccessToken)
	}
	if state.requestAccess.State != capability.StateConsumed {
		t.Fatalf("replay reactivated request access: %v", state.requestAccess.State)
	}
}

func TestCreateInitial_OuterCommitFailurePublishesNoOriginatorState(t *testing.T) {
	svc, state, _, _, _, _, manager := buildHarness(t, capability.StateActive)
	// Force the outer transaction to fail after every originator concern was staged.
	manager.commitErr = errors.New("late injected commit collision")

	_, err := svc.CreateInitial(context.Background(), application.CreateInitialCommand{
		PreOnboardingRequestID: "por-m57",
		CertificateUsage:       "PARTNER_AUTH",
		IdempotencyKey:         "idem-m57-00000006",
	})
	if !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("commit failure error = %v", err)
	}
	if state.requestAccess.State != capability.StateActive {
		t.Fatalf("request access state = %v, want ACTIVE after rollback", state.requestAccess.State)
	}
	if len(state.enrollments) != 0 || len(state.enrollmentAccess) != 0 || len(state.results) != 0 || len(state.idem) != 0 || len(state.audits) != 0 {
		t.Fatalf("partial state leaked: enrollments=%d access=%d results=%d idem=%d audits=%d", len(state.enrollments), len(state.enrollmentAccess), len(state.results), len(state.idem), len(state.audits))
	}
}

func TestRecoverInitial_RequiresMatchingAuthoritativeEnrollment(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*fakeState)
	}{
		{
			name: "missing enrollment",
			mutate: func(state *fakeState) {
				delete(state.enrollments, "enr-m57")
			},
		},
		{
			name: "mismatched partner binding",
			mutate: func(state *fakeState) {
				rec := state.enrollments["enr-m57"]
				rec.PartnerID = "different-partner"
				state.enrollments["enr-m57"] = rec
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, state, idGen, challengeGen, tokenGen, _, _ := buildHarness(t, capability.StateActive)
			cmd := application.CreateInitialCommand{
				PreOnboardingRequestID: "por-m57",
				CertificateUsage:       "PARTNER_AUTH",
				IdempotencyKey:         "idem-m57-authoritative-enrollment",
			}
			if _, err := svc.CreateInitial(context.Background(), cmd); err != nil {
				t.Fatal(err)
			}
			proof := recognizeConsumed(t, state, "request-access-secret")
			tc.mutate(state)

			if _, err := svc.RecoverInitial(context.Background(), proof, recoveryCommand(cmd)); !errors.Is(err, application.ErrIdempotencyReplayUnavailable) {
				t.Fatalf("recovery error = %v, want ErrIdempotencyReplayUnavailable", err)
			}
			if state.requestAccess.State != capability.StateConsumed {
				t.Fatalf("failed recovery changed request access state = %v", state.requestAccess.State)
			}
			if len(state.enrollmentAccess) != 1 || len(state.results) != 1 || len(state.idem) != 1 || len(state.audits) != 1 {
				t.Fatalf("failed recovery mutated committed originator state: access=%d results=%d idem=%d audits=%d", len(state.enrollmentAccess), len(state.results), len(state.idem), len(state.audits))
			}
			if idGen.calls != 1 || challengeGen.calls != 1 || tokenGen.calls != 1 {
				t.Fatalf("failed recovery reminted originator material id=%d challenge=%d token=%d", idGen.calls, challengeGen.calls, tokenGen.calls)
			}
		})
	}
}

func TestRecoverInitial_ProtectorFailureClassificationNeverRemints(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{name: "permanent", err: replaycapsule.ErrPermanent, want: application.ErrIdempotencyReplayUnavailable},
		{name: "transient", err: replaycapsule.ErrTransient, want: application.ErrDependencyUnavailable},
		{name: "unknown", err: errors.New("opaque protector backend failure"), want: application.ErrDependencyUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creator, state, _, _, _, clock, manager := buildHarness(t, capability.StateActive)
			cmd := application.CreateInitialCommand{
				PreOnboardingRequestID: "por-m57",
				CertificateUsage:       "PARTNER_AUTH",
				IdempotencyKey:         "idem-m57-protector-failure",
			}
			first, err := creator.CreateInitial(context.Background(), cmd)
			if err != nil {
				t.Fatal(err)
			}
			proof := recognizeConsumed(t, state, "request-access-secret")
			recoverySvc, idGen, challengeGen, tokenGen := buildRecoveryOnlyService(t, manager, clock, replayOpenErrorProtector{err: tc.err})

			if _, err := recoverySvc.RecoverInitial(context.Background(), proof, recoveryCommand(cmd)); !errors.Is(err, tc.want) {
				t.Fatalf("recovery error = %v, want %v", err, tc.want)
			}
			if idGen.calls != 0 || challengeGen.calls != 0 || tokenGen.calls != 0 {
				t.Fatalf("failed recovery reminted originator material id=%d challenge=%d token=%d", idGen.calls, challengeGen.calls, tokenGen.calls)
			}
			if state.requestAccess.State != capability.StateConsumed || len(state.enrollments) != 1 || len(state.enrollmentAccess) != 1 || len(state.results) != 1 || len(state.idem) != 1 || len(state.audits) != 1 {
				t.Fatal("protector failure changed committed originator state")
			}
			if first.EnrollmentAccessToken == "" {
				t.Fatal("test fixture did not issue original secret")
			}
		})
	}
}

func TestCreateInitial_ResultLocatorCollisionRollsBackWithoutConsumption(t *testing.T) {
	svc, state, idGen, challengeGen, tokenGen, _, _ := buildHarness(t, capability.StateActive)
	state.results["enrollment-create:enr-m57"] = application.CreateResultSnapshot{EnrollmentID: "preexisting-result"}

	_, err := svc.CreateInitial(context.Background(), application.CreateInitialCommand{
		PreOnboardingRequestID: "por-m57",
		CertificateUsage:       "PARTNER_AUTH",
		IdempotencyKey:         "idem-m57-result-collision",
	})
	if !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("result collision error = %v, want ErrDependencyUnavailable", err)
	}
	if state.requestAccess.State != capability.StateActive {
		t.Fatalf("result collision consumed request access = %v", state.requestAccess.State)
	}
	if len(state.enrollments) != 0 || len(state.enrollmentAccess) != 0 || len(state.idem) != 0 || len(state.audits) != 0 {
		t.Fatalf("result collision leaked partial state: enrollments=%d access=%d idem=%d audits=%d", len(state.enrollments), len(state.enrollmentAccess), len(state.idem), len(state.audits))
	}
	if got := state.results["enrollment-create:enr-m57"].EnrollmentID; got != "preexisting-result" {
		t.Fatalf("result collision overwrote preexisting result = %q", got)
	}
	if idGen.calls != 1 || challengeGen.calls != 1 || tokenGen.calls != 1 {
		t.Fatalf("unexpected generator calls id=%d challenge=%d token=%d", idGen.calls, challengeGen.calls, tokenGen.calls)
	}
}

func TestCreateInitial_PersistedStateContainsNoCredentialPlaintext(t *testing.T) {
	svc, state, _, _, _, _, _ := buildHarness(t, capability.StateActive)
	cmd := application.CreateInitialCommand{
		PreOnboardingRequestID: "por-m57",
		CertificateUsage:       "PARTNER_AUTH",
		IdempotencyKey:         "idem-m57-no-plaintext",
	}
	if _, err := svc.CreateInitial(context.Background(), cmd); err != nil {
		t.Fatal(err)
	}

	persisted := fmt.Sprintf("%#v", state)
	for _, secret := range []string{"request-access-secret", "enrollment-access-secret-original"} {
		if strings.Contains(persisted, secret) {
			t.Fatalf("persisted application state contains credential plaintext %q", secret)
		}
	}
	for _, event := range state.audits {
		audit := fmt.Sprintf("%#v", event)
		if strings.Contains(audit, "request-access-secret") || strings.Contains(audit, "enrollment-access-secret-original") {
			t.Fatalf("audit event contains credential plaintext: %s", audit)
		}
	}
}
