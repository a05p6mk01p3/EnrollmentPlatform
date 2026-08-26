package runtime_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/replaycapsule"
)

// openFaultProtector seals normally through a real protector but can inject a
// failure on Open. It models transient protector dependency outages (the only
// transient class the in-memory AES-GCM protector cannot produce by itself).
type openFaultProtector struct {
	real      idempotencyruntime.Protector
	openErr   error
	openCalls int
}

func (p *openFaultProtector) Seal(ctx context.Context, plaintext, aad []byte) (*idempotencyruntime.ProtectedEnvelope, error) {
	return p.real.Seal(ctx, plaintext, aad)
}

func (p *openFaultProtector) Open(ctx context.Context, env *idempotencyruntime.ProtectedEnvelope, aad []byte) ([]byte, error) {
	p.openCalls++
	if p.openErr != nil {
		return nil, p.openErr
	}
	return p.real.Open(ctx, env, aad)
}

// countingProtector delegates to the real AES-GCM protector and counts Open
// calls so tests can prove the recovery path actually reached Protector.Open.
type countingProtector struct {
	real      idempotencyruntime.Protector
	openCalls int
}

func (p *countingProtector) Seal(ctx context.Context, plaintext, aad []byte) (*idempotencyruntime.ProtectedEnvelope, error) {
	return p.real.Seal(ctx, plaintext, aad)
}

func (p *countingProtector) Open(ctx context.Context, env *idempotencyruntime.ProtectedEnvelope, aad []byte) ([]byte, error) {
	p.openCalls++
	return p.real.Open(ctx, env, aad)
}

type c1Deps struct {
	store     *runtime.MemoryStore
	recorder  *runtime.MemoryAuditRecorder
	clock     *runtime.MockClock
	verifier  capability.Verifier
	protector idempotencyruntime.Protector
}

func newC1Deps(t *testing.T, now time.Time) c1Deps {
	t.Helper()
	recorder := runtime.NewMemoryAuditRecorder()
	store := runtime.NewMemoryStore(recorder)
	clock := runtime.NewMockClock(now)
	verifier, err := capability.NewHMACVerifier([]byte("capability-verifier-key-m56a-32bytes!"))
	if err != nil {
		t.Fatal(err)
	}
	real, err := replaycapsule.NewAEADProtector([]byte("replay-capsule-protector-key-32!"), "m56a", func() time.Time { return now.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	return c1Deps{store: store, recorder: recorder, clock: clock, verifier: verifier, protector: real}
}

func newC1Service(t *testing.T, d c1Deps, tokens *lifecycleCountedToken, ids *seqID, replayLifetime, idemLifetime, tokenLifetime time.Duration) *application.Service {
	t.Helper()
	svc, err := application.NewService(application.ServiceConfig{
		UOWManager:                 d.store,
		Clock:                      d.clock,
		DeviceAllocator:            runtime.DefaultDeviceAllocator{},
		PartnerAuth:                runtime.NewMemoryPartnerAuthorityChecker(),
		PartnerEligibility:         runtime.NewMemoryPartnerEligibilityChecker(),
		RetentionPolicy:            application.StaticIdempotencyRetentionPolicy{Duration: idemLifetime},
		ReplayCapsulePolicy:        application.StaticReplayCapsuleRetentionPolicy{Duration: replayLifetime},
		RequestAccessTokenLifetime: application.StaticRequestAccessTokenLifetime{Duration: tokenLifetime},
		Create: &application.CreateDependencies{
			IDGenerator:    ids,
			TokenGenerator: tokens,
			Verifier:       d.verifier,
			Protector:      d.protector,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func humanCmd(idemKey string) application.CreateOriginatorCommand {
	return application.CreateOriginatorCommand{
		CreateCommand: application.CreateCommand{
			PartnerID:     "P1",
			ClaimedDevice: domain.ClaimedDevice{Hostname: "h-c1"},
			Agent:         domain.Agent{Platform: "linux", Version: "1"},
		},
		CredentialKind:    authpolicy.CredentialKindHumanOIDC,
		CredentialBinding: "issuer|subject",
		IdempotencyKey:    idemKey,
		CorrelationID:     "corr-c1",
	}
}

func tpCmd(idemKey, tpID string) application.CreateOriginatorCommand {
	return application.CreateOriginatorCommand{
		CreateCommand: application.CreateCommand{
			PartnerID:     "P1",
			ClaimedDevice: domain.ClaimedDevice{Hostname: "h-c1-tp"},
			Agent:         domain.Agent{Platform: "linux", Version: "1"},
		},
		CredentialKind:    authpolicy.CredentialKindTemporaryPrincipalToken,
		CredentialBinding: tpID,
		IdempotencyKey:    idemKey,
		CorrelationID:     "corr-c1-tp",
	}
}

func scopeForCmd(t *testing.T, cmd application.CreateOriginatorCommand) idempotencyruntime.EffectiveScope {
	t.Helper()
	cred, err := idempotencyruntime.NewCredentialScope(cmd.CredentialKind, cmd.CredentialBinding)
	if err != nil {
		t.Fatal(err)
	}
	key, err := idempotencyruntime.NewIdempotencyKey(cmd.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := idempotencyruntime.NewEffectiveScope(cred, "POST", "/v1/pre-onboarding-requests", key)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func lookupCommittedRecord(t *testing.T, store *runtime.MemoryStore, scope idempotencyruntime.EffectiveScope) (idempotencyruntime.Record, bool) {
	t.Helper()
	uow, err := store.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer uow.Rollback(context.Background())
	rec, ok, err := uow.IdempotencyStore().Lookup(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	return rec, ok
}

type replayState struct {
	requests       int
	requestAccess  int
	createResults  int
	idemCommitted  int
	submittedAudit int
}

func captureReplayState(store *runtime.MemoryStore, recorder *runtime.MemoryAuditRecorder) replayState {
	return replayState{
		requests:       store.CountRequests(),
		requestAccess:  store.CountRequestAccess(),
		createResults:  store.CountCreateResults(),
		idemCommitted:  store.CountIdemCommitted(),
		submittedAudit: recorder.CountByType(application.AuditEventSubmitted),
	}
}

func assertReplayStateUnchanged(t *testing.T, before, after replayState) {
	t.Helper()
	if before != after {
		t.Fatalf("replay mutated state: before=%+v after=%+v", before, after)
	}
}

func assertTPQuota(t *testing.T, store *runtime.MemoryStore, tpID string, want int) {
	t.Helper()
	uow, err := store.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tpRec, ok, err := uow.TemporaryPrincipalStore().Get(context.Background(), tpID)
	uow.Rollback(context.Background())
	if err != nil || !ok {
		t.Fatal("TP record missing after replay failure")
	}
	if tpRec.CommittedSubmissions != want {
		t.Fatalf("CommittedSubmissions = %d, want %d", tpRec.CommittedSubmissions, want)
	}
}

func TestM56_C1_LifetimePolicy(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

	t.Run("A: capsule expires at replay lifetime, shorter than idempotency", func(t *testing.T) {
		d := newC1Deps(t, now)
		svc := newC1Service(t, d, &lifecycleCountedToken{}, &seqID{}, 5*time.Minute, 24*time.Hour, 30*time.Minute)
		cmd := humanCmd("idem-c1-lifetime-a")
		if _, err := svc.CreateOriginator(ctx, cmd); err != nil {
			t.Fatal(err)
		}
		rec, ok := lookupCommittedRecord(t, d.store, scopeForCmd(t, cmd))
		if !ok {
			t.Fatal("committed idempotency record missing")
		}
		if !rec.CapsuleExpiresAt.Equal(now.Add(5 * time.Minute)) {
			t.Fatalf("committed CapsuleExpiresAt = %v, want %v (replay policy)", rec.CapsuleExpiresAt, now.Add(5*time.Minute))
		}
		if !rec.ExpiresAt.Equal(now.Add(24 * time.Hour)) {
			t.Fatalf("committed record ExpiresAt = %v, want %v (idempotency retention)", rec.ExpiresAt, now.Add(24*time.Hour))
		}
		// Past the 5m capsule lifetime, well before the 24h idempotency record.
		d.clock.Advance(6 * time.Minute)
		if _, err := svc.CreateOriginator(ctx, cmd); !errors.Is(err, application.ErrIdempotencyReplayUnavailable) {
			t.Fatalf("expected ErrIdempotencyReplayUnavailable after capsule expiry, got %v", err)
		}
	})

	t.Run("B: capsule lifetime longer than idempotency is capped against the actual record", func(t *testing.T) {
		d := newC1Deps(t, now)
		svc := newC1Service(t, d, &lifecycleCountedToken{}, &seqID{}, 24*time.Hour, time.Hour, 30*time.Minute)
		cmd := humanCmd("idem-c1-lifetime-b")
		if _, err := svc.CreateOriginator(ctx, cmd); err != nil {
			t.Fatalf("NEW must succeed with a capped capsule, got %v", err)
		}
		rec, ok := lookupCommittedRecord(t, d.store, scopeForCmd(t, cmd))
		if !ok {
			t.Fatal("committed idempotency record missing")
		}
		// The cap is proven against the ACTUAL committed record, not by
		// recomputing now+retention in the test.
		if !rec.CapsuleExpiresAt.Equal(rec.ExpiresAt) {
			t.Fatalf("CapsuleExpiresAt = %v must equal record ExpiresAt = %v (capped)", rec.CapsuleExpiresAt, rec.ExpiresAt)
		}
		if !rec.ExpiresAt.Equal(now.Add(time.Hour)) {
			t.Fatalf("record ExpiresAt = %v, want %v (1h idempotency retention)", rec.ExpiresAt, now.Add(time.Hour))
		}
		d.clock.Advance(90 * time.Minute)
		if _, err := svc.CreateOriginator(ctx, cmd); !errors.Is(err, application.ErrIdempotencyReplayUnavailable) {
			t.Fatalf("expected ErrIdempotencyReplayUnavailable after idempotency expiry, got %v", err)
		}
	})

	t.Run("C: request access token lifetime stays independent", func(t *testing.T) {
		d := newC1Deps(t, now)
		svc := newC1Service(t, d, &lifecycleCountedToken{}, &seqID{}, 5*time.Minute, 24*time.Hour, 30*time.Minute)
		cmd := humanCmd("idem-c1-lifetime-c")
		res, err := svc.CreateOriginator(ctx, cmd)
		if err != nil {
			t.Fatal(err)
		}
		rec, ok := lookupCommittedRecord(t, d.store, scopeForCmd(t, cmd))
		if !ok {
			t.Fatal("committed idempotency record missing")
		}
		key, err := d.verifier.Derive(authpolicy.CredentialKindRequestAccessToken, res.RequestAccessToken)
		if err != nil {
			t.Fatal(err)
		}
		ra, err := d.store.LookupRequestAccess(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		if !ra.ExpiresAt.Equal(now.Add(30 * time.Minute)) {
			t.Fatalf("RequestAccessRecord expiry = %v, want %v (token lifetime only)", ra.ExpiresAt, now.Add(30*time.Minute))
		}
		if ra.ExpiresAt.Equal(rec.CapsuleExpiresAt) || ra.ExpiresAt.Equal(rec.ExpiresAt) {
			t.Fatalf("RequestAccessRecord expiry %v must not equal capsule expiry %v or record expiry %v", ra.ExpiresAt, rec.CapsuleExpiresAt, rec.ExpiresAt)
		}
	})
}

// commitRecordWithoutCapsule seeds a committed idempotency record and its
// create-result snapshot directly, with no protected capsule, to model
// permanent capsule loss.
func commitRecordWithoutCapsule(t *testing.T, store *runtime.MemoryStore, now time.Time, cmd application.CreateOriginatorCommand) {
	t.Helper()
	ctx := context.Background()
	fp, err := application.ComputeCreateFingerprint(cmd)
	if err != nil {
		t.Fatal(err)
	}
	scope := scopeForCmd(t, cmd)
	loc, err := idempotencyruntime.NewResultLocator("preonboarding-create:por-c1-missing")
	if err != nil {
		t.Fatal(err)
	}

	uow, err := store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.ResultStore().SaveCreateResult(ctx, loc, application.PreOnboardingCreateResultSnapshot{
		PreOnboardingRequestID: "por-c1-missing",
		PartnerID:              cmd.PartnerID,
		ExpiresAt:              now.Add(30 * time.Minute),
		Status:                 string(domain.StatePendingApproval),
		ETag:                   "etag",
		Location:               "/v1/pre-onboarding-requests/por-c1-missing",
		CommittedAt:            now,
	}); err != nil {
		t.Fatal(err)
	}
	idemStore := uow.IdempotencyStore()
	res, err := idemStore.Reserve(ctx, idempotencyruntime.ReserveRequest{
		Scope: scope, Fingerprint: fp, Now: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil || res.Status != idempotencyruntime.ReservationNew {
		t.Fatalf("fixture Reserve: status=%s err=%v", res.Status, err)
	}
	if _, err := idemStore.Commit(ctx, idempotencyruntime.CommitRequest{
		Token: res.Token, Scope: scope, Result: loc, Capsule: nil,
	}); err != nil {
		t.Fatal(err)
	}
	if err := uow.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestM56_C1_MissingCapsule(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	d := newC1Deps(t, now)
	tokens := &lifecycleCountedToken{}
	svc := newC1Service(t, d, tokens, &seqID{}, time.Hour, 24*time.Hour, 30*time.Minute)
	cmd := humanCmd("idem-c1-missing-capsule")
	commitRecordWithoutCapsule(t, d.store, now, cmd)

	_, err := svc.CreateOriginator(ctx, cmd)
	if !errors.Is(err, application.ErrIdempotencyReplayUnavailable) {
		t.Fatalf("expected ErrIdempotencyReplayUnavailable for missing capsule, got %v", err)
	}
	if tokens.GetCalls() != 0 {
		t.Fatalf("missing-capsule replay minted a replacement token: calls=%d", tokens.GetCalls())
	}
}

// recordMutator rewrites a committed idempotency record's capsule into a
// specific replay failure state while preserving the authoritative committed
// scope, fingerprint, result and record expiry.
type recordMutator func(t *testing.T, d c1Deps, scope idempotencyruntime.EffectiveScope, fp idempotencyruntime.Fingerprint, rec idempotencyruntime.Record) idempotencyruntime.Record

func mutateMissingCapsule(t *testing.T, d c1Deps, scope idempotencyruntime.EffectiveScope, fp idempotencyruntime.Fingerprint, rec idempotencyruntime.Record) idempotencyruntime.Record {
	rec.Capsule = nil
	rec.CapsuleExpiresAt = time.Time{}
	return rec
}

func mutateExpiredCapsule(now time.Time) recordMutator {
	return func(t *testing.T, d c1Deps, scope idempotencyruntime.EffectiveScope, fp idempotencyruntime.Fingerprint, rec idempotencyruntime.Record) idempotencyruntime.Record {
		orig := rec.Capsule
		past := now.Add(-time.Minute)
		env, err := idempotencyruntime.NewProtectedEnvelope(orig.Ciphertext(), orig.Nonce(), orig.KeyID(), orig.KeyVersion(), past)
		if err != nil {
			t.Fatal(err)
		}
		rec.Capsule = env
		rec.CapsuleExpiresAt = past
		return rec
	}
}

func mutateMalformedEnvelope(t *testing.T, d c1Deps, scope idempotencyruntime.EffectiveScope, fp idempotencyruntime.Fingerprint, rec idempotencyruntime.Record) idempotencyruntime.Record {
	orig := rec.Capsule
	env, err := idempotencyruntime.NewProtectedEnvelope(orig.Ciphertext(), orig.Nonce(), "wrong-key-id", orig.KeyVersion(), orig.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	rec.Capsule = env
	rec.CapsuleExpiresAt = env.ExpiresAt()
	return rec
}

func mutateTamperedCiphertext(t *testing.T, d c1Deps, scope idempotencyruntime.EffectiveScope, fp idempotencyruntime.Fingerprint, rec idempotencyruntime.Record) idempotencyruntime.Record {
	orig := rec.Capsule
	ct := orig.Ciphertext()
	ct[0] ^= 0xFF
	env, err := idempotencyruntime.NewProtectedEnvelope(ct, orig.Nonce(), orig.KeyID(), orig.KeyVersion(), orig.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	rec.Capsule = env
	rec.CapsuleExpiresAt = env.ExpiresAt()
	return rec
}

func mutateSealedWithWrongAAD(t *testing.T, d c1Deps, scope idempotencyruntime.EffectiveScope, fp idempotencyruntime.Fingerprint, rec idempotencyruntime.Record) idempotencyruntime.Record {
	aad, err := (replaycapsule.PreOnboardingAAD{ResourceID: "por-wrong-aad", Scope: scope, Fingerprint: fp}).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	env, err := d.protector.Seal(context.Background(), []byte("any-originator-secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	rec.Capsule = env
	rec.CapsuleExpiresAt = env.ExpiresAt()
	return rec
}

// TestM56_C1_NoRemintMatrix exercises every replay failure class against one
// committed TemporaryPrincipal originator operation and proves: no replacement
// token minting, no conversion back to NEW, no state mutation, no TP quota
// consumption, and no duplicate PREONBOARD_SUBMITTED. All permanent classes
// run through the REAL AES-GCM protector path (Open is reached and fails with
// a real cryptographic/metadata error); only the transient outage uses the
// documented fault seam, because the in-memory protector has no outage mode.
func TestM56_C1_NoRemintMatrix(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	tpID := "tp-c1-matrix"

	cases := []struct {
		name         string
		mutate       recordMutator
		wantErr      error
		wantOpenCall int
	}{
		{"missing", mutateMissingCapsule, application.ErrIdempotencyReplayUnavailable, 0},
		{"expired", mutateExpiredCapsule(now), application.ErrIdempotencyReplayUnavailable, 0},
		{"malformed", mutateMalformedEnvelope, application.ErrIdempotencyReplayUnavailable, 1},
		{"integrity", mutateTamperedCiphertext, application.ErrIdempotencyReplayUnavailable, 1},
		{"wrong_aad", mutateSealedWithWrongAAD, application.ErrIdempotencyReplayUnavailable, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newC1Deps(t, now)
			counting := &countingProtector{real: d.protector}
			d.protector = counting
			d.store.SeedTemporaryPrincipal(&domain.TemporaryPrincipal{
				TemporaryPrincipalID: tpID,
				PartnerID:            "P1",
				Status:               domain.TPStatusActive,
				ExpiresAt:            now.Add(time.Hour),
				MaxSubmissions:       5,
				CommittedSubmissions: 0,
			})
			tokens := &lifecycleCountedToken{}
			svc := newC1Service(t, d, tokens, &seqID{}, time.Hour, 24*time.Hour, 30*time.Minute)
			cmd := tpCmd("idem-c1-matrix-"+tc.name, tpID)

			if _, err := svc.CreateOriginator(ctx, cmd); err != nil {
				t.Fatalf("NEW failed: %v", err)
			}
			if tokens.GetCalls() != 1 {
				t.Fatalf("NEW generator calls = %d, want 1", tokens.GetCalls())
			}
			before := captureReplayState(d.store, d.recorder)

			scope := scopeForCmd(t, cmd)
			fp, err := application.ComputeCreateFingerprint(cmd)
			if err != nil {
				t.Fatal(err)
			}
			rec, ok := lookupCommittedRecord(t, d.store, scope)
			if !ok {
				t.Fatal("committed idempotency record missing")
			}
			d.store.SeedCommittedIdempotencyRecord(scope, tc.mutate(t, d, scope, fp, rec))

			if _, err := svc.CreateOriginator(ctx, cmd); !errors.Is(err, tc.wantErr) {
				t.Fatalf("replay error = %v, want %v", err, tc.wantErr)
			}
			if tokens.GetCalls() != 1 {
				t.Fatalf("replay minted a replacement token: calls=%d, want 1", tokens.GetCalls())
			}
			if counting.openCalls != tc.wantOpenCall {
				t.Fatalf("Protector.Open calls = %d, want %d", counting.openCalls, tc.wantOpenCall)
			}
			assertReplayStateUnchanged(t, before, captureReplayState(d.store, d.recorder))
			assertTPQuota(t, d.store, tpID, 1)
		})
	}
}

func TestM56_C1_NoRemintTransientOutage(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	tpID := "tp-c1-transient"

	d := newC1Deps(t, now)
	fault := &openFaultProtector{real: d.protector}
	d.protector = fault
	d.store.SeedTemporaryPrincipal(&domain.TemporaryPrincipal{
		TemporaryPrincipalID: tpID,
		PartnerID:            "P1",
		Status:               domain.TPStatusActive,
		ExpiresAt:            now.Add(time.Hour),
		MaxSubmissions:       5,
		CommittedSubmissions: 0,
	})
	tokens := &lifecycleCountedToken{}
	svc := newC1Service(t, d, tokens, &seqID{}, time.Hour, 24*time.Hour, 30*time.Minute)
	cmd := tpCmd("idem-c1-transient", tpID)

	if _, err := svc.CreateOriginator(ctx, cmd); err != nil {
		t.Fatalf("NEW failed: %v", err)
	}
	if tokens.GetCalls() != 1 {
		t.Fatalf("NEW generator calls = %d, want 1", tokens.GetCalls())
	}
	before := captureReplayState(d.store, d.recorder)

	fault.openErr = replaycapsule.ErrTransient
	if _, err := svc.CreateOriginator(ctx, cmd); !errors.Is(err, application.ErrDependencyUnavailable) {
		t.Fatalf("replay error = %v, want ErrDependencyUnavailable", err)
	}
	if tokens.GetCalls() != 1 {
		t.Fatalf("transient replay minted a replacement token: calls=%d, want 1", tokens.GetCalls())
	}
	if fault.openCalls != 1 {
		t.Fatalf("Protector.Open calls = %d, want 1", fault.openCalls)
	}
	assertReplayStateUnchanged(t, before, captureReplayState(d.store, d.recorder))
	assertTPQuota(t, d.store, tpID, 1)
}
