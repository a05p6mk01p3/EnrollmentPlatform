package runtime_test

import (
	"context"
	"errors"
	"testing"

	authnpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
)

// scriptedStore is an adversarial test Store: each method is scripted to
// return arbitrary (possibly malformed) output so the Service's fail-closed
// output validation can be proven.
type scriptedStore struct {
	reserveFn func(context.Context, runtime.ReserveRequest) (runtime.Reservation, error)
	commitFn  func(context.Context, runtime.CommitRequest) (runtime.Record, error)
	lookupFn  func(context.Context, runtime.EffectiveScope) (runtime.Record, bool, error)
}

func (s scriptedStore) Reserve(ctx context.Context, req runtime.ReserveRequest) (runtime.Reservation, error) {
	if s.reserveFn == nil {
		return runtime.Reservation{}, nil
	}
	return s.reserveFn(ctx, req)
}

func (s scriptedStore) Commit(ctx context.Context, req runtime.CommitRequest) (runtime.Record, error) {
	if s.commitFn == nil {
		return runtime.Record{}, nil
	}
	return s.commitFn(ctx, req)
}

func (s scriptedStore) Lookup(ctx context.Context, scope runtime.EffectiveScope) (runtime.Record, bool, error) {
	if s.lookupFn == nil {
		return runtime.Record{}, false, nil
	}
	return s.lookupFn(ctx, scope)
}

// adversarialFixture builds a valid scope/fingerprint/request plus an
// additional distinct fingerprint and a real non-zero owner token (obtained
// from a reference MemoryStore reservation) for malformed-output tests.
func adversarialFixture(t *testing.T) (scope runtime.EffectiveScope, fp, otherFP runtime.Fingerprint, req runtime.ReserveRequest, ownerToken runtime.ReservationToken) {
	t.Helper()
	now := testNow()
	cred := mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "issuer-a|subject-a")
	scope = mustEffectiveScope(t, cred, "POST", "/v1/enrollments", mustKey(t, "0123456789abcdef"))
	fp = mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"INITIAL"}`))
	otherFP = mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"RENEWAL"}`))
	req = reserveReq(scope, fp, now)

	res, err := runtime.NewMemoryStore().Reserve(context.Background(), req)
	if err != nil || res.Status != runtime.ReservationNew || res.Token.IsZero() {
		t.Fatalf("reference reservation failed: status=%s err=%v", res.Status, err)
	}
	return scope, fp, otherFP, req, res.Token
}

func TestServiceRejectsMalformedReserveOutputs(t *testing.T) {
	_, fp, otherFP, req, ownerToken := adversarialFixture(t)

	cases := []struct {
		name string
		res  runtime.Reservation
	}{
		{"unknown status", runtime.Reservation{Status: runtime.ReservationStatus("BOGUS")}},
		{"NEW without owner token", runtime.Reservation{Status: runtime.ReservationNew, Fingerprint: fp, ExpiresAt: req.ExpiresAt}},
		{"NEW with mismatched fingerprint", runtime.Reservation{Status: runtime.ReservationNew, Token: ownerToken, Fingerprint: otherFP, ExpiresAt: req.ExpiresAt}},
		{"NEW carrying a result", runtime.Reservation{Status: runtime.ReservationNew, Token: ownerToken, Fingerprint: fp, Result: mustResult(t, "enr-1"), ExpiresAt: req.ExpiresAt}},
		{"REPLAY carrying a token", runtime.Reservation{Status: runtime.ReservationReplay, Token: ownerToken, Result: mustResult(t, "enr-1"), Fingerprint: fp, ExpiresAt: req.ExpiresAt}},
		{"REPLAY without result", runtime.Reservation{Status: runtime.ReservationReplay, Fingerprint: fp, ExpiresAt: req.ExpiresAt}},
		{"REPLAY with mismatched fingerprint", runtime.Reservation{Status: runtime.ReservationReplay, Result: mustResult(t, "enr-1"), Fingerprint: otherFP, ExpiresAt: req.ExpiresAt}},
		{"IN_PROGRESS carrying a token", runtime.Reservation{Status: runtime.ReservationInProgress, Token: ownerToken, Fingerprint: fp, ExpiresAt: req.ExpiresAt}},
		{"IN_PROGRESS carrying a result", runtime.Reservation{Status: runtime.ReservationInProgress, Result: mustResult(t, "enr-1"), Fingerprint: fp, ExpiresAt: req.ExpiresAt}},
		{"IN_PROGRESS with mismatched fingerprint", runtime.Reservation{Status: runtime.ReservationInProgress, Fingerprint: otherFP, ExpiresAt: req.ExpiresAt}},
		{"CONFLICT carrying a token", runtime.Reservation{Status: runtime.ReservationConflict, Token: ownerToken, Fingerprint: otherFP, ExpiresAt: req.ExpiresAt}},
		{"CONFLICT carrying a result", runtime.Reservation{Status: runtime.ReservationConflict, Result: mustResult(t, "enr-1"), Fingerprint: otherFP, ExpiresAt: req.ExpiresAt}},
		{"CONFLICT without authoritative fingerprint", runtime.Reservation{Status: runtime.ReservationConflict, ExpiresAt: req.ExpiresAt}},
		{"CONFLICT with same fingerprint", runtime.Reservation{Status: runtime.ReservationConflict, Fingerprint: fp, ExpiresAt: req.ExpiresAt}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := scriptedStore{reserveFn: func(context.Context, runtime.ReserveRequest) (runtime.Reservation, error) {
				return tc.res, nil
			}}
			svc, err := runtime.NewService(store, newTestProtector(), runtime.WithClock(fixedClock{now: testNow()}))
			if err != nil {
				t.Fatalf("NewService: %v", err)
			}
			got, err := svc.Reserve(context.Background(), req)
			if !errors.Is(err, runtime.ErrMalformedStoreOutput) {
				t.Fatalf("err = %v, want ErrMalformedStoreOutput", err)
			}
			if got.Status != "" {
				t.Fatalf("malformed output must not surface a classification, got %s", got.Status)
			}
		})
	}
}

func TestMalformedNewCannotSurfaceAsExecutionAuthority(t *testing.T) {
	_, fp, _, req, _ := adversarialFixture(t)

	// A Store returning NEW with a zero token (and no error) must never
	// surface as a successful NEW classification from Service.Reserve.
	store := scriptedStore{reserveFn: func(context.Context, runtime.ReserveRequest) (runtime.Reservation, error) {
		return runtime.Reservation{Status: runtime.ReservationNew, Fingerprint: fp, ExpiresAt: req.ExpiresAt}, nil
	}}
	svc, err := runtime.NewService(store, newTestProtector(), runtime.WithClock(fixedClock{now: testNow()}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	got, err := svc.Reserve(context.Background(), req)
	if !errors.Is(err, runtime.ErrMalformedStoreOutput) {
		t.Fatalf("err = %v, want ErrMalformedStoreOutput", err)
	}
	if got.Status == runtime.ReservationNew {
		t.Fatal("malformed NEW must not surface as execution authority")
	}
}

func TestServiceRejectsMalformedCommitOutputs(t *testing.T) {
	scope, fp, _, req, ownerToken := adversarialFixture(t)
	result := mustResult(t, "enr-123")
	commitReq := runtime.CommitRequest{Token: ownerToken, Scope: scope, Result: result}

	cases := []struct {
		name string
		rec  runtime.Record
	}{
		{"non-committed status", runtime.Record{Status: runtime.RecordActive, Fingerprint: fp, Result: result, ExpiresAt: req.ExpiresAt}},
		{"unknown status", runtime.Record{Status: runtime.RecordStatus("BOGUS"), Fingerprint: fp, Result: result, ExpiresAt: req.ExpiresAt}},
		{"zero fingerprint", runtime.Record{Status: runtime.RecordCommitted, Result: result, ExpiresAt: req.ExpiresAt}},
		{"zero expiry", runtime.Record{Status: runtime.RecordCommitted, Fingerprint: fp, Result: result}},
		{"different result", runtime.Record{Status: runtime.RecordCommitted, Fingerprint: fp, Result: mustResult(t, "enr-OTHER"), ExpiresAt: req.ExpiresAt}},
		{"zero result", runtime.Record{Status: runtime.RecordCommitted, Fingerprint: fp, ExpiresAt: req.ExpiresAt}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := scriptedStore{commitFn: func(context.Context, runtime.CommitRequest) (runtime.Record, error) {
				return tc.rec, nil
			}}
			svc, err := runtime.NewService(store, newTestProtector(), runtime.WithClock(fixedClock{now: testNow()}))
			if err != nil {
				t.Fatalf("NewService: %v", err)
			}
			if _, err := svc.Commit(context.Background(), commitReq); !errors.Is(err, runtime.ErrMalformedStoreOutput) {
				t.Fatalf("err = %v, want ErrMalformedStoreOutput", err)
			}
		})
	}
}

func TestServiceRejectsMalformedLookupOutputBeforeOpen(t *testing.T) {
	scope, fp, _, req, _ := adversarialFixture(t)
	protector := newTestProtector()

	// Malformed committed record: zero result.
	store := scriptedStore{lookupFn: func(context.Context, runtime.EffectiveScope) (runtime.Record, bool, error) {
		return runtime.Record{Status: runtime.RecordCommitted, Fingerprint: fp, ExpiresAt: req.ExpiresAt}, true, nil
	}}
	svc, err := runtime.NewService(store, protector, runtime.WithClock(fixedClock{now: testNow()}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if _, err := svc.RecoverSecret(context.Background(), runtime.RecoverSecretRequest{Scope: scope, Fingerprint: fp}); !errors.Is(err, runtime.ErrMalformedStoreOutput) {
		t.Fatalf("err = %v, want ErrMalformedStoreOutput", err)
	}
	if protector.OpenCalls() != 0 {
		t.Fatalf("Open must not be called on malformed record; calls=%d", protector.OpenCalls())
	}
}

// scopePair builds two distinct effective scopes (differing credential scope)
// that share the same method, route and fingerprint. Because Fingerprint does
// NOT include credential scope or key, a malformed Store could otherwise pass
// one scope's result off as the other's.
func scopePair(t *testing.T) (scopeA, scopeB runtime.EffectiveScope, fp runtime.Fingerprint, req runtime.ReserveRequest, token runtime.ReservationToken) {
	t.Helper()
	now := testNow()
	credA := mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "issuer-a|subject-a")
	credB := mustCredentialScope(t, authnpolicy.CredentialKindAdminOIDC, "issuer-a|subject-a")
	key := mustKey(t, "0123456789abcdef")
	scopeA = mustEffectiveScope(t, credA, "POST", "/v1/enrollments", key)
	scopeB = mustEffectiveScope(t, credB, "POST", "/v1/enrollments", key)
	fp = mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"INITIAL"}`))
	req = reserveReq(scopeA, fp, now)

	res, err := runtime.NewMemoryStore().Reserve(context.Background(), req)
	if err != nil || res.Status != runtime.ReservationNew || res.Token.IsZero() {
		t.Fatalf("reference reservation failed: status=%s err=%v", res.Status, err)
	}
	return scopeA, scopeB, fp, req, res.Token
}

func TestReserveRejectsResultBoundToWrongScope(t *testing.T) {
	scopeA, scopeB, fp, req, token := scopePair(t)
	_ = scopeA

	cases := []struct {
		name string
		res  runtime.Reservation
	}{
		{"NEW bound to ScopeB", runtime.Reservation{Scope: scopeB, Status: runtime.ReservationNew, Token: token, Fingerprint: fp, ExpiresAt: req.ExpiresAt}},
		{"REPLAY bound to ScopeB", runtime.Reservation{Scope: scopeB, Status: runtime.ReservationReplay, Result: mustResult(t, "enr-1"), Fingerprint: fp, ExpiresAt: req.ExpiresAt}},
		{"IN_PROGRESS bound to ScopeB", runtime.Reservation{Scope: scopeB, Status: runtime.ReservationInProgress, Fingerprint: fp, ExpiresAt: req.ExpiresAt}},
		{"CONFLICT bound to ScopeB", runtime.Reservation{Scope: scopeB, Status: runtime.ReservationConflict, Fingerprint: mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"RENEWAL"}`)), ExpiresAt: req.ExpiresAt}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := scriptedStore{reserveFn: func(context.Context, runtime.ReserveRequest) (runtime.Reservation, error) {
				return tc.res, nil
			}}
			svc, err := runtime.NewService(store, newTestProtector(), runtime.WithClock(fixedClock{now: testNow()}))
			if err != nil {
				t.Fatalf("NewService: %v", err)
			}
			got, err := svc.Reserve(context.Background(), req)
			if !errors.Is(err, runtime.ErrMalformedStoreOutput) {
				t.Fatalf("err = %v, want ErrMalformedStoreOutput", err)
			}
			if got.Status == runtime.ReservationNew {
				t.Fatal("NEW authority must not surface from a result bound to another scope")
			}
			if got.Status != "" {
				t.Fatalf("no classification may surface, got %s", got.Status)
			}
		})
	}
}

func TestCommitRejectsRecordBoundToWrongScope(t *testing.T) {
	scopeA, scopeB, fp, req, token := scopePair(t)
	result := mustResult(t, "enr-123")
	commitReq := runtime.CommitRequest{Token: token, Scope: scopeA, Result: result}

	store := scriptedStore{commitFn: func(context.Context, runtime.CommitRequest) (runtime.Record, error) {
		return runtime.Record{Scope: scopeB, Status: runtime.RecordCommitted, Fingerprint: fp, Result: result, ExpiresAt: req.ExpiresAt}, nil
	}}
	svc, err := runtime.NewService(store, newTestProtector(), runtime.WithClock(fixedClock{now: testNow()}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if _, err := svc.Commit(context.Background(), commitReq); !errors.Is(err, runtime.ErrMalformedStoreOutput) {
		t.Fatalf("err = %v, want ErrMalformedStoreOutput", err)
	}
}

func TestRecoverSecretRejectsRecordBoundToWrongScopeWithSameFingerprint(t *testing.T) {
	scopeA, scopeB, fp, req, _ := scopePair(t)
	protector := newTestProtector()

	// A real, openable capsule whose protected envelope is valid.
	env, err := protector.Seal(context.Background(), []byte("originator-secret"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Lookup(ScopeA) returns a fully valid committed record, but bound to
	// ScopeB, with the SAME fingerprint as ScopeA. Recovery must fail closed
	// before Protector.Open even though the fingerprint matches.
	store := scriptedStore{lookupFn: func(context.Context, runtime.EffectiveScope) (runtime.Record, bool, error) {
		return runtime.Record{
			Scope:       scopeB,
			Status:      runtime.RecordCommitted,
			Fingerprint: fp,
			Result:      mustResult(t, "enr-123"),
			Capsule:     env,
			ExpiresAt:   req.ExpiresAt,
		}, true, nil
	}}
	svc, err := runtime.NewService(store, protector, runtime.WithClock(fixedClock{now: testNow()}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	got, err := svc.RecoverSecret(context.Background(), runtime.RecoverSecretRequest{Scope: scopeA, Fingerprint: fp})
	if err == nil {
		t.Fatal("RecoverSecret must fail for a record bound to another scope")
	}
	if got != nil {
		t.Fatalf("recovered secret must be nil, got %q", got)
	}
	if protector.OpenCalls() != 0 {
		t.Fatalf("Open must not be called for a record bound to another scope; calls=%d", protector.OpenCalls())
	}
}

// SOL-M5.4-001 (Test A): Lookup returns an otherwise-valid committed record
// containing a zero-value ProtectedEnvelope (or other malformed envelope).
// RecoverSecret must fail and Protector.OpenCalls() must remain zero.
func TestRecoverSecretRejectsZeroValueOrMalformedCapsuleInLookupOutputBeforeOpen(t *testing.T) {
	scope, fp, _, req, _ := adversarialFixture(t)

	cases := []struct {
		name    string
		capsule *runtime.ProtectedEnvelope
	}{
		{"zero-value ProtectedEnvelope", &runtime.ProtectedEnvelope{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			protector := newTestProtector()
			store := scriptedStore{lookupFn: func(context.Context, runtime.EffectiveScope) (runtime.Record, bool, error) {
				return runtime.Record{
					Scope:       scope,
					Status:      runtime.RecordCommitted,
					Fingerprint: fp,
					Result:      mustResult(t, "enr-123"),
					Capsule:     tc.capsule,
					ExpiresAt:   req.ExpiresAt,
				}, true, nil
			}}
			svc, err := runtime.NewService(store, protector, runtime.WithClock(fixedClock{now: testNow()}))
			if err != nil {
				t.Fatalf("NewService: %v", err)
			}
			got, err := svc.RecoverSecret(context.Background(), runtime.RecoverSecretRequest{Scope: scope, Fingerprint: fp})
			if err == nil {
				t.Fatal("RecoverSecret must fail for a record with a malformed capsule")
			}
			if !errors.Is(err, runtime.ErrMalformedStoreOutput) {
				t.Fatalf("err = %v, want ErrMalformedStoreOutput", err)
			}
			if got != nil {
				t.Fatalf("recovered secret must be nil, got %q", got)
			}
			if protector.OpenCalls() != 0 {
				t.Fatalf("Protector.Open must not be called on a malformed capsule; calls=%d", protector.OpenCalls())
			}
		})
	}
}

// SOL-M5.4-001 (Test B): CommitRequest contains a zero-value envelope (&runtime.ProtectedEnvelope{}).
// Service.Commit must reject it before Store.Commit.
// Prove no malformed record is persisted / reservation remains usable.
func TestServiceCommitRejectsZeroValueCapsuleBeforeStoreCommit(t *testing.T) {
	store := runtime.NewMemoryStore()
	protector := newTestProtector()
	svc, err := runtime.NewService(store, protector, runtime.WithClock(fixedClock{now: testNow()}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	cred := mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "issuer-a|subject-a")
	scope := mustEffectiveScope(t, cred, "POST", "/v1/enrollments", mustKey(t, "0123456789abcdef"))
	fp := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"INITIAL"}`))

	ctx := context.Background()
	res, err := svc.Reserve(ctx, reserveReq(scope, fp, testNow()))
	if err != nil || res.Status != runtime.ReservationNew {
		t.Fatalf("Reserve: status=%s err=%v", res.Status, err)
	}

	// Attempt commit with a zero-value ProtectedEnvelope.
	zeroEnv := &runtime.ProtectedEnvelope{}
	_, err = svc.Commit(ctx, runtime.CommitRequest{
		Token:   res.Token,
		Scope:   scope,
		Result:  mustResult(t, "enr-123"),
		Capsule: zeroEnv,
	})
	if err == nil {
		t.Fatal("Commit with a zero-value envelope must fail")
	}

	// Verify the reservation is still active in the store and was not corrupted.
	rec, found, err := store.Lookup(ctx, scope)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !found {
		t.Fatal("reservation record must still exist after rejected commit")
	}
	if rec.Status != runtime.RecordActive {
		t.Fatalf("record status = %s, want RecordActive", rec.Status)
	}

	// Verify the reservation remains usable: a subsequent valid commit succeeds!
	validEnv, err := protector.Seal(ctx, []byte("valid-secret"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	committedRec, err := svc.Commit(ctx, runtime.CommitRequest{
		Token:   res.Token,
		Scope:   scope,
		Result:  mustResult(t, "enr-123"),
		Capsule: validEnv,
	})
	if err != nil {
		t.Fatalf("subsequent valid Commit: %v", err)
	}
	if committedRec.Status != runtime.RecordCommitted {
		t.Fatalf("committedRec.Status = %s, want RecordCommitted", committedRec.Status)
	}
}

// SOL-M5.4-001 (Test C): Store.Commit receives a valid request but returns an
// otherwise-valid committed Record containing a zero-value envelope.
// Service.Commit must reject it as malformed Store output.
func TestServiceCommitRejectsZeroValueCapsuleInStoreCommitOutput(t *testing.T) {
	scope, fp, _, req, ownerToken := adversarialFixture(t)
	result := mustResult(t, "enr-123")
	protector := newTestProtector()

	validEnv, err := protector.Seal(context.Background(), []byte("secret"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	commitReq := runtime.CommitRequest{Token: ownerToken, Scope: scope, Result: result, Capsule: validEnv}

	store := scriptedStore{commitFn: func(context.Context, runtime.CommitRequest) (runtime.Record, error) {
		return runtime.Record{
			Scope:       scope,
			Status:      runtime.RecordCommitted,
			Fingerprint: fp,
			Result:      result,
			Capsule:     &runtime.ProtectedEnvelope{}, // zero-value envelope in store output
			ExpiresAt:   req.ExpiresAt,
		}, nil
	}}

	svc, err := runtime.NewService(store, protector, runtime.WithClock(fixedClock{now: testNow()}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	if _, err := svc.Commit(context.Background(), commitReq); !errors.Is(err, runtime.ErrMalformedStoreOutput) {
		t.Fatalf("Commit err = %v, want ErrMalformedStoreOutput", err)
	}
}
