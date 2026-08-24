package runtime_test

import (
	"context"
	"errors"
	"testing"
	"time"

	authnpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
)

func testNow() time.Time {
	return time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
}

func testExpires(now time.Time) time.Time {
	return now.Add(time.Hour)
}

func newTestService(t *testing.T) (*runtime.Service, *runtime.MemoryStore, *testProtector) {
	t.Helper()
	return newTestServiceWithClock(t, testNow())
}

func newTestServiceWithClock(t *testing.T, now time.Time) (*runtime.Service, *runtime.MemoryStore, *testProtector) {
	t.Helper()
	store := runtime.NewMemoryStore()
	protector := newTestProtector()
	svc, err := runtime.NewService(store, protector, runtime.WithClock(fixedClock{now: now}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, store, protector
}

func reserveReq(scope runtime.EffectiveScope, fingerprint runtime.Fingerprint, now time.Time) runtime.ReserveRequest {
	return runtime.ReserveRequest{
		Scope:       scope,
		Fingerprint: fingerprint,
		Now:         now,
		ExpiresAt:   testExpires(now),
	}
}

func TestFirstReservationReturnsNewWithNonZeroOwner(t *testing.T) {
	svc, _, _ := newTestService(t)
	scope := mustEffectiveScope(t,
		mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "issuer-a|subject-a"),
		"POST", "/v1/enrollments", mustKey(t, "0123456789abcdef"))
	fp := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"INITIAL"}`))

	res, err := svc.Reserve(context.Background(), reserveReq(scope, fp, testNow()))
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if res.Status != runtime.ReservationNew {
		t.Fatalf("Status = %s, want %s", res.Status, runtime.ReservationNew)
	}
	if res.Token.IsZero() {
		t.Fatal("NEW reservation must carry a non-zero owner token")
	}
	if !res.Fingerprint.Equal(fp) {
		t.Fatal("NEW reservation fingerprint must match the requested fingerprint")
	}
}

func TestNewCommitReplayLifecycle(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	now := testNow()
	cred := mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "issuer-a|subject-a")
	scope := mustEffectiveScope(t, cred, "POST", "/v1/enrollments", mustKey(t, "0123456789abcdef"))
	fp := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"INITIAL"}`))

	res, err := svc.Reserve(ctx, reserveReq(scope, fp, now))
	if err != nil || res.Status != runtime.ReservationNew {
		t.Fatalf("first Reserve: status=%s err=%v", res.Status, err)
	}

	result := mustResult(t, "enr-123")
	record, err := svc.Commit(ctx, runtime.CommitRequest{Token: res.Token, Scope: scope, Result: result})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if record.Status != runtime.RecordCommitted {
		t.Fatalf("committed record Status = %s, want %s", record.Status, runtime.RecordCommitted)
	}
	if !record.Result.Equal(result) {
		t.Fatalf("committed result = %q, want %q", record.Result.String(), result.String())
	}

	replay, err := svc.Reserve(ctx, reserveReq(scope, fp, now))
	if err != nil {
		t.Fatalf("replay Reserve: %v", err)
	}
	if replay.Status != runtime.ReservationReplay {
		t.Fatalf("replay Status = %s, want %s", replay.Status, runtime.ReservationReplay)
	}
	if !replay.Result.Equal(result) {
		t.Fatalf("replay result = %q, want %q", replay.Result.String(), result.String())
	}
}

func TestDifferentFingerprintConflictsBeforeAndAfterCommit(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	now := testNow()
	cred := mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "issuer-a|subject-a")
	scope := mustEffectiveScope(t, cred, "POST", "/v1/enrollments", mustKey(t, "0123456789abcdef"))
	fpA := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"INITIAL"}`))
	fpB := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"RENEWAL"}`))

	res, err := svc.Reserve(ctx, reserveReq(scope, fpA, now))
	if err != nil || res.Status != runtime.ReservationNew {
		t.Fatalf("first Reserve: status=%s err=%v", res.Status, err)
	}

	conflict, err := svc.Reserve(ctx, reserveReq(scope, fpB, now))
	if err != nil {
		t.Fatalf("conflict Reserve: %v", err)
	}
	if conflict.Status != runtime.ReservationConflict {
		t.Fatalf("active conflict Status = %s, want %s", conflict.Status, runtime.ReservationConflict)
	}
	if !conflict.Fingerprint.Equal(fpA) {
		t.Fatal("conflict must report the authoritative existing fingerprint")
	}

	// After commit the different fingerprint still conflicts.
	if _, err := svc.Commit(ctx, runtime.CommitRequest{Token: res.Token, Scope: scope, Result: mustResult(t, "enr-123")}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	conflict, err = svc.Reserve(ctx, reserveReq(scope, fpB, now))
	if err != nil {
		t.Fatalf("post-commit conflict Reserve: %v", err)
	}
	if conflict.Status != runtime.ReservationConflict {
		t.Fatalf("post-commit conflict Status = %s, want %s", conflict.Status, runtime.ReservationConflict)
	}
}

func TestSameFingerprintWhileActiveIsInProgress(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	now := testNow()
	cred := mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "issuer-a|subject-a")
	scope := mustEffectiveScope(t, cred, "POST", "/v1/enrollments", mustKey(t, "0123456789abcdef"))
	fp := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"INITIAL"}`))

	if res, err := svc.Reserve(ctx, reserveReq(scope, fp, now)); err != nil || res.Status != runtime.ReservationNew {
		t.Fatalf("first Reserve: status=%s err=%v", res.Status, err)
	}

	inProgress, err := svc.Reserve(ctx, reserveReq(scope, fp, now))
	if err != nil {
		t.Fatalf("in-progress Reserve: %v", err)
	}
	if inProgress.Status != runtime.ReservationInProgress {
		t.Fatalf("in-progress Status = %s, want %s", inProgress.Status, runtime.ReservationInProgress)
	}
}

func TestCommitRejectsZeroUnknownMismatchedAndStale(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	now := testNow()
	credA := mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "issuer-a|subject-a")
	credB := mustCredentialScope(t, authnpolicy.CredentialKindAdminOIDC, "issuer-a|subject-a")
	scopeA := mustEffectiveScope(t, credA, "POST", "/v1/enrollments", mustKey(t, "0123456789abcdef"))
	scopeB := mustEffectiveScope(t, credB, "POST", "/v1/enrollments", mustKey(t, "0123456789abcdeg"))
	fpA := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"INITIAL"}`))

	resA, err := svc.Reserve(ctx, reserveReq(scopeA, fpA, now))
	if err != nil {
		t.Fatalf("Reserve A: %v", err)
	}

	result := mustResult(t, "enr-123")

	t.Run("zero token", func(t *testing.T) {
		_, err := svc.Commit(ctx, runtime.CommitRequest{Token: runtime.ReservationToken{}, Scope: scopeA, Result: result})
		if !errors.Is(err, runtime.ErrZeroReservationToken) {
			t.Fatalf("err = %v, want ErrZeroReservationToken", err)
		}
	})

	t.Run("token for different scope", func(t *testing.T) {
		_, err := svc.Commit(ctx, runtime.CommitRequest{Token: resA.Token, Scope: scopeB, Result: result})
		if !errors.Is(err, runtime.ErrReservationScopeMismatch) {
			t.Fatalf("err = %v, want ErrReservationScopeMismatch", err)
		}
	})

	// Commit scope A successfully, then the same token is stale.
	if _, err := svc.Commit(ctx, runtime.CommitRequest{Token: resA.Token, Scope: scopeA, Result: result}); err != nil {
		t.Fatalf("Commit A: %v", err)
	}
	t.Run("stale token after commit", func(t *testing.T) {
		_, err := svc.Commit(ctx, runtime.CommitRequest{Token: resA.Token, Scope: scopeA, Result: result})
		if !errors.Is(err, runtime.ErrReservationNotFound) {
			t.Fatalf("err = %v, want ErrReservationNotFound", err)
		}
	})
}

func TestDependencyFailuresAreNeverClassifications(t *testing.T) {
	protector := newTestProtector()
	svc, err := runtime.NewService(failingStore{}, protector)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	ctx := context.Background()
	now := testNow()
	scope := mustEffectiveScope(t,
		mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "issuer-a|subject-a"),
		"POST", "/v1/enrollments", mustKey(t, "0123456789abcdef"))
	fp := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"INITIAL"}`))

	res, err := svc.Reserve(ctx, reserveReq(scope, fp, now))
	if err == nil {
		t.Fatal("failing store Reserve must return an error")
	}
	if res.Status != "" {
		t.Fatalf("failing store Reserve must not return a classification, got %s", res.Status)
	}

	if _, err := svc.RecoverSecret(ctx, runtime.RecoverSecretRequest{Scope: scope, Fingerprint: fp}); err == nil {
		t.Fatal("failing store Lookup must return an error")
	}
	if protector.OpenCalls() != 0 {
		t.Fatalf("protector Open must not be called when the store fails; calls=%d", protector.OpenCalls())
	}
}

func TestStructuralIntegrity(t *testing.T) {
	store := runtime.NewMemoryStore()
	protector := newTestProtector()

	if _, err := runtime.NewService(nil, protector); !errors.Is(err, runtime.ErrNilStore) {
		t.Fatalf("nil store err = %v, want ErrNilStore", err)
	}
	if _, err := runtime.NewService(store, nil); !errors.Is(err, runtime.ErrNilProtector) {
		t.Fatalf("nil protector err = %v, want ErrNilProtector", err)
	}

	// typed-nil store via a nil interface holding a typed-nil pointer.
	var typedNilStore *runtime.MemoryStore
	if _, err := runtime.NewService(typedNilStore, protector); !errors.Is(err, runtime.ErrNilStore) {
		t.Fatalf("typed-nil store err = %v, want ErrNilStore", err)
	}

	// Zero-value store and service fail closed, never become permissive.
	var zeroStore runtime.MemoryStore
	if _, err := zeroStore.Reserve(context.Background(), reserveReq(
		mustEffectiveScope(t, mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "s"), "POST", "/v1/enrollments", mustKey(t, "0123456789abcdef")),
		mustFingerprint(t, "POST", "/v1/enrollments", nil), testNow())); !errors.Is(err, runtime.ErrUnusableStore) {
		t.Fatalf("zero store err = %v, want ErrUnusableStore", err)
	}

	var zeroService runtime.Service
	if _, err := zeroService.Reserve(context.Background(), reserveReq(
		mustEffectiveScope(t, mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "s"), "POST", "/v1/enrollments", mustKey(t, "0123456789abcdef")),
		mustFingerprint(t, "POST", "/v1/enrollments", nil), testNow())); !errors.Is(err, runtime.ErrNilStore) {
		t.Fatalf("zero service err = %v, want ErrNilStore", err)
	}
	if err := zeroService.Validate(); !errors.Is(err, runtime.ErrNilStore) {
		t.Fatalf("zero service Validate err = %v, want ErrNilStore", err)
	}
}

func TestConstructionRejectsStructurallyUnusableStore(t *testing.T) {
	protector := newTestProtector()

	// A non-nil pointer to a zero-value MemoryStore is structurally unusable
	// and must be rejected at construction, not accepted as a permissive
	// fallback.
	zeroStore := &runtime.MemoryStore{}
	if err := zeroStore.Validate(); !errors.Is(err, runtime.ErrUnusableStore) {
		t.Fatalf("zero MemoryStore.Validate err = %v, want ErrUnusableStore", err)
	}
	if _, err := runtime.NewService(zeroStore, protector); !errors.Is(err, runtime.ErrUnusableStore) {
		t.Fatalf("NewService(&MemoryStore{}) err = %v, want ErrUnusableStore", err)
	}

	// Typed-nil store.
	var typedNilStore *runtime.MemoryStore
	if _, err := runtime.NewService(typedNilStore, protector); !errors.Is(err, runtime.ErrNilStore) {
		t.Fatalf("typed-nil store err = %v, want ErrNilStore", err)
	}

	// Nil/typed-nil protector.
	validStore := runtime.NewMemoryStore()
	if _, err := runtime.NewService(validStore, nil); !errors.Is(err, runtime.ErrNilProtector) {
		t.Fatalf("nil protector err = %v, want ErrNilProtector", err)
	}
	var typedNilProtector *testProtector
	if _, err := runtime.NewService(validStore, typedNilProtector); !errors.Is(err, runtime.ErrNilProtector) {
		t.Fatalf("typed-nil protector err = %v, want ErrNilProtector", err)
	}

	// Nil clock option must be rejected (time authority is server-side).
	if _, err := runtime.NewService(validStore, protector, runtime.WithClock(nil)); !errors.Is(err, runtime.ErrNilClock) {
		t.Fatalf("nil clock err = %v, want ErrNilClock", err)
	}

	// Explicitly valid constructed dependencies are still accepted.
	svc, err := runtime.NewService(validStore, protector, runtime.WithClock(fixedClock{now: testNow()}))
	if err != nil {
		t.Fatalf("NewService with valid dependencies: %v", err)
	}
	if err := svc.Validate(); err != nil {
		t.Fatalf("Validate on valid service: %v", err)
	}
}
