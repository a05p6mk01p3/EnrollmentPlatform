package runtime_test

import (
	"context"
	"testing"

	authnpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
)

// These tests are written from an EXTERNAL package (runtime_test) to prove a
// hypothetical out-of-package Store adapter can persist and restore every
// value it must legitimately return to the Service — using only the public,
// validated, adapter-facing representations, without reflection, unsafe, or
// parsing of diagnostic String() formats.

func TestAdapterRoundTripsEffectiveScope(t *testing.T) {
	cred := mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "issuer-a|subject-a")
	key := mustKey(t, "0123456789abcdef")
	scope := mustEffectiveScope(t, cred, "POST", "/v1/enrollments", key)

	// Persist the exact components (no diagnostic string parsing).
	kindStr := string(cred.Kind())
	binding := cred.Binding()
	method := scope.Method()
	route := scope.Route()
	keyVal := scope.Key().String()

	// Restore through validated constructors.
	cred2, err := runtime.NewCredentialScope(authnpolicy.CredentialKind(kindStr), binding)
	if err != nil {
		t.Fatalf("NewCredentialScope: %v", err)
	}
	key2, err := runtime.NewIdempotencyKey(keyVal)
	if err != nil {
		t.Fatalf("NewIdempotencyKey: %v", err)
	}
	scope2, err := runtime.NewEffectiveScope(cred2, method, route, key2)
	if err != nil {
		t.Fatalf("NewEffectiveScope: %v", err)
	}
	if !scope.Equal(scope2) {
		t.Fatalf("EffectiveScope round-trip mismatch: %+v vs %+v", scope, scope2)
	}
}

func TestAdapterRoundTripsFingerprint(t *testing.T) {
	fp := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"INITIAL"}`))

	// Persist version + digest; restore via the validated constructor.
	fp2, err := runtime.NewFingerprint(fp.Version(), fp.Digest())
	if err != nil {
		t.Fatalf("NewFingerprint: %v", err)
	}
	if !fp.Equal(fp2) {
		t.Fatal("Fingerprint round-trip mismatch")
	}
	if fp2.Version() != runtime.FingerprintVersion1 {
		t.Fatalf("version = %d, want %d", fp2.Version(), runtime.FingerprintVersion1)
	}

	// Restore rejects an unknown version.
	if _, err := runtime.NewFingerprint(runtime.FingerprintVersion(999), fp.Digest()); err == nil {
		t.Fatal("NewFingerprint must reject an unsupported version")
	}
}

func TestAdapterCreatesPersistsAndRestoresReservationToken(t *testing.T) {
	// Create.
	token, err := runtime.NewReservationToken()
	if err != nil {
		t.Fatalf("NewReservationToken: %v", err)
	}
	if token.IsZero() {
		t.Fatal("created token must be non-zero")
	}

	// Persist the exact value.
	value := token.Value()
	if value == "" {
		t.Fatal("token value must be non-empty")
	}

	// Restore.
	token2, err := runtime.ReservationTokenFromString(value)
	if err != nil {
		t.Fatalf("ReservationTokenFromString: %v", err)
	}
	if !token.Equal(token2) {
		t.Fatal("ReservationToken round-trip mismatch")
	}

	// Restore rejects malformed values.
	for _, bad := range []string{"", " ", "leading space", "trail ", "bad\nnewline", "bad\tvalue"} {
		if _, err := runtime.ReservationTokenFromString(bad); err == nil {
			t.Errorf("ReservationTokenFromString(%q) must fail", bad)
		}
	}
}

// TestAdapterReconstructedValuesAreAcceptedByService proves an external Store
// can reconstruct a Reservation and a Record from persisted components and
// have the Service accept them (validated, not rejected) — i.e. the adapter
// can legitimately produce every value the Service requires.
func TestAdapterReconstructedValuesAreAcceptedByService(t *testing.T) {
	cred := mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "issuer-a|subject-a")
	key := mustKey(t, "0123456789abcdef")
	scope := mustEffectiveScope(t, cred, "POST", "/v1/enrollments", key)
	fp := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"INITIAL"}`))
	now := testNow()
	expires := testExpires(now)
	result := mustResult(t, "enr-123")

	token, err := runtime.NewReservationToken()
	if err != nil {
		t.Fatalf("NewReservationToken: %v", err)
	}

	// A reconstructed NEW Reservation.
	newRes := runtime.Reservation{Scope: scope, Status: runtime.ReservationNew, Token: token, Fingerprint: fp, ExpiresAt: expires}
	reserveStore := scriptedStore{reserveFn: func(context.Context, runtime.ReserveRequest) (runtime.Reservation, error) {
		return newRes, nil
	}}
	svc, err := runtime.NewService(reserveStore, newTestProtector(), runtime.WithClock(fixedClock{now: now}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	got, err := svc.Reserve(context.Background(), runtime.ReserveRequest{Scope: scope, Fingerprint: fp, Now: now, ExpiresAt: expires})
	if err != nil {
		t.Fatalf("Reserve rejected a reconstructed NEW reservation: %v", err)
	}
	if got.Status != runtime.ReservationNew || !got.Token.Equal(token) {
		t.Fatalf("reconstructed NEW not accepted: status=%s", got.Status)
	}

	// A reconstructed committed Record with a capsule, restored from persisted
	// components, is accepted through RecoverSecret.
	protector := newTestProtector()
	env, err := protector.Seal(context.Background(), []byte("originator-secret"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	rec := runtime.Record{
		Scope:       scope,
		Status:      runtime.RecordCommitted,
		Fingerprint: fp,
		Result:      result,
		Capsule:     env,
		CreatedAt:   now,
		ExpiresAt:   expires,
	}
	lookupStore := scriptedStore{lookupFn: func(context.Context, runtime.EffectiveScope) (runtime.Record, bool, error) {
		return rec, true, nil
	}}
	svc2, err := runtime.NewService(lookupStore, protector, runtime.WithClock(fixedClock{now: now}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	secret, err := svc2.RecoverSecret(context.Background(), runtime.RecoverSecretRequest{Scope: scope, Fingerprint: fp})
	if err != nil {
		t.Fatalf("RecoverSecret rejected a reconstructed record: %v", err)
	}
	if string(secret) != "originator-secret" {
		t.Fatalf("recovered secret = %q, want originator-secret", secret)
	}
	if protector.OpenCalls() != 1 {
		t.Fatalf("OpenCalls = %d, want 1", protector.OpenCalls())
	}

	// A reconstructed record with a mismatched scope is still rejected.
	otherCred := mustCredentialScope(t, authnpolicy.CredentialKindAdminOIDC, "issuer-a|subject-a")
	otherScope := mustEffectiveScope(t, otherCred, "POST", "/v1/enrollments", key)
	badRec := rec
	badRec.Scope = otherScope
	badStore := scriptedStore{lookupFn: func(context.Context, runtime.EffectiveScope) (runtime.Record, bool, error) {
		return badRec, true, nil
	}}
	svc3, err := runtime.NewService(badStore, newTestProtector(), runtime.WithClock(fixedClock{now: now}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if _, err := svc3.RecoverSecret(context.Background(), runtime.RecoverSecretRequest{Scope: scope, Fingerprint: fp}); err == nil {
		t.Fatal("RecoverSecret must reject a reconstructed record bound to another scope")
	}
}
