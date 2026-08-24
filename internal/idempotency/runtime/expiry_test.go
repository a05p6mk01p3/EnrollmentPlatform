package runtime_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	authnpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
)

func expiryTime(offset time.Duration) time.Time {
	return time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC).Add(offset)
}

func expiryFixture(t *testing.T, now time.Time) (*runtime.Service, *testProtector, runtime.EffectiveScope, runtime.Fingerprint) {
	t.Helper()
	store := runtime.NewMemoryStore()
	protector := newTestProtector()
	svc, err := runtime.NewService(store, protector, runtime.WithClock(fixedClock{now: now}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	cred := mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "issuer-a|subject-a")
	scope := mustEffectiveScope(t, cred, "POST", "/v1/enrollments", mustKey(t, "0123456789abcdef"))
	fp := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"INITIAL"}`))
	return svc, protector, scope, fp
}

func TestRecoverSecretRejectsExplicitlyExpiredCapsuleBeforeOpen(t *testing.T) {
	now := expiryTime(0)
	svc, protector, scope, fp := expiryFixture(t, now)
	ctx := context.Background()

	// A protector that would otherwise successfully Open this capsule.
	protector.sealExpiresAt = expiryTime(-1 * time.Hour) // already expired

	env, err := protector.Seal(ctx, []byte("originator-secret"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	res, err := svc.Reserve(ctx, runtime.ReserveRequest{Scope: scope, Fingerprint: fp, Now: now, ExpiresAt: expiryTime(1 * time.Hour)})
	if err != nil || res.Status != runtime.ReservationNew {
		t.Fatalf("Reserve: status=%s err=%v", res.Status, err)
	}
	if _, err := svc.Commit(ctx, runtime.CommitRequest{Token: res.Token, Scope: scope, Result: mustResult(t, "enr-123"), Capsule: env}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	got, err := svc.RecoverSecret(ctx, runtime.RecoverSecretRequest{Scope: scope, Fingerprint: fp})
	if !errors.Is(err, runtime.ErrCapsuleExpired) {
		t.Fatalf("err = %v, want ErrCapsuleExpired", err)
	}
	if got != nil {
		t.Fatalf("RecoverSecret must return nil plaintext for an expired capsule, got %q", got)
	}
	if protector.OpenCalls() != 0 {
		t.Fatalf("Open must not be called for an already-expired capsule; calls=%d", protector.OpenCalls())
	}
}

func TestRecoverSecretRejectsExpiredRecordBeforeOpen(t *testing.T) {
	now := expiryTime(0)
	svc, protector, scope, fp := expiryFixture(t, now)
	ctx := context.Background()

	// Record expires one hour before the current server time.
	env, err := protector.Seal(ctx, []byte("originator-secret"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	res, err := svc.Reserve(ctx, runtime.ReserveRequest{
		Scope:       scope,
		Fingerprint: fp,
		Now:         expiryTime(-2 * time.Hour),
		ExpiresAt:   expiryTime(-1 * time.Hour),
	})
	if err != nil || res.Status != runtime.ReservationNew {
		t.Fatalf("Reserve: status=%s err=%v", res.Status, err)
	}
	if _, err := svc.Commit(ctx, runtime.CommitRequest{Token: res.Token, Scope: scope, Result: mustResult(t, "enr-123"), Capsule: env}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	got, err := svc.RecoverSecret(ctx, runtime.RecoverSecretRequest{Scope: scope, Fingerprint: fp})
	if !errors.Is(err, runtime.ErrRecordExpired) {
		t.Fatalf("err = %v, want ErrRecordExpired", err)
	}
	if got != nil {
		t.Fatalf("RecoverSecret must return nil plaintext for an expired record, got %q", got)
	}
	if protector.OpenCalls() != 0 {
		t.Fatalf("Open must not be called for an expired record; calls=%d", protector.OpenCalls())
	}
}

func TestCapsuleExpiryCannotOutliveRecordExpiry(t *testing.T) {
	now := expiryTime(0)
	store := runtime.NewMemoryStore()
	protector := newTestProtector()
	svc, err := runtime.NewService(store, protector, runtime.WithClock(fixedClock{now: now}))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	cred := mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "issuer-a|subject-a")
	scope := mustEffectiveScope(t, cred, "POST", "/v1/enrollments", mustKey(t, "0123456789abcdef"))
	fp := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"INITIAL"}`))
	ctx := context.Background()

	// Capsule expires one hour AFTER the record's expiry: structurally
	// impossible and rejected at commit, before any state is persisted.
	protector.sealExpiresAt = expiryTime(2 * time.Hour)
	env, err := protector.Seal(ctx, []byte("originator-secret"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	res, err := svc.Reserve(ctx, runtime.ReserveRequest{Scope: scope, Fingerprint: fp, Now: now, ExpiresAt: expiryTime(1 * time.Hour)})
	if err != nil || res.Status != runtime.ReservationNew {
		t.Fatalf("Reserve: status=%s err=%v", res.Status, err)
	}
	if _, err := svc.Commit(ctx, runtime.CommitRequest{Token: res.Token, Scope: scope, Result: mustResult(t, "enr-123"), Capsule: env}); !errors.Is(err, runtime.ErrCapsuleOutlivesRecord) {
		t.Fatalf("Commit err = %v, want ErrCapsuleOutlivesRecord", err)
	}

	// The rejected commit must not have consumed the reservation.
	record, found, err := store.Lookup(ctx, scope)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !found {
		t.Fatal("reservation record must still exist after a rejected commit")
	}
	if record.Status != runtime.RecordActive {
		t.Fatalf("record Status = %s, want %s", record.Status, runtime.RecordActive)
	}
}

func TestExpiredRecordNeverBecomesNew(t *testing.T) {
	now := expiryTime(0)
	svc, _, scope, fp := expiryFixture(t, now)
	ctx := context.Background()

	res, err := svc.Reserve(ctx, runtime.ReserveRequest{
		Scope:       scope,
		Fingerprint: fp,
		Now:         expiryTime(-2 * time.Hour),
		ExpiresAt:   expiryTime(-1 * time.Hour),
	})
	if err != nil || res.Status != runtime.ReservationNew {
		t.Fatalf("Reserve: status=%s err=%v", res.Status, err)
	}
	if _, err := svc.Commit(ctx, runtime.CommitRequest{Token: res.Token, Scope: scope, Result: mustResult(t, "enr-123")}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// The record is expired relative to the server clock, but expiry must
	// never reactivate it into a NEW execution authorization.
	replay, err := svc.Reserve(ctx, runtime.ReserveRequest{Scope: scope, Fingerprint: fp, Now: now, ExpiresAt: expiryTime(1 * time.Hour)})
	if err != nil {
		t.Fatalf("replay Reserve: %v", err)
	}
	if replay.Status != runtime.ReservationReplay {
		t.Fatalf("expired record Reserve status = %s, want %s (never NEW)", replay.Status, runtime.ReservationReplay)
	}

	otherFP := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"RENEWAL"}`))
	conflict, err := svc.Reserve(ctx, runtime.ReserveRequest{Scope: scope, Fingerprint: otherFP, Now: now, ExpiresAt: expiryTime(1 * time.Hour)})
	if err != nil {
		t.Fatalf("conflict Reserve: %v", err)
	}
	if conflict.Status != runtime.ReservationConflict {
		t.Fatalf("expired record different-fingerprint status = %s, want %s", conflict.Status, runtime.ReservationConflict)
	}
}

func TestRecoverSecretRequestCarriesNoClientTimeAuthority(t *testing.T) {
	typ := reflect.TypeOf(runtime.RecoverSecretRequest{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		if strings.Contains(name, "time") || strings.Contains(name, "now") || strings.Contains(name, "expiry") {
			t.Errorf("RecoverSecretRequest field %q smuggles client time authority", typ.Field(i).Name)
		}
	}
}

// SOL-M5.4-001 (Test E): Zero capsule expiry remains permitted and preserved.
func TestZeroCapsuleExpiryPermittedAndPreserved(t *testing.T) {
	now := expiryTime(0)
	svc, protector, scope, fp := expiryFixture(t, now)
	ctx := context.Background()

	// Zero capsule expiry means "no capsule expiry declared"; valid record expiry is 1 hour.
	protector.sealExpiresAt = time.Time{} // zero expiry
	env, err := protector.Seal(ctx, []byte("originator-secret"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	res, err := svc.Reserve(ctx, runtime.ReserveRequest{Scope: scope, Fingerprint: fp, Now: now, ExpiresAt: expiryTime(1 * time.Hour)})
	if err != nil || res.Status != runtime.ReservationNew {
		t.Fatalf("Reserve: status=%s err=%v", res.Status, err)
	}
	rec, err := svc.Commit(ctx, runtime.CommitRequest{Token: res.Token, Scope: scope, Result: mustResult(t, "enr-123"), Capsule: env})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if !rec.CapsuleExpiresAt.IsZero() {
		t.Fatalf("CapsuleExpiresAt = %v, want zero", rec.CapsuleExpiresAt)
	}

	got, err := svc.RecoverSecret(ctx, runtime.RecoverSecretRequest{Scope: scope, Fingerprint: fp})
	if err != nil {
		t.Fatalf("RecoverSecret: %v", err)
	}
	if string(got) != "originator-secret" {
		t.Fatalf("recovered secret = %q, want originator-secret", got)
	}
	if protector.OpenCalls() != 1 {
		t.Fatalf("OpenCalls = %d, want 1", protector.OpenCalls())
	}
}
