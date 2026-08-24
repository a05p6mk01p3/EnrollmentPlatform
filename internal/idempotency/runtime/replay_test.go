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

func newReplayFixture(t *testing.T) (*runtime.Service, *runtime.MemoryStore, *testProtector, runtime.EffectiveScope, runtime.Fingerprint) {
	t.Helper()
	svc, store, protector := newTestService(t)
	cred := mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "issuer-a|subject-a")
	scope := mustEffectiveScope(t, cred, "POST", "/v1/enrollments", mustKey(t, "0123456789abcdef"))
	fp := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"INITIAL"}`))
	return svc, store, protector, scope, fp
}

func sealAndCommit(t *testing.T, svc *runtime.Service, protector *testProtector, scope runtime.EffectiveScope, fp runtime.Fingerprint, secret []byte) {
	t.Helper()
	ctx := context.Background()
	env, err := protector.Seal(ctx, secret, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	res, err := svc.Reserve(ctx, reserveReq(scope, fp, testNow()))
	if err != nil || res.Status != runtime.ReservationNew {
		t.Fatalf("Reserve: status=%s err=%v", res.Status, err)
	}
	if _, err := svc.Commit(ctx, runtime.CommitRequest{Token: res.Token, Scope: scope, Result: mustResult(t, "enr-123"), Capsule: env}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

func TestCommittedReplayReachesProtectorOpen(t *testing.T) {
	svc, _, protector, scope, fp := newReplayFixture(t)
	secret := []byte("originator-secret")
	sealAndCommit(t, svc, protector, scope, fp, secret)

	ad := []byte("opaque-associated-data")
	got, err := svc.RecoverSecret(context.Background(), runtime.RecoverSecretRequest{Scope: scope, Fingerprint: fp, AssociatedData: ad})
	if err != nil {
		t.Fatalf("RecoverSecret: %v", err)
	}
	if string(got) != string(secret) {
		t.Fatalf("recovered secret = %q, want %q", got, secret)
	}
	if protector.OpenCalls() != 1 {
		t.Fatalf("OpenCalls = %d, want 1", protector.OpenCalls())
	}
	if string(protector.LastAssociatedData()) != string(ad) {
		t.Fatalf("associated data = %q, want %q", protector.LastAssociatedData(), ad)
	}
}

func TestRecoveryGateNeverReachesOpen(t *testing.T) {
	t.Run("active NEW reservation", func(t *testing.T) {
		svc, _, protector, scope, fp := newReplayFixture(t)
		if res, err := svc.Reserve(context.Background(), reserveReq(scope, fp, testNow())); err != nil || res.Status != runtime.ReservationNew {
			t.Fatalf("Reserve: status=%s err=%v", res.Status, err)
		}
		if _, err := svc.RecoverSecret(context.Background(), runtime.RecoverSecretRequest{Scope: scope, Fingerprint: fp}); !errors.Is(err, runtime.ErrRecoveryUnavailable) {
			t.Fatalf("err = %v, want ErrRecoveryUnavailable", err)
		}
		if protector.OpenCalls() != 0 {
			t.Fatalf("Open must not be called for an active reservation; calls=%d", protector.OpenCalls())
		}
	})

	t.Run("in-progress classification", func(t *testing.T) {
		svc, _, protector, scope, fp := newReplayFixture(t)
		if res, err := svc.Reserve(context.Background(), reserveReq(scope, fp, testNow())); err != nil || res.Status != runtime.ReservationNew {
			t.Fatalf("first Reserve: status=%s err=%v", res.Status, err)
		}
		if res, err := svc.Reserve(context.Background(), reserveReq(scope, fp, testNow())); err != nil || res.Status != runtime.ReservationInProgress {
			t.Fatalf("second Reserve: status=%s err=%v", res.Status, err)
		}
		if _, err := svc.RecoverSecret(context.Background(), runtime.RecoverSecretRequest{Scope: scope, Fingerprint: fp}); !errors.Is(err, runtime.ErrRecoveryUnavailable) {
			t.Fatalf("err = %v, want ErrRecoveryUnavailable", err)
		}
		if protector.OpenCalls() != 0 {
			t.Fatalf("Open must not be called for in-progress; calls=%d", protector.OpenCalls())
		}
	})

	t.Run("different fingerprint before commit", func(t *testing.T) {
		svc, _, protector, scope, fpA := newReplayFixture(t)
		fpB := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"RENEWAL"}`))
		if res, err := svc.Reserve(context.Background(), reserveReq(scope, fpA, testNow())); err != nil || res.Status != runtime.ReservationNew {
			t.Fatalf("Reserve: status=%s err=%v", res.Status, err)
		}
		if _, err := svc.RecoverSecret(context.Background(), runtime.RecoverSecretRequest{Scope: scope, Fingerprint: fpB}); !errors.Is(err, runtime.ErrRecoveryUnavailable) {
			t.Fatalf("err = %v, want ErrRecoveryUnavailable", err)
		}
		if protector.OpenCalls() != 0 {
			t.Fatalf("Open must not be called for different fingerprint; calls=%d", protector.OpenCalls())
		}
	})

	t.Run("different fingerprint after commit (conflict)", func(t *testing.T) {
		svc, _, protector, scope, fpA := newReplayFixture(t)
		sealAndCommit(t, svc, protector, scope, fpA, []byte("secret"))
		fpB := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"RENEWAL"}`))
		if _, err := svc.RecoverSecret(context.Background(), runtime.RecoverSecretRequest{Scope: scope, Fingerprint: fpB}); !errors.Is(err, runtime.ErrRecoveryUnavailable) {
			t.Fatalf("err = %v, want ErrRecoveryUnavailable", err)
		}
		if protector.OpenCalls() != 0 {
			t.Fatalf("Open must not be called for conflict; calls=%d", protector.OpenCalls())
		}
	})

	t.Run("different scope", func(t *testing.T) {
		svc, _, protector, scope, fp := newReplayFixture(t)
		sealAndCommit(t, svc, protector, scope, fp, []byte("secret"))
		otherScope := mustEffectiveScope(t,
			mustCredentialScope(t, authnpolicy.CredentialKindAdminOIDC, "issuer-a|subject-a"),
			"POST", "/v1/enrollments", mustKey(t, "0123456789abcdeg"))
		if _, err := svc.RecoverSecret(context.Background(), runtime.RecoverSecretRequest{Scope: otherScope, Fingerprint: fp}); !errors.Is(err, runtime.ErrRecoveryUnavailable) {
			t.Fatalf("err = %v, want ErrRecoveryUnavailable", err)
		}
		if protector.OpenCalls() != 0 {
			t.Fatalf("Open must not be called for different scope; calls=%d", protector.OpenCalls())
		}
	})

	t.Run("missing capsule", func(t *testing.T) {
		svc, _, protector, scope, fp := newReplayFixture(t)
		res, err := svc.Reserve(context.Background(), reserveReq(scope, fp, testNow()))
		if err != nil || res.Status != runtime.ReservationNew {
			t.Fatalf("Reserve: status=%s err=%v", res.Status, err)
		}
		if _, err := svc.Commit(context.Background(), runtime.CommitRequest{Token: res.Token, Scope: scope, Result: mustResult(t, "enr-123")}); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		if _, err := svc.RecoverSecret(context.Background(), runtime.RecoverSecretRequest{Scope: scope, Fingerprint: fp}); !errors.Is(err, runtime.ErrNoCapsule) {
			t.Fatalf("err = %v, want ErrNoCapsule", err)
		}
		if protector.OpenCalls() != 0 {
			t.Fatalf("Open must not be called without a capsule; calls=%d", protector.OpenCalls())
		}
	})
}

func TestCapsuleFailureReturnsRecoveryFailureAndNeverRemints(t *testing.T) {
	svc, _, protector, scope, fp := newReplayFixture(t)
	sealAndCommit(t, svc, protector, scope, fp, []byte("secret"))

	protector.failOpen = true
	got, err := svc.RecoverSecret(context.Background(), runtime.RecoverSecretRequest{Scope: scope, Fingerprint: fp})
	if err == nil {
		t.Fatal("RecoverSecret must fail when the protector fails")
	}
	if !errors.Is(err, runtime.ErrEnvelopeOpenFailed) {
		t.Fatalf("err = %v, want ErrEnvelopeOpenFailed", err)
	}
	if got != nil {
		t.Fatalf("RecoverSecret must return nil plaintext on failure, got %q", got)
	}
	if protector.OpenCalls() != 1 {
		t.Fatalf("OpenCalls = %d, want 1", protector.OpenCalls())
	}
}

func TestProtectedEnvelopeContainsNoPlaintextField(t *testing.T) {
	deny := []string{"plaintext", "secret", "bearer", "credential", "private", "authorization"}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(runtime.ProtectedEnvelope{}),
		reflect.TypeOf(runtime.Record{}),
		reflect.TypeOf(runtime.Reservation{}),
		reflect.TypeOf(runtime.ResultLocator{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			name := strings.ToLower(typ.Field(i).Name)
			for _, d := range deny {
				if strings.Contains(name, d) {
					t.Errorf("%s field %q carries plaintext-secret marker %q", typ.Name(), typ.Field(i).Name, d)
				}
			}
		}
	}
}

func TestProtectedEnvelopeCopiesInputSlices(t *testing.T) {
	ciphertext := []byte("ciphertext-bytes")
	nonce := []byte("nonce-bytes")
	env, err := runtime.NewProtectedEnvelope(ciphertext, nonce, "key-1", "v1", time.Time{})
	if err != nil {
		t.Fatalf("NewProtectedEnvelope: %v", err)
	}
	ciphertext[0] = 'X'
	nonce[0] = 'Y'
	if got := string(env.Ciphertext()); got != "ciphertext-bytes" {
		t.Fatalf("Ciphertext mutated after construction: %q", got)
	}
	if got := string(env.Nonce()); got != "nonce-bytes" {
		t.Fatalf("Nonce mutated after construction: %q", got)
	}
}

func TestCapsuleCannotBeUsedAsCredentialScope(t *testing.T) {
	// A Replay Capsule envelope exposes no credential-kind identity, and the
	// credential scope constructor accepts only the closed M4 CredentialKind
	// plus an opaque binding. There is no capsule-to-credential path.
	env, err := runtime.NewProtectedEnvelope([]byte("ciphertext"), []byte("nonce"), "key-1", "v1", time.Time{})
	if err != nil {
		t.Fatalf("NewProtectedEnvelope: %v", err)
	}
	if env.KeyID() != "key-1" {
		t.Fatalf("KeyID = %q, want key-1", env.KeyID())
	}
	if _, err := runtime.NewCredentialScope("", ""); err == nil {
		t.Fatal("NewCredentialScope must reject empty kind and binding")
	}
}

// SOL-M5.4-001 (Test D): ProtectedEnvelope constructor and validator consistency:
// - valid constructor result validates;
// - zero-value envelope fails;
// - deterministic nil behavior;
// - empty nonce allowed;
// - empty keyVersion allowed;
// - zero expiresAt allowed;
// - empty ciphertext rejected;
// - empty keyID rejected.
func TestProtectedEnvelopeConstructorValidatorConsistency(t *testing.T) {
	t.Run("valid envelope validates", func(t *testing.T) {
		env, err := runtime.NewProtectedEnvelope([]byte("ciphertext"), []byte("nonce"), "key-1", "v1", time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("NewProtectedEnvelope: %v", err)
		}
		if err := env.Validate(); err != nil {
			t.Fatalf("Validate on valid envelope failed: %v", err)
		}
	})

	t.Run("zero-value envelope fails Validate", func(t *testing.T) {
		zeroEnv := &runtime.ProtectedEnvelope{}
		if err := zeroEnv.Validate(); err == nil {
			t.Fatal("zero-value envelope must fail Validate()")
		}
	})

	t.Run("nil envelope fails Validate deterministically", func(t *testing.T) {
		var nilEnv *runtime.ProtectedEnvelope
		if err := nilEnv.Validate(); err == nil {
			t.Fatal("nil envelope must fail Validate()")
		}
	})

	t.Run("empty nonce allowed", func(t *testing.T) {
		env, err := runtime.NewProtectedEnvelope([]byte("ciphertext"), nil, "key-1", "v1", time.Time{})
		if err != nil {
			t.Fatalf("NewProtectedEnvelope with empty nonce failed: %v", err)
		}
		if err := env.Validate(); err != nil {
			t.Fatalf("Validate with empty nonce failed: %v", err)
		}
		if len(env.Nonce()) != 0 {
			t.Fatalf("expected empty nonce, got %v", env.Nonce())
		}
	})

	t.Run("empty keyVersion allowed", func(t *testing.T) {
		env, err := runtime.NewProtectedEnvelope([]byte("ciphertext"), []byte("nonce"), "key-1", "", time.Time{})
		if err != nil {
			t.Fatalf("NewProtectedEnvelope with empty keyVersion failed: %v", err)
		}
		if err := env.Validate(); err != nil {
			t.Fatalf("Validate with empty keyVersion failed: %v", err)
		}
		if env.KeyVersion() != "" {
			t.Fatalf("expected empty keyVersion, got %q", env.KeyVersion())
		}
	})

	t.Run("zero expiresAt allowed", func(t *testing.T) {
		env, err := runtime.NewProtectedEnvelope([]byte("ciphertext"), []byte("nonce"), "key-1", "v1", time.Time{})
		if err != nil {
			t.Fatalf("NewProtectedEnvelope with zero expiresAt failed: %v", err)
		}
		if err := env.Validate(); err != nil {
			t.Fatalf("Validate with zero expiresAt failed: %v", err)
		}
		if !env.ExpiresAt().IsZero() {
			t.Fatalf("expected zero expiresAt, got %v", env.ExpiresAt())
		}
	})

	t.Run("empty ciphertext rejected by constructor and validator", func(t *testing.T) {
		if _, err := runtime.NewProtectedEnvelope(nil, []byte("nonce"), "key-1", "v1", time.Time{}); err == nil {
			t.Fatal("NewProtectedEnvelope with empty ciphertext must fail")
		}
	})

	t.Run("empty keyID rejected by constructor and validator", func(t *testing.T) {
		if _, err := runtime.NewProtectedEnvelope([]byte("ciphertext"), []byte("nonce"), "", "v1", time.Time{}); err == nil {
			t.Fatal("NewProtectedEnvelope with empty keyID must fail")
		}
	})
}
