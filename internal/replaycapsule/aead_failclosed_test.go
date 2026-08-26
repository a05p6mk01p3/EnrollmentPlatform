package replaycapsule_test

import (
	"context"
	"errors"
	"testing"
	"time"

	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/replaycapsule"
)

func aeadFixture() (*replaycapsule.AEADProtector, func() time.Time) {
	key := []byte("test-key-32bytes-012345678901234")
	keyID := "key-1"
	expiry := func() time.Time { return time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC) }
	p, _ := replaycapsule.NewAEADProtector(key, keyID, expiry)
	return p, expiry
}

// TestAEAD_NilEnvelopeFailsClosed proves a nil envelope is rejected without a
// panic and without being classified as a transient failure.
func TestAEAD_NilEnvelopeFailsClosed(t *testing.T) {
	p, _ := aeadFixture()
	if _, err := p.Open(context.Background(), nil, []byte("aad")); err == nil {
		t.Fatal("expected error for nil envelope, got nil")
	} else if errors.Is(err, replaycapsule.ErrTransient) {
		t.Fatalf("nil envelope must not be classified transient: %v", err)
	}
}

// TestAEAD_PermanentFailuresAreNotTransient proves that integrity/metadata
// failures are distinguishable from transient dependency outages: they must
// never surface as replaycapsule.ErrTransient.
func TestAEAD_PermanentFailuresAreNotTransient(t *testing.T) {
	p, _ := aeadFixture()
	plaintext := []byte("secret-token-plaintext")
	aad := []byte("associated-data-payload")
	env, err := p.Seal(context.Background(), plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	assertNotTransient := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: expected error, got nil", name)
		}
		if errors.Is(err, replaycapsule.ErrTransient) {
			t.Fatalf("%s: must not be classified transient: %v", name, err)
		}
	}

	// wrong AAD
	_, err = p.Open(context.Background(), env, []byte("wrong-aad"))
	assertNotTransient("wrong AAD", err)

	// tampered ciphertext
	ct := env.Ciphertext()
	ct[0] ^= 0xFF
	envCT, err := idempotencyruntime.NewProtectedEnvelope(ct, env.Nonce(), env.KeyID(), env.KeyVersion(), env.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Open(context.Background(), envCT, aad)
	assertNotTransient("tampered ciphertext", err)

	// tampered nonce
	nonce := env.Nonce()
	nonce[0] ^= 0xFF
	envNonce, err := idempotencyruntime.NewProtectedEnvelope(env.Ciphertext(), nonce, env.KeyID(), env.KeyVersion(), env.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Open(context.Background(), envNonce, aad)
	assertNotTransient("tampered nonce", err)

	// wrong protection key (same key id, different key material)
	wrongProtector, err := replaycapsule.NewAEADProtector([]byte("wrong-key-32bytes-01234567890123"), "key-1", func() time.Time { return env.ExpiresAt() })
	if err != nil {
		t.Fatal(err)
	}
	_, err = wrongProtector.Open(context.Background(), env, aad)
	assertNotTransient("wrong protection key", err)

	// invalid envelope metadata (mismatched key id)
	envWrongKeyID, err := idempotencyruntime.NewProtectedEnvelope(env.Ciphertext(), env.Nonce(), "wrong-key-id", env.KeyVersion(), env.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Open(context.Background(), envWrongKeyID, aad)
	assertNotTransient("mismatched key id", err)
}

// TestAEAD_TransientSealFailureIsDistinguishable proves a seal failure from an
// injected transient source surfaces as ErrTransient (retryable), not as a
// permanent integrity failure.
func TestAEAD_TransientSealFailureIsDistinguishable(t *testing.T) {
	// A nil protector is an internal dependency failure, not a caller error.
	var p *replaycapsule.AEADProtector
	if _, err := p.Seal(context.Background(), []byte("x"), []byte("aad")); !errors.Is(err, replaycapsule.ErrTransient) {
		t.Fatalf("nil protector Seal must be transient, got %v", err)
	}
	if _, err := p.Open(context.Background(), nil, []byte("aad")); !errors.Is(err, replaycapsule.ErrTransient) {
		t.Fatalf("nil protector Open must be transient, got %v", err)
	}
}
