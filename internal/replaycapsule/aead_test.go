package replaycapsule_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/replaycapsule"
)

func TestAEAD_RoundTrip(t *testing.T) {
	key := []byte("test-key-32bytes-012345678901234")
	keyID := "key-1"
	expiry := func() time.Time { return time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC) }

	protector, err := replaycapsule.NewAEADProtector(key, keyID, expiry)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("secret-token-plaintext")
	aad := []byte("associated-data-payload")

	// 1. Seal
	env, err := protector.Seal(context.Background(), plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}

	if env.KeyID() != keyID {
		t.Errorf("expected KeyID %s, got %s", keyID, env.KeyID())
	}
	if env.ExpiresAt() != expiry() {
		t.Errorf("expected ExpiresAt %v, got %v", expiry(), env.ExpiresAt())
	}

	// Verify ProtectedEnvelope exposes no plaintext field/accessor
	// Check by reflection that the struct has no exported fields returning plaintext
	envType := reflect.TypeOf(env).Elem()
	for i := 0; i < envType.NumField(); i++ {
		field := envType.Field(i)
		if field.PkgPath == "" { // Exported field
			t.Errorf("ProtectedEnvelope has exported field %s", field.Name)
		}
	}

	// 2. Open / Recovery
	decrypted, err := protector.Open(context.Background(), env, aad)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(decrypted, plaintext) {
		t.Fatalf("decrypted plaintext mismatch. Got %s, want %s", string(decrypted), string(plaintext))
	}
}

func TestAEAD_AdversarialTampering(t *testing.T) {
	key := []byte("test-key-32bytes-012345678901234")
	keyID := "key-1"
	expiry := func() time.Time { return time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC) }

	protector, _ := replaycapsule.NewAEADProtector(key, keyID, expiry)
	plaintext := []byte("secret-token-plaintext")
	aad := []byte("associated-data-payload")

	env, _ := protector.Seal(context.Background(), plaintext, aad)

	// 1. Wrong AAD fails
	_, err := protector.Open(context.Background(), env, []byte("wrong-aad"))
	if err == nil {
		t.Error("expected error when opening with wrong AAD, got nil")
	}

	// 2. Modified ciphertext fails
	ciphertext := env.Ciphertext()
	ciphertext[0] ^= 0xFF
	envTamperedCipher, _ := idempotencyruntime.NewProtectedEnvelope(ciphertext, env.Nonce(), env.KeyID(), env.KeyVersion(), env.ExpiresAt())
	_, err = protector.Open(context.Background(), envTamperedCipher, aad)
	if err == nil {
		t.Error("expected error with tampered ciphertext, got nil")
	}

	// 3. Modified nonce fails
	nonce := env.Nonce()
	nonce[0] ^= 0xFF
	envTamperedNonce, _ := idempotencyruntime.NewProtectedEnvelope(env.Ciphertext(), nonce, env.KeyID(), env.KeyVersion(), env.ExpiresAt())
	_, err = protector.Open(context.Background(), envTamperedNonce, aad)
	if err == nil {
		t.Error("expected error with tampered nonce, got nil")
	}

	// 4. Wrong protection key fails
	wrongKey := []byte("wrong-key-32bytes-01234567890123")
	wrongProtector, _ := replaycapsule.NewAEADProtector(wrongKey, keyID, expiry)
	_, err = wrongProtector.Open(context.Background(), env, aad)
	if err == nil {
		t.Error("expected error when opening with wrong protector key, got nil")
	}

	// 5. Malformed envelope (wrong key ID) fails closed
	wrongKeyIDEnv, _ := idempotencyruntime.NewProtectedEnvelope(env.Ciphertext(), env.Nonce(), "wrong-key-id", env.KeyVersion(), env.ExpiresAt())
	_, err = protector.Open(context.Background(), wrongKeyIDEnv, aad)
	if err == nil {
		t.Error("expected error with mismatched key id, got nil")
	}

	// 6. Defensive copy semantics
	// Mutating the slices returned by Ciphertext() and Nonce() must not modify the envelope's internal bytes
	c1 := env.Ciphertext()
	c1[0] ^= 0xFF
	c2 := env.Ciphertext()
	if c1[0] == c2[0] {
		t.Error("Ciphertext accessor did not return a defensive copy")
	}

	n1 := env.Nonce()
	n1[0] ^= 0xFF
	n2 := env.Nonce()
	if n1[0] == n2[0] {
		t.Error("Nonce accessor did not return a defensive copy")
	}
}

func TestAEAD_IndependentNonces(t *testing.T) {
	key := []byte("test-key-32bytes-012345678901234")
	keyID := "key-1"
	expiry := func() time.Time { return time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC) }

	protector, _ := replaycapsule.NewAEADProtector(key, keyID, expiry)
	plaintext := []byte("secret-token-plaintext")
	aad := []byte("associated-data-payload")

	env1, _ := protector.Seal(context.Background(), plaintext, aad)
	env2, _ := protector.Seal(context.Background(), plaintext, aad)

	// Since GCM nonces are randomly generated, they must be different for successive seals
	if reflect.DeepEqual(env1.Nonce(), env2.Nonce()) {
		t.Error("succesive seals produced identical nonces")
	}
}
