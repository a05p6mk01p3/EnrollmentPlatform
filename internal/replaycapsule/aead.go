package replaycapsule

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
)

// ErrTransient marks dependency failures callers may map to retryable 503.
var ErrTransient = errors.New("replay capsule: transient protector failure")

// ErrPermanent is the base sentinel for deterministic, known-permanent
// recovery-material failures (malformed envelope, key metadata invalidity,
// authenticated-integrity failure, or wrong associated data). Callers may map
// only this typed class to the non-retryable 409 replay-unavailable posture;
// unclassified errors must never be asserted as permanent loss.
var ErrPermanent = errors.New("replay capsule: permanent protector failure")

// ErrMalformedEnvelope marks a protected envelope that is structurally invalid
// or carries permanently-invalid key metadata. It is a known permanent
// recovery-material failure.
var ErrMalformedEnvelope = fmt.Errorf("%w: malformed or invalid protected envelope", ErrPermanent)

// ErrIntegrityFailure marks an authenticated encryption/integrity failure,
// including a wrong associated-data binding. It is a known permanent
// recovery-material failure.
var ErrIntegrityFailure = fmt.Errorf("%w: authenticated integrity failure", ErrPermanent)

// AEADProtector is an injected-key, authenticated-encryption Protector.
type AEADProtector struct {
	aead   cipher.AEAD
	keyID  string
	expiry func() time.Time
	random io.Reader
}

func NewAEADProtector(key []byte, keyID string, expiry func() time.Time) (*AEADProtector, error) {
	if len(key) != 32 || keyID == "" {
		return nil, fmt.Errorf("replay capsule: require 32-byte key and key id")
	}
	b, err := aes.NewCipher(append([]byte(nil), key...))
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	if expiry == nil {
		expiry = func() time.Time { return time.Time{} }
	}
	return &AEADProtector{aead: a, keyID: keyID, expiry: expiry, random: rand.Reader}, nil
}
func (p *AEADProtector) Seal(_ context.Context, plaintext, aad []byte) (*runtime.ProtectedEnvelope, error) {
	if p == nil || p.aead == nil {
		return nil, ErrTransient
	}
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := io.ReadFull(p.random, nonce); err != nil {
		return nil, fmt.Errorf("%w", ErrTransient)
	}
	ciphertext := p.aead.Seal(nil, nonce, plaintext, aad)
	return runtime.NewProtectedEnvelope(ciphertext, nonce, p.keyID, "1", p.expiry())
}
func (p *AEADProtector) Open(_ context.Context, env *runtime.ProtectedEnvelope, aad []byte) ([]byte, error) {
	if p == nil || p.aead == nil {
		return nil, ErrTransient
	}
	if env == nil || env.KeyID() != p.keyID {
		return nil, ErrMalformedEnvelope
	}
	plaintext, err := p.aead.Open(nil, env.Nonce(), env.Ciphertext(), aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIntegrityFailure, err)
	}
	return plaintext, nil
}
