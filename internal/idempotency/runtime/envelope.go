package runtime

import (
	"errors"
	"time"
)

// ProtectedEnvelope is the at-rest representation of a protected Replay
// Capsule. It may contain only non-plaintext protection material: ciphertext,
// nonce/IV packaging, key identifier/version, and expiry metadata.
//
// It deliberately has NO field for originator secret plaintext, and its byte
// fields are copied on construction and access so callers cannot mutate stored
// protection material.
type ProtectedEnvelope struct {
	ciphertext []byte
	nonce      []byte
	keyID      string
	keyVersion string
	expiresAt  time.Time
}

// Validate reports whether the ProtectedEnvelope has structurally valid
// protection metadata: non-nil receiver, non-empty ciphertext, and non-empty
// key identifier.
//
// Nonce, keyVersion, and expiresAt may be empty/zero where the protector's
// packaging does not carry them.
func (e *ProtectedEnvelope) Validate() error {
	if e == nil {
		return errors.New("protected envelope: nil envelope")
	}
	if len(e.ciphertext) == 0 {
		return errors.New("protected envelope: ciphertext must be non-empty")
	}
	if e.keyID == "" {
		return errors.New("protected envelope: key identifier must be non-empty")
	}
	return nil
}

// NewProtectedEnvelope constructs a ProtectedEnvelope. It fails closed when
// the ciphertext is empty or the key identifier is empty. nonce, keyVersion,
// and expiresAt may be empty/zero where the protector's format does not carry
// them; a zero expiresAt means "no expiry declared by this envelope".
func NewProtectedEnvelope(ciphertext, nonce []byte, keyID, keyVersion string, expiresAt time.Time) (*ProtectedEnvelope, error) {
	env := &ProtectedEnvelope{
		ciphertext: append([]byte(nil), ciphertext...),
		nonce:      append([]byte(nil), nonce...),
		keyID:      keyID,
		keyVersion: keyVersion,
		expiresAt:  expiresAt,
	}
	if err := env.Validate(); err != nil {
		return nil, err
	}
	return env, nil
}

// Ciphertext returns a defensive copy of the ciphertext.
func (e *ProtectedEnvelope) Ciphertext() []byte {
	if e == nil {
		return nil
	}
	return append([]byte(nil), e.ciphertext...)
}

// Nonce returns a defensive copy of the nonce/IV packaging.
func (e *ProtectedEnvelope) Nonce() []byte {
	if e == nil {
		return nil
	}
	return append([]byte(nil), e.nonce...)
}

// KeyID returns the key identifier.
func (e *ProtectedEnvelope) KeyID() string {
	if e == nil {
		return ""
	}
	return e.keyID
}

// KeyVersion returns the key version.
func (e *ProtectedEnvelope) KeyVersion() string {
	if e == nil {
		return ""
	}
	return e.keyVersion
}

// ExpiresAt returns the envelope expiry metadata. A zero value means the
// envelope declares no expiry; interpretation belongs to the protector.
func (e *ProtectedEnvelope) ExpiresAt() time.Time {
	if e == nil {
		return time.Time{}
	}
	return e.expiresAt
}

// clone returns a deep copy of the envelope, or nil when e is nil.
func (e *ProtectedEnvelope) clone() *ProtectedEnvelope {
	if e == nil {
		return nil
	}
	return &ProtectedEnvelope{
		ciphertext: append([]byte(nil), e.ciphertext...),
		nonce:      append([]byte(nil), e.nonce...),
		keyID:      e.keyID,
		keyVersion: e.keyVersion,
		expiresAt:  e.expiresAt,
	}
}
