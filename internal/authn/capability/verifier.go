package capability

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
)

// VerifierKey is a non-reversible, kind-namespaced lookup key for a
// capability verifier. It is comparable and safe to use as a store key; it
// reveals nothing about the plaintext credential.
type VerifierKey string

// Verifier derives and matches non-reversible capability verifiers.
// Implementations must never retain the plaintext token and must never expose
// it through the key.
type Verifier interface {
	// Derive returns the non-reversible verifier for a token, namespaced by
	// the given CredentialKind so the same plaintext never collides across
	// credential kinds.
	Derive(kind authpolicy.CredentialKind, token string) (VerifierKey, error)
}

// HMACVerifier derives verifiers via HMAC-SHA-256 over (kind, token) using
// injected key material. It is the current implementation mechanism only: it
// is encapsulated behind the Verifier interface, key material is injected
// (never global, never hardcoded in production), and replacing it does not
// change domain or runtime semantics. It is not a new protocol requirement.
type HMACVerifier struct {
	key []byte
}

// NewHMACVerifier returns an HMACVerifier for the given key material. An
// empty key is rejected. The key is copied and never exposed.
func NewHMACVerifier(key []byte) (*HMACVerifier, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("capability: HMAC verifier requires non-empty key material")
	}
	return &HMACVerifier{key: append([]byte(nil), key...)}, nil
}

// Derive computes the kind-namespaced HMAC-SHA-256 verifier key.
func (v *HMACVerifier) Derive(kind authpolicy.CredentialKind, token string) (VerifierKey, error) {
	h := hmac.New(sha256.New, v.key)
	_, _ = h.Write([]byte(kind))
	_, _ = h.Write([]byte{0x00})
	_, _ = h.Write([]byte(token))
	return VerifierKey(hex.EncodeToString(h.Sum(nil))), nil
}
