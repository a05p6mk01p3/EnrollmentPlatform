// Package runtime hosts the provider-neutral idempotency coordination and
// replay-safety kernel (M5.4). It models the immutable value types (key,
// scope, fingerprint, result locator, protected envelope), the atomic
// reservation port, the in-memory reference store, and the narrow replay
// protection boundary.
//
// This package does NOT authenticate, authorize, emit HTTP, persist to
// PostgreSQL, mint secrets, or perform any business mutation. Future route
// adapters invoke it only after the applicable authentication/authorization
// gates have run.
package runtime

import (
	"fmt"
)

const (
	idempotencyKeyMinLen  = 16
	idempotencyKeyMaxLen  = 128
	idempotencyKeyMinByte = 0x21 // '!'
	idempotencyKeyMaxByte = 0x7E // '~'
)

// IdempotencyKey is the exact, immutable Idempotency-Key value supplied by a
// client. Identity is byte-exact: no trimming, case-folding, Unicode
// normalization, URL normalization, or any other canonicalization is ever
// applied. Two keys differing by even one byte remain different keys.
type IdempotencyKey struct {
	value string
}

// NewIdempotencyKey validates and constructs an IdempotencyKey. It fails
// closed on empty, too-short, too-long, non-printable, or non-ASCII values
// rather than repairing them into valid authority.
func NewIdempotencyKey(raw string) (IdempotencyKey, error) {
	if err := validateIdempotencyKeyBytes([]byte(raw)); err != nil {
		return IdempotencyKey{}, err
	}
	return IdempotencyKey{value: raw}, nil
}

func validateIdempotencyKeyBytes(b []byte) error {
	if len(b) < idempotencyKeyMinLen || len(b) > idempotencyKeyMaxLen {
		return fmt.Errorf("idempotency key must be %d..%d bytes, got %d", idempotencyKeyMinLen, idempotencyKeyMaxLen, len(b))
	}
	for i, c := range b {
		if c < idempotencyKeyMinByte || c > idempotencyKeyMaxByte {
			return fmt.Errorf("idempotency key contains invalid byte 0x%02x at offset %d; only printable ASCII 0x21..0x7E is allowed", c, i)
		}
	}
	return nil
}

// String returns the exact key value. The returned string is immutable.
func (k IdempotencyKey) String() string { return k.value }

// IsZero reports whether the key is the unusable zero value.
func (k IdempotencyKey) IsZero() bool { return k.value == "" }

// Equal reports exact key equality.
func (k IdempotencyKey) Equal(other IdempotencyKey) bool { return k.value == other.value }
