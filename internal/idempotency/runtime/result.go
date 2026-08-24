package runtime

import (
	"fmt"
	"strings"
)

// ResultLocator is an application-owned, opaque, non-secret, immutable
// reference to a committed idempotency result. It deliberately does NOT carry
// arbitrary serialized HTTP response bytes, originator secret plaintext, raw
// bearer credentials, private keys, or reversible active-token verifier
// material.
type ResultLocator struct {
	value string
}

// NewResultLocator constructs a ResultLocator from an application-defined
// exact value. It fails closed on empty or whitespace-padded values rather
// than trimming them into validity.
func NewResultLocator(value string) (ResultLocator, error) {
	if value == "" {
		return ResultLocator{}, fmt.Errorf("result locator: value must be non-empty")
	}
	if value != strings.TrimSpace(value) {
		return ResultLocator{}, fmt.Errorf("result locator: value must not have leading/trailing whitespace")
	}
	return ResultLocator{value: value}, nil
}

// String returns the exact locator value.
func (r ResultLocator) String() string { return r.value }

// IsZero reports whether the locator is the unusable zero value.
func (r ResultLocator) IsZero() bool { return r.value == "" }

// Equal reports exact locator equality.
func (r ResultLocator) Equal(other ResultLocator) bool { return r.value == other.value }
