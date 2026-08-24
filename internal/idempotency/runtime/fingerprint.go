package runtime

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
)

// FingerprintVersion identifies the exact fingerprint construction algorithm.
// It is explicit in the value so an existing record can never be silently
// reinterpreted under a different version.
type FingerprintVersion uint32

// FingerprintVersion1 is the only fingerprint version currently defined:
// SHA-256 over length-framed fingerprint version, canonical HTTP method,
// canonical OpenAPI route template, and route-provided canonical request
// representation bytes.
const FingerprintVersion1 FingerprintVersion = 1

// fingerprintDomain is a fixed domain-separation prefix written into every
// fingerprint so idempotency fingerprints cannot be confused with digests
// produced for other purposes.
const fingerprintDomain = "enrollment-idempotency-fingerprint"

// Fingerprint is an immutable, versioned internal request fingerprint. The
// digest is an internal implementation value, not an authentication secret.
type Fingerprint struct {
	version FingerprintVersion
	digest  [sha256.Size]byte
}

// FingerprintRequest computes the deterministic versioned fingerprint over the
// canonical method, canonical route template, and the route-provided canonical
// request representation bytes. The canonical bytes are opaque to this kernel:
// route-specific canonicalization is owned by the future application operation.
func FingerprintRequest(version FingerprintVersion, method, route string, canonical []byte) (Fingerprint, error) {
	if version != FingerprintVersion1 {
		return Fingerprint{}, fmt.Errorf("fingerprint: unsupported version %d", version)
	}
	if method == "" || method != strings.ToUpper(method) {
		return Fingerprint{}, fmt.Errorf("fingerprint: method must be a non-empty canonical uppercase HTTP method")
	}
	if route == "" {
		return Fingerprint{}, fmt.Errorf("fingerprint: route template must be non-empty")
	}

	h := sha256.New()
	writeFingerprintField(h, []byte(fingerprintDomain))
	writeFingerprintField(h, uvarintBytes(uint64(version)))
	writeFingerprintField(h, []byte(method))
	writeFingerprintField(h, []byte(route))
	writeFingerprintField(h, canonical)

	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return Fingerprint{version: version, digest: digest}, nil
}

// writeFingerprintField writes a length-framed byte field into the digest.
// The explicit length framing makes component boundaries unambiguous.
func writeFingerprintField(h hash.Hash, b []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(b)))
	h.Write(length[:])
	h.Write(b)
}

func uvarintBytes(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

// Version returns the fingerprint version.
func (f Fingerprint) Version() FingerprintVersion { return f.version }

// Digest returns the exact fingerprint digest bytes. The returned array is a
// value copy, so the caller cannot mutate the fingerprint's internal state.
// Together with Version it is the stable adapter-facing persistence
// representation.
func (f Fingerprint) Digest() [sha256.Size]byte { return f.digest }

// NewFingerprint restores a Fingerprint from its persisted version and digest.
// It is an adapter-facing persistence/restore API, not an HTTP/wire format,
// and it validates that the version is one the kernel understands.
func NewFingerprint(version FingerprintVersion, digest [sha256.Size]byte) (Fingerprint, error) {
	if version != FingerprintVersion1 {
		return Fingerprint{}, fmt.Errorf("fingerprint: unsupported version %d on restore", version)
	}
	return Fingerprint{version: version, digest: digest}, nil
}

// IsZero reports whether the fingerprint is the unusable zero value.
func (f Fingerprint) IsZero() bool { return f.version == 0 }

// Equal reports exact fingerprint equality.
func (f Fingerprint) Equal(other Fingerprint) bool {
	return f.version == other.version && f.digest == other.digest
}

// String renders the fingerprint as a diagnostic-only hex string.
func (f Fingerprint) String() string {
	return fmt.Sprintf("v%d:%s", f.version, hex.EncodeToString(f.digest[:]))
}
