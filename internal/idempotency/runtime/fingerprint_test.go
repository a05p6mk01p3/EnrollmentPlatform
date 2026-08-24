package runtime_test

import (
	"testing"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
)

func TestFingerprintDeterminismAndComponentSeparation(t *testing.T) {
	canonical := []byte(`{"operation":"INITIAL"}`)

	base := mustFingerprint(t, "POST", "/v1/enrollments", canonical)
	same := mustFingerprint(t, "POST", "/v1/enrollments", canonical)
	if !base.Equal(same) {
		t.Fatal("identical inputs must produce identical fingerprints")
	}

	otherMethod := mustFingerprint(t, "PUT", "/v1/enrollments", canonical)
	otherRoute := mustFingerprint(t, "POST", "/v1/enrollments/{id}/complete", canonical)
	otherCanonical := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"RENEWAL"}`))

	for name, other := range map[string]runtime.Fingerprint{
		"method":    otherMethod,
		"route":     otherRoute,
		"canonical": otherCanonical,
	} {
		if base.Equal(other) {
			t.Errorf("fingerprint differing only in %s must not be equal", name)
		}
	}
}

func TestFingerprintVersionIsExplicit(t *testing.T) {
	if _, err := runtime.FingerprintRequest(runtime.FingerprintVersion(999), "POST", "/v1/enrollments", nil); err == nil {
		t.Fatal("unsupported fingerprint version must be rejected")
	}
	f := mustFingerprint(t, "POST", "/v1/enrollments", nil)
	if f.Version() != runtime.FingerprintVersion1 {
		t.Fatalf("Version() = %d, want %d", f.Version(), runtime.FingerprintVersion1)
	}
}

func TestFingerprintCanonicalBytesAreOpaqueRouteOwnedBytes(t *testing.T) {
	// The kernel must fingerprint the exact byte representation it is given.
	// JSON field reordering or whitespace changes must produce different
	// fingerprints, proving no cross-route JSON canonicalization is applied.
	a := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"a":1,"b":2}`))
	b := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"b":2,"a":1}`))
	c := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"a":1, "b":2}`))

	if a.Equal(b) {
		t.Fatal("JSON field reordering must not be normalized away")
	}
	if a.Equal(c) {
		t.Fatal("JSON whitespace must not be normalized away")
	}

	// Empty canonical bytes are a legitimate route-owned representation.
	empty := mustFingerprint(t, "POST", "/v1/enrollments/{id}/complete", nil)
	emptyAgain := mustFingerprint(t, "POST", "/v1/enrollments/{id}/complete", []byte{})
	if !empty.Equal(emptyAgain) {
		t.Fatal("nil and empty canonical byte slices must be equivalent for the same route")
	}
}

func TestFingerprintRejectsMalformedInputs(t *testing.T) {
	if _, err := runtime.FingerprintRequest(runtime.FingerprintVersion1, "post", "/v1/enrollments", nil); err == nil {
		t.Fatal("lowercase method must be rejected")
	}
	if _, err := runtime.FingerprintRequest(runtime.FingerprintVersion1, "", "/v1/enrollments", nil); err == nil {
		t.Fatal("empty method must be rejected")
	}
	if _, err := runtime.FingerprintRequest(runtime.FingerprintVersion1, "POST", "", nil); err == nil {
		t.Fatal("empty route must be rejected")
	}
}
