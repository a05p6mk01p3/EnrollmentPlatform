package replaycapsule_test

import (
	"encoding/hex"
	"reflect"
	"testing"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/replaycapsule"
)

// fixedEnrollmentAADVectorHex is an independently frozen CR-M5.6-001 vector
// for the createEnrollment originator mapping. It is not derived from the
// production encoder at test time.
const fixedEnrollmentAADVectorHex = "0000000000000026656e726f6c6c6d656e742d706c6174666f726d2f7265706c61792d63617073756c652d6161640000000000000004000000010000000000000010637265617465456e726f6c6c6d656e74000000000000000a454e524f4c4c4d454e540000000000000009656e722d3132333435000000000000001252657175657374416363657373546f6b656e0000000000000009706f722d31323334350000000000000004504f5354000000000000000f2f76312f656e726f6c6c6d656e747300000000000000166964656d2d6b65792d656e726f6c6c2d61626364656600000000000000040000000100000000000000200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200000000000000017454e524f4c4c4d454e545f4143434553535f544f4b454e000000000000000400000001"

func fixedEnrollmentAADFixture(t *testing.T) replaycapsule.EnrollmentAAD {
	t.Helper()
	cred, err := idempotencyruntime.NewCredentialScope(authpolicy.CredentialKindRequestAccessToken, "por-12345")
	if err != nil {
		t.Fatal(err)
	}
	key, err := idempotencyruntime.NewIdempotencyKey("idem-key-enroll-abcdef")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := idempotencyruntime.NewEffectiveScope(cred, "POST", "/v1/enrollments", key)
	if err != nil {
		t.Fatal(err)
	}
	digest := [32]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}
	fp, err := idempotencyruntime.NewFingerprint(idempotencyruntime.FingerprintVersion1, digest)
	if err != nil {
		t.Fatal(err)
	}
	return replaycapsule.EnrollmentAAD{ResourceID: "enr-12345", Scope: scope, Fingerprint: fp}
}

func TestEnrollmentAAD_FixedByteVector(t *testing.T) {
	got, err := fixedEnrollmentAADFixture(t).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString(fixedEnrollmentAADVectorHex)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Enrollment AAD byte vector mismatch.\nGot:  %s\nWant: %s", hex.EncodeToString(got), fixedEnrollmentAADVectorHex)
	}
}

func TestEnrollmentAAD_OriginatorIsolation(t *testing.T) {
	enrollment := fixedEnrollmentAADFixture(t)
	enrollmentBytes, err := enrollment.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	preBytes, err := (replaycapsule.PreOnboardingAAD{ResourceID: "enr-12345", Scope: enrollment.Scope, Fingerprint: enrollment.Fingerprint}).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(enrollmentBytes, preBytes) {
		t.Fatal("createEnrollment and createPreOnboardingRequest produced identical AAD")
	}
}
