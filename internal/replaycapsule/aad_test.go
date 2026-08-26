package replaycapsule_test

import (
	"encoding/hex"
	"reflect"
	"testing"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/replaycapsule"
)

// fixedAADVectorHex is the authoritative, statically-defined CR-M5.6-001 AAD v1
// byte sequence for the canonical test input below. It is expressed as a fixed
// hexadecimal literal and is NOT derived from the production encoder. Any
// change to field order, framing, integer encoding, fingerprint encoding, or
// field omission/addition must change these bytes.
//
// Canonical input:
//
//	domain              = "enrollment-platform/replay-capsule-aad"
//	version             = 1
//	operation           = "createPreOnboardingRequest"
//	resourceKind        = "PRE_ONBOARDING_REQUEST"
//	resourceID          = "por-12345"
//	credentialKind      = "TemporaryPrincipalToken"
//	credentialBinding   = "tp-binding-99"
//	method              = "POST"
//	route               = "/v1/pre-onboarding-requests"
//	idempotencyKey      = "idem-key-888-abcdef"
//	fingerprintVersion  = 1
//	fingerprintDigest   = 0x01..0x20 (32 bytes)
//	issuedCredentialType= "REQUEST_ACCESS_TOKEN"
//	issuedCredentialVersion = 1
const fixedAADVectorHex = "0000000000000026656e726f6c6c6d656e742d706c6174666f726d2f7265706c61792d63617073756c652d616164000000000000000400000001000000000000001a6372656174655072654f6e626f617264696e675265717565737400000000000000165052455f4f4e424f415244494e475f524551554553540000000000000009706f722d3132333435000000000000001754656d706f726172795072696e636970616c546f6b656e000000000000000d74702d62696e64696e672d39390000000000000004504f5354000000000000001b2f76312f7072652d6f6e626f617264696e672d726571756573747300000000000000136964656d2d6b65792d3838382d61626364656600000000000000040000000100000000000000200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200000000000000014524551554553545f4143434553535f544f4b454e000000000000000400000001"

func fixedAADFixture(t *testing.T) replaycapsule.PreOnboardingAAD {
	t.Helper()
	cred, err := idempotencyruntime.NewCredentialScope(authpolicy.CredentialKind("TemporaryPrincipalToken"), "tp-binding-99")
	if err != nil {
		t.Fatal(err)
	}
	key, err := idempotencyruntime.NewIdempotencyKey("idem-key-888-abcdef")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := idempotencyruntime.NewEffectiveScope(cred, "POST", "/v1/pre-onboarding-requests", key)
	if err != nil {
		t.Fatal(err)
	}
	digest := [32]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}
	fp, err := idempotencyruntime.NewFingerprint(idempotencyruntime.FingerprintVersion(1), digest)
	if err != nil {
		t.Fatal(err)
	}
	return replaycapsule.PreOnboardingAAD{ResourceID: "por-12345", Scope: scope, Fingerprint: fp}
}

func TestAAD_FixedByteVector(t *testing.T) {
	got, err := fixedAADFixture(t).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString(fixedAADVectorHex)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("AAD byte vector mismatch.\nGot:  %s\nWant: %s", hex.EncodeToString(got), fixedAADVectorHex)
	}
}

func TestAAD_DeterministicRepeat(t *testing.T) {
	a1 := fixedAADFixture(t)
	a2 := fixedAADFixture(t)
	b1, err := a1.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	b2, err := a2.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(b1, b2) {
		t.Fatal("identical inputs produced different AAD bytes")
	}
}

func TestAAD_PublicFieldMutationMatrix(t *testing.T) {
	base := fixedAADFixture(t)
	baseBytes, err := base.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	assertChanged := func(name string, mut replaycapsule.PreOnboardingAAD) {
		t.Helper()
		b, err := mut.Bytes()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if reflect.DeepEqual(baseBytes, b) {
			t.Fatalf("%s mutation did not change AAD bytes", name)
		}
	}

	// 1. originator_resource_id
	m := base
	m.ResourceID = "por-99999"
	assertChanged("resource_id", m)

	// 2. credential kind
	credKind, err := idempotencyruntime.NewCredentialScope(authpolicy.CredentialKindHumanOIDC, "tp-binding-99")
	if err != nil {
		t.Fatal(err)
	}
	m = base
	m.Scope, err = idempotencyruntime.NewEffectiveScope(credKind, "POST", "/v1/pre-onboarding-requests", base.Scope.Key())
	if err != nil {
		t.Fatal(err)
	}
	assertChanged("credential_kind", m)

	// 3. credential binding
	credBinding, err := idempotencyruntime.NewCredentialScope(authpolicy.CredentialKindTemporaryPrincipalToken, "tp-binding-different")
	if err != nil {
		t.Fatal(err)
	}
	m = base
	m.Scope, err = idempotencyruntime.NewEffectiveScope(credBinding, "POST", "/v1/pre-onboarding-requests", base.Scope.Key())
	if err != nil {
		t.Fatal(err)
	}
	assertChanged("credential_binding", m)

	// 4. method
	m = base
	m.Scope, err = idempotencyruntime.NewEffectiveScope(base.Scope.Credential(), "PUT", "/v1/pre-onboarding-requests", base.Scope.Key())
	if err != nil {
		t.Fatal(err)
	}
	assertChanged("method", m)

	// 5. route
	m = base
	m.Scope, err = idempotencyruntime.NewEffectiveScope(base.Scope.Credential(), "POST", "/v1/pre-onboarding-requests/different", base.Scope.Key())
	if err != nil {
		t.Fatal(err)
	}
	assertChanged("route", m)

	// 6. Idempotency-Key
	key2, err := idempotencyruntime.NewIdempotencyKey("idem-key-different-abcdef")
	if err != nil {
		t.Fatal(err)
	}
	m = base
	m.Scope, err = idempotencyruntime.NewEffectiveScope(base.Scope.Credential(), "POST", "/v1/pre-onboarding-requests", key2)
	if err != nil {
		t.Fatal(err)
	}
	assertChanged("idempotency_key", m)

	// 7. fingerprint digest
	fp2, err := idempotencyruntime.NewFingerprint(idempotencyruntime.FingerprintVersion(1), [32]byte{0x02})
	if err != nil {
		t.Fatal(err)
	}
	m = base
	m.Fingerprint = fp2
	assertChanged("fingerprint_digest", m)
}

func TestAAD_IdentityIsolation(t *testing.T) {
	base := fixedAADFixture(t)
	baseBytes, err := base.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	// TP-A vs TP-B: different effective-scope binding => different AAD.
	credB, err := idempotencyruntime.NewCredentialScope(authpolicy.CredentialKindTemporaryPrincipalToken, "tp-binding-B")
	if err != nil {
		t.Fatal(err)
	}
	scopeB, err := idempotencyruntime.NewEffectiveScope(credB, "POST", "/v1/pre-onboarding-requests", base.Scope.Key())
	if err != nil {
		t.Fatal(err)
	}
	bB, err := (replaycapsule.PreOnboardingAAD{ResourceID: base.ResourceID, Scope: scopeB, Fingerprint: base.Fingerprint}).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(baseBytes, bB) {
		t.Fatal("TP-A and TP-B bindings produced the same AAD bytes")
	}

	// HumanOIDC vs TemporaryPrincipal: different credential kind => different AAD.
	credH, err := idempotencyruntime.NewCredentialScope(authpolicy.CredentialKindHumanOIDC, "tp-binding-99")
	if err != nil {
		t.Fatal(err)
	}
	scopeH, err := idempotencyruntime.NewEffectiveScope(credH, "POST", "/v1/pre-onboarding-requests", base.Scope.Key())
	if err != nil {
		t.Fatal(err)
	}
	bH, err := (replaycapsule.PreOnboardingAAD{ResourceID: base.ResourceID, Scope: scopeH, Fingerprint: base.Fingerprint}).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(baseBytes, bH) {
		t.Fatal("HumanOIDC and TemporaryPrincipal produced the same AAD bytes")
	}
}
