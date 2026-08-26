package replaycapsule

import (
	"reflect"
	"testing"
)

func baseAADFields() aadFields {
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i + 1)
	}
	return aadFields{
		domain:                  "enrollment-platform/replay-capsule-aad",
		version:                 1,
		operation:               "createPreOnboardingRequest",
		resourceKind:            "PRE_ONBOARDING_REQUEST",
		resourceID:              "por-12345",
		credentialKind:          "TemporaryPrincipalToken",
		credentialBinding:       "tp-binding-99",
		method:                  "POST",
		route:                   "/v1/pre-onboarding-requests",
		idempotencyKey:          "idem-key-888-abcdef",
		fingerprintVersion:      1,
		fingerprintDigest:       digest,
		issuedCredentialType:    "REQUEST_ACCESS_TOKEN",
		issuedCredentialVersion: 1,
	}
}

// TestAAD_AllFourteenFieldMutationMatrix independently mutates every one of the
// 14 CR-M5.6-001 semantic fields (including the frozen production constants)
// and proves each produces a distinct AAD byte sequence. The frozen constants
// are exercised here through the package-local lower-level encoder; they are
// not made mutable in production.
func TestAAD_AllFourteenFieldMutationMatrix(t *testing.T) {
	baseBytes, err := encodeAAD(baseAADFields())
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func(*aadFields)
	}{
		{"1_aad_domain", func(f *aadFields) { f.domain = "example/replay-capsule-aad" }},
		{"2_aad_version", func(f *aadFields) { f.version = 2 }},
		{"3_originator_operation", func(f *aadFields) { f.operation = "createEnrollmentRequest" }},
		{"4_originator_resource_kind", func(f *aadFields) { f.resourceKind = "ENROLLMENT" }},
		{"5_originator_resource_id", func(f *aadFields) { f.resourceID = "por-99999" }},
		{"6_credential_kind", func(f *aadFields) { f.credentialKind = "HumanOIDC" }},
		{"7_credential_binding", func(f *aadFields) { f.credentialBinding = "tp-binding-different" }},
		{"8_method", func(f *aadFields) { f.method = "PUT" }},
		{"9_route", func(f *aadFields) { f.route = "/v1/pre-onboarding-requests/different" }},
		{"10_idempotency_key", func(f *aadFields) { f.idempotencyKey = "idem-key-different-abcdef" }},
		{"11_fingerprint_version", func(f *aadFields) { f.fingerprintVersion = 2 }},
		{"12_fingerprint_digest", func(f *aadFields) {
			f.fingerprintDigest = append([]byte(nil), f.fingerprintDigest...)
			f.fingerprintDigest[0] ^= 0xFF
		}},
		{"13_issued_credential_type", func(f *aadFields) { f.issuedCredentialType = "ENROLLMENT_ACCESS_TOKEN" }},
		{"14_issued_credential_version", func(f *aadFields) { f.issuedCredentialVersion = 2 }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fields := baseAADFields()
			tc.mutate(&fields)
			got, err := encodeAAD(fields)
			if err != nil {
				t.Fatal(err)
			}
			if reflect.DeepEqual(baseBytes, got) {
				t.Fatalf("mutation of %s did not change AAD bytes", tc.name)
			}
		})
	}
}

// TestAAD_HasNoSecretOrCorrelationInputs proves the AAD encoder has no input
// path for idempotency_record_id, correlation ID, or a secret: the aadFields
// struct contains only the 14 normative semantic fields.
func TestAAD_HasNoSecretOrCorrelationInputs(t *testing.T) {
	// The aadFields struct is the complete lower-level input surface. It must
	// contain exactly the 14 normative fields and nothing else.
	var f aadFields
	rt := reflect.TypeOf(f)
	if rt.NumField() != 14 {
		t.Fatalf("aadFields has %d fields, want exactly 14", rt.NumField())
	}
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		switch name {
		case "domain", "version", "operation", "resourceKind", "resourceID",
			"credentialKind", "credentialBinding", "method", "route", "idempotencyKey",
			"fingerprintVersion", "fingerprintDigest", "issuedCredentialType", "issuedCredentialVersion":
		default:
			t.Fatalf("aadFields has unexpected field %q", name)
		}
	}
}
