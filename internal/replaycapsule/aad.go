// Package replaycapsule owns deterministic, versioned associated-data encoding
// for protocol replay capsules. It deliberately has no HTTP dependency.
package replaycapsule

import (
	"encoding/binary"
	"fmt"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
)

const (
	Domain                              = "enrollment-platform/replay-capsule-aad"
	Version                      uint32 = 1
	CreatePreOnboardingOperation        = "createPreOnboardingRequest"
	PreOnboardingResourceKind           = "PRE_ONBOARDING_REQUEST"
	RequestAccessCredentialType         = "REQUEST_ACCESS_TOKEN"
	IssuedCredentialVersion      uint32 = 1
)

// PreOnboardingAAD contains the complete CR-M5.6-001 v1 tuple for a
// RequestAccessToken issued by createPreOnboardingRequest.
type PreOnboardingAAD struct {
	ResourceID  string
	Scope       runtime.EffectiveScope
	Fingerprint runtime.Fingerprint
}

// Bytes renders the exact, ordered, length-framed, domain-separated AAD v1
// byte sequence. It fails closed on an incomplete tuple rather than emitting a
// partial encoding.
func (a PreOnboardingAAD) Bytes() ([]byte, error) {
	if a.ResourceID == "" || a.Scope.IsZero() || a.Fingerprint.IsZero() {
		return nil, fmt.Errorf("replay capsule AAD: incomplete pre-onboarding tuple")
	}
	digest := a.Fingerprint.Digest()
	return encodeAAD(aadFields{
		domain:                  Domain,
		version:                 Version,
		operation:               CreatePreOnboardingOperation,
		resourceKind:            PreOnboardingResourceKind,
		resourceID:              a.ResourceID,
		credentialKind:          string(a.Scope.Credential().Kind()),
		credentialBinding:       a.Scope.Credential().Binding(),
		method:                  a.Scope.Method(),
		route:                   a.Scope.Route(),
		idempotencyKey:          a.Scope.Key().String(),
		fingerprintVersion:      uint32(a.Fingerprint.Version()),
		fingerprintDigest:       digest[:],
		issuedCredentialType:    RequestAccessCredentialType,
		issuedCredentialVersion: IssuedCredentialVersion,
	})
}

// aadFields is the lower-level, fully-parameterized CR-M5.6-001 AAD v1 tuple.
// It exists so package-local tests can exercise every semantic field —
// including the frozen production constants — without making those constants
// mutable in production.
type aadFields struct {
	domain                  string
	version                 uint32
	operation               string
	resourceKind            string
	resourceID              string
	credentialKind          string
	credentialBinding       string
	method                  string
	route                   string
	idempotencyKey          string
	fingerprintVersion      uint32
	fingerprintDigest       []byte
	issuedCredentialType    string
	issuedCredentialVersion uint32
}

// encodeAAD renders the exact ordered AAD v1 sequence: 14 fields, each
// length-framed by an 8-byte unsigned big-endian byte length. Integer/version
// fields are encoded as 4-byte unsigned big-endian. The fingerprint is its
// authoritative raw digest (never a diagnostic String()).
//
// The encoding is deterministic, domain-separated, versioned, ordered, and
// unambiguous. It contains no correlation ID, no idempotency_record_id, no
// secret plaintext, and no raw authentication material.
func encodeAAD(f aadFields) ([]byte, error) {
	digest := append([]byte(nil), f.fingerprintDigest...)
	fields := [][]byte{
		[]byte(f.domain), u32(f.version),
		[]byte(f.operation),
		[]byte(f.resourceKind),
		[]byte(f.resourceID),
		[]byte(f.credentialKind),
		[]byte(f.credentialBinding),
		[]byte(f.method),
		[]byte(f.route),
		[]byte(f.idempotencyKey),
		u32(f.fingerprintVersion),
		digest,
		[]byte(f.issuedCredentialType),
		u32(f.issuedCredentialVersion),
	}
	var out []byte
	for _, field := range fields {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(field)))
		out = append(out, n[:]...)
		out = append(out, field...)
	}
	return out, nil
}

func u32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}
