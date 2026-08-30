// Package application coordinates enrollment lifecycle use cases around the
// existing pure enrollment aggregate. It owns no HTTP or persistence details.
package application

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"

	domain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/domain/enrollment"
	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
)

const (
	// OperationInitial is the only create-enrollment business execution owned
	// by M5.7. RENEWAL and REKEY remain contract-visible but are deliberately
	// outside this application slice.
	OperationInitial = "INITIAL"

	// PopFormatEnrollmentJWS is the contract-defined PoP format advertised by
	// the initial challenge. M5.7 creates the challenge but does not verify PoP.
	PopFormatEnrollmentJWS = "enrollment-pop+jws"
)

// Challenge is the server-created challenge returned by createEnrollment.
// Nonce is Base64URL without padding; ChallengeVersion starts at 1.
type Challenge struct {
	Nonce            string
	ChallengeVersion int
	ExpiresAt        time.Time
	PopFormat        string
}

func (c Challenge) Validate(now time.Time) error {
	if strings.TrimSpace(c.Nonce) == "" || strings.Contains(c.Nonce, "=") {
		return errors.New("enrollment application: challenge nonce must be unpadded Base64URL")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(c.Nonce)
	if err != nil || len(nonce) < 16 {
		return errors.New("enrollment application: challenge nonce must encode at least 128 bits")
	}
	if c.ChallengeVersion < 1 {
		return errors.New("enrollment application: challenge_version must be positive")
	}
	if !c.ExpiresAt.After(now) {
		return errors.New("enrollment application: challenge expiry must be after creation time")
	}
	if c.PopFormat != PopFormatEnrollmentJWS {
		return errors.New("enrollment application: unsupported challenge pop format")
	}
	return nil
}

// AcceptedEvidence is the immutable, server-owned record of evidence accepted
// for one challenge. Representation is an opaque, already-admitted encoding;
// OPEN-004A deliberately does not define its wire format in this milestone.
// Fingerprint is supplied by the trusted admission boundary and is compared
// byte-for-byte for resource-idempotent retries.
type AcceptedEvidence struct {
	Fingerprint      idempotencyruntime.Fingerprint
	ChallengeVersion int
	Representation   []byte
	AcceptedAt       time.Time
}

func (e AcceptedEvidence) Clone() AcceptedEvidence {
	e.Representation = append([]byte(nil), e.Representation...)
	return e
}

func (e AcceptedEvidence) Validate() error {
	if e.Fingerprint.IsZero() {
		return errors.New("enrollment application: accepted evidence fingerprint is required")
	}
	if e.ChallengeVersion < 1 {
		return errors.New("enrollment application: accepted evidence challenge_version must be positive")
	}
	if len(e.Representation) == 0 {
		return errors.New("enrollment application: accepted evidence representation is required")
	}
	if e.AcceptedAt.IsZero() {
		return errors.New("enrollment application: accepted evidence accepted_at is required")
	}
	return nil
}

// EvidenceRequirements is a snapshot of server-side policy output advertised
// to the Agent. Concrete values remain policy/configuration inputs; this type
// deliberately does not freeze OPEN-004/OPEN-005/OPEN-006 values.
type EvidenceRequirements struct {
	TPMEvidenceProtocolVersions []string
	MinimumAssurance            string
	AllowedKeyProfiles          []string
}

func (r EvidenceRequirements) Clone() EvidenceRequirements {
	return EvidenceRequirements{
		TPMEvidenceProtocolVersions: append([]string(nil), r.TPMEvidenceProtocolVersions...),
		MinimumAssurance:            r.MinimumAssurance,
		AllowedKeyProfiles:          append([]string(nil), r.AllowedKeyProfiles...),
	}
}

func (r EvidenceRequirements) Validate() error {
	if len(r.TPMEvidenceProtocolVersions) == 0 || len(r.TPMEvidenceProtocolVersions) > 128 {
		return errors.New("enrollment application: TPM evidence protocol versions must contain 1..128 values")
	}
	for _, v := range r.TPMEvidenceProtocolVersions {
		if strings.TrimSpace(v) == "" || len(v) > 4096 {
			return errors.New("enrollment application: TPM evidence protocol versions contain an invalid value")
		}
	}
	switch r.MinimumAssurance {
	case "A0", "A1", "A2", "A3":
	default:
		return errors.New("enrollment application: minimum assurance must be A0, A1, A2, or A3")
	}
	if len(r.AllowedKeyProfiles) == 0 || len(r.AllowedKeyProfiles) > 128 {
		return errors.New("enrollment application: allowed key profiles must contain 1..128 values")
	}
	for _, v := range r.AllowedKeyProfiles {
		if strings.TrimSpace(v) == "" || len(v) > 4096 {
			return errors.New("enrollment application: allowed key profiles contain an invalid value")
		}
	}
	return nil
}

// EnrollmentRecord is the application persistence snapshot created atomically
// by the INITIAL exchange. The existing domain aggregate remains the sole
// owner of enrollment state-machine transitions.
type EnrollmentRecord struct {
	Aggregate            *domain.Enrollment
	DeviceID             string
	PartnerID            string
	Operation            string
	CertificateUsage     string
	AssuranceLevel       string
	CertificateID        string
	Challenge            Challenge
	EvidenceRequirements EvidenceRequirements
	AcceptedEvidence     *AcceptedEvidence
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

func (r EnrollmentRecord) Validate() error {
	if r.Aggregate == nil || r.Aggregate.ID() == "" {
		return errors.New("enrollment application: enrollment aggregate/id is required")
	}
	if !r.Aggregate.State().Valid() {
		return errors.New("enrollment application: enrollment state is invalid")
	}
	if strings.TrimSpace(r.DeviceID) == "" || strings.TrimSpace(r.PartnerID) == "" {
		return errors.New("enrollment application: authoritative device and partner bindings are required")
	}
	if r.Operation != OperationInitial {
		return errors.New("enrollment application: M5.7 record must be INITIAL")
	}
	if strings.TrimSpace(r.CertificateUsage) == "" {
		return errors.New("enrollment application: certificate usage is required")
	}
	if r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() || r.UpdatedAt.Before(r.CreatedAt) {
		return errors.New("enrollment application: created_at/updated_at must be ordered and non-zero")
	}
	if err := r.Challenge.Validate(r.CreatedAt); err != nil {
		return err
	}
	if err := r.EvidenceRequirements.Validate(); err != nil {
		return err
	}
	if r.AcceptedEvidence != nil {
		if err := r.AcceptedEvidence.Validate(); err != nil {
			return err
		}
		if r.AcceptedEvidence.ChallengeVersion != r.Challenge.ChallengeVersion {
			return errors.New("enrollment application: accepted evidence challenge version does not match active record")
		}
	}
	return nil
}

// EnrollmentSnapshot is an immutable read representation. It contains no
// correlation identifier and no mutable aggregate pointer.
type EnrollmentSnapshot struct {
	EnrollmentID         string
	DeviceID             string
	Operation            string
	CertificateUsage     string
	AssuranceLevel       string
	CertificateID        string
	State                domain.State
	Challenge            *Challenge
	EvidenceRequirements EvidenceRequirements
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

func (s EnrollmentSnapshot) Clone() EnrollmentSnapshot {
	s.EvidenceRequirements = s.EvidenceRequirements.Clone()
	if s.Challenge != nil {
		challenge := *s.Challenge
		s.Challenge = &challenge
	}
	return s
}

func (r EnrollmentRecord) Snapshot() EnrollmentSnapshot {
	s := EnrollmentSnapshot{
		DeviceID:             r.DeviceID,
		Operation:            r.Operation,
		CertificateUsage:     r.CertificateUsage,
		AssuranceLevel:       r.AssuranceLevel,
		CertificateID:        r.CertificateID,
		EvidenceRequirements: r.EvidenceRequirements.Clone(),
		CreatedAt:            r.CreatedAt,
		UpdatedAt:            r.UpdatedAt,
	}
	if r.Aggregate != nil {
		s.EnrollmentID = string(r.Aggregate.ID())
		s.State = r.Aggregate.State()
	}
	challenge := r.Challenge
	s.Challenge = &challenge
	return s
}
