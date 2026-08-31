// Package application — Phase-2 Evidence Evaluation Foundation (M5.9).
//
// This file defines the closed evaluation result taxonomy, the provider-neutral
// AttestationVerifier port, the extended evaluation material persisted at
// evidence acceptance, and the server-side assurance / authority policy seams.
//
// Normative source: Protocol v0.2.7 and M5.9-IMPL-001.

package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// §2. RESULT TAXONOMY
// ---------------------------------------------------------------------------

// EvaluationResult is a closed, explicit Phase-2 verifier/policy outcome.
// Zero-value (0) is invalid; unknown values must fail closed. The type is
// deliberately not a string so that a missing or uninitialised value cannot
// accidentally mean "positive".
type EvaluationResult int

const (
	// EvaluationResultPositive means the verifier returned trustworthy
	// affirmative evidence and current server policy authorises issuance.
	EvaluationResultPositive EvaluationResult = iota + 1 // 1

	// EvaluationResultDefinitiveNegative means a compatible authoritative
	// verifier conclusively denied the evidence, or current server policy
	// produces a definitive deny.
	EvaluationResultDefinitiveNegative // 2

	// EvaluationResultIndeterminate means the verifier was unavailable, unable
	// to decide, the policy authority was unavailable, a freshness/version
	// conflict was detected, or infrastructure failure prevented a trustworthy
	// decision.
	EvaluationResultIndeterminate // 3
)

// Valid reports whether r is one of the three defined outcomes.
func (r EvaluationResult) Valid() bool {
	switch r {
	case EvaluationResultPositive, EvaluationResultDefinitiveNegative, EvaluationResultIndeterminate:
		return true
	default:
		return false
	}
}

func (r EvaluationResult) String() string {
	switch r {
	case EvaluationResultPositive:
		return "POSITIVE"
	case EvaluationResultDefinitiveNegative:
		return "DEFINITIVE_NEGATIVE"
	case EvaluationResultIndeterminate:
		return "INDETERMINATE"
	default:
		return fmt.Sprintf("EvaluationResult(%d)", int(r))
	}
}

// IsTerminal reports whether this result is a definitive lifecycle outcome
// (POSITIVE -> AUTHORIZED, DEFINITIVE_NEGATIVE -> REJECTED).
func (r EvaluationResult) IsTerminal() bool {
	return r == EvaluationResultPositive || r == EvaluationResultDefinitiveNegative
}

// ---------------------------------------------------------------------------
// §14. DENIAL CATEGORY
// ---------------------------------------------------------------------------

// DenialCategory is a closed, bounded, typed category for DEFINITIVE_NEGATIVE
// outcomes. It MUST NOT contain arbitrary verifier error text, TPM payload,
// JWS, CSR DER, credentials, or private material.
type DenialCategory string

const (
	DenialCategoryVerifierDenied        DenialCategory = "VERIFIER_DENIED"
	DenialCategoryPolicyDenied          DenialCategory = "POLICY_DENIED"
	DenialCategoryAssuranceInsufficient DenialCategory = "ASSURANCE_INSUFFICIENT"
	DenialCategoryProfileMismatch       DenialCategory = "PROFILE_MISMATCH"
	DenialCategoryEligibilityExpired    DenialCategory = "ELIGIBILITY_EXPIRED"
	DenialCategoryDeviceNotEligible     DenialCategory = "DEVICE_NOT_ELIGIBLE"
	DenialCategoryPartnerNotEligible    DenialCategory = "PARTNER_NOT_ELIGIBLE"
	DenialCategoryBindingMismatch       DenialCategory = "BINDING_MISMATCH"
)

// Valid reports whether c is a known denial category.
func (c DenialCategory) Valid() bool {
	switch c {
	case DenialCategoryVerifierDenied,
		DenialCategoryPolicyDenied,
		DenialCategoryAssuranceInsufficient,
		DenialCategoryProfileMismatch,
		DenialCategoryEligibilityExpired,
		DenialCategoryDeviceNotEligible,
		DenialCategoryPartnerNotEligible,
		DenialCategoryBindingMismatch:
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// §3. ATTESTATION VERIFIER PORT
// ---------------------------------------------------------------------------

// TPMEvidenceMaterial is the opaque, already-admitted TPM material passed to
// the verifier. It is deliberately provider-neutral and does not define
// vendor API, trust anchor structure, or TPM payload semantics (OPEN-004A-D
// remains open).
type TPMEvidenceMaterial struct {
	Format  string          `json:"format"`
	Version string          `json:"version"`
	Payload json.RawMessage `json:"payload"`
}

// Valid reports whether the material has the minimum required fields.
func (m TPMEvidenceMaterial) Valid() bool {
	return strings.TrimSpace(m.Format) != "" &&
		strings.TrimSpace(m.Version) != "" &&
		len(m.Payload) > 0
}

// Clone returns a defensive copy.
func (m TPMEvidenceMaterial) Clone() TPMEvidenceMaterial {
	m.Payload = append(json.RawMessage(nil), m.Payload...)
	return m
}

// AttestationVerificationRequest is the bounded input to a verifier. It
// carries only server-derived expected bindings and admitted opaque TPM
// material. It deliberately does NOT carry agent_assertions as attestation
// authority or client-supplied expected bindings.
type AttestationVerificationRequest struct {
	EnrollmentID     string
	ChallengeVersion int
	Nonce            string
	CSRSha256        string
	PublicKeySha256  string
	TPMMaterial      TPMEvidenceMaterial
}

func (r AttestationVerificationRequest) Validate() error {
	if strings.TrimSpace(r.EnrollmentID) == "" || r.ChallengeVersion < 1 {
		return errors.New("enrollment evaluation: verification request missing enrollment/challenge binding")
	}
	if strings.TrimSpace(r.Nonce) == "" || strings.TrimSpace(r.CSRSha256) == "" || strings.TrimSpace(r.PublicKeySha256) == "" {
		return errors.New("enrollment evaluation: verification request missing required binding")
	}
	if !r.TPMMaterial.Valid() {
		return errors.New("enrollment evaluation: verification request TPM material invalid")
	}
	return nil
}

// AttestationVerificationResult is the bounded, provider-neutral verifier
// output. The verifier is responsible for trustworthy classification; this
// type deliberately carries no raw TPM-derived fact bags.
type AttestationVerificationResult struct {
	// Outcome is the verifier's classification. It must be one of the three
	// EvaluationResult values; unknown/zero is invalid.
	Outcome EvaluationResult

	// AchievedAssurance is the verifier-backed assurance level.
	// For POSITIVE outcomes the verifier MUST populate this with a
	// valid AssuranceLevel. Empty is invalid for POSITIVE.
	AchievedAssurance string

	// VerifierReference is an optional provider-neutral identifier for audit.
	VerifierReference string

	// VerifierVersion is an optional provider-neutral version for audit.
	VerifierVersion string

	// VerifiedBindings confirms which mandatory server-derived bindings
	// the verifier explicitly validated. For POSITIVE: all fields must be
	// true. For DEFINITIVE_NEGATIVE: these may be false. For INDETERMINATE:
	// not required.
	VerifiedBindings VerifiedBindings
}

// VerifiedBindings is a small, closed, provider-neutral representation of
// the mandatory server-derived bindings the verifier confirmed trustworthy.
// It does NOT freeze TPM wire details, vendor-specific claims, trust-anchor
// representation, or OPEN-004 implementation semantics.
type VerifiedBindings struct {
	// EnrollmentBound is true when the verifier confirmed the evidence
	// is bound to the exact enrollment/transaction identity.
	EnrollmentBound bool

	// ChallengeBound is true when the verifier confirmed the evidence
	// is bound to the specific challenge nonce/version.
	ChallengeBound bool

	// KeyBound is true when the verifier confirmed the evidence is
	// bound to the specific public key / SPKI.
	KeyBound bool

	// TPMBound is true when the verifier confirmed the TPM payload
	// is trustworthy and correctly structured.
	TPMBound bool
}

// All returns true when every binding is confirmed.
func (b VerifiedBindings) All() bool {
	return b.EnrollmentBound && b.ChallengeBound && b.KeyBound && b.TPMBound
}

// Valid checks that the result has the minimum required integrity.
//
// F7 CORRECTION: POSITIVE requires complete bindings and non-empty assurance.
// Malformed/incomplete POSITIVE results are INDETERMINATE, never DEFINITIVE_NEGATIVE.
func (r AttestationVerificationResult) Valid() bool {
	if !r.Outcome.Valid() {
		return false
	}
	switch r.Outcome {
	case EvaluationResultPositive:
		// Must have non-empty, valid assurance.
		if r.AchievedAssurance == "" || !AssuranceLevel(r.AchievedAssurance).Valid() {
			return false
		}
		// Must have all mandatory binding confirmations.
		if !r.VerifiedBindings.All() {
			return false
		}
		return true
	case EvaluationResultDefinitiveNegative:
		return true
	case EvaluationResultIndeterminate:
		return true
	default:
		return false
	}
}

// AttestationVerifier is the smallest provider-neutral port for TPM evidence
// evaluation. It receives only admitted opaque TPM material and server-derived
// expected bindings. Implementations must never trust client-supplied expected
// bindings or agent_assertions as attestation authority.
//
// OPEN-004A-D remains open: this interface deliberately defines no vendor API,
// trust anchor structure, TPM payload semantics, or concrete supported-format
// list.
type AttestationVerifier interface {
	Verify(ctx context.Context, req AttestationVerificationRequest) (AttestationVerificationResult, error)
}

// ---------------------------------------------------------------------------
// §6. EVALUATION MATERIAL
// ---------------------------------------------------------------------------

// EvaluationMaterial is the minimum explicit material persisted at evidence
// acceptance that is required for Phase-2 evaluation. It is separate from
// AcceptedEvidence.Representation (which remains EvidenceIdentityV1 /
// idempotency only).
//
// All mutable fields are defensively copied at admission, staging, and
// readback.
type EvaluationMaterial struct {
	CSRSha256       string          `json:"csr_sha256"`
	PublicKeySha256 string          `json:"public_key_sha256"`
	TPMFormat       string          `json:"tpm_format"`
	TPMVersion      string          `json:"tpm_version"`
	TPMPayload      json.RawMessage `json:"tpm_payload"`
	AgentAssertions json.RawMessage `json:"agent_assertions,omitempty"`
}

// Clone returns a defensive deep copy.
func (m EvaluationMaterial) Clone() EvaluationMaterial {
	return EvaluationMaterial{
		CSRSha256:       m.CSRSha256,
		PublicKeySha256: m.PublicKeySha256,
		TPMFormat:       m.TPMFormat,
		TPMVersion:      m.TPMVersion,
		TPMPayload:      append(json.RawMessage(nil), m.TPMPayload...),
		AgentAssertions: append(json.RawMessage(nil), m.AgentAssertions...),
	}
}

// Validate checks that the minimum required fields are present.
func (m EvaluationMaterial) Validate() error {
	if strings.TrimSpace(m.CSRSha256) == "" || strings.TrimSpace(m.PublicKeySha256) == "" {
		return errors.New("enrollment evaluation: evaluation material missing CSR/PK hashes")
	}
	if strings.TrimSpace(m.TPMFormat) == "" || strings.TrimSpace(m.TPMVersion) == "" {
		return errors.New("enrollment evaluation: evaluation material missing TPM format/version")
	}
	if len(m.TPMPayload) == 0 {
		return errors.New("enrollment evaluation: evaluation material missing TPM payload")
	}
	return nil
}

// ToTPMMaterial converts the evaluation material into the verifier input
// format (defensive copy of payload).
func (m EvaluationMaterial) ToTPMMaterial() TPMEvidenceMaterial {
	return TPMEvidenceMaterial{
		Format:  m.TPMFormat,
		Version: m.TPMVersion,
		Payload: append(json.RawMessage(nil), m.TPMPayload...),
	}
}

// ---------------------------------------------------------------------------
// §8. ASSURANCE AUTHORITY
// ---------------------------------------------------------------------------

// AssuranceLevel is the server-side achieved assurance after combining
// verifier-backed facts, non-authoritative agent assertions, and current
// authoritative server policy.
//
// Zero value is invalid and must never authorise issuance.
type AssuranceLevel string

const (
	AssuranceA0 AssuranceLevel = "A0"
	AssuranceA1 AssuranceLevel = "A1"
	AssuranceA2 AssuranceLevel = "A2"
	AssuranceA3 AssuranceLevel = "A3"
)

// Valid reports whether l is a known assurance level.
func (l AssuranceLevel) Valid() bool {
	switch l {
	case AssuranceA0, AssuranceA1, AssuranceA2, AssuranceA3:
		return true
	default:
		return false
	}
}

// RequiresVerifierBacking reports whether this level can only be achieved
// through verifier-backed remote-attestation evidence (not local agent
// assertions alone). This describes attestation CAPABILITY, not issuance
// authorization. OPEN-005 remains open.
func (l AssuranceLevel) RequiresVerifierBacking() bool {
	return l == AssuranceA2 || l == AssuranceA3
}

// ---------------------------------------------------------------------------
// §11. AUTHORITY / POLICY PORTS (FRESHNESS)
// ---------------------------------------------------------------------------

// PartnerEligibility contains the current partner eligibility and its revision.
type PartnerEligibility struct {
	PartnerID string
	Eligible  bool
	Revision  uint64
}

// Validate checks structural integrity: PartnerID must be non-empty and
// revision must be non-zero.
func (pe PartnerEligibility) Validate() error {
	if strings.TrimSpace(pe.PartnerID) == "" {
		return errors.New("enrollment evaluation: partner eligibility missing PartnerID")
	}
	if pe.Revision == 0 {
		return errors.New("enrollment evaluation: partner eligibility missing revision")
	}
	return nil
}

// DeviceEligibility contains the current device eligibility and its revision.
type DeviceEligibility struct {
	DeviceID string
	Eligible bool
	Revision uint64
}

// Validate checks structural integrity: DeviceID must be non-empty and
// revision must be non-zero.
func (de DeviceEligibility) Validate() error {
	if strings.TrimSpace(de.DeviceID) == "" {
		return errors.New("enrollment evaluation: device eligibility missing DeviceID")
	}
	if de.Revision == 0 {
		return errors.New("enrollment evaluation: device eligibility missing revision")
	}
	return nil
}

// ApprovalRebind is the authoritative approval/rebind decision for a
// specific PartnerID + DeviceID combination. The authority must return
// the record bound to both identities; cross-partner lookups are forbidden.
type ApprovalRebind struct {
	// PartnerID is the partner for which this approval was issued.
	PartnerID string

	// DeviceID is the device for which this approval was issued.
	DeviceID string

	// Approved is true when approval/rebind is explicitly granted or
	// not applicable for this flow.
	Approved bool

	// Reference is an immutable identifier of the applicable approval/
	// rebind record (or the authority-defined N/A sentinel).
	Reference string

	// Revision is the monotonic authority revision used for freshness.
	Revision uint64
}

// Validate checks structural integrity: PartnerID, DeviceID and Reference
// must be non-empty; Revision must be non-zero.
func (ar ApprovalRebind) Validate() error {
	if strings.TrimSpace(ar.PartnerID) == "" || strings.TrimSpace(ar.DeviceID) == "" {
		return errors.New("enrollment evaluation: approval/rebind missing PartnerID or DeviceID")
	}
	if strings.TrimSpace(ar.Reference) == "" {
		return errors.New("enrollment evaluation: approval/rebind missing reference")
	}
	if ar.Revision == 0 {
		return errors.New("enrollment evaluation: approval/rebind missing revision")
	}
	return nil
}

// CertificateProfile contains the current server-side certificate profile
// assignment and its revision. DeviceID and CertificateUsage are the exact
// authoritative scope used to resolve this profile; a returned profile whose
// scope does not match the evaluation is a malformed/wrong-resource fact and
// must never be treated as an authoritative denial.
type CertificateProfile struct {
	DeviceID         string
	CertificateUsage string
	ProfileID        string
	Version          string
	Revision         uint64
}

// Validate checks structural integrity: the scoped identity, profile
// identity/version and revision must all be present and valid.
func (cp CertificateProfile) Validate() error {
	if strings.TrimSpace(cp.DeviceID) == "" || strings.TrimSpace(cp.CertificateUsage) == "" {
		return errors.New("enrollment evaluation: certificate profile missing device/usage scope")
	}
	if strings.TrimSpace(cp.ProfileID) == "" || strings.TrimSpace(cp.Version) == "" {
		return errors.New("enrollment evaluation: certificate profile missing profile identity/version")
	}
	if cp.Revision == 0 {
		return errors.New("enrollment evaluation: certificate profile missing revision")
	}
	return nil
}

// AssurancePolicy contains the current minimum assurance policy. PartnerID and
// CertificateUsage are the exact authoritative scope used to resolve this
// policy; a returned policy whose scope does not match the evaluation is a
// malformed/wrong-resource fact and must never be treated as an authoritative
// denial.
type AssurancePolicy struct {
	PartnerID        string
	CertificateUsage string
	MinimumAssurance AssuranceLevel
	Revision         uint64
}

// Validate checks structural integrity: the scoped identity must be present,
// MinimumAssurance must be a recognized value and Revision must be non-zero.
func (ap AssurancePolicy) Validate() error {
	if strings.TrimSpace(ap.PartnerID) == "" || strings.TrimSpace(ap.CertificateUsage) == "" {
		return errors.New("enrollment evaluation: assurance policy missing partner/usage scope")
	}
	if !ap.MinimumAssurance.Valid() {
		return errors.New("enrollment evaluation: assurance policy has invalid MinimumAssurance")
	}
	if ap.Revision == 0 {
		return errors.New("enrollment evaluation: assurance policy missing revision")
	}
	return nil
}

// IsSufficient reports whether the achieved assurance meets or exceeds the
// minimum.
func (p AssurancePolicy) IsSufficient(achieved AssuranceLevel) bool {
	if !achieved.Valid() || !p.MinimumAssurance.Valid() {
		return false
	}
	levels := map[AssuranceLevel]int{
		AssuranceA0: 0, AssuranceA1: 1, AssuranceA2: 2, AssuranceA3: 3,
	}
	return levels[achieved] >= levels[p.MinimumAssurance]
}

// PolicyVersion is a server-wide policy version identifier for freshness.
type PolicyVersion struct {
	Version  string
	Revision uint64
}

// Validate checks structural integrity.
func (pv PolicyVersion) Validate() error {
	if strings.TrimSpace(pv.Version) == "" {
		return errors.New("enrollment evaluation: policy version is empty")
	}
	if pv.Revision == 0 {
		return errors.New("enrollment evaluation: policy version missing revision")
	}
	return nil
}

// EvaluationAuthority provides the current authoritative facts needed for a
// Phase-2 evaluation decision. Every fact carries a revision/version identity
// for commit-time freshness validation.
type EvaluationAuthority interface {
	GetPartnerEligibility(ctx context.Context, partnerID string) (PartnerEligibility, error)
	GetDeviceEligibility(ctx context.Context, deviceID string) (DeviceEligibility, error)
	GetApprovalRebind(ctx context.Context, deviceID, partnerID string) (ApprovalRebind, error)
	GetCertificateProfile(ctx context.Context, deviceID, certificateUsage string) (CertificateProfile, error)
	GetAssurancePolicy(ctx context.Context, partnerID, certificateUsage string) (AssurancePolicy, error)
	GetPolicyVersion(ctx context.Context) (PolicyVersion, error)
}

// ---------------------------------------------------------------------------
// §12. EVALUATION READ-SET
// ---------------------------------------------------------------------------

// EvaluationReadSet captures the exact authoritative facts read during a
// Phase-2 evaluation. At commit, every entry is revalidated; if any revision
// has changed the evaluation is INDETERMINATE and must not publish a
// definitive outcome.
type EvaluationReadSet struct {
	PartnerEligibility PartnerEligibility
	DeviceEligibility  DeviceEligibility
	ApprovalRebind     ApprovalRebind
	CertificateProfile CertificateProfile
	AssurancePolicy    AssurancePolicy
	PolicyVersion      PolicyVersion
	// CertificateUsage is the usage scope used when resolving profile and
	// assurance policy. It is captured so commit-time freshness validation
	// can re-resolve the same scoped authorities.
	CertificateUsage string
}

// Validate checks that all read-set facts are structurally valid and that
// their identities are internally consistent with the evaluation scope. A
// malformed, contradictory, or wrong-resource read-set must never reach a
// policy decision.
func (rs EvaluationReadSet) Validate() error {
	if err := rs.PartnerEligibility.Validate(); err != nil {
		return err
	}
	if err := rs.DeviceEligibility.Validate(); err != nil {
		return err
	}
	if err := rs.ApprovalRebind.Validate(); err != nil {
		return err
	}
	if err := rs.CertificateProfile.Validate(); err != nil {
		return err
	}
	if err := rs.AssurancePolicy.Validate(); err != nil {
		return err
	}
	if err := rs.PolicyVersion.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(rs.CertificateUsage) == "" {
		return errors.New("enrollment evaluation: read-set missing certificate usage scope")
	}
	// Cross-scope identity: every fact must be bound to the same resource
	// identities used by the decision.
	if rs.PartnerEligibility.PartnerID != rs.AssurancePolicy.PartnerID ||
		rs.PartnerEligibility.PartnerID != rs.ApprovalRebind.PartnerID {
		return errors.New("enrollment evaluation: read-set partner identity mismatch")
	}
	if rs.DeviceEligibility.DeviceID != rs.CertificateProfile.DeviceID ||
		rs.DeviceEligibility.DeviceID != rs.ApprovalRebind.DeviceID {
		return errors.New("enrollment evaluation: read-set device identity mismatch")
	}
	if rs.CertificateUsage != rs.CertificateProfile.CertificateUsage ||
		rs.CertificateUsage != rs.AssurancePolicy.CertificateUsage {
		return errors.New("enrollment evaluation: read-set certificate usage mismatch")
	}
	return nil
}

// ---------------------------------------------------------------------------
// §13. POSITIVE DECISION SNAPSHOT
// ---------------------------------------------------------------------------

// EvaluationDecisionSnapshot is the immutable, server-owned snapshot produced
// by a positive (AUTHORIZED) Phase-2 decision. It is defensively copied before
// persistence and contains no mutable pointers.
type EvaluationDecisionSnapshot struct {
	PartnerID          string
	DeviceID           string
	ApprovalReference  string
	CertificateProfile string
	ProfileVersion     string
	PolicyVersion      string
	AchievedAssurance  AssuranceLevel
	CSRSha256          string
	PublicKeySha256    string
	ChallengeVersion   int
	ChallengeNonce     string
	EvidenceReference  string
	CorrelationID      string
	DecidedAt          time.Time
}

func (s EvaluationDecisionSnapshot) Clone() EvaluationDecisionSnapshot {
	return s
}

func (s EvaluationDecisionSnapshot) Validate() error {
	if strings.TrimSpace(s.PartnerID) == "" || strings.TrimSpace(s.DeviceID) == "" {
		return errors.New("enrollment evaluation: decision snapshot missing partner/device")
	}
	if strings.TrimSpace(s.ApprovalReference) == "" {
		return errors.New("enrollment evaluation: decision snapshot missing approval reference")
	}
	if strings.TrimSpace(s.CertificateProfile) == "" || strings.TrimSpace(s.ProfileVersion) == "" {
		return errors.New("enrollment evaluation: decision snapshot missing profile")
	}
	if strings.TrimSpace(s.PolicyVersion) == "" {
		return errors.New("enrollment evaluation: decision snapshot missing policy version")
	}
	if !s.AchievedAssurance.Valid() {
		return errors.New("enrollment evaluation: decision snapshot assurance is invalid")
	}
	if strings.TrimSpace(s.CSRSha256) == "" || strings.TrimSpace(s.PublicKeySha256) == "" {
		return errors.New("enrollment evaluation: decision snapshot missing CSR/PK hashes")
	}
	if s.ChallengeVersion < 1 || strings.TrimSpace(s.ChallengeNonce) == "" {
		return errors.New("enrollment evaluation: decision snapshot missing challenge binding")
	}
	if strings.TrimSpace(s.EvidenceReference) == "" {
		return errors.New("enrollment evaluation: decision snapshot missing evidence reference")
	}
	if strings.TrimSpace(s.CorrelationID) == "" {
		return errors.New("enrollment evaluation: decision snapshot missing correlation ID")
	}
	if s.DecidedAt.IsZero() {
		return errors.New("enrollment evaluation: decision snapshot missing timestamp")
	}
	return nil
}

// ---------------------------------------------------------------------------
// §14. NEGATIVE COMMIT METADATA
// ---------------------------------------------------------------------------

// VerifierIdentifier is a bounded, provider-neutral identifier for the
// attestation verifier that produced a decision (its reference or version).
// It is audit provenance only and must never carry diagnostic/error text or
// arbitrary unbounded content.
type VerifierIdentifier string

// verifierIdentifierMaxLen bounds a verifier identifier. The bound is a small
// provider-neutral limit consistent with repository identifier conventions;
// it does not encode any vendor-specific semantics.
const verifierIdentifierMaxLen = 128

// validVerifierIdentifier reports whether s is a safe provider-neutral
// identifier: empty is permitted (the fields are optional), otherwise it must
// be 1..128 printable ASCII bytes in 0x21..0x7E.
func validVerifierIdentifier(s string) bool {
	if len(s) == 0 {
		return true
	}
	if len(s) > verifierIdentifierMaxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7E {
			return false
		}
	}
	return true
}

// Valid reports whether the identifier may be persisted as audit provenance.
func (v VerifierIdentifier) Valid() bool { return validVerifierIdentifier(string(v)) }

// EvaluationDenialMetadata is the bounded, non-secret metadata published
// atomically with a DEFINITIVE_NEGATIVE commitment. It deliberately excludes
// arbitrary verifier error text, TPM payload, JWS, CSR DER, credentials, and
// private material.
type EvaluationDenialMetadata struct {
	Category           DenialCategory
	EnrollmentID       string
	EvidenceReference  string
	CertificateProfile string
	ProfileVersion     string
	PolicyVersion      string
	VerifierReference  VerifierIdentifier
	VerifierVersion    VerifierIdentifier
	CorrelationID      string
	DeniedAt           time.Time
}

func (m EvaluationDenialMetadata) Validate() error {
	if !m.Category.Valid() {
		return errors.New("enrollment evaluation: invalid denial category")
	}
	if strings.TrimSpace(m.EnrollmentID) == "" {
		return errors.New("enrollment evaluation: denial metadata missing enrollment ID")
	}
	if strings.TrimSpace(m.EvidenceReference) == "" {
		return errors.New("enrollment evaluation: denial metadata missing evidence reference")
	}
	if strings.TrimSpace(m.CorrelationID) == "" {
		return errors.New("enrollment evaluation: denial metadata missing correlation ID")
	}
	if !m.VerifierReference.Valid() {
		return errors.New("enrollment evaluation: denial metadata verifier reference is not a bounded identifier")
	}
	if !m.VerifierVersion.Valid() {
		return errors.New("enrollment evaluation: denial metadata verifier version is not a bounded identifier")
	}
	if m.DeniedAt.IsZero() {
		return errors.New("enrollment evaluation: denial metadata missing timestamp")
	}
	return nil
}

// ---------------------------------------------------------------------------
// §17. INTERNAL MILESTONE
// ---------------------------------------------------------------------------

// AttestationVerifiedMarker is an internal milestone, not a domain state.
// It is published atomically with the positive AUTHORIZED commit alongside
// the ISSUANCE_AUTHORIZED audit event.
type AttestationVerifiedMarker struct {
	EnrollmentID  string
	AchievedLevel AssuranceLevel
	VerifiedAt    time.Time
}

func (m AttestationVerifiedMarker) Validate() error {
	if strings.TrimSpace(m.EnrollmentID) == "" || !m.AchievedLevel.Valid() {
		return errors.New("enrollment evaluation: invalid ATTESTATION_VERIFIED marker")
	}
	if m.VerifiedAt.IsZero() {
		return errors.New("enrollment evaluation: ATTESTATION_VERIFIED marker missing timestamp")
	}
	return nil
}

// ---------------------------------------------------------------------------
// §19. EVALUATION UNIT OF WORK EXTENSION
// ---------------------------------------------------------------------------

// EvaluationUnitOfWork extends the existing ContinuationUnitOfWork with the
// persistence boundaries needed for Phase-2 evaluation. It owns staging for
// state transitions, decision snapshots, denial metadata, and audit events.
type EvaluationUnitOfWork interface {
	ContinuationUnitOfWork

	// StageAuthorized stages the positive commit: state transition,
	// decision snapshot, milestone, read-set, and audit event.
	// The readSet is used at commit-time for freshness validation.
	StageAuthorized(ctx context.Context, enrollmentID string, snapshot EvaluationDecisionSnapshot, marker AttestationVerifiedMarker, readSet EvaluationReadSet) error

	// StageRejected stages the negative commit: state transition,
	// denial metadata, read-set, and audit event.
	// The readSet is used at commit-time for freshness validation.
	StageRejected(ctx context.Context, enrollmentID string, metadata EvaluationDenialMetadata, readSet EvaluationReadSet) error

	// GetEvaluationMaterial retrieves the persisted evaluation material
	// for an enrollment.
	GetEvaluationMaterial(ctx context.Context, enrollmentID string) (EvaluationMaterial, bool, error)

	// GetEnrollmentForEvaluation retrieves the enrollment record with
	// all fields needed for Phase-2 evaluation.
	GetEnrollmentForEvaluation(ctx context.Context, enrollmentID string) (EnrollmentRecord, bool, error)
}

// ---------------------------------------------------------------------------
// §19. EVALUATION UOW MANAGER
// ---------------------------------------------------------------------------

// EvaluationUnitOfWorkManager begins an evaluation-scoped Unit of Work.
type EvaluationUnitOfWorkManager interface {
	BeginEvaluation(ctx context.Context) (EvaluationUnitOfWork, error)
}
