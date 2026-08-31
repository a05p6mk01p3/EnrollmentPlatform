// Package application — Phase-2 EvaluateEnrollment use case (M5.9).
//
// This file implements the dedicated application-level Phase-2 evaluation
// use case. It is deliberately NOT exposed through an HTTP route, NOT
// automatically called by SubmitEvidence, and NOT wired to a worker/scheduler.
//
// Production composition may remain completely unaware of this function.

package application

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	domain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/domain/enrollment"
)

// ---------------------------------------------------------------------------
// §9. EVALUATE ENROLLMENT
// ---------------------------------------------------------------------------

// EvaluationDependencies are the Phase-2 evaluation-specific dependencies
// injected alongside the existing Service.
type EvaluationDependencies struct {
	Verifier   AttestationVerifier
	Authority  EvaluationAuthority
	UOWManager EvaluationUnitOfWorkManager
	Clock      Clock
}

// Validate checks that all dependencies are non-nil and pass their own
// validation (where applicable). Fail-closed: typed nil is rejected via
// reflection following the repository convention (isNilLike).
func (d EvaluationDependencies) Validate() error {
	if isNilLike(d.Verifier) {
		return errors.New("enrollment evaluation: attestation verifier is nil")
	}
	if isNilLike(d.Authority) {
		return errors.New("enrollment evaluation: evaluation authority is nil")
	}
	if isNilLike(d.UOWManager) {
		return errors.New("enrollment evaluation: UOW manager is nil")
	}
	if isNilLike(d.Clock) {
		return errors.New("enrollment evaluation: clock is nil")
	}
	return nil
}

// EvaluateEnrollmentCommand is the input for Phase-2 evaluation.
// It requires no authentication (the caller is internal) and carries only
// the enrollment identifier and correlation reference.
type EvaluateEnrollmentCommand struct {
	EnrollmentID  string
	CorrelationID string
}

// EvaluateEnrollmentResult is the stable output of a Phase-2 evaluation.
type EvaluateEnrollmentResult struct {
	Outcome EvaluationResult
	// For POSITIVE: the enrollment is now AUTHORIZED.
	// For DEFINITIVE_NEGATIVE: the enrollment is now REJECTED.
	// For INDETERMINATE: the enrollment remains EVIDENCE_RECEIVED.
	State domain.State
}

// EvaluateEnrollment executes the Phase-2 evaluation for an enrollment in
// EVIDENCE_RECEIVED. It loads the persisted evaluation material, invokes the
// AttestationVerifier, resolves current authoritative policy/eligibility
// facts, and commits exactly one logical outcome with full freshness
// validation.
//
// The use case MUST NOT:
//   - be exposed through a new HTTP route;
//   - be automatically called by SubmitEvidence;
//   - invoke CA progression;
//   - call MarkCARequested.
//
// Repeated invocation after AUTHORIZED or REJECTED recognises the committed
// terminal result and performs no new authoritative mutation/event.
func EvaluateEnrollment(ctx context.Context, deps EvaluationDependencies, cmd EvaluateEnrollmentCommand) (EvaluateEnrollmentResult, error) {
	if err := deps.Validate(); err != nil {
		return EvaluateEnrollmentResult{}, fmt.Errorf("enrollment evaluation: %w", err)
	}
	if strings.TrimSpace(cmd.EnrollmentID) == "" {
		return EvaluateEnrollmentResult{}, errors.New("enrollment evaluation: enrollment ID is required")
	}

	now := deps.Clock.Now()
	if now.IsZero() {
		return EvaluateEnrollmentResult{}, errors.New("enrollment evaluation: clock returned zero time")
	}

	uow, err := deps.UOWManager.BeginEvaluation(ctx)
	if err != nil {
		return EvaluateEnrollmentResult{}, fmt.Errorf("enrollment evaluation: begin UOW: %w", err)
	}
	defer uow.Rollback(ctx)

	// 1. Load enrollment and verify it is in EVIDENCE_RECEIVED.
	record, found, err := uow.GetEnrollmentForEvaluation(ctx, cmd.EnrollmentID)
	if err != nil {
		return EvaluateEnrollmentResult{}, fmt.Errorf("enrollment evaluation: get enrollment: %w", err)
	}
	if !found {
		return EvaluateEnrollmentResult{}, ErrEnrollmentNotFound
	}
	if record.Aggregate == nil {
		return EvaluateEnrollmentResult{}, fmt.Errorf("enrollment evaluation: aggregate is nil")
	}

	switch record.Aggregate.State() {
	case domain.StateAuthorized:
		// Already authorised; return terminal result without mutation.
		return EvaluateEnrollmentResult{Outcome: EvaluationResultPositive, State: domain.StateAuthorized}, nil
	case domain.StateRejected:
		// Already rejected; return terminal result without mutation.
		return EvaluateEnrollmentResult{Outcome: EvaluationResultDefinitiveNegative, State: domain.StateRejected}, nil
	case domain.StateEvidenceReceived:
		// Proceed with evaluation.
	default:
		return EvaluateEnrollmentResult{}, fmt.Errorf("enrollment evaluation: enrollment in unexpected state %s", record.Aggregate.State())
	}

	// A definitive decision requires a trusted correlation identifier. An
	// empty correlation must fail closed as INDETERMINATE and must never
	// publish AUTHORIZED or REJECTED.
	if strings.TrimSpace(cmd.CorrelationID) == "" {
		return EvaluateEnrollmentResult{Outcome: EvaluationResultIndeterminate, State: domain.StateEvidenceReceived}, nil
	}

	// 2. Load evaluation material.
	material, found, err := uow.GetEvaluationMaterial(ctx, cmd.EnrollmentID)
	if err != nil {
		return EvaluateEnrollmentResult{}, fmt.Errorf("enrollment evaluation: get material: %w", err)
	}
	if !found || material.Validate() != nil {
		return EvaluateEnrollmentResult{Outcome: EvaluationResultIndeterminate, State: domain.StateEvidenceReceived}, nil
	}

	// 3. Load current authoritative policy/eligibility facts.
	readSet, err := loadEvaluationReadSet(ctx, deps.Authority, record.PartnerID, record.DeviceID, record.CertificateUsage)
	if err != nil {
		return EvaluateEnrollmentResult{Outcome: EvaluationResultIndeterminate, State: domain.StateEvidenceReceived}, nil
	}
	if err := readSet.Validate(); err != nil {
		return EvaluateEnrollmentResult{Outcome: EvaluationResultIndeterminate, State: domain.StateEvidenceReceived}, nil
	}

	// 4. Invoke AttestationVerifier.
	verifierResult, verifierErr := deps.Verifier.Verify(ctx, AttestationVerificationRequest{
		EnrollmentID:     cmd.EnrollmentID,
		ChallengeVersion: record.Challenge.ChallengeVersion,
		Nonce:            record.Challenge.Nonce,
		CSRSha256:        material.CSRSha256,
		PublicKeySha256:  material.PublicKeySha256,
		TPMMaterial:      material.ToTPMMaterial(),
	})

	// 5. Classify result.
	result := classifyVerifierResult(verifierResult, verifierErr)

	// 6. If verifier was positive, derive achieved assurance and evaluate policy.
	if result == EvaluationResultPositive {
		result = evaluatePolicy(readSet, verifierResult)
	}

	// 7. INDETERMINATE -> no mutation, return.
	if result == EvaluationResultIndeterminate {
		return EvaluateEnrollmentResult{Outcome: EvaluationResultIndeterminate, State: domain.StateEvidenceReceived}, nil
	}

	// 8. Commit the definitive outcome.
	if result == EvaluationResultPositive {
		return commitPositive(ctx, uow, cmd, record, material, verifierResult, readSet, now)
	}
	return commitNegative(ctx, uow, cmd, record, verifierResult, readSet, now)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func loadEvaluationReadSet(ctx context.Context, authority EvaluationAuthority, partnerID, deviceID, certificateUsage string) (EvaluationReadSet, error) {
	var rs EvaluationReadSet

	pe, err := authority.GetPartnerEligibility(ctx, partnerID)
	if err != nil {
		return rs, err
	}
	rs.PartnerEligibility = pe

	de, err := authority.GetDeviceEligibility(ctx, deviceID)
	if err != nil {
		return rs, err
	}
	rs.DeviceEligibility = de

	ar, err := authority.GetApprovalRebind(ctx, deviceID, partnerID)
	if err != nil {
		return rs, err
	}
	rs.ApprovalRebind = ar

	cp, err := authority.GetCertificateProfile(ctx, deviceID, certificateUsage)
	if err != nil {
		return rs, err
	}
	rs.CertificateProfile = cp

	ap, err := authority.GetAssurancePolicy(ctx, partnerID, certificateUsage)
	if err != nil {
		return rs, err
	}
	rs.AssurancePolicy = ap

	pv, err := authority.GetPolicyVersion(ctx)
	if err != nil {
		return rs, err
	}
	rs.PolicyVersion = pv

	rs.CertificateUsage = certificateUsage

	// Structural integrity of each authority fact and internal cross-scope
	// consistency are validated by EvaluationReadSet.Validate. Here we enforce
	// the evaluation resource identity: a fact returned for the wrong resource
	// is INDETERMINATE, never an authoritative denial.
	if rs.PartnerEligibility.PartnerID != partnerID {
		return rs, fmt.Errorf("enrollment evaluation: partner eligibility resolved for wrong partner %q", rs.PartnerEligibility.PartnerID)
	}
	if rs.DeviceEligibility.DeviceID != deviceID {
		return rs, fmt.Errorf("enrollment evaluation: device eligibility resolved for wrong device %q", rs.DeviceEligibility.DeviceID)
	}
	if rs.ApprovalRebind.PartnerID != partnerID || rs.ApprovalRebind.DeviceID != deviceID {
		return rs, fmt.Errorf("enrollment evaluation: approval/rebind resolved for wrong resource")
	}
	if rs.CertificateProfile.DeviceID != deviceID || rs.CertificateProfile.CertificateUsage != certificateUsage {
		return rs, fmt.Errorf("enrollment evaluation: certificate profile resolved for wrong device/usage scope")
	}
	if rs.AssurancePolicy.PartnerID != partnerID || rs.AssurancePolicy.CertificateUsage != certificateUsage {
		return rs, fmt.Errorf("enrollment evaluation: assurance policy resolved for wrong partner/usage scope")
	}

	return rs, nil
}

func classifyVerifierResult(vr AttestationVerificationResult, verifierErr error) EvaluationResult {
	// Adapter error -> INDETERMINATE.
	if verifierErr != nil {
		return EvaluationResultIndeterminate
	}
	// Zero/invalid result -> INDETERMINATE (fail closed).
	if !vr.Valid() {
		return EvaluationResultIndeterminate
	}
	// Valid outcome.
	return vr.Outcome
}

func evaluatePolicy(rs EvaluationReadSet, vr AttestationVerificationResult) EvaluationResult {
	// Partner eligibility.
	if !rs.PartnerEligibility.Eligible {
		return EvaluationResultDefinitiveNegative
	}
	// Device eligibility.
	if !rs.DeviceEligibility.Eligible {
		return EvaluationResultDefinitiveNegative
	}
	// Approval/rebind.
	if !rs.ApprovalRebind.Approved {
		return EvaluationResultDefinitiveNegative
	}
	// Minimum assurance against CURRENT authoritative policy.
	// OPEN-005 remains open: no globally hardcoded A2/A3 threshold.
	level := AssuranceLevel(vr.AchievedAssurance)
	if !level.Valid() {
		// Unreachable for validated POSITIVE results; fail closed if ever hit.
		return EvaluationResultIndeterminate
	}
	if !rs.AssurancePolicy.IsSufficient(level) {
		return EvaluationResultDefinitiveNegative
	}
	// Profile must be present. This is structurally validated earlier; fail
	// closed as INDETERMINATE rather than a definitive denial if ever absent.
	if strings.TrimSpace(rs.CertificateProfile.ProfileID) == "" {
		return EvaluationResultIndeterminate
	}
	return EvaluationResultPositive
}

func commitPositive(
	ctx context.Context,
	uow EvaluationUnitOfWork,
	cmd EvaluateEnrollmentCommand,
	record EnrollmentRecord,
	material EvaluationMaterial,
	vr AttestationVerificationResult,
	rs EvaluationReadSet,
	now time.Time,
) (EvaluateEnrollmentResult, error) {
	// Derive evidence reference from the accepted evidence fingerprint.
	evidenceRef := evidenceReference(record)

	snapshot := EvaluationDecisionSnapshot{
		PartnerID:          record.PartnerID,
		DeviceID:           record.DeviceID,
		ApprovalReference:  rs.ApprovalRebind.Reference,
		CertificateProfile: rs.CertificateProfile.ProfileID,
		ProfileVersion:     rs.CertificateProfile.Version,
		PolicyVersion:      rs.PolicyVersion.Version,
		AchievedAssurance:  AssuranceLevel(vr.AchievedAssurance),
		CSRSha256:          material.CSRSha256,
		PublicKeySha256:    material.PublicKeySha256,
		ChallengeVersion:   record.Challenge.ChallengeVersion,
		ChallengeNonce:     record.Challenge.Nonce,
		EvidenceReference:  evidenceRef,
		DecidedAt:          now,
		CorrelationID:      cmd.CorrelationID,
	}

	if err := snapshot.Validate(); err != nil {
		return EvaluateEnrollmentResult{}, fmt.Errorf("enrollment evaluation: invalid decision snapshot: %w", err)
	}

	marker := AttestationVerifiedMarker{
		EnrollmentID:  cmd.EnrollmentID,
		AchievedLevel: AssuranceLevel(vr.AchievedAssurance),
		VerifiedAt:    now,
	}
	if err := marker.Validate(); err != nil {
		return EvaluateEnrollmentResult{}, fmt.Errorf("enrollment evaluation: invalid attestation marker: %w", err)
	}

	if err := uow.StageAuthorized(ctx, cmd.EnrollmentID, snapshot, marker, rs); err != nil {
		return EvaluateEnrollmentResult{}, fmt.Errorf("enrollment evaluation: stage authorized: %w", err)
	}

	if err := uow.Commit(ctx); err != nil {
		return EvaluateEnrollmentResult{Outcome: EvaluationResultIndeterminate, State: domain.StateEvidenceReceived}, nil
	}

	return EvaluateEnrollmentResult{Outcome: EvaluationResultPositive, State: domain.StateAuthorized}, nil
}

func evidenceReference(record EnrollmentRecord) string {
	if record.AcceptedEvidence != nil && !record.AcceptedEvidence.Fingerprint.IsZero() {
		return record.AcceptedEvidence.Fingerprint.String()
	}
	return ""
}

func commitNegative(
	ctx context.Context,
	uow EvaluationUnitOfWork,
	cmd EvaluateEnrollmentCommand,
	record EnrollmentRecord,
	vr AttestationVerificationResult,
	rs EvaluationReadSet,
	now time.Time,
) (EvaluateEnrollmentResult, error) {
	category := determineDenialCategory(vr, rs)

	metadata := EvaluationDenialMetadata{
		Category:           category,
		EnrollmentID:       cmd.EnrollmentID,
		EvidenceReference:  evidenceReference(record),
		CertificateProfile: rs.CertificateProfile.ProfileID,
		ProfileVersion:     rs.CertificateProfile.Version,
		PolicyVersion:      rs.PolicyVersion.Version,
		VerifierReference:  VerifierIdentifier(vr.VerifierReference),
		VerifierVersion:    VerifierIdentifier(vr.VerifierVersion),
		CorrelationID:      cmd.CorrelationID,
		DeniedAt:           now,
	}

	if err := metadata.Validate(); err != nil {
		// A denial whose provenance cannot be trusted is INDETERMINATE, never
		// a published terminal denial.
		return EvaluateEnrollmentResult{Outcome: EvaluationResultIndeterminate, State: domain.StateEvidenceReceived}, nil
	}

	if err := uow.StageRejected(ctx, cmd.EnrollmentID, metadata, rs); err != nil {
		return EvaluateEnrollmentResult{}, fmt.Errorf("enrollment evaluation: stage rejected: %w", err)
	}

	if err := uow.Commit(ctx); err != nil {
		return EvaluateEnrollmentResult{Outcome: EvaluationResultIndeterminate, State: domain.StateEvidenceReceived}, nil
	}

	return EvaluateEnrollmentResult{Outcome: EvaluationResultDefinitiveNegative, State: domain.StateRejected}, nil
}

func determineDenialCategory(vr AttestationVerificationResult, rs EvaluationReadSet) DenialCategory {
	if vr.Outcome == EvaluationResultDefinitiveNegative {
		return DenialCategoryVerifierDenied
	}
	if !rs.PartnerEligibility.Eligible {
		return DenialCategoryPartnerNotEligible
	}
	if !rs.DeviceEligibility.Eligible {
		return DenialCategoryDeviceNotEligible
	}
	if !rs.ApprovalRebind.Approved {
		return DenialCategoryPolicyDenied
	}
	level := AssuranceLevel(vr.AchievedAssurance)
	if !level.Valid() || !rs.AssurancePolicy.IsSufficient(level) {
		return DenialCategoryAssuranceInsufficient
	}
	if strings.TrimSpace(rs.CertificateProfile.ProfileID) == "" {
		return DenialCategoryProfileMismatch
	}
	return DenialCategoryPolicyDenied
}

// ---------------------------------------------------------------------------
// §4. TEST DOUBLE CONTAINMENT
// ---------------------------------------------------------------------------
// No deterministic/successful verifier lives in this production file.
// Production code has no automatic route to a test verifier.
// All test verifiers MUST live in *_test.go files only.
