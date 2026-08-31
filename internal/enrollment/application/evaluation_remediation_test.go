// Package application_test — M5.9-IMPL-FIX-005 remediation certification tests.
//
// These tests prove the ten adversarial-audit findings (M59-FINAL-001 through
// M59-FINAL-010) are actually fixed. They exercise the real evaluation path,
// directly inspect persisted decision artifacts, and inject failures to prove
// all-or-none atomicity, provenance, ownership, usage-scoping and malformed
// authority handling.
package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	domain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/domain/enrollment"
	application "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/application"
	enrollmentruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/runtime"
)

// ---------------------------------------------------------------------------
// §3.2 / FINAL-010A — REAL admission path feeds evaluation material.
// ---------------------------------------------------------------------------

// malformedPositiveVerifier returns POSITIVE with an invalid (missing binding)
// result and a nil adapter error. FINAL-010B forbids using errorVerifier for
// this classification.
type malformedPositiveVerifier struct{}

func (malformedPositiveVerifier) Verify(ctx context.Context, req application.AttestationVerificationRequest) (application.AttestationVerificationResult, error) {
	if err := req.Validate(); err != nil {
		return application.AttestationVerificationResult{}, err
	}
	return application.AttestationVerificationResult{
		Outcome:           application.EvaluationResultPositive,
		AchievedAssurance: "A2",
		// VerifiedBindings left zero => structurally invalid POSITIVE.
	}, nil
}

func TestAdmissionToEvaluationIntegration(t *testing.T) {
	// Use the REAL Service admission path (CreateInitial + SubmitEvidence).
	// No StoreEnrollment / SetEvaluationMaterial seeding of evaluation material.
	h := newAppTestHarness(t)
	ev := newTestEvidenceHelper(t)
	jws := ev.buildJWS(t, h.enrID, h.nonce, 1, nil, nil)

	res, err := h.service.SubmitEvidence(h.ctx, application.EvidenceSubmissionCommand{
		EnrollmentID:     h.enrID,
		ChallengeVersion: 1,
		CsrDerBase64:     ev.csrB64,
		PopFormat:        "enrollment-pop+jws",
		PopJWS:           jws,
		TpmFormat:        "enrollment-tpm-evidence",
		TpmVersion:       "1",
		TpmPayload:       h.tpmJSON,
	})
	if err != nil {
		t.Fatalf("SubmitEvidence failed: %v", err)
	}
	if res.State != domain.StateEvidenceReceived {
		t.Fatalf("expected EVIDENCE_RECEIVED after admission, got %s", res.State)
	}

	// Configure evaluation authority for the same partner/device/usage.
	h.store.SetPartnerEligibility("partner-app-test", true, 1)
	h.store.SetDeviceEligibility("device-app-test", true, 1)
	h.store.SetApprovalRebind("partner-app-test", "device-app-test", "appr-int", true, 1)
	h.store.SetCertificateProfile("device-app-test", "PARTNER_AUTH", "profile-int", "v1", 1)
	h.store.SetAssurancePolicy("partner-app-test", "PARTNER_AUTH", application.AssuranceA1, 1)
	h.store.SetPolicyVersion("policy-v1", 1)

	clock := testClock{now: time.Date(2026, 8, 29, 12, 30, 0, 0, time.UTC)}
	deps := application.EvaluationDependencies{
		Verifier:   positiveVerifier{},
		Authority:  h.store.NewEvaluationAuthority(),
		UOWManager: h.store,
		Clock:      clock,
	}
	result, err := application.EvaluateEnrollment(h.ctx, deps, application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrID,
		CorrelationID: "corr-integration",
	})
	if err != nil {
		t.Fatalf("EvaluateEnrollment failed: %v", err)
	}
	if result.Outcome != application.EvaluationResultPositive || result.State != domain.StateAuthorized {
		t.Fatalf("expected POSITIVE/AUTHORIZED, got %s/%s", result.Outcome, result.State)
	}

	// The persisted snapshot must carry the CSR/PK hashes computed by the real
	// admission boundary, proving material flowed from admission into
	// evaluation without a second SetEvaluationMaterial.
	snap, ok := h.store.GetDecisionSnapshot(h.enrID)
	if !ok {
		t.Fatal("decision snapshot must be persisted")
	}
	if snap.CSRSha256 != ev.csrSha256Hex {
		t.Fatalf("snapshot CSR hash mismatch: got %s want %s", snap.CSRSha256, ev.csrSha256Hex)
	}
	if snap.PublicKeySha256 != ev.publicKeySha256Hex {
		t.Fatalf("snapshot PK hash mismatch: got %s want %s", snap.PublicKeySha256, ev.publicKeySha256Hex)
	}
	if snap.CorrelationID != "corr-integration" {
		t.Fatalf("snapshot correlation mismatch: got %s", snap.CorrelationID)
	}
}

// ---------------------------------------------------------------------------
// §10.B — malformed POSITIVE (not errorVerifier) is INDETERMINATE.
// ---------------------------------------------------------------------------

func TestEmptyCorrelationIDIsIndeterminate(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID: h.enrollmentID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != application.EvaluationResultIndeterminate {
		t.Fatalf("empty correlation must be INDETERMINATE, got %s", result.Outcome)
	}
	if result.State != domain.StateEvidenceReceived {
		t.Fatalf("empty correlation must remain EVIDENCE_RECEIVED, got %s", result.State)
	}
	assertNoTerminalArtifacts(t, h.store, h.enrollmentID)
}

func TestMalformedPositiveVerifierIsIndeterminate(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(malformedPositiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != application.EvaluationResultIndeterminate {
		t.Fatalf("malformed POSITIVE must be INDETERMINATE, got %s", result.Outcome)
	}
	if result.State != domain.StateEvidenceReceived {
		t.Fatalf("INDETERMINATE must remain EVIDENCE_RECEIVED, got %s", result.State)
	}
	assertNoTerminalArtifacts(t, h.store, h.enrollmentID)
}

// ---------------------------------------------------------------------------
// §10.C — positive atomicity (all-or-none, absence after staged failure).
// ---------------------------------------------------------------------------

func TestPositiveAtomicityAllOrNone(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-pos-atomic",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != application.EvaluationResultPositive {
		t.Fatalf("expected POSITIVE, got %s", result.Outcome)
	}

	rec, _ := h.store.GetEnrollment(h.enrollmentID)
	if rec.Aggregate.State() != domain.StateAuthorized {
		t.Fatalf("state must be AUTHORIZED, got %s", rec.Aggregate.State())
	}
	if _, ok := h.store.GetDecisionSnapshot(h.enrollmentID); !ok {
		t.Fatal("decision snapshot must be persisted")
	}
	if _, ok := h.store.GetAttestationMarker(h.enrollmentID); !ok {
		t.Fatal("ATTESTATION_VERIFIED marker must be persisted")
	}
	assertEventPresent(t, h.store, h.enrollmentID, application.AuditEventIssuanceAuthorized)
	assertEventPresent(t, h.store, h.enrollmentID, application.AuditEventAttestationVerified)
}

func TestPositiveAtomicityAbsentAfterStagedFailure(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	uow, err := h.store.BeginEvaluation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rs := remediationReadSet(h)
	snap := remediationSnapshot(h, material, "corr-pos-fail")
	marker := remediationMarker(h)

	if err := uow.StageAuthorized(context.Background(), h.enrollmentID, snap, marker, rs); err != nil {
		t.Fatalf("stage: %v", err)
	}
	// Force commit-time failure after staging: mutate authority revision.
	h.store.SetPartnerEligibility(h.partnerID, true, 99)

	if err := uow.Commit(context.Background()); err == nil {
		t.Fatal("commit must fail after staged freshness violation")
	}
	rec, _ := h.store.GetEnrollment(h.enrollmentID)
	if rec.Aggregate.State() != domain.StateEvidenceReceived {
		t.Fatalf("state must remain EVIDENCE_RECEIVED, got %s", rec.Aggregate.State())
	}
	assertNoTerminalArtifacts(t, h.store, h.enrollmentID)
}

// ---------------------------------------------------------------------------
// §10.D — negative atomicity (all-or-none, absence after staged failure).
// ---------------------------------------------------------------------------

func TestNegativeAtomicityAllOrNone(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(definitiveNegativeVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-neg-atomic",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != application.EvaluationResultDefinitiveNegative {
		t.Fatalf("expected DEFINITIVE_NEGATIVE, got %s", result.Outcome)
	}

	rec, _ := h.store.GetEnrollment(h.enrollmentID)
	if rec.Aggregate.State() != domain.StateRejected {
		t.Fatalf("state must be REJECTED, got %s", rec.Aggregate.State())
	}
	if _, ok := h.store.GetDenialMetadata(h.enrollmentID); !ok {
		t.Fatal("denial metadata must be persisted")
	}
	assertEventPresent(t, h.store, h.enrollmentID, application.AuditEventIssuanceDenied)
}

func TestNegativeAtomicityAbsentAfterStagedFailure(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	uow, err := h.store.BeginEvaluation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rs := remediationReadSet(h)
	md := remediationMetadata(h, application.DenialCategoryPolicyDenied, "corr-neg-fail")

	if err := uow.StageRejected(context.Background(), h.enrollmentID, md, rs); err != nil {
		t.Fatalf("stage: %v", err)
	}
	h.store.SetDeviceEligibility(h.deviceID, true, 99)

	if err := uow.Commit(context.Background()); err == nil {
		t.Fatal("commit must fail after staged freshness violation")
	}
	rec, _ := h.store.GetEnrollment(h.enrollmentID)
	if rec.Aggregate.State() != domain.StateEvidenceReceived {
		t.Fatalf("state must remain EVIDENCE_RECEIVED, got %s", rec.Aggregate.State())
	}
	assertNoTerminalArtifacts(t, h.store, h.enrollmentID)
}

// ---------------------------------------------------------------------------
// §10.E — positive snapshot provenance (exact persisted fields).
// ---------------------------------------------------------------------------

func TestPositiveSnapshotProvenancePersistedFields(t *testing.T) {
	h := newEvalTestHarness(t)
	h.store.SetApprovalRebind(h.partnerID, h.deviceID, "appr-exact-xyz", true, 1)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	fp := testFingerprint()
	decidedAt := time.Date(2026, 8, 30, 13, 0, 0, 0, time.UTC)
	h.clock.t = decidedAt

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-exact-001",
	})
	if err != nil || result.Outcome != application.EvaluationResultPositive {
		t.Fatalf("evaluation failed: err=%v outcome=%s", err, result.Outcome)
	}

	snap, ok := h.store.GetDecisionSnapshot(h.enrollmentID)
	if !ok {
		t.Fatal("snapshot must be persisted")
	}
	if snap.PartnerID != h.partnerID || snap.DeviceID != h.deviceID {
		t.Fatalf("snapshot resource identity wrong: %+v", snap)
	}
	if snap.ApprovalReference != "appr-exact-xyz" {
		t.Fatalf("snapshot ApprovalReference must come from approval authority, got %s", snap.ApprovalReference)
	}
	if snap.CertificateProfile != "profile-default" || snap.ProfileVersion != "v1" {
		t.Fatalf("snapshot profile wrong: %s/%s", snap.CertificateProfile, snap.ProfileVersion)
	}
	if snap.PolicyVersion != "policy-v1" {
		t.Fatalf("snapshot PolicyVersion wrong: %s", snap.PolicyVersion)
	}
	if snap.AchievedAssurance != application.AssuranceA2 {
		t.Fatalf("snapshot assurance wrong: %s", snap.AchievedAssurance)
	}
	if snap.CSRSha256 != material.CSRSha256 || snap.PublicKeySha256 != material.PublicKeySha256 {
		t.Fatalf("snapshot CSR/PK hash wrong: %+v", snap)
	}
	if snap.ChallengeVersion != 1 || snap.ChallengeNonce != "dGVzdC1ub25jZS1iYXNlNjQtMTIzNA" {
		t.Fatalf("snapshot challenge binding wrong: %+v", snap)
	}
	if snap.EvidenceReference != fp.String() {
		t.Fatalf("snapshot EvidenceReference must equal fingerprint: got %s want %s", snap.EvidenceReference, fp.String())
	}
	if snap.CorrelationID != "corr-exact-001" {
		t.Fatalf("snapshot CorrelationID wrong: %s", snap.CorrelationID)
	}
	if !snap.DecidedAt.Equal(decidedAt) {
		t.Fatalf("snapshot DecidedAt must equal trusted clock: got %s want %s", snap.DecidedAt, decidedAt)
	}
}

// ---------------------------------------------------------------------------
// §10.F — negative provenance (exact persisted fields + bounded identifiers).
// ---------------------------------------------------------------------------

func TestNegativeProvenancePersistedFields(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	fp := testFingerprint()
	result, err := application.EvaluateEnrollment(context.Background(), h.deps(definitiveNegativeVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-neg-exact",
	})
	if err != nil || result.Outcome != application.EvaluationResultDefinitiveNegative {
		t.Fatalf("evaluation failed: err=%v outcome=%s", err, result.Outcome)
	}

	md, ok := h.store.GetDenialMetadata(h.enrollmentID)
	if !ok {
		t.Fatal("denial metadata must be persisted")
	}
	if md.Category != application.DenialCategoryVerifierDenied {
		t.Fatalf("denial category wrong: %s", md.Category)
	}
	if md.EvidenceReference != fp.String() {
		t.Fatalf("denial EvidenceReference must equal fingerprint: got %s want %s", md.EvidenceReference, fp.String())
	}
	if md.CorrelationID != "corr-neg-exact" {
		t.Fatalf("denial CorrelationID must equal command correlation: got %s", md.CorrelationID)
	}
	if md.EnrollmentID != h.enrollmentID {
		t.Fatalf("denial EnrollmentID wrong: %s", md.EnrollmentID)
	}

	// The ISSUANCE_DENIED audit event must propagate the decision correlation.
	found := false
	for _, ev := range h.store.AuditEvents() {
		if ev.Type == application.AuditEventIssuanceDenied && ev.EnrollmentID == h.enrollmentID {
			found = true
			if ev.CorrelationID != "corr-neg-exact" {
				t.Fatalf("ISSUANCE_DENIED event correlation wrong: %s", ev.CorrelationID)
			}
		}
	}
	if !found {
		t.Fatal("ISSUANCE_DENIED event must be published")
	}
}

func TestNegativeRejectsArbitraryDiagnosticText(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	// A verifier whose reference is arbitrary diagnostic/error text (newlines,
	// control characters) must not be persisted; the decision becomes
	// INDETERMINATE.
	diagVerifier := funcVerifier(func(ctx context.Context, req application.AttestationVerificationRequest) (application.AttestationVerificationResult, error) {
		if err := req.Validate(); err != nil {
			return application.AttestationVerificationResult{}, err
		}
		return application.AttestationVerificationResult{
			Outcome:           application.EvaluationResultDefinitiveNegative,
			AchievedAssurance: "A0",
			VerifierReference: "ERROR: TPM parse failed\nat vendor.sdk (stack trace)",
			VerifierVersion:   "\x01\x02",
		}, nil
	})

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(diagVerifier), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-neg-diag",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != application.EvaluationResultIndeterminate {
		t.Fatalf("unbounded verifier diagnostic must be INDETERMINATE, got %s", result.Outcome)
	}
	rec, _ := h.store.GetEnrollment(h.enrollmentID)
	if rec.Aggregate.State() != domain.StateEvidenceReceived {
		t.Fatalf("state must remain EVIDENCE_RECEIVED, got %s", rec.Aggregate.State())
	}
	assertNoTerminalArtifacts(t, h.store, h.enrollmentID)
}

// ---------------------------------------------------------------------------
// §10.G — four concurrency combinations: first valid commit wins.
// ---------------------------------------------------------------------------

func TestConcurrencyFirstCommitWinsAllFourCombos(t *testing.T) {
	t.Run("positive/positive", func(t *testing.T) {
		h := newEvalTestHarness(t)
		material := h.makeMaterial()
		h.seedWithEvidence(h.clock.t, material)

		uow1, _ := h.store.BeginEvaluation(context.Background())
		uow2, _ := h.store.BeginEvaluation(context.Background())
		if err := uow1.StageAuthorized(context.Background(), h.enrollmentID, remediationSnapshot(h, material, "corr-pp-1"), remediationMarker(h), remediationReadSet(h)); err != nil {
			t.Fatal(err)
		}
		if err := uow2.StageAuthorized(context.Background(), h.enrollmentID, remediationSnapshot(h, material, "corr-pp-2"), remediationMarker(h), remediationReadSet(h)); err != nil {
			t.Fatal(err)
		}
		if err := uow1.Commit(context.Background()); err != nil {
			t.Fatalf("first positive commit must succeed: %v", err)
		}
		if err := uow2.Commit(context.Background()); err == nil {
			t.Fatal("second positive commit must fail (no resurrection/overwrite)")
		}

		rec, _ := h.store.GetEnrollment(h.enrollmentID)
		if rec.Aggregate.State() != domain.StateAuthorized {
			t.Fatalf("state must be AUTHORIZED, got %s", rec.Aggregate.State())
		}
		snap, ok := h.store.GetDecisionSnapshot(h.enrollmentID)
		if !ok || snap.CorrelationID != "corr-pp-1" {
			t.Fatalf("first snapshot must win, got %+v", snap)
		}
		if countEvents(h.store, h.enrollmentID, application.AuditEventIssuanceAuthorized) != 1 {
			t.Fatal("exactly one ISSUANCE_AUTHORIZED event must exist")
		}
		if countEvents(h.store, h.enrollmentID, application.AuditEventAttestationVerified) != 1 {
			t.Fatal("exactly one ATTESTATION_VERIFIED event must exist")
		}
	})

	t.Run("positive/negative", func(t *testing.T) {
		h := newEvalTestHarness(t)
		material := h.makeMaterial()
		h.seedWithEvidence(h.clock.t, material)

		uow1, _ := h.store.BeginEvaluation(context.Background())
		uow2, _ := h.store.BeginEvaluation(context.Background())
		if err := uow1.StageAuthorized(context.Background(), h.enrollmentID, remediationSnapshot(h, material, "corr-pn-1"), remediationMarker(h), remediationReadSet(h)); err != nil {
			t.Fatal(err)
		}
		if err := uow2.StageRejected(context.Background(), h.enrollmentID, remediationMetadata(h, application.DenialCategoryPolicyDenied, "corr-pn-2"), remediationReadSet(h)); err != nil {
			t.Fatal(err)
		}
		if err := uow1.Commit(context.Background()); err != nil {
			t.Fatalf("first positive commit must succeed: %v", err)
		}
		if err := uow2.Commit(context.Background()); err == nil {
			t.Fatal("second negative commit must fail after positive")
		}
		rec, _ := h.store.GetEnrollment(h.enrollmentID)
		if rec.Aggregate.State() != domain.StateAuthorized {
			t.Fatalf("state must be AUTHORIZED, got %s", rec.Aggregate.State())
		}
		if _, ok := h.store.GetDenialMetadata(h.enrollmentID); ok {
			t.Fatal("no denial metadata may be published after positive won")
		}
		if countEvents(h.store, h.enrollmentID, application.AuditEventIssuanceDenied) != 0 {
			t.Fatal("no ISSUANCE_DENIED event may exist")
		}
	})

	t.Run("negative/positive", func(t *testing.T) {
		h := newEvalTestHarness(t)
		material := h.makeMaterial()
		h.seedWithEvidence(h.clock.t, material)

		uow1, _ := h.store.BeginEvaluation(context.Background())
		uow2, _ := h.store.BeginEvaluation(context.Background())
		if err := uow1.StageRejected(context.Background(), h.enrollmentID, remediationMetadata(h, application.DenialCategoryPolicyDenied, "corr-np-1"), remediationReadSet(h)); err != nil {
			t.Fatal(err)
		}
		if err := uow2.StageAuthorized(context.Background(), h.enrollmentID, remediationSnapshot(h, material, "corr-np-2"), remediationMarker(h), remediationReadSet(h)); err != nil {
			t.Fatal(err)
		}
		if err := uow1.Commit(context.Background()); err != nil {
			t.Fatalf("first negative commit must succeed: %v", err)
		}
		if err := uow2.Commit(context.Background()); err == nil {
			t.Fatal("second positive commit must fail after negative")
		}
		rec, _ := h.store.GetEnrollment(h.enrollmentID)
		if rec.Aggregate.State() != domain.StateRejected {
			t.Fatalf("state must be REJECTED, got %s", rec.Aggregate.State())
		}
		if _, ok := h.store.GetDecisionSnapshot(h.enrollmentID); ok {
			t.Fatal("no decision snapshot may be published after negative won")
		}
		md, ok := h.store.GetDenialMetadata(h.enrollmentID)
		if !ok || md.CorrelationID != "corr-np-1" {
			t.Fatalf("first denial must win, got %+v", md)
		}
		if countEvents(h.store, h.enrollmentID, application.AuditEventIssuanceDenied) != 1 {
			t.Fatal("exactly one ISSUANCE_DENIED event must exist")
		}
	})

	t.Run("negative/negative different reasons", func(t *testing.T) {
		h := newEvalTestHarness(t)
		material := h.makeMaterial()
		h.seedWithEvidence(h.clock.t, material)

		uow1, _ := h.store.BeginEvaluation(context.Background())
		uow2, _ := h.store.BeginEvaluation(context.Background())
		if err := uow1.StageRejected(context.Background(), h.enrollmentID, remediationMetadata(h, application.DenialCategoryPolicyDenied, "corr-nn-1"), remediationReadSet(h)); err != nil {
			t.Fatal(err)
		}
		if err := uow2.StageRejected(context.Background(), h.enrollmentID, remediationMetadata(h, application.DenialCategoryVerifierDenied, "corr-nn-2"), remediationReadSet(h)); err != nil {
			t.Fatal(err)
		}
		if err := uow1.Commit(context.Background()); err != nil {
			t.Fatalf("first negative commit must succeed: %v", err)
		}
		if err := uow2.Commit(context.Background()); err == nil {
			t.Fatal("second negative commit must fail (no denial overwrite)")
		}
		rec, _ := h.store.GetEnrollment(h.enrollmentID)
		if rec.Aggregate.State() != domain.StateRejected {
			t.Fatalf("state must be REJECTED, got %s", rec.Aggregate.State())
		}
		md, ok := h.store.GetDenialMetadata(h.enrollmentID)
		if !ok || md.Category != application.DenialCategoryPolicyDenied {
			t.Fatalf("first denial category must win (no overwrite), got %+v", md)
		}
		if countEvents(h.store, h.enrollmentID, application.AuditEventIssuanceDenied) != 1 {
			t.Fatal("exactly one ISSUANCE_DENIED event must exist")
		}
	})
}

// ---------------------------------------------------------------------------
// §10.H — material ownership / aliasing.
// ---------------------------------------------------------------------------

func TestMaterialOwnershipNoAliasing(t *testing.T) {
	h := newEvalTestHarness(t)

	material := application.EvaluationMaterial{
		CSRSha256:       "sha256-csr-test",
		PublicKeySha256: "sha256-pk-test",
		TPMFormat:       "enrollment-tpm-evidence",
		TPMVersion:      "1.0",
		TPMPayload:      json.RawMessage(`{"ek":"original-tpm"}`),
		AgentAssertions: json.RawMessage(`{"a":"original-assertion"}`),
	}
	// Capture the authoritative pre-mutation bytes (independent backing copy).
	originalTPM := append([]byte(nil), material.TPMPayload...)
	originalAssertions := append([]byte(nil), material.AgentAssertions...)

	// A. Caller input after admission: mutate the EXISTING backing bytes in
	// place; persisted bytes must remain the original pre-mutation bytes.
	h.seedWithEvidence(h.clock.t, material)
	material.TPMPayload[0] ^= 0xFF
	material.AgentAssertions[0] ^= 0xFF

	rec, _ := h.store.GetEnrollment(h.enrollmentID)
	if rec.EvaluationMaterial == nil {
		t.Fatal("material must be persisted on the record")
	}
	if !bytes.Equal(rec.EvaluationMaterial.TPMPayload, originalTPM) {
		t.Fatalf("persisted TPMPayload aliased caller memory: got %q want %q", rec.EvaluationMaterial.TPMPayload, originalTPM)
	}
	if !bytes.Equal(rec.EvaluationMaterial.AgentAssertions, originalAssertions) {
		t.Fatalf("persisted AgentAssertions aliased caller memory: got %q want %q", rec.EvaluationMaterial.AgentAssertions, originalAssertions)
	}

	// B. GetEnrollment readback must not alias persisted state.
	rec2, _ := h.store.GetEnrollment(h.enrollmentID)
	rec2.EvaluationMaterial.TPMPayload[0] ^= 0xFF
	rec2.EvaluationMaterial.AgentAssertions[0] ^= 0xFF
	rec3, _ := h.store.GetEnrollment(h.enrollmentID)
	if !bytes.Equal(rec3.EvaluationMaterial.TPMPayload, originalTPM) {
		t.Fatalf("GetEnrollment readback aliases persisted material: got %q want %q", rec3.EvaluationMaterial.TPMPayload, originalTPM)
	}
	if !bytes.Equal(rec3.EvaluationMaterial.AgentAssertions, originalAssertions) {
		t.Fatalf("GetEnrollment readback aliases persisted material: got %q want %q", rec3.EvaluationMaterial.AgentAssertions, originalAssertions)
	}

	// C. GetEvaluationMaterial readback must not alias persisted state.
	uow, err := h.store.BeginEvaluation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer uow.Rollback(context.Background())
	retrieved, found, err := uow.GetEvaluationMaterial(context.Background(), h.enrollmentID)
	if err != nil || !found {
		t.Fatal("material must be retrievable")
	}
	retrieved.TPMPayload[0] ^= 0xFF
	retrieved.AgentAssertions[0] ^= 0xFF
	recheck, _, _ := uow.GetEvaluationMaterial(context.Background(), h.enrollmentID)
	if !bytes.Equal(recheck.TPMPayload, originalTPM) {
		t.Fatalf("GetEvaluationMaterial readback aliases persisted material: got %q want %q", recheck.TPMPayload, originalTPM)
	}
	if !bytes.Equal(recheck.AgentAssertions, originalAssertions) {
		t.Fatalf("GetEvaluationMaterial readback aliases persisted material: got %q want %q", recheck.AgentAssertions, originalAssertions)
	}
}

// TestStagedMaterialOwnershipBeforeCommit proves the staged
// EvidenceAcceptanceWrite owns a deep clone of EvaluationMaterial at the
// staging boundary (M59-REAUDIT-001): in-place mutation of the caller's
// backing bytes after StageEvidenceAcceptance and before Commit must not
// change what Commit persists.
func TestStagedMaterialOwnershipBeforeCommit(t *testing.T) {
	h := newEvalTestHarness(t)
	h.seedChallengeIssued(h.enrollmentID)

	material := application.EvaluationMaterial{
		CSRSha256:       "sha256-csr-test",
		PublicKeySha256: "sha256-pk-test",
		TPMFormat:       "enrollment-tpm-evidence",
		TPMVersion:      "1.0",
		TPMPayload:      json.RawMessage(`{"ek":"staged-tpm"}`),
		AgentAssertions: json.RawMessage(`{"a":"staged-assertion"}`),
	}
	originalTPM := append([]byte(nil), material.TPMPayload...)
	originalAssertions := append([]byte(nil), material.AgentAssertions...)

	uow, err := h.store.BeginEvaluation(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	write := application.EvidenceAcceptanceWrite{
		EnrollmentID:             h.enrollmentID,
		ExpectedChallengeVersion: 1,
		Evidence: application.AcceptedEvidence{
			Fingerprint:      testFingerprint(),
			ChallengeVersion: 1,
			Representation:   []byte("evidence-repr"),
			AcceptedAt:       h.clock.t,
		},
		Material:   &material,
		AcceptedAt: h.clock.t,
	}
	if err := uow.EnrollmentContinuation().StageEvidenceAcceptance(context.Background(), write); err != nil {
		t.Fatalf("stage evidence: %v", err)
	}

	// Mutate the EXISTING caller-owned backing bytes in place after staging.
	material.TPMPayload[0] ^= 0xFF
	material.AgentAssertions[0] ^= 0xFF

	if err := uow.Commit(context.Background()); err != nil {
		t.Fatalf("commit: %v", err)
	}

	rec, _ := h.store.GetEnrollment(h.enrollmentID)
	if rec.EvaluationMaterial == nil {
		t.Fatal("material must be persisted")
	}
	if !bytes.Equal(rec.EvaluationMaterial.TPMPayload, originalTPM) {
		t.Fatalf("persisted TPMPayload must be original pre-mutation bytes: got %q want %q", rec.EvaluationMaterial.TPMPayload, originalTPM)
	}
	if !bytes.Equal(rec.EvaluationMaterial.AgentAssertions, originalAssertions) {
		t.Fatalf("persisted AgentAssertions must be original pre-mutation bytes: got %q want %q", rec.EvaluationMaterial.AgentAssertions, originalAssertions)
	}
}

// ---------------------------------------------------------------------------
// §10.I — usage-scoped authority isolation.
// ---------------------------------------------------------------------------

func TestCertificateUsageScopeIsolation(t *testing.T) {
	h := newEvalTestHarness(t)

	// Same device, two different usages, two different profiles.
	h.store.SetCertificateProfile(h.deviceID, "clientAuth", "profile-clientauth", "v1", 1)
	h.store.SetCertificateProfile(h.deviceID, "serverAuth", "profile-serverauth", "v9", 1)
	// Same partner, two different usages, two different minimum assurance.
	h.store.SetAssurancePolicy(h.partnerID, "clientAuth", application.AssuranceA2, 1)
	h.store.SetAssurancePolicy(h.partnerID, "serverAuth", application.AssuranceA3, 1)

	auth := h.store.NewEvaluationAuthority()
	ca, err := auth.GetCertificateProfile(context.Background(), h.deviceID, "clientAuth")
	if err != nil || ca.ProfileID != "profile-clientauth" || ca.Version != "v1" {
		t.Fatalf("clientAuth profile wrong: %+v err=%v", ca, err)
	}
	sa, err := auth.GetCertificateProfile(context.Background(), h.deviceID, "serverAuth")
	if err != nil || sa.ProfileID != "profile-serverauth" || sa.Version != "v9" {
		t.Fatalf("serverAuth profile wrong: %+v err=%v", sa, err)
	}
	if ca.ProfileID == sa.ProfileID {
		t.Fatal("cross-usage profile must not leak")
	}

	caPolicy, err := auth.GetAssurancePolicy(context.Background(), h.partnerID, "clientAuth")
	if err != nil || caPolicy.MinimumAssurance != application.AssuranceA2 {
		t.Fatalf("clientAuth policy wrong: %+v err=%v", caPolicy, err)
	}
	saPolicy, err := auth.GetAssurancePolicy(context.Background(), h.partnerID, "serverAuth")
	if err != nil || saPolicy.MinimumAssurance != application.AssuranceA3 {
		t.Fatalf("serverAuth policy wrong: %+v err=%v", saPolicy, err)
	}
	if caPolicy.MinimumAssurance == saPolicy.MinimumAssurance {
		t.Fatal("cross-usage assurance policy must not leak")
	}

	// A freshness change in one usage must not invalidate the other. Seed an
	// enrollment at clientAuth (the harness default) and evaluate against
	// serverAuth facts changed in parallel.
	h.seedWithEvidence(h.clock.t, h.makeMaterial())
	h.store.SetAssurancePolicy(h.partnerID, "serverAuth", application.AssuranceA1, 2)

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-usage",
	})
	if err != nil || result.Outcome != application.EvaluationResultPositive {
		t.Fatalf("serverAuth freshness change must not affect clientAuth evaluation: err=%v outcome=%s", err, result.Outcome)
	}
}

// ---------------------------------------------------------------------------
// §10.J — malformed authority facts are INDETERMINATE, never definitive denial.
// ---------------------------------------------------------------------------

func TestMalformedAuthorityIsIndeterminate(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()

	cases := []struct {
		name string
		fake func(*evalTestHarness) application.EvaluationAuthority
	}{
		{
			name: "partner eligibility wrong resource",
			fake: func(h *evalTestHarness) application.EvaluationAuthority {
				f := newFakeAuthority(h)
				f.pe = application.PartnerEligibility{PartnerID: "other-partner", Eligible: false, Revision: 1}
				return f
			},
		},
		{
			name: "device eligibility wrong resource",
			fake: func(h *evalTestHarness) application.EvaluationAuthority {
				f := newFakeAuthority(h)
				f.de = application.DeviceEligibility{DeviceID: "other-device", Eligible: false, Revision: 1}
				return f
			},
		},
		{
			name: "approval rebind missing reference",
			fake: func(h *evalTestHarness) application.EvaluationAuthority {
				f := newFakeAuthority(h)
				f.ar = application.ApprovalRebind{PartnerID: h.partnerID, DeviceID: h.deviceID, Approved: false, Reference: "", Revision: 1}
				return f
			},
		},
		{
			name: "approval rebind wrong resource",
			fake: func(h *evalTestHarness) application.EvaluationAuthority {
				f := newFakeAuthority(h)
				f.ar = application.ApprovalRebind{PartnerID: "other-partner", DeviceID: h.deviceID, Approved: true, Reference: "appr", Revision: 1}
				return f
			},
		},
		{
			name: "certificate profile wrong usage scope",
			fake: func(h *evalTestHarness) application.EvaluationAuthority {
				f := newFakeAuthority(h)
				f.cp = application.CertificateProfile{DeviceID: h.deviceID, CertificateUsage: "otherUsage", ProfileID: "p", Version: "v1", Revision: 1}
				return f
			},
		},
		{
			name: "certificate profile empty identity",
			fake: func(h *evalTestHarness) application.EvaluationAuthority {
				f := newFakeAuthority(h)
				f.cp = application.CertificateProfile{DeviceID: h.deviceID, CertificateUsage: "clientAuth", ProfileID: "", Version: "v1", Revision: 1}
				return f
			},
		},
		{
			name: "assurance policy invalid minimum assurance",
			fake: func(h *evalTestHarness) application.EvaluationAuthority {
				f := newFakeAuthority(h)
				f.ap = application.AssurancePolicy{PartnerID: h.partnerID, CertificateUsage: "clientAuth", MinimumAssurance: "BOGUS", Revision: 1}
				return f
			},
		},
		{
			name: "assurance policy wrong partner scope",
			fake: func(h *evalTestHarness) application.EvaluationAuthority {
				f := newFakeAuthority(h)
				f.ap = application.AssurancePolicy{PartnerID: "other-partner", CertificateUsage: "clientAuth", MinimumAssurance: application.AssuranceA2, Revision: 1}
				return f
			},
		},
		{
			name: "policy version empty",
			fake: func(h *evalTestHarness) application.EvaluationAuthority {
				f := newFakeAuthority(h)
				f.pv = application.PolicyVersion{Version: "", Revision: 1}
				return f
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newEvalTestHarness(t)
			h.seedWithEvidence(h.clock.t, material)

			deps := application.EvaluationDependencies{
				Verifier:   positiveVerifier{},
				Authority:  tc.fake(h),
				UOWManager: h.store,
				Clock:      h.clock,
			}
			result, err := application.EvaluateEnrollment(context.Background(), deps, application.EvaluateEnrollmentCommand{
				EnrollmentID:  h.enrollmentID,
				CorrelationID: "corr-malformed",
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Outcome != application.EvaluationResultIndeterminate {
				t.Fatalf("malformed authority must be INDETERMINATE, got %s", result.Outcome)
			}
			rec, _ := h.store.GetEnrollment(h.enrollmentID)
			if rec.Aggregate.State() != domain.StateEvidenceReceived {
				t.Fatalf("state must remain EVIDENCE_RECEIVED, got %s", rec.Aggregate.State())
			}
			assertNoTerminalArtifacts(t, h.store, h.enrollmentID)
		})
	}
}

// ---------------------------------------------------------------------------
// FINAL-008 — generic store cannot resurrect terminal state or replace
// accepted evidence/material.
// ---------------------------------------------------------------------------

func TestStoreEnrollmentCannotOverwriteOrResurrect(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	// Reach AUTHORIZED.
	if _, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-008",
	}); err != nil {
		t.Fatal(err)
	}

	// Attempt to overwrite the terminal enrollment via the generic store.
	rec, _ := h.store.GetEnrollment(h.enrollmentID)
	rec.EvaluationMaterial.TPMPayload = json.RawMessage(`{"ek":"replaced"}`)
	if err := h.store.StoreEnrollment(rec); err == nil {
		t.Fatal("StoreEnrollment must not overwrite an existing enrollment")
	}
	persisted, _ := h.store.GetEnrollment(h.enrollmentID)
	if persisted.Aggregate.State() != domain.StateAuthorized {
		t.Fatalf("terminal state must remain AUTHORIZED, got %s", persisted.Aggregate.State())
	}
	if string(persisted.EvaluationMaterial.TPMPayload) != string(material.TPMPayload) {
		t.Fatal("evaluation material must not be replaced through StoreEnrollment")
	}
}

// ---------------------------------------------------------------------------
// FINAL-009 — one trusted decision clock.
// ---------------------------------------------------------------------------

func TestDecisionClockIsTrustedNotWallClock(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	// A deliberately skewed clock far from the process wall clock.
	decidedAt := time.Date(2099, 1, 2, 3, 4, 5, 0, time.UTC)
	h.clock.t = decidedAt

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-clock",
	})
	if err != nil || result.Outcome != application.EvaluationResultPositive {
		t.Fatalf("evaluation failed: err=%v outcome=%s", err, result.Outcome)
	}

	snap, _ := h.store.GetDecisionSnapshot(h.enrollmentID)
	if !snap.DecidedAt.Equal(decidedAt) {
		t.Fatalf("snapshot DecidedAt must use trusted clock: got %s want %s", snap.DecidedAt, decidedAt)
	}
	marker, _ := h.store.GetAttestationMarker(h.enrollmentID)
	if !marker.VerifiedAt.Equal(decidedAt) {
		t.Fatalf("marker VerifiedAt must use trusted clock: got %s want %s", marker.VerifiedAt, decidedAt)
	}
	rec, _ := h.store.GetEnrollment(h.enrollmentID)
	if !rec.UpdatedAt.Equal(decidedAt) {
		t.Fatalf("record UpdatedAt must use trusted clock: got %s want %s", rec.UpdatedAt, decidedAt)
	}
	for _, ev := range h.store.AuditEvents() {
		if ev.EnrollmentID == h.enrollmentID && ev.Type == application.AuditEventIssuanceAuthorized {
			if !ev.Timestamp.Equal(decidedAt) {
				t.Fatalf("ISSUANCE_AUTHORIZED timestamp must use trusted clock: got %s want %s", ev.Timestamp, decidedAt)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// seedChallengeIssued seeds a valid CHALLENGE_ISSUED enrollment (no accepted
// evidence, no evaluation material) so tests can exercise the real evidence
// staging/commit boundary.
func (h *evalTestHarness) seedChallengeIssued(enrollmentID string) {
	agg, err := domain.RestoreEnrollment(domain.EnrollmentID(enrollmentID), domain.StateChallengeIssued)
	if err != nil {
		h.t.Fatal(err)
	}
	rec := application.EnrollmentRecord{
		Aggregate:        agg,
		DeviceID:         h.deviceID,
		PartnerID:        h.partnerID,
		Operation:        application.OperationInitial,
		CertificateUsage: "clientAuth",
		Challenge: application.Challenge{
			Nonce:            "dGVzdC1ub25jZS1iYXNlNjQtMTIzNA",
			ChallengeVersion: 1,
			ExpiresAt:        h.clock.t.Add(time.Hour),
			PopFormat:        application.PopFormatEnrollmentJWS,
		},
		EvidenceRequirements: application.EvidenceRequirements{
			TPMEvidenceProtocolVersions: []string{"v1"},
			MinimumAssurance:            "A2",
			AllowedKeyProfiles:          []string{"default"},
		},
		CreatedAt: h.clock.t,
		UpdatedAt: h.clock.t,
	}
	if err := h.store.StoreEnrollment(rec); err != nil {
		h.t.Fatal("failed to seed challenge-issued enrollment:", err)
	}
}

// remediationReadSet returns a fully-populated read-set matching the harness
// authority configuration at revision 1.
func remediationReadSet(h *evalTestHarness) application.EvaluationReadSet {
	return application.EvaluationReadSet{
		PartnerEligibility: application.PartnerEligibility{PartnerID: h.partnerID, Eligible: true, Revision: 1},
		DeviceEligibility:  application.DeviceEligibility{DeviceID: h.deviceID, Eligible: true, Revision: 1},
		ApprovalRebind:     application.ApprovalRebind{PartnerID: h.partnerID, DeviceID: h.deviceID, Approved: true, Reference: "appr-1", Revision: 1},
		CertificateProfile: application.CertificateProfile{DeviceID: h.deviceID, CertificateUsage: "clientAuth", ProfileID: "profile-default", Version: "v1", Revision: 1},
		AssurancePolicy:    application.AssurancePolicy{PartnerID: h.partnerID, CertificateUsage: "clientAuth", MinimumAssurance: application.AssuranceA2, Revision: 1},
		PolicyVersion:      application.PolicyVersion{Version: "policy-v1", Revision: 1},
		CertificateUsage:   "clientAuth",
	}
}

func remediationSnapshot(h *evalTestHarness, material application.EvaluationMaterial, correlationID string) application.EvaluationDecisionSnapshot {
	return application.EvaluationDecisionSnapshot{
		PartnerID:          h.partnerID,
		DeviceID:           h.deviceID,
		ApprovalReference:  "appr-1",
		CertificateProfile: "profile-default",
		ProfileVersion:     "v1",
		PolicyVersion:      "policy-v1",
		AchievedAssurance:  application.AssuranceA2,
		CSRSha256:          material.CSRSha256,
		PublicKeySha256:    material.PublicKeySha256,
		ChallengeVersion:   1,
		ChallengeNonce:     "dGVzdC1ub25jZS1iYXNlNjQtMTIzNA",
		EvidenceReference:  testFingerprint().String(),
		CorrelationID:      correlationID,
		DecidedAt:          h.clock.t,
	}
}

func remediationMarker(h *evalTestHarness) application.AttestationVerifiedMarker {
	return application.AttestationVerifiedMarker{
		EnrollmentID:  h.enrollmentID,
		AchievedLevel: application.AssuranceA2,
		VerifiedAt:    h.clock.t,
	}
}

func remediationMetadata(h *evalTestHarness, category application.DenialCategory, correlationID string) application.EvaluationDenialMetadata {
	return application.EvaluationDenialMetadata{
		Category:           category,
		EnrollmentID:       h.enrollmentID,
		EvidenceReference:  testFingerprint().String(),
		CertificateProfile: "profile-default",
		ProfileVersion:     "v1",
		PolicyVersion:      "policy-v1",
		CorrelationID:      correlationID,
		DeniedAt:           h.clock.t,
	}
}

// fakeAuthority returns configurable authority facts for malformed-authority
// tests. It starts from a valid read-set matching the harness and each test
// overrides exactly one fact to make it malformed or wrong-resource.
type fakeAuthority struct {
	pe application.PartnerEligibility
	de application.DeviceEligibility
	ar application.ApprovalRebind
	cp application.CertificateProfile
	ap application.AssurancePolicy
	pv application.PolicyVersion
}

func newFakeAuthority(h *evalTestHarness) *fakeAuthority {
	return &fakeAuthority{
		pe: application.PartnerEligibility{PartnerID: h.partnerID, Eligible: true, Revision: 1},
		de: application.DeviceEligibility{DeviceID: h.deviceID, Eligible: true, Revision: 1},
		ar: application.ApprovalRebind{PartnerID: h.partnerID, DeviceID: h.deviceID, Approved: true, Reference: "appr-1", Revision: 1},
		cp: application.CertificateProfile{DeviceID: h.deviceID, CertificateUsage: "clientAuth", ProfileID: "p", Version: "v1", Revision: 1},
		ap: application.AssurancePolicy{PartnerID: h.partnerID, CertificateUsage: "clientAuth", MinimumAssurance: application.AssuranceA2, Revision: 1},
		pv: application.PolicyVersion{Version: "policy-v1", Revision: 1},
	}
}

func (f *fakeAuthority) GetPartnerEligibility(ctx context.Context, partnerID string) (application.PartnerEligibility, error) {
	return f.pe, nil
}
func (f *fakeAuthority) GetDeviceEligibility(ctx context.Context, deviceID string) (application.DeviceEligibility, error) {
	return f.de, nil
}
func (f *fakeAuthority) GetApprovalRebind(ctx context.Context, deviceID, partnerID string) (application.ApprovalRebind, error) {
	return f.ar, nil
}
func (f *fakeAuthority) GetCertificateProfile(ctx context.Context, deviceID, certificateUsage string) (application.CertificateProfile, error) {
	return f.cp, nil
}
func (f *fakeAuthority) GetAssurancePolicy(ctx context.Context, partnerID, certificateUsage string) (application.AssurancePolicy, error) {
	return f.ap, nil
}
func (f *fakeAuthority) GetPolicyVersion(ctx context.Context) (application.PolicyVersion, error) {
	return f.pv, nil
}

// funcVerifier adapts a closure to the AttestationVerifier interface.
type funcVerifier func(ctx context.Context, req application.AttestationVerificationRequest) (application.AttestationVerificationResult, error)

func (f funcVerifier) Verify(ctx context.Context, req application.AttestationVerificationRequest) (application.AttestationVerificationResult, error) {
	return f(ctx, req)
}

// assertNoTerminalArtifacts asserts that no positive/negative decision
// artifacts (state change, snapshot, denial, marker, terminal events) exist
// for the enrollment.
func assertNoTerminalArtifacts(t *testing.T, store *enrollmentruntime.MemoryStore, enrollmentID string) {
	t.Helper()
	rec, _ := store.GetEnrollment(enrollmentID)
	if rec.Aggregate.State() != domain.StateEvidenceReceived {
		t.Fatalf("state must remain EVIDENCE_RECEIVED, got %s", rec.Aggregate.State())
	}
	if _, ok := store.GetDecisionSnapshot(enrollmentID); ok {
		t.Fatal("no decision snapshot may be published")
	}
	if _, ok := store.GetDenialMetadata(enrollmentID); ok {
		t.Fatal("no denial metadata may be published")
	}
	if _, ok := store.GetAttestationMarker(enrollmentID); ok {
		t.Fatal("no ATTESTATION_VERIFIED marker may be published")
	}
	for _, ev := range store.AuditEvents() {
		if ev.EnrollmentID == enrollmentID {
			switch ev.Type {
			case application.AuditEventIssuanceAuthorized, application.AuditEventIssuanceDenied, application.AuditEventAttestationVerified:
				t.Fatalf("terminal event %s must not be published", ev.Type)
			}
		}
	}
}

func assertEventPresent(t *testing.T, store *enrollmentruntime.MemoryStore, enrollmentID, eventType string) {
	t.Helper()
	if countEvents(store, enrollmentID, eventType) == 0 {
		t.Fatalf("event %s must be published for %s", eventType, enrollmentID)
	}
}

func countEvents(store *enrollmentruntime.MemoryStore, enrollmentID, eventType string) int {
	n := 0
	for _, ev := range store.AuditEvents() {
		if ev.EnrollmentID == enrollmentID && ev.Type == eventType {
			n++
		}
	}
	return n
}
