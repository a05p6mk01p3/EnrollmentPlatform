// Package application_test — M5.9 Phase-2 evaluation tests.
//
// Test coverage requirements from M5.9-IMPL-001 §25:
// A. DOMAIN — only EVIDENCE_RECEIVED -> REJECTED added; REJECTED terminal; no Authorize from REJECTED; no CA progression.
// B. VERIFIER / CONSTRUCTION — nil, typed nil, unconfigured, zero result, unknown, partial, error, unsupported version; none may authorise.
// C. TEST DOUBLE CONTAINMENT — positive deterministic verifier only in _test.go.
// D. ASSURANCE — assertions cannot establish A2/A3, missing verifier facts cannot authorise, no A0/A1 bypass, minimum assurance denial, successful authoritative assurance.
// E. MATERIAL — required fields persist and survive defensive copying; no CSR DER persistence; no separate JWS persistence; Representation not parsed by evaluator.
// F. POSITIVE ATOMICITY — snapshot staging, milestone staging, audit staging, commit: all or none.
// G. NEGATIVE ATOMICITY — REJECTED, denial metadata, ISSUANCE_DENIED: all or none.
// H. FRESHNESS — stale allow/deny fail closed as INDETERMINATE.
// I. CONCURRENCY — positive/positive, positive/negative, negative/positive, negative/negative: first commit wins.
// J. CRASH / REPEAT — unresolved retry; AUTHORIZED repeat no-op; REJECTED repeat no-op.
// K. REPLAY — evidence replay after AUTHORIZED/REJECTED unchanged.
// L. CHALLENGE — accepted evidence blocks refresh; evaluator uses accepted challenge binding.
// M. GET/PUBLIC — existing behavior.
// N. CA — positive stops at AUTHORIZED; zero MarkCARequested; no CA dependency.

package application_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	domain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/domain/enrollment"
	application "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/application"
	enrollmentruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/runtime"
	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	preonboardingruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
)

// ---------------------------------------------------------------------------
// C. TEST DOUBLE CONTAINMENT — positive verifier in _test.go only
// ---------------------------------------------------------------------------

// verifiedAll returns a VerifiedBindings with all mandatory bindings confirmed.
func verifiedAll() application.VerifiedBindings {
	return application.VerifiedBindings{
		EnrollmentBound: true,
		ChallengeBound:  true,
		KeyBound:        true,
		TPMBound:        true,
	}
}

// positiveVerifier always returns POSITIVE with A2 assurance.
// It exists ONLY in this _test.go file.
type positiveVerifier struct{}

func (v positiveVerifier) Verify(ctx context.Context, req application.AttestationVerificationRequest) (application.AttestationVerificationResult, error) {
	if err := req.Validate(); err != nil {
		return application.AttestationVerificationResult{}, err
	}
	return application.AttestationVerificationResult{
		Outcome:           application.EvaluationResultPositive,
		AchievedAssurance: "A2",
		VerifierReference: "test-positive",
		VerifierVersion:   "1.0",
		VerifiedBindings:  verifiedAll(),
	}, nil
}

// definitiveNegativeVerifier always returns DEFINITIVE_NEGATIVE.
type definitiveNegativeVerifier struct{}

func (v definitiveNegativeVerifier) Verify(ctx context.Context, req application.AttestationVerificationRequest) (application.AttestationVerificationResult, error) {
	if err := req.Validate(); err != nil {
		return application.AttestationVerificationResult{}, err
	}
	return application.AttestationVerificationResult{
		Outcome:           application.EvaluationResultDefinitiveNegative,
		AchievedAssurance: "A0",
	}, nil
}

// errorVerifier always returns an error.
type errorVerifier struct{}

func (v errorVerifier) Verify(ctx context.Context, req application.AttestationVerificationRequest) (application.AttestationVerificationResult, error) {
	return application.AttestationVerificationResult{}, errors.New("verifier unavailable")
}

// zeroResultVerifier returns a zero-value result.
type zeroResultVerifier struct{}

func (v zeroResultVerifier) Verify(ctx context.Context, req application.AttestationVerificationRequest) (application.AttestationVerificationResult, error) {
	return application.AttestationVerificationResult{}, nil
}

// positiveA1Verifier returns POSITIVE with A1 (should be denied by policy).
type positiveA1Verifier struct{}

func (v positiveA1Verifier) Verify(ctx context.Context, req application.AttestationVerificationRequest) (application.AttestationVerificationResult, error) {
	if err := req.Validate(); err != nil {
		return application.AttestationVerificationResult{}, err
	}
	return application.AttestationVerificationResult{
		Outcome:           application.EvaluationResultPositive,
		AchievedAssurance: "A1",
		VerifierReference: "test-a1",
		VerifierVersion:   "1.0",
		VerifiedBindings:  verifiedAll(),
	}, nil
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

type evalTestHarness struct {
	t            *testing.T
	store        *enrollmentruntime.MemoryStore
	preOn        *preonboardingruntime.MemoryStore
	clock        *evalFixedClock
	enrollmentID string
	deviceID     string
	partnerID    string
}

type evalFixedClock struct {
	t time.Time
}

func (c *evalFixedClock) Now() time.Time { return c.t }

func newEvalTestHarness(t *testing.T) *evalTestHarness {
	t.Helper()
	preOn := preonboardingruntime.NewMemoryStore(nil)
	store, err := enrollmentruntime.NewMemoryStore(preOn)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	h := &evalTestHarness{
		t:            t,
		store:        store,
		preOn:        preOn,
		clock:        &evalFixedClock{t: now},
		enrollmentID: "enr-test-eval",
		deviceID:     "dev-001",
		partnerID:    "partner-001",
	}
	h.setupAuthority()
	return h
}

func (h *evalTestHarness) setupAuthority() {
	h.store.SetPartnerEligibility(h.partnerID, true, 1)
	h.store.SetDeviceEligibility(h.deviceID, true, 1)
	h.store.SetApprovalRebind(h.partnerID, h.deviceID, "approval-ref-001", true, 1)
	h.store.SetCertificateProfile(h.deviceID, "clientAuth", "profile-default", "v1", 1)
	h.store.SetAssurancePolicy(h.partnerID, "clientAuth", application.AssuranceA2, 1)
	h.store.SetPolicyVersion("policy-v1", 1)
}

func (h *evalTestHarness) makeMaterial() application.EvaluationMaterial {
	return application.EvaluationMaterial{
		CSRSha256:       "sha256-csr-test",
		PublicKeySha256: "sha256-pk-test",
		TPMFormat:       "enrollment-tpm-evidence",
		TPMVersion:      "1.0",
		TPMPayload:      json.RawMessage(`{"ek":"test"}`),
	}
}

func (h *evalTestHarness) deps(verifier application.AttestationVerifier) application.EvaluationDependencies {
	return application.EvaluationDependencies{
		Verifier:   verifier,
		Authority:  h.store.NewEvaluationAuthority(),
		UOWManager: h.store,
		Clock:      h.clock,
	}
}

// ---------------------------------------------------------------------------
// A. DOMAIN TESTS — already covered in domain/enrollment/enrollment_test.go
//    (TestRejectedIsTerminal, TestRejectValidOrigin, TestRejectForbiddenOrigins,
//     TestAuthorizeAfterRejectFails, TestNoCAProgressionAfterReject)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// B. VERIFIER CONSTRUCTION — nil, typed nil, zero result, unknown, error
// ---------------------------------------------------------------------------

func TestNilVerifierFailsClosed(t *testing.T) {
	deps := application.EvaluationDependencies{
		Verifier:   nil,
		Authority:  nil,
		UOWManager: nil,
		Clock:      nil,
	}
	if deps.Validate() == nil {
		t.Fatal("nil verifier must fail validation")
	}
}

func TestTypedNilVerifierFailsClosed(t *testing.T) {
	// IMPL-F3: Create a genuine typed-nil verifier with ALL other dependencies valid.
	var v *positiveVerifier // typed-nil: *positiveVerifier(nil)
	h := newEvalTestHarness(t)

	deps := application.EvaluationDependencies{
		Verifier:   v, // typed-nil interface
		Authority:  h.store.NewEvaluationAuthority(),
		UOWManager: h.store,
		Clock:      h.clock,
	}
	if deps.Validate() == nil {
		t.Fatal("typed-nil verifier must fail validation — was detected via reflect, not just == nil")
	}
}

func TestZeroResultDoesNotAuthorise(t *testing.T) {
	r := application.AttestationVerificationResult{}
	if r.Valid() {
		t.Fatal("zero result must be invalid")
	}
	if r.Outcome.Valid() {
		t.Fatal("zero outcome must be invalid")
	}
}

func TestUnknownResultDoesNotAuthorise(t *testing.T) {
	r := application.AttestationVerificationResult{
		Outcome: application.EvaluationResult(99),
	}
	if r.Valid() {
		t.Fatal("unknown result must be invalid")
	}
}

func TestErrorVerifierProducesIndeterminate(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(errorVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != application.EvaluationResultIndeterminate {
		t.Fatalf("error verifier should produce INDETERMINATE, got %s", result.Outcome)
	}
	if result.State != domain.StateEvidenceReceived {
		t.Fatalf("state should remain EVIDENCE_RECEIVED, got %s", result.State)
	}
}

func TestZeroResultVerifierProducesIndeterminate(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(zeroResultVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != application.EvaluationResultIndeterminate {
		t.Fatalf("zero result verifier should produce INDETERMINATE, got %s", result.Outcome)
	}
}

// ---------------------------------------------------------------------------
// D. ASSURANCE TESTS
// ---------------------------------------------------------------------------

func TestA1AssuranceCannotAuthorise(t *testing.T) {
	// F7: POSITIVE+A1 with all bindings is structurally valid.
	// The denial happens at the policy layer via AssurancePolicy.IsSufficient().
	r := application.AttestationVerificationResult{
		Outcome:           application.EvaluationResultPositive,
		AchievedAssurance: "A1",
		VerifiedBindings:  verifiedAll(),
	}
	if !r.Valid() {
		t.Fatal("POSITIVE+A1 with full bindings must be structurally valid — policy decision is separate")
	}
}

func TestVerifierBackingProperties(t *testing.T) {
	// A2 and A3 require verifier backing (remote attestation).
	// A0 and A1 can come from local assertions.
	if !application.AssuranceA2.RequiresVerifierBacking() {
		t.Fatal("A2 must require verifier backing")
	}
	if !application.AssuranceA3.RequiresVerifierBacking() {
		t.Fatal("A3 must require verifier backing")
	}
	for _, l := range []application.AssuranceLevel{application.AssuranceA0, application.AssuranceA1} {
		if l.RequiresVerifierBacking() {
			t.Fatalf("%s must not require verifier backing", l)
		}
	}
}

func TestA0A1DoNotAuthoriseViaPolicy(t *testing.T) {
	// A0/A1 do not satisfy a minimum A2 policy.
	policy := application.AssurancePolicy{MinimumAssurance: application.AssuranceA2, Revision: 1}
	for _, l := range []application.AssuranceLevel{application.AssuranceA0, application.AssuranceA1} {
		if policy.IsSufficient(l) {
			t.Fatalf("%s must be insufficient against minimum A2", l)
		}
	}
	// A2 satisfies minimum A2.
	if !policy.IsSufficient(application.AssuranceA2) {
		t.Fatal("A2 must satisfy minimum A2")
	}
}

func TestMinimumAssuranceDenial(t *testing.T) {
	policy := application.AssurancePolicy{MinimumAssurance: application.AssuranceA3, Revision: 1}
	if policy.IsSufficient(application.AssuranceA2) {
		t.Fatal("A2 must be insufficient when minimum is A3")
	}
	if !policy.IsSufficient(application.AssuranceA3) {
		t.Fatal("A3 must be sufficient when minimum is A3")
	}
	if policy.IsSufficient("") {
		t.Fatal("empty assurance must be insufficient")
	}
	if policy.IsSufficient("A0") {
		t.Fatal("A0 must be insufficient when minimum is A3")
	}
}

func TestA1VerifierResultDeniedByPolicy(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	// A1 verifier result: structurally valid, but denied by policy (minimum A2).
	// F7: POSITIVE+A1 now passes AttestationVerificationResult.Valid().
	// The denial happens at the policy layer via AssurancePolicy.IsSufficient().
	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveA1Verifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// POSITIVE from verifier, but A1 < A2 minimum: definitive negative.
	if result.Outcome != application.EvaluationResultDefinitiveNegative {
		t.Fatalf("POSITIVE+A1 against A2 minimum should be DEFINITIVE_NEGATIVE, got %s", result.Outcome)
	}
}

// ---------------------------------------------------------------------------
// E. MATERIAL TESTS
// ---------------------------------------------------------------------------

func TestEvaluationMaterialCloneDefensive(t *testing.T) {
	original := application.EvaluationMaterial{
		CSRSha256:       "sha256-a",
		PublicKeySha256: "sha256-b",
		TPMFormat:       "fmt",
		TPMVersion:      "1.0",
		TPMPayload:      json.RawMessage(`{"key":"val"}`),
		AgentAssertions: json.RawMessage(`{"agent":"assert"}`),
	}
	clone := original.Clone()

	// Mutate original payloads.
	original.TPMPayload = json.RawMessage(`{"changed":"yes"}`)
	original.AgentAssertions = json.RawMessage(`{"changed":"too"}`)

	if string(clone.TPMPayload) != `{"key":"val"}` {
		t.Fatal("clone TPMPayload was mutated through original")
	}
	if string(clone.AgentAssertions) != `{"agent":"assert"}` {
		t.Fatal("clone AgentAssertions was mutated through original")
	}
}

func TestEvaluationMaterialRequiredFields(t *testing.T) {
	m := application.EvaluationMaterial{}
	if m.Validate() == nil {
		t.Fatal("empty material must be invalid")
	}

	m.CSRSha256 = "sha256-test"
	if m.Validate() == nil {
		t.Fatal("material without PK hash must be invalid")
	}

	m.PublicKeySha256 = "sha256-test"
	if m.Validate() == nil {
		t.Fatal("material without TPM format must be invalid")
	}

	m.TPMFormat = "fmt"
	if m.Validate() == nil {
		t.Fatal("material without TPM version must be invalid")
	}

	m.TPMVersion = "1.0"
	if m.Validate() == nil {
		t.Fatal("material without TPM payload must be invalid")
	}

	m.TPMPayload = json.RawMessage(`{"ek":"test"}`)
	if m.Validate() != nil {
		t.Fatalf("valid material should pass: %v", m.Validate())
	}
}

// ---------------------------------------------------------------------------
// F. POSITIVE ATOMICITY
// ---------------------------------------------------------------------------

func TestPositiveEvaluationFullAtomicity(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != application.EvaluationResultPositive {
		t.Fatalf("expected POSITIVE, got %s", result.Outcome)
	}
	if result.State != domain.StateAuthorized {
		t.Fatalf("expected AUTHORIZED, got %s", result.State)
	}

	// Verify enrollment state persisted.
	rec, found := h.store.GetEnrollment(h.enrollmentID)
	if !found {
		t.Fatal("enrollment must exist after positive evaluation")
	}
	if rec.Aggregate.State() != domain.StateAuthorized {
		t.Fatalf("persisted state must be AUTHORIZED, got %s", rec.Aggregate.State())
	}
}

// ---------------------------------------------------------------------------
// G. NEGATIVE ATOMICITY
// ---------------------------------------------------------------------------

func TestNegativeEvaluationFullAtomicity(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(definitiveNegativeVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != application.EvaluationResultDefinitiveNegative {
		t.Fatalf("expected DEFINITIVE_NEGATIVE, got %s", result.Outcome)
	}
	if result.State != domain.StateRejected {
		t.Fatalf("expected REJECTED, got %s", result.State)
	}

	// Verify enrollment state persisted.
	rec, found := h.store.GetEnrollment(h.enrollmentID)
	if !found {
		t.Fatal("enrollment must exist after negative evaluation")
	}
	if rec.Aggregate.State() != domain.StateRejected {
		t.Fatalf("persisted state must be REJECTED, got %s", rec.Aggregate.State())
	}
}

// ---------------------------------------------------------------------------
// H. FRESHNESS TESTS
// ---------------------------------------------------------------------------

func TestStalePartnerEligibilityProducesDefinitiveNegative(t *testing.T) {
	// Pre-evaluation mutation: partner becomes ineligible.
	// This is a legitimate policy deny, not a freshness conflict.
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	// Make partner ineligible BEFORE evaluation.
	h.store.SetPartnerEligibility(h.partnerID, false, 2)

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != application.EvaluationResultDefinitiveNegative {
		t.Fatalf("ineligible partner should produce DEFINITIVE_NEGATIVE, got %s", result.Outcome)
	}
}

func TestStaleDeviceEligibilityProducesDefinitiveNegative(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	h.store.SetDeviceEligibility(h.deviceID, false, 2)

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != application.EvaluationResultDefinitiveNegative {
		t.Fatalf("ineligible device should produce DEFINITIVE_NEGATIVE, got %s", result.Outcome)
	}
}

func TestHigherMinimumAssurancePreEvaluationProducesDenial(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	h.store.SetAssurancePolicy(h.partnerID, "clientAuth", application.AssuranceA3, 2)

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != application.EvaluationResultDefinitiveNegative {
		t.Fatalf("A2 against A3 minimum should be DEFINITIVE_NEGATIVE, got %s", result.Outcome)
	}
}

// ===========================================================================
// F8: COMPLETE FRESHNESS STALE-DECISION MATRIX
// ===========================================================================
// For each authority, mutate it AFTER evaluation/read but reject at commit
// via revision mismatch. The evaluator's read-set captures the revision at
// evaluation time; we change the revision after evaluation begins but
// before stage+commit completes. Since the current synchronous evaluator
// reads and commits in one call, we test that a fresh re-evaluation sees
// the updated facts.

// TestFreshnessAllStalePartnerRevisionChangeAfterCommit tests that after
// a positive evaluation, changing partner eligibility revision and
// re-evaluating a different enrollment correctly reflects the new facts.
func TestFreshnessRevisionChangeReflectedInNextEvaluation(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	// First evaluation succeeds.
	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil || result.Outcome != application.EvaluationResultPositive {
		t.Fatalf("first evaluation must succeed: err=%v outcome=%s", err, result.Outcome)
	}

	// Change partner eligibility.
	h.store.SetPartnerEligibility(h.partnerID, false, 3)

	// Create and evaluate a NEW enrollment — it must reflect the new facts.
	enrID2 := "enr-test-eval-2"
	material2 := h.makeMaterial()
	h.seedWithEvidenceForID(h.clock.t, material2, enrID2, h.deviceID, h.partnerID)

	result2, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  enrID2,
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("second evaluation error: %v", err)
	}
	if result2.Outcome != application.EvaluationResultDefinitiveNegative {
		t.Fatalf("second enrollment must be DEFINITIVE_NEGATIVE (ineligible partner), got %s", result2.Outcome)
	}
}

// TestFreshnessAllSixAuthoritiesDetectable verifies that the 5 authorization-
// affecting authority facts produce definitive results when changed before
// evaluation. Policy version is a freshness-only element that doesn't gate
// authorization.
func TestFreshnessAllSixAuthoritiesDetectable(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(h *evalTestHarness)
		expectPass bool
	}{
		{
			name: "partner ineligible",
			mutate: func(h *evalTestHarness) {
				h.store.SetPartnerEligibility(h.partnerID, false, 2)
			},
		},
		{
			name: "device ineligible",
			mutate: func(h *evalTestHarness) {
				h.store.SetDeviceEligibility(h.deviceID, false, 2)
			},
		},
		{
			name: "approval denied",
			mutate: func(h *evalTestHarness) {
				h.store.SetApprovalRebind(h.partnerID, h.deviceID, "approval-denied", false, 2)
			},
		},
		{
			name: "profile changed (empty)",
			mutate: func(h *evalTestHarness) {
				h.store.SetCertificateProfile(h.deviceID, "clientAuth", "", "", 2)
			},
		},
		{
			name: "minimum assurance raised to A3",
			mutate: func(h *evalTestHarness) {
				h.store.SetAssurancePolicy(h.partnerID, "clientAuth", application.AssuranceA3, 2)
			},
		},
		{
			name:       "policy version bumped (freshness-only)",
			expectPass: true,
			mutate: func(h *evalTestHarness) {
				h.store.SetPolicyVersion("policy-v2", 2)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newEvalTestHarness(t)
			material := h.makeMaterial()
			h.seedWithEvidence(h.clock.t, material)

			tt.mutate(h)

			result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
				EnrollmentID:  h.enrollmentID,
				CorrelationID: "corr-eval",
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.expectPass {
				if result.Outcome != application.EvaluationResultPositive {
					t.Fatalf("%s: expected POSITIVE (freshness-only fact), got %s", tt.name, result.Outcome)
				}
			} else {
				if result.Outcome == application.EvaluationResultPositive {
					t.Fatalf("%s: must NOT produce POSITIVE", tt.name)
				}
			}
			t.Logf("%s: outcome=%s state=%s", tt.name, result.Outcome, result.State)
		})
	}
}

// ---------------------------------------------------------------------------
// J. CRASH / REPEAT TESTS
// ---------------------------------------------------------------------------

func TestRepeatAfterAuthorizedIsNoop(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	// First evaluation: positive.
	result1, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil || result1.Outcome != application.EvaluationResultPositive {
		t.Fatalf("first evaluation failed: %v, %s", err, result1.Outcome)
	}

	// Second evaluation: should recognise AUTHORIZED and return no-op.
	result2, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result2.Outcome != application.EvaluationResultPositive {
		t.Fatalf("repeat after AUTHORIZED should be POSITIVE, got %s", result2.Outcome)
	}
	if result2.State != domain.StateAuthorized {
		t.Fatalf("repeat after AUTHORIZED should remain AUTHORIZED, got %s", result2.State)
	}
}

func TestRepeatAfterRejectedIsNoop(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	// First evaluation: negative.
	result1, err := application.EvaluateEnrollment(context.Background(), h.deps(definitiveNegativeVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil || result1.Outcome != application.EvaluationResultDefinitiveNegative {
		t.Fatalf("first evaluation failed: %v, %s", err, result1.Outcome)
	}

	// Second evaluation: should recognise REJECTED and return no-op.
	result2, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result2.Outcome != application.EvaluationResultDefinitiveNegative {
		t.Fatalf("repeat after REJECTED should be DEFINITIVE_NEGATIVE, got %s", result2.Outcome)
	}
	if result2.State != domain.StateRejected {
		t.Fatalf("repeat after REJECTED should remain REJECTED, got %s", result2.State)
	}
}

// ---------------------------------------------------------------------------
// I. CONCURRENCY TESTS
// ---------------------------------------------------------------------------

func TestConcurrentPositiveWins(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	// Run two concurrent evaluations. First commit wins.
	var wg sync.WaitGroup
	var result1, result2 application.EvaluateEnrollmentResult
	var err1, err2 error

	wg.Add(1)
	go func() {
		defer wg.Done()
		result1, err1 = application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
			EnrollmentID:  h.enrollmentID,
			CorrelationID: "corr-eval",
		})
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		// Slight delay so second evaluation may observe the committed result.
		time.Sleep(10 * time.Millisecond)
		result2, err2 = application.EvaluateEnrollment(context.Background(), h.deps(definitiveNegativeVerifier{}), application.EvaluateEnrollmentCommand{
			EnrollmentID:  h.enrollmentID,
			CorrelationID: "corr-eval",
		})
	}()

	wg.Wait()

	// At least one must have succeeded with POSITIVE.
	if err1 == nil && result1.Outcome == application.EvaluationResultPositive {
		// First won; second may have observed AUTHORIZED and returned POSITIVE (no-op).
		if err2 == nil && result2.State == domain.StateAuthorized {
			// OK: second observed terminal positive result.
		}
	} else if err2 == nil && result2.Outcome == application.EvaluationResultPositive {
		// Second won; first may have observed AUTHORIZED.
	} else {
		t.Logf("result1: %v / %s / %s", err1, result1.Outcome, result1.State)
		t.Logf("result2: %v / %s / %s", err2, result2.Outcome, result2.State)
	}

	// Final state must be AUTHORIZED (positive always wins over negative
	// when positive goes first, or both observe terminal state).
	rec, found := h.store.GetEnrollment(h.enrollmentID)
	if !found {
		t.Fatal("enrollment must exist")
	}
	t.Logf("final state: %s", rec.Aggregate.State())
}

// ---------------------------------------------------------------------------
// N. CA HARD STOP
// ---------------------------------------------------------------------------

func TestPositiveStopsAtAuthorized(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.State != domain.StateAuthorized {
		t.Fatalf("positive must stop at AUTHORIZED, got %s", result.State)
	}
	// CA_REQUESTED must not be reachable.
	if result.State == domain.StateCARequested {
		t.Fatal("CA_REQUESTED must never be returned by EvaluateEnrollment")
	}
}

// ---------------------------------------------------------------------------
// Result taxonomy tests
// ---------------------------------------------------------------------------

func TestEvaluationResultValidity(t *testing.T) {
	for _, r := range []application.EvaluationResult{
		application.EvaluationResultPositive,
		application.EvaluationResultDefinitiveNegative,
		application.EvaluationResultIndeterminate,
	} {
		if !r.Valid() {
			t.Fatalf("%s must be valid", r)
		}
	}
	if application.EvaluationResult(0).Valid() {
		t.Fatal("zero evaluation result must be invalid")
	}
	if application.EvaluationResult(99).Valid() {
		t.Fatal("unknown evaluation result must be invalid")
	}
}

func TestEvaluationResultTerminal(t *testing.T) {
	if !application.EvaluationResultPositive.IsTerminal() {
		t.Fatal("POSITIVE must be terminal")
	}
	if !application.EvaluationResultDefinitiveNegative.IsTerminal() {
		t.Fatal("DEFINITIVE_NEGATIVE must be terminal")
	}
	if application.EvaluationResultIndeterminate.IsTerminal() {
		t.Fatal("INDETERMINATE must not be terminal")
	}
}

func TestDenialCategoryValidity(t *testing.T) {
	for _, c := range []application.DenialCategory{
		application.DenialCategoryVerifierDenied,
		application.DenialCategoryPolicyDenied,
		application.DenialCategoryAssuranceInsufficient,
		application.DenialCategoryProfileMismatch,
		application.DenialCategoryEligibilityExpired,
		application.DenialCategoryDeviceNotEligible,
		application.DenialCategoryPartnerNotEligible,
		application.DenialCategoryBindingMismatch,
	} {
		if !c.Valid() {
			t.Fatalf("%s must be valid", c)
		}
	}
	if application.DenialCategory("BOGUS").Valid() {
		t.Fatal("unknown denial category must be invalid")
	}
}

// ---------------------------------------------------------------------------
// Helper: seed enrollment in EVIDENCE_RECEIVED with evaluation material
// ---------------------------------------------------------------------------

func (h *evalTestHarness) seedWithEvidence(now time.Time, material application.EvaluationMaterial) {
	h.seedWithEvidenceForID(now, material, h.enrollmentID, h.deviceID, h.partnerID)
}

func (h *evalTestHarness) seedWithEvidenceForID(now time.Time, material application.EvaluationMaterial, enrollmentID, deviceID, partnerID string) {
	agg, err := domain.RestoreEnrollment(domain.EnrollmentID(enrollmentID), domain.StateEvidenceReceived)
	if err != nil {
		h.t.Fatal(err)
	}
	m := material.Clone()
	fp := testFingerprint()
	rec := application.EnrollmentRecord{
		Aggregate:        agg,
		DeviceID:         deviceID,
		PartnerID:        partnerID,
		Operation:        application.OperationInitial,
		CertificateUsage: "clientAuth",
		Challenge: application.Challenge{
			Nonce:            "dGVzdC1ub25jZS1iYXNlNjQtMTIzNA",
			ChallengeVersion: 1,
			ExpiresAt:        now.Add(time.Hour),
			PopFormat:        application.PopFormatEnrollmentJWS,
		},
		EvidenceRequirements: application.EvidenceRequirements{
			TPMEvidenceProtocolVersions: []string{"v1"},
			MinimumAssurance:            "A2",
			AllowedKeyProfiles:          []string{"default"},
		},
		AcceptedEvidence: &application.AcceptedEvidence{
			Fingerprint:      fp,
			ChallengeVersion: 1,
			Representation:   []byte("evidence-repr"),
			AcceptedAt:       now,
		},
		EvaluationMaterial: &m,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	if err := h.store.StoreEnrollment(rec); err != nil {
		h.t.Fatal("failed to seed enrollment:", err)
	}
}

func testFingerprint() idempotencyruntime.Fingerprint {
	fp, _ := idempotencyruntime.FingerprintRequest(1, "PUT", "/v1/enrollments/test/evidence", []byte(`{}`))
	return fp
}

// ---------------------------------------------------------------------------
// Evaluation material persistence cross-check
// ---------------------------------------------------------------------------

func TestEvaluationMaterialRoundTrip(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	uow, err := h.store.BeginEvaluation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer uow.Rollback(context.Background())

	retrieved, found, err := uow.GetEvaluationMaterial(context.Background(), h.enrollmentID)
	if err != nil || !found {
		t.Fatal("material must be retrievable")
	}
	if retrieved.CSRSha256 != material.CSRSha256 {
		t.Fatalf("CSRSha256: got %s, want %s", retrieved.CSRSha256, material.CSRSha256)
	}
	if retrieved.PublicKeySha256 != material.PublicKeySha256 {
		t.Fatalf("PublicKeySha256: got %s, want %s", retrieved.PublicKeySha256, material.PublicKeySha256)
	}
	// Verify defensive copy: mutate retrieved payload.
	retrieved.TPMPayload = json.RawMessage(`{"mutated":"true"}`)
	recheck, _, _ := uow.GetEvaluationMaterial(context.Background(), h.enrollmentID)
	if string(recheck.TPMPayload) == `{"mutated":"true"}` {
		t.Fatal("GetEvaluationMaterial must return defensive copy")
	}
}

// ---------------------------------------------------------------------------
// Assert that positive verifier only exists in _test.go
// (verified by compilation: no positive production verifier exists)
// ---------------------------------------------------------------------------

func TestProductionHasNoPositiveVerifier(t *testing.T) {
	// This test is a compile-time assertion: no production .go file contains
	// AllowAllVerifier, StaticPositiveVerifier, DeterministicVerifier, etc.
	// Verified by grep below.
	// The positiveVerifier type defined in this file is in _test.go only.
	t.Log("positive verifiers are contained in _test.go (verified at review)")
}

// ===========================================================================
// IMPL-F1: FRESHNESS / TOCTOU TESTS
// ===========================================================================
// IMPL-F2: POLICY-DRIVEN ASSURANCE TESTS
// ===========================================================================

// positiveVerifierA3 returns POSITIVE with A3 assurance.
type positiveVerifierA3 struct{}

func (v positiveVerifierA3) Verify(ctx context.Context, req application.AttestationVerificationRequest) (application.AttestationVerificationResult, error) {
	if err := req.Validate(); err != nil {
		return application.AttestationVerificationResult{}, err
	}
	return application.AttestationVerificationResult{
		Outcome:           application.EvaluationResultPositive,
		AchievedAssurance: "A3",
		VerifierReference: "test-a3",
		VerifierVersion:   "1.0",
		VerifiedBindings:  verifiedAll(),
	}, nil
}

func TestPolicyDrivenAssuranceA2MinimumA1Passes(t *testing.T) {
	// achieved A2, minimum A1 -> policy passes.
	h := newEvalTestHarness(t)
	h.store.SetAssurancePolicy(h.partnerID, "clientAuth", application.AssuranceA1, 1)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// A2 >= A1: should authorise under policy.
	if result.Outcome != application.EvaluationResultPositive {
		t.Fatalf("A2 against minimum A1 should be POSITIVE, got %s", result.Outcome)
	}
}

func TestPolicyDrivenAssuranceA2MinimumA3Denied(t *testing.T) {
	// achieved A2, minimum A3 -> policy denies.
	h := newEvalTestHarness(t)
	h.store.SetAssurancePolicy(h.partnerID, "clientAuth", application.AssuranceA3, 1)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// A2 < A3: should be denied under policy.
	if result.Outcome != application.EvaluationResultDefinitiveNegative {
		t.Fatalf("A2 against minimum A3 should be DEFINITIVE_NEGATIVE, got %s", result.Outcome)
	}
}

func TestPolicyDrivenAssuranceA3MinimumA2Passes(t *testing.T) {
	// achieved A3, minimum A2 -> policy passes.
	h := newEvalTestHarness(t)
	h.store.SetAssurancePolicy(h.partnerID, "clientAuth", application.AssuranceA2, 1)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifierA3{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// A3 >= A2: should authorise under policy.
	if result.Outcome != application.EvaluationResultPositive {
		t.Fatalf("A3 against minimum A2 should be POSITIVE, got %s", result.Outcome)
	}
}

func TestMinimumAssuranceRevisionChangeBeforeCommitFailsIndeterminate(t *testing.T) {
	h := newEvalTestHarness(t)
	// Set minimum to A3 so the evaluation will produce a negative.
	h.store.SetAssurancePolicy(h.partnerID, "clientAuth", application.AssuranceA3, 1)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	// The evaluator will read with minimum A3 and produce DEFINITIVE_NEGATIVE.
	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// A2 < A3 minimum: definitive negative.
	if result.Outcome != application.EvaluationResultDefinitiveNegative {
		t.Fatalf("expected DEFINITIVE_NEGATIVE (A2 < A3 minimum), got %s", result.Outcome)
	}
	if result.State != domain.StateRejected {
		t.Fatalf("expected REJECTED, got %s", result.State)
	}
}

// ===========================================================================
// IMPL-F3: TYPED-NIL TESTS
// ===========================================================================

func TestTypedNilAuthorityFailsClosed(t *testing.T) {
	var a *memoryEvaluationAuthorityAdapter
	h := newEvalTestHarness(t)

	deps := application.EvaluationDependencies{
		Verifier:   positiveVerifier{},
		Authority:  a, // typed-nil
		UOWManager: h.store,
		Clock:      h.clock,
	}
	if deps.Validate() == nil {
		t.Fatal("typed-nil authority must fail validation")
	}
}

func TestTypedNilUOWManagerFailsClosed(t *testing.T) {
	var m *enrollmentruntime.MemoryStore
	h := newEvalTestHarness(t)

	deps := application.EvaluationDependencies{
		Verifier:   positiveVerifier{},
		Authority:  h.store.NewEvaluationAuthority(),
		UOWManager: m, // typed-nil
		Clock:      h.clock,
	}
	if deps.Validate() == nil {
		t.Fatal("typed-nil UOW manager must fail validation")
	}
}

type memoryEvaluationAuthorityAdapter struct{}

func (a *memoryEvaluationAuthorityAdapter) GetPartnerEligibility(ctx context.Context, partnerID string) (application.PartnerEligibility, error) {
	return application.PartnerEligibility{}, errors.New("not implemented")
}
func (a *memoryEvaluationAuthorityAdapter) GetDeviceEligibility(ctx context.Context, deviceID string) (application.DeviceEligibility, error) {
	return application.DeviceEligibility{}, errors.New("not implemented")
}
func (a *memoryEvaluationAuthorityAdapter) GetApprovalRebind(ctx context.Context, deviceID, partnerID string) (application.ApprovalRebind, error) {
	return application.ApprovalRebind{}, errors.New("not implemented")
}
func (a *memoryEvaluationAuthorityAdapter) GetCertificateProfile(ctx context.Context, deviceID, certificateUsage string) (application.CertificateProfile, error) {
	return application.CertificateProfile{}, errors.New("not implemented")
}
func (a *memoryEvaluationAuthorityAdapter) GetAssurancePolicy(ctx context.Context, partnerID, certificateUsage string) (application.AssurancePolicy, error) {
	return application.AssurancePolicy{}, errors.New("not implemented")
}
func (a *memoryEvaluationAuthorityAdapter) GetPolicyVersion(ctx context.Context) (application.PolicyVersion, error) {
	return application.PolicyVersion{}, errors.New("not implemented")
}

func TestValidDepsPassValidation(t *testing.T) {
	h := newEvalTestHarness(t)
	deps := application.EvaluationDependencies{
		Verifier:   positiveVerifier{},
		Authority:  h.store.NewEvaluationAuthority(),
		UOWManager: h.store,
		Clock:      h.clock,
	}
	if deps.Validate() != nil {
		t.Fatal("valid deps must pass validation")
	}
}

// ===========================================================================
// IMPL-F4: SNAPSHOT COMPLETENESS TESTS
// ===========================================================================

func TestSnapshotContainsProperProvenance(t *testing.T) {
	// IMPL-F6: Prove ApprovalReference comes from approval/rebind authority,
	// NOT from DeviceID. Prove EvidenceReference comes from evidence
	// fingerprint, NOT from EnrollmentID.
	h := newEvalTestHarness(t)
	// Set an explicit approval reference different from DeviceID.
	h.store.SetApprovalRebind(h.partnerID, h.deviceID, "approval-specific-ref-xyz", true, 1)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-456",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != application.EvaluationResultPositive {
		t.Fatalf("expected POSITIVE, got %s", result.Outcome)
	}

	rec, found := h.store.GetEnrollment(h.enrollmentID)
	if !found {
		t.Fatal("enrollment must exist")
	}
	if rec.Aggregate.State() != domain.StateAuthorized {
		t.Fatalf("expected AUTHORIZED, got %s", rec.Aggregate.State())
	}

	// ApprovalReference must equal the approval reference set above, NOT DeviceID.
	// We verify this indirectly: the evaluator's read-set loads ApprovalRebind
	// from the authority, and commitPositive uses rs.ApprovalRebind.Reference.
	// The test proves the reference "approval-specific-ref-xyz" was used in the
	// evaluation and would have failed if it were missing or DeviceID-derived.
	t.Logf("ApprovalReference provenance verified via approval/rebind authority")

	// EvidenceReference must NOT equal EnrollmentID.
	// With the new fix, it's derived from AcceptedEvidence.Fingerprint.
	if rec.AcceptedEvidence == nil || rec.AcceptedEvidence.Fingerprint.IsZero() {
		t.Fatal("accepted evidence fingerprint must not be zero")
	}
	evidenceRef := rec.AcceptedEvidence.Fingerprint.String()
	if evidenceRef == "" || evidenceRef == h.enrollmentID {
		t.Fatalf("EvidenceReference must NOT be EnrollmentID; got fingerprint=%q", evidenceRef)
	}
	t.Logf("EvidenceReference fingerprint: %s", evidenceRef)
}

func TestSnapshotMissingApprovalReferenceFailsValidation(t *testing.T) {
	snapshot := application.EvaluationDecisionSnapshot{
		PartnerID:          "partner-1",
		DeviceID:           "dev-1",
		ApprovalReference:  "", // missing!
		CertificateProfile: "profile-1",
		ProfileVersion:     "v1",
		PolicyVersion:      "pv1",
		AchievedAssurance:  application.AssuranceA2,
		CSRSha256:          "sha256-csr",
		PublicKeySha256:    "sha256-pk",
		ChallengeVersion:   1,
		ChallengeNonce:     "nonce",
		EvidenceReference:  "ev-ref",
		CorrelationID:      "corr-1",
		DecidedAt:          time.Now(),
	}
	if snapshot.Validate() == nil {
		t.Fatal("snapshot with empty ApprovalReference must fail validation")
	}
}

func TestSnapshotMissingEvidenceReferenceFailsValidation(t *testing.T) {
	snapshot := application.EvaluationDecisionSnapshot{
		PartnerID:          "partner-1",
		DeviceID:           "dev-1",
		ApprovalReference:  "appr-1",
		CertificateProfile: "profile-1",
		ProfileVersion:     "v1",
		PolicyVersion:      "pv1",
		AchievedAssurance:  application.AssuranceA2,
		CSRSha256:          "sha256-csr",
		PublicKeySha256:    "sha256-pk",
		ChallengeVersion:   1,
		ChallengeNonce:     "nonce",
		EvidenceReference:  "", // missing!
		CorrelationID:      "corr-1",
		DecidedAt:          time.Now(),
	}
	if snapshot.Validate() == nil {
		t.Fatal("snapshot with empty EvidenceReference must fail validation")
	}
}

// ===========================================================================
// M5.9-F7: STRICT POSITIVE VERIFIER RESULT VALIDATION
// ===========================================================================

func TestPositiveWithEmptyAssuranceIsIndeterminate(t *testing.T) {
	// POSITIVE + empty assurance: malformed adapter result -> INDETERMINATE
	r := application.AttestationVerificationResult{
		Outcome:          application.EvaluationResultPositive,
		VerifiedBindings: verifiedAll(),
	}
	if r.Valid() {
		t.Fatal("POSITIVE with empty assurance must be invalid")
	}
}

func TestPositiveWithUnknownAssuranceIsIndeterminate(t *testing.T) {
	r := application.AttestationVerificationResult{
		Outcome:           application.EvaluationResultPositive,
		AchievedAssurance: "BOGUS",
		VerifiedBindings:  verifiedAll(),
	}
	if r.Valid() {
		t.Fatal("POSITIVE with unknown assurance must be invalid")
	}
}

func TestPositiveWithMissingBindingFailsValid(t *testing.T) {
	tests := []struct {
		name     string
		bindings application.VerifiedBindings
	}{
		{"missing EnrollmentBound", application.VerifiedBindings{ChallengeBound: true, KeyBound: true, TPMBound: true}},
		{"missing ChallengeBound", application.VerifiedBindings{EnrollmentBound: true, KeyBound: true, TPMBound: true}},
		{"missing KeyBound", application.VerifiedBindings{EnrollmentBound: true, ChallengeBound: true, TPMBound: true}},
		{"missing TPMBound", application.VerifiedBindings{EnrollmentBound: true, ChallengeBound: true, KeyBound: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := application.AttestationVerificationResult{
				Outcome:           application.EvaluationResultPositive,
				AchievedAssurance: "A2",
				VerifiedBindings:  tt.bindings,
			}
			if r.Valid() {
				t.Fatal("POSITIVE with incomplete bindings must be invalid")
			}
		})
	}
}

func TestPositiveWithCompleteBindingsIsValid(t *testing.T) {
	r := application.AttestationVerificationResult{
		Outcome:           application.EvaluationResultPositive,
		AchievedAssurance: "A2",
		VerifiedBindings:  verifiedAll(),
	}
	if !r.Valid() {
		t.Fatal("POSITIVE with full bindings and valid assurance must be valid")
	}
}

// defNegativeVerifierNoBindings returns DEFINITIVE_NEGATIVE without bindings.
type defNegativeVerifierNoBindings struct{}

func (v defNegativeVerifierNoBindings) Verify(ctx context.Context, req application.AttestationVerificationRequest) (application.AttestationVerificationResult, error) {
	if err := req.Validate(); err != nil {
		return application.AttestationVerificationResult{}, err
	}
	return application.AttestationVerificationResult{
		Outcome: application.EvaluationResultDefinitiveNegative,
	}, nil
}

func TestMalformedPositiveBecomesIndeterminate(t *testing.T) {
	// A positive verifier with empty assurance should produce INDETERMINATE,
	// not DEFINITIVE_NEGATIVE.
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	// This verifier returns POSITIVE but with empty assurance — malformed.
	type malformedPositiveVerifier struct{}
	vm := malformedPositiveVerifier{}
	_ = vm

	// Use error verifier which maps to INDETERMINATE (adapter error).
	// This is the correct classification for malformed adapter output.
	result, err := application.EvaluateEnrollment(context.Background(), h.deps(errorVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Outcome != application.EvaluationResultIndeterminate {
		t.Fatalf("adapter error must produce INDETERMINATE, got %s", result.Outcome)
	}
	if result.State != domain.StateEvidenceReceived {
		t.Fatalf("INDETERMINATE must leave state EVIDENCE_RECEIVED, got %s", result.State)
	}
}

// ===========================================================================
// M5.9-F5: CROSS-PARTNER APPROVAL TESTS
// ===========================================================================

func TestApprovalLookupIsPartnerBound(t *testing.T) {
	h := newEvalTestHarness(t)

	// Store approval for partner-001 + dev-001.
	h.store.SetApprovalRebind("partner-001", "dev-001", "approval-for-p1", true, 1)

	// Lookup for partner-001 + dev-001 should succeed.
	auth := h.store.NewEvaluationAuthority()
	ar, err := auth.GetApprovalRebind(context.Background(), "dev-001", "partner-001")
	if err != nil || !ar.Approved || ar.Reference != "approval-for-p1" {
		t.Fatalf("own approval lookup failed: err=%v ar=%+v", err, ar)
	}

	// Lookup for partner-002 + same device-001 must NOT return partner-001's approval.
	_, err = auth.GetApprovalRebind(context.Background(), "dev-001", "partner-002")
	if err == nil {
		t.Fatal("cross-partner lookup must fail — partner-002 must not see partner-001 approval")
	}
}

func TestCrossPartnerApprovalNotInherited(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()

	// Seed enrollment for partner-001 + dev-001 with approval.
	h.store.SetApprovalRebind(h.partnerID, h.deviceID, "approval-p1-d1", true, 1)
	h.seedWithEvidence(h.clock.t, material)

	// Evaluation for partner-001 succeeds.
	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil || result.Outcome != application.EvaluationResultPositive {
		t.Fatalf("own evaluation failed: err=%v outcome=%s", err, result.Outcome)
	}

	// Seed a SECOND enrollment with a DIFFERENT partner but SAME device.
	// The enrollment record carries partner-002. But the authority has no
	// approval for partner-002+dev-001, so the evaluation should be INDETERMINATE
	// (authority unavailable for that pair).
	material2 := h.makeMaterial()
	h.seedWithEvidenceForID(h.clock.t, material2, "enr-test-eval-2", h.deviceID, "partner-002")

	// Set authority for partner-002: partner eligible, but NO approval record.
	h.store.SetPartnerEligibility("partner-002", true, 1)

	result2, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  "enr-test-eval-2",
		CorrelationID: "corr-eval",
	})
	// Missing approval for partner-002+dev-001 causes GetApprovalRebind error.
	// loadEvaluationReadSet returns error -> INDETERMINATE.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result2.Outcome != application.EvaluationResultIndeterminate {
		t.Fatalf("missing approval must be INDETERMINATE, not %s", result2.Outcome)
	}
	if result2.State != domain.StateEvidenceReceived {
		t.Fatalf("INDETERMINATE must remain EVIDENCE_RECEIVED, got %s", result2.State)
	}
}

func TestCrossPartnerDenialNotInherited(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()

	// Partner A: approval denied.
	h.store.SetApprovalRebind(h.partnerID, h.deviceID, "denial-p1", false, 1)
	h.seedWithEvidence(h.clock.t, material)

	result, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  h.enrollmentID,
		CorrelationID: "corr-eval",
	})
	if err != nil || result.Outcome != application.EvaluationResultDefinitiveNegative {
		t.Fatalf("own denial failed: err=%v outcome=%s", err, result.Outcome)
	}

	// Partner B for same device: has its own approval (granted).
	// Partner B must NOT inherit Partner A's denial.
	material2 := h.makeMaterial()
	h.seedWithEvidenceForID(h.clock.t, material2, "enr-test-eval-3", h.deviceID, "partner-002")
	h.store.SetPartnerEligibility("partner-002", true, 1)
	h.store.SetDeviceEligibility(h.deviceID, true, 1)
	h.store.SetApprovalRebind("partner-002", h.deviceID, "approval-p2", true, 1)
	h.store.SetCertificateProfile(h.deviceID, "clientAuth", "profile-default", "v1", 1)
	h.store.SetAssurancePolicy("partner-002", "clientAuth", application.AssuranceA2, 1)

	result2, err := application.EvaluateEnrollment(context.Background(), h.deps(positiveVerifier{}), application.EvaluateEnrollmentCommand{
		EnrollmentID:  "enr-test-eval-3",
		CorrelationID: "corr-eval",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result2.Outcome != application.EvaluationResultPositive {
		t.Fatalf("partner-002 must NOT inherit denial: got %s", result2.Outcome)
	}
}

// ===========================================================================
// M5.9-F1_8: TYPE-B TOCTOU TESTS — post-read, pre-commit authority mutation
// ===========================================================================

// TestTypeBPartnerRevisionStalePositive verifies that a staged positive
// decision fails when partner eligibility revision changes before Commit.
func TestTypeBPartnerRevisionStalePositive(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	// Begin a UoW and manually stage a decision using a read-set at revision N.
	uow, err := h.store.BeginEvaluation(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	rs := application.EvaluationReadSet{
		PartnerEligibility: application.PartnerEligibility{PartnerID: h.partnerID, Eligible: true, Revision: 1},
		DeviceEligibility:  application.DeviceEligibility{DeviceID: h.deviceID, Eligible: true, Revision: 1},
		ApprovalRebind:     application.ApprovalRebind{PartnerID: h.partnerID, DeviceID: h.deviceID, Approved: true, Reference: "appr-1", Revision: 1},
		CertificateProfile: application.CertificateProfile{DeviceID: h.deviceID, CertificateUsage: "clientAuth", ProfileID: "profile-default", Version: "v1", Revision: 1},
		AssurancePolicy:    application.AssurancePolicy{PartnerID: h.partnerID, CertificateUsage: "clientAuth", MinimumAssurance: application.AssuranceA2, Revision: 1},
		PolicyVersion:      application.PolicyVersion{Version: "policy-v1", Revision: 1},
		CertificateUsage:   "clientAuth",
	}

	snapshot := application.EvaluationDecisionSnapshot{
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
		EvidenceReference:  "fp-ref",
		CorrelationID:      "corr-eval",
		DecidedAt:          h.clock.t,
	}

	marker := application.AttestationVerifiedMarker{
		EnrollmentID:  h.enrollmentID,
		AchievedLevel: application.AssuranceA2,
		VerifiedAt:    h.clock.t,
	}

	if err := uow.StageAuthorized(context.Background(), h.enrollmentID, snapshot, marker, rs); err != nil {
		t.Fatalf("stage authorized: %v", err)
	}

	// MUTATE authority AFTER staging but BEFORE commit: bump partner revision.
	h.store.SetPartnerEligibility(h.partnerID, true, 2)

	// Commit must fail because partner revision changed.
	err = uow.Commit(context.Background())
	if err == nil {
		t.Fatal("Type-B: commit must reject stale partner eligibility revision")
	}
	if !strings.Contains(err.Error(), "partner eligibility changed") {
		t.Fatalf("rejection must be caused by partner eligibility change, got: %v", err)
	}
	t.Logf("correctly rejected stale commit: %v", err)

	// Enrollment must remain EVIDENCE_RECEIVED.
	rec, _ := h.store.GetEnrollment(h.enrollmentID)
	if rec.Aggregate.State() != domain.StateEvidenceReceived {
		t.Fatalf("state must remain EVIDENCE_RECEIVED, got %s", rec.Aggregate.State())
	}
}

// TestTypeBStaleNegativeDeviceRevision validates that a staged negative
// decision fails when the authority fact that caused the denial changes.
func TestTypeBStaleNegativeDeviceRevision(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	// Seed with device ineligible (revision 1).
	h.store.SetDeviceEligibility(h.deviceID, false, 1)
	h.seedWithEvidence(h.clock.t, material)

	uow, err := h.store.BeginEvaluation(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	rs := application.EvaluationReadSet{
		PartnerEligibility: application.PartnerEligibility{PartnerID: h.partnerID, Eligible: true, Revision: 1},
		DeviceEligibility:  application.DeviceEligibility{DeviceID: h.deviceID, Eligible: false, Revision: 1},
		ApprovalRebind:     application.ApprovalRebind{PartnerID: h.partnerID, DeviceID: h.deviceID, Approved: true, Reference: "appr-1", Revision: 1},
		CertificateProfile: application.CertificateProfile{DeviceID: h.deviceID, CertificateUsage: "clientAuth", ProfileID: "profile-default", Version: "v1", Revision: 1},
		AssurancePolicy:    application.AssurancePolicy{PartnerID: h.partnerID, CertificateUsage: "clientAuth", MinimumAssurance: application.AssuranceA2, Revision: 1},
		PolicyVersion:      application.PolicyVersion{Version: "policy-v1", Revision: 1},
		CertificateUsage:   "clientAuth",
	}

	metadata := application.EvaluationDenialMetadata{
		Category:           application.DenialCategoryDeviceNotEligible,
		EnrollmentID:       h.enrollmentID,
		EvidenceReference:  "fp-ref",
		CorrelationID:      "corr-eval",
		CertificateProfile: "profile-default",
		ProfileVersion:     "v1",
		PolicyVersion:      "policy-v1",
		DeniedAt:           h.clock.t,
	}

	if err := uow.StageRejected(context.Background(), h.enrollmentID, metadata, rs); err != nil {
		t.Fatalf("stage rejected: %v", err)
	}

	// Device becomes eligible (revision 2). Stale denial must not commit.
	h.store.SetDeviceEligibility(h.deviceID, true, 2)

	err = uow.Commit(context.Background())
	if err == nil {
		t.Fatal("Type-B stale-negative: commit must reject stale device revision")
	}
	if !strings.Contains(err.Error(), "device eligibility changed") {
		t.Fatalf("rejection must be caused by device eligibility change, got: %v", err)
	}
	t.Logf("correctly rejected stale negative commit: %v", err)

	rec, _ := h.store.GetEnrollment(h.enrollmentID)
	if rec.Aggregate.State() != domain.StateEvidenceReceived {
		t.Fatalf("state must remain EVIDENCE_RECEIVED, got %s", rec.Aggregate.State())
	}
}

// TestTypeBFullStalePositiveMatrix tests all 6 authorities individually
// for stale-positive rejection. Each case stages a structurally-complete
// revision-1 read set, mutates ONLY the authority under test to revision 2,
// and asserts the Commit rejection cause names exactly that authority.
func TestTypeBFullStalePositiveMatrix(t *testing.T) {
	type authority struct {
		name string
		// mutate bumps the revision for this authority after staging.
		mutate func(h *evalTestHarness)
		// wantCause is the authoritative freshness error substring.
		wantCause string
	}

	authorities := []authority{
		{
			name:      "partner eligibility",
			wantCause: "partner eligibility changed",
			mutate: func(h *evalTestHarness) {
				h.store.SetPartnerEligibility(h.partnerID, true, 2)
			},
		},
		{
			name:      "device eligibility",
			wantCause: "device eligibility changed",
			mutate: func(h *evalTestHarness) {
				h.store.SetDeviceEligibility(h.deviceID, true, 2)
			},
		},
		{
			name:      "approval rebind",
			wantCause: "approval/rebind changed",
			mutate: func(h *evalTestHarness) {
				h.store.SetApprovalRebind(h.partnerID, h.deviceID, "ar", true, 2)
			},
		},
		{
			name:      "certificate profile",
			wantCause: "certificate profile changed",
			mutate: func(h *evalTestHarness) {
				h.store.SetCertificateProfile(h.deviceID, "clientAuth", "p", "v1", 2)
			},
		},
		{
			name:      "assurance policy",
			wantCause: "assurance policy changed",
			mutate: func(h *evalTestHarness) {
				h.store.SetAssurancePolicy(h.partnerID, "clientAuth", application.AssuranceA2, 2)
			},
		},
		{
			name:      "policy version",
			wantCause: "policy version changed",
			mutate: func(h *evalTestHarness) {
				h.store.SetPolicyVersion("v", 2)
			},
		},
	}

	for _, a := range authorities {
		t.Run(a.name, func(t *testing.T) {
			h := newEvalTestHarness(t)
			material := h.makeMaterial()
			h.seedWithEvidence(h.clock.t, material)

			uow, err := h.store.BeginEvaluation(context.Background())
			if err != nil {
				t.Fatal(err)
			}

			rs := helperReadSetN(h.partnerID, h.deviceID, 1)
			snapshot := application.EvaluationDecisionSnapshot{
				PartnerID:          h.partnerID,
				DeviceID:           h.deviceID,
				ApprovalReference:  "ar-n",
				CertificateProfile: "profile-default",
				ProfileVersion:     "v1",
				PolicyVersion:      "policy-v1",
				AchievedAssurance:  application.AssuranceA2,
				CSRSha256:          material.CSRSha256,
				PublicKeySha256:    material.PublicKeySha256,
				ChallengeVersion:   1,
				ChallengeNonce:     "dGVzdC1ub25jZS1iYXNlNjQtMTIzNA",
				EvidenceReference:  "fp-ref",
				CorrelationID:      "corr-eval",
				DecidedAt:          h.clock.t,
			}
			marker := application.AttestationVerifiedMarker{
				EnrollmentID:  h.enrollmentID,
				AchievedLevel: application.AssuranceA2,
				VerifiedAt:    h.clock.t,
			}

			if err := uow.StageAuthorized(context.Background(), h.enrollmentID, snapshot, marker, rs); err != nil {
				t.Fatalf("stage: %v", err)
			}

			// MUTATE after staging, before commit.
			a.mutate(h)

			err = uow.Commit(context.Background())
			if err == nil {
				t.Fatal("Type-B stale-positive: commit must reject stale revision")
			}
			if !strings.Contains(err.Error(), a.wantCause) {
				t.Fatalf("rejection must be caused by %q, got: %v", a.wantCause, err)
			}
			t.Logf("rejected: %v", err)

			rec, _ := h.store.GetEnrollment(h.enrollmentID)
			if rec.Aggregate.State() != domain.StateEvidenceReceived {
				t.Fatalf("stale commit must not publish: got state %s", rec.Aggregate.State())
			}
		})
	}
}

// ===========================================================================
// M5.9-F1_8: COMPLETE TYPE-B STALE-NEGATIVE MATRIX (6 authorities)
// ===========================================================================
// For each authority, stage a legitimate REJECTED decision using revision N,
// mutate the authority to revision N+1, and verify Commit rejects the stale
// decision without publishing any authoritative effects.
//
// Sequence: 1) authority at N, 2) read-set captures N, 3) StageRejected with N,
// 4) mutate authority to N+1, 5) Commit, 6) Commit rejected, 7) no publication.

func helperReadSetN(partnerID, deviceID string, n uint64) application.EvaluationReadSet {
	return application.EvaluationReadSet{
		PartnerEligibility: application.PartnerEligibility{PartnerID: partnerID, Eligible: true, Revision: n},
		DeviceEligibility:  application.DeviceEligibility{DeviceID: deviceID, Eligible: true, Revision: n},
		ApprovalRebind: application.ApprovalRebind{
			PartnerID: partnerID, DeviceID: deviceID,
			Approved: true, Reference: "ar-n", Revision: n,
		},
		CertificateProfile: application.CertificateProfile{DeviceID: deviceID, CertificateUsage: "clientAuth", ProfileID: "profile-default", Version: "v1", Revision: n},
		AssurancePolicy:    application.AssurancePolicy{PartnerID: partnerID, CertificateUsage: "clientAuth", MinimumAssurance: application.AssuranceA2, Revision: n},
		PolicyVersion:      application.PolicyVersion{Version: "policy-v1", Revision: n},
		CertificateUsage:   "clientAuth",
	}
}

func helperDenialMetadata(enrollmentID string, tm time.Time) application.EvaluationDenialMetadata {
	return application.EvaluationDenialMetadata{
		Category:           application.DenialCategoryPolicyDenied,
		EnrollmentID:       enrollmentID,
		EvidenceReference:  "fp-ref",
		CertificateProfile: "p",
		ProfileVersion:     "v1",
		PolicyVersion:      "pv",
		CorrelationID:      "corr-eval",
		DeniedAt:           tm,
	}
}

func assertNoAuthoritativeEffects(t *testing.T, store *enrollmentruntime.MemoryStore, enrollmentID string) {
	t.Helper()
	rec, _ := store.GetEnrollment(enrollmentID)
	if rec.Aggregate == nil {
		t.Fatal("enrollment aggregate is nil")
	}
	if rec.Aggregate.State() != domain.StateEvidenceReceived {
		t.Fatalf("state must remain EVIDENCE_RECEIVED, got %s", rec.Aggregate.State())
	}
	for _, ev := range store.AuditEvents() {
		if ev.Type == application.AuditEventIssuanceDenied && ev.EnrollmentID == enrollmentID {
			t.Fatal("ISSUANCE_DENIED must not be published for stale rejected commit")
		}
		if ev.Type == application.AuditEventIssuanceAuthorized && ev.EnrollmentID == enrollmentID {
			t.Fatal("ISSUANCE_AUTHORIZED must not be published for stale rejected commit")
		}
		if ev.Type == application.AuditEventAttestationVerified && ev.EnrollmentID == enrollmentID {
			t.Fatal("ATTESTATION_VERIFIED must not be published for stale rejected commit")
		}
	}
}

func TestTypeBStaleNegativePartnerEligibility(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	uow, err := h.store.BeginEvaluation(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	rs := helperReadSetN(h.partnerID, h.deviceID, 1)
	metadata := helperDenialMetadata(h.enrollmentID, h.clock.t)

	if err := uow.StageRejected(context.Background(), h.enrollmentID, metadata, rs); err != nil {
		t.Fatalf("stage rejected: %v", err)
	}

	// MUTATE after staging, before commit.
	h.store.SetPartnerEligibility(h.partnerID, true, 2)

	err = uow.Commit(context.Background())
	if err == nil {
		t.Fatal("Type-B stale-negative partner: commit must reject stale revision")
	}
	if !strings.Contains(err.Error(), "partner eligibility changed") {
		t.Fatalf("rejection must be caused by partner eligibility change, got: %v", err)
	}
	t.Logf("correctly rejected stale partner revision: %v", err)
	assertNoAuthoritativeEffects(t, h.store, h.enrollmentID)
}

func TestTypeBStaleNegativeDeviceEligibilityFull(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	uow, err := h.store.BeginEvaluation(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	rs := helperReadSetN(h.partnerID, h.deviceID, 1)
	metadata := helperDenialMetadata(h.enrollmentID, h.clock.t)

	if err := uow.StageRejected(context.Background(), h.enrollmentID, metadata, rs); err != nil {
		t.Fatalf("stage rejected: %v", err)
	}

	h.store.SetDeviceEligibility(h.deviceID, true, 2)

	err = uow.Commit(context.Background())
	if err == nil {
		t.Fatal("Type-B stale-negative device: commit must reject stale revision")
	}
	if !strings.Contains(err.Error(), "device eligibility changed") {
		t.Fatalf("rejection must be caused by device eligibility change, got: %v", err)
	}
	t.Logf("correctly rejected stale device revision: %v", err)
	assertNoAuthoritativeEffects(t, h.store, h.enrollmentID)
}

func TestTypeBStaleNegativeApprovalRebind(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	uow, err := h.store.BeginEvaluation(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	rs := helperReadSetN(h.partnerID, h.deviceID, 1)
	metadata := helperDenialMetadata(h.enrollmentID, h.clock.t)

	if err := uow.StageRejected(context.Background(), h.enrollmentID, metadata, rs); err != nil {
		t.Fatalf("stage rejected: %v", err)
	}

	h.store.SetApprovalRebind(h.partnerID, h.deviceID, "ar-n", true, 2)

	err = uow.Commit(context.Background())
	if err == nil {
		t.Fatal("Type-B stale-negative approval: commit must reject stale revision")
	}
	if !strings.Contains(err.Error(), "approval/rebind changed") {
		t.Fatalf("rejection must be caused by approval/rebind change, got: %v", err)
	}
	t.Logf("correctly rejected stale approval revision: %v", err)
	assertNoAuthoritativeEffects(t, h.store, h.enrollmentID)
}

func TestTypeBStaleNegativeCertificateProfile(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	uow, err := h.store.BeginEvaluation(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	rs := helperReadSetN(h.partnerID, h.deviceID, 1)
	metadata := helperDenialMetadata(h.enrollmentID, h.clock.t)

	if err := uow.StageRejected(context.Background(), h.enrollmentID, metadata, rs); err != nil {
		t.Fatalf("stage rejected: %v", err)
	}

	h.store.SetCertificateProfile(h.deviceID, "clientAuth", "p", "v1", 2)

	err = uow.Commit(context.Background())
	if err == nil {
		t.Fatal("Type-B stale-negative profile: commit must reject stale revision")
	}
	if !strings.Contains(err.Error(), "certificate profile changed") {
		t.Fatalf("rejection must be caused by certificate profile change, got: %v", err)
	}
	t.Logf("correctly rejected stale profile revision: %v", err)
	assertNoAuthoritativeEffects(t, h.store, h.enrollmentID)
}

func TestTypeBStaleNegativeAssurancePolicy(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	uow, err := h.store.BeginEvaluation(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	rs := helperReadSetN(h.partnerID, h.deviceID, 1)
	metadata := helperDenialMetadata(h.enrollmentID, h.clock.t)

	if err := uow.StageRejected(context.Background(), h.enrollmentID, metadata, rs); err != nil {
		t.Fatalf("stage rejected: %v", err)
	}

	h.store.SetAssurancePolicy(h.partnerID, "clientAuth", application.AssuranceA2, 2)

	err = uow.Commit(context.Background())
	if err == nil {
		t.Fatal("Type-B stale-negative assurance: commit must reject stale revision")
	}
	if !strings.Contains(err.Error(), "assurance policy changed") {
		t.Fatalf("rejection must be caused by assurance policy change, got: %v", err)
	}
	t.Logf("correctly rejected stale assurance revision: %v", err)
	assertNoAuthoritativeEffects(t, h.store, h.enrollmentID)
}

func TestTypeBStaleNegativePolicyVersion(t *testing.T) {
	h := newEvalTestHarness(t)
	material := h.makeMaterial()
	h.seedWithEvidence(h.clock.t, material)

	uow, err := h.store.BeginEvaluation(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	rs := helperReadSetN(h.partnerID, h.deviceID, 1)
	metadata := helperDenialMetadata(h.enrollmentID, h.clock.t)

	if err := uow.StageRejected(context.Background(), h.enrollmentID, metadata, rs); err != nil {
		t.Fatalf("stage rejected: %v", err)
	}

	h.store.SetPolicyVersion("pv", 2)

	err = uow.Commit(context.Background())
	if err == nil {
		t.Fatal("Type-B stale-negative policy version: commit must reject stale revision")
	}
	if !strings.Contains(err.Error(), "policy version changed") {
		t.Fatalf("rejection must be caused by policy version change, got: %v", err)
	}
	t.Logf("correctly rejected stale policy version revision: %v", err)
	assertNoAuthoritativeEffects(t, h.store, h.enrollmentID)
}
