// Package runtime — M5.9 Phase-2 evaluation memory adapter.
//
// This file extends the in-memory store with evaluation material persistence,
// the EvaluationUnitOfWork interface, and freshness-aware commit semantics.
//
// It does NOT add CA dependencies, production verifier implementations,
// production triggers, or new HTTP endpoints.

package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	domain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/domain/enrollment"
	application "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/application"
)

// evaluationStoreState holds the Phase-2 evaluation persistence within MemoryStore.
// All of its maps are guarded by MemoryStore.mu; the authority facts inside
// authorityState carry their own lock (see the lock-order note there).
type evaluationStoreState struct {
	// decisionSnapshots maps enrollment ID -> positive decision snapshot.
	decisionSnapshots map[string]application.EvaluationDecisionSnapshot
	// denialMetadata maps enrollment ID -> denial metadata.
	denialMetadata map[string]application.EvaluationDenialMetadata
	// attestationMarkers maps enrollment ID -> ATTESTATION_VERIFIED marker.
	attestationMarkers map[string]application.AttestationVerifiedMarker
	// authorityState holds the current authority facts for freshness.
	authorityState *authorityState
}

// approvalRebindKey is the composite key for approval/rebind lookups.
type approvalRebindKey struct {
	PartnerID string
	DeviceID  string
}

// certProfileKey is the composite key binding DeviceID + CertificateUsage.
type certProfileKey struct {
	DeviceID         string
	CertificateUsage string
}

// assurancePolicyKey is the composite key binding PartnerID + CertificateUsage.
type assurancePolicyKey struct {
	PartnerID        string
	CertificateUsage string
}

// authorityState is the mutable, lock-protected authority facts.
//
// LOCK ORDER: store.mu → authorityState.mu.
// All authority mutations acquire store.mu.RLock() (or store.mu.Lock() for
// Set* methods on MemoryStore) before authorityState.mu.Lock(), preventing
// TOCTOU between freshness-validate and publish.
type authorityState struct {
	mu                 sync.RWMutex
	partnerEligibility map[string]application.PartnerEligibility
	deviceEligibility  map[string]application.DeviceEligibility
	approvalRebind     map[approvalRebindKey]application.ApprovalRebind
	certificateProfile map[certProfileKey]application.CertificateProfile
	assurancePolicy    map[assurancePolicyKey]application.AssurancePolicy
	policyVersion      *application.PolicyVersion
}

func newAuthorityState() *authorityState {
	return &authorityState{
		partnerEligibility: make(map[string]application.PartnerEligibility),
		deviceEligibility:  make(map[string]application.DeviceEligibility),
		approvalRebind:     make(map[approvalRebindKey]application.ApprovalRebind),
		certificateProfile: make(map[certProfileKey]application.CertificateProfile),
		assurancePolicy:    make(map[assurancePolicyKey]application.AssurancePolicy),
	}
}

func newEvaluationStoreState() *evaluationStoreState {
	return &evaluationStoreState{
		decisionSnapshots:  make(map[string]application.EvaluationDecisionSnapshot),
		denialMetadata:     make(map[string]application.EvaluationDenialMetadata),
		attestationMarkers: make(map[string]application.AttestationVerifiedMarker),
		authorityState:     newAuthorityState(),
	}
}

// ---------------------------------------------------------------------------
// Evaluation memory UOW
// ---------------------------------------------------------------------------

// evaluationMemoryUOW wraps a standard memoryUOW and adds Phase-2 evaluation
// staging. It implements EvaluationUnitOfWork.
type evaluationMemoryUOW struct {
	*memoryUOW
	eval *evaluationStoreState
	// Staged evaluation mutations (all-or-none at commit).
	stagedAuthorized *stagedAuthorization
	stagedRejected   *stagedRejection
}

type stagedAuthorization struct {
	enrollmentID string
	snapshot     application.EvaluationDecisionSnapshot
	marker       application.AttestationVerifiedMarker
	readSet      application.EvaluationReadSet
	decidedAt    time.Time
	event        application.AuditEvent
}

type stagedRejection struct {
	enrollmentID string
	metadata     application.EvaluationDenialMetadata
	readSet      application.EvaluationReadSet
	decidedAt    time.Time
	event        application.AuditEvent
}

// BeginEvaluation starts a new evaluation-scoped Unit of Work.
func (s *MemoryStore) BeginEvaluation(ctx context.Context) (application.EvaluationUnitOfWork, error) {
	base, err := s.Begin(ctx)
	if err != nil {
		return nil, err
	}
	baseUOW, ok := base.(*memoryUOW)
	if !ok {
		_ = base.Rollback(ctx)
		return nil, errors.New("enrollment evaluation runtime: incompatible UOW type")
	}
	return &evaluationMemoryUOW{
		memoryUOW: baseUOW,
		eval:      s.eval,
	}, nil
}

func (u *evaluationMemoryUOW) StageAuthorized(ctx context.Context, enrollmentID string, snapshot application.EvaluationDecisionSnapshot, marker application.AttestationVerifiedMarker, readSet application.EvaluationReadSet) error {
	if u.closed {
		return errors.New("enrollment evaluation runtime: transaction closed")
	}
	if u.stagedAuthorized != nil || u.stagedRejected != nil {
		return errors.New("enrollment evaluation runtime: evaluation already staged")
	}
	if snapshot.Validate() != nil {
		return errors.New("enrollment evaluation runtime: invalid decision snapshot")
	}
	if marker.Validate() != nil {
		return errors.New("enrollment evaluation runtime: invalid attestation marker")
	}

	// Verify enrollment exists and is in EVIDENCE_RECEIVED.
	rec, found, err := u.getEnrollmentRecordLocked(enrollmentID)
	if err != nil {
		return fmt.Errorf("enrollment evaluation runtime: %w", err)
	}
	if !found || rec.Aggregate == nil {
		return errors.New("enrollment evaluation runtime: enrollment not found")
	}
	if rec.Aggregate.State() != domain.StateEvidenceReceived {
		return errors.New("enrollment evaluation runtime: enrollment not in EVIDENCE_RECEIVED")
	}

	u.stagedAuthorized = &stagedAuthorization{
		enrollmentID: enrollmentID,
		snapshot:     snapshot.Clone(),
		marker:       marker,
		readSet:      readSet,
		decidedAt:    snapshot.DecidedAt,
		event: application.AuditEvent{
			Type:             application.AuditEventIssuanceAuthorized,
			EnrollmentID:     enrollmentID,
			DeviceID:         rec.DeviceID,
			Operation:        rec.Operation,
			CertificateUsage: rec.CertificateUsage,
			CorrelationID:    snapshot.CorrelationID,
			Timestamp:        snapshot.DecidedAt,
		},
	}
	return nil
}

func (u *evaluationMemoryUOW) StageRejected(ctx context.Context, enrollmentID string, metadata application.EvaluationDenialMetadata, readSet application.EvaluationReadSet) error {
	if u.closed {
		return errors.New("enrollment evaluation runtime: transaction closed")
	}
	if u.stagedAuthorized != nil || u.stagedRejected != nil {
		return errors.New("enrollment evaluation runtime: evaluation already staged")
	}
	if metadata.Validate() != nil {
		return errors.New("enrollment evaluation runtime: invalid denial metadata")
	}

	// Verify enrollment exists and is in EVIDENCE_RECEIVED.
	rec, found, err := u.getEnrollmentRecordLocked(enrollmentID)
	if err != nil {
		return fmt.Errorf("enrollment evaluation runtime: %w", err)
	}
	if !found || rec.Aggregate == nil {
		return errors.New("enrollment evaluation runtime: enrollment not found")
	}
	if rec.Aggregate.State() != domain.StateEvidenceReceived {
		return errors.New("enrollment evaluation runtime: enrollment not in EVIDENCE_RECEIVED")
	}

	u.stagedRejected = &stagedRejection{
		enrollmentID: enrollmentID,
		metadata:     metadata,
		readSet:      readSet,
		decidedAt:    metadata.DeniedAt,
		event: application.AuditEvent{
			Type:             application.AuditEventIssuanceDenied,
			EnrollmentID:     enrollmentID,
			DeviceID:         rec.DeviceID,
			Operation:        rec.Operation,
			CertificateUsage: rec.CertificateUsage,
			CorrelationID:    metadata.CorrelationID,
			Timestamp:        metadata.DeniedAt,
		},
	}
	return nil
}

func (u *evaluationMemoryUOW) GetEvaluationMaterial(ctx context.Context, enrollmentID string) (application.EvaluationMaterial, bool, error) {
	u.store.mu.RLock()
	defer u.store.mu.RUnlock()
	rec, ok := u.store.enrollments[enrollmentID]
	if !ok || rec.EvaluationMaterial == nil {
		return application.EvaluationMaterial{}, false, nil
	}
	return rec.EvaluationMaterial.Clone(), true, nil
}

func (u *evaluationMemoryUOW) GetEnrollmentForEvaluation(ctx context.Context, enrollmentID string) (application.EnrollmentRecord, bool, error) {
	return u.getEnrollmentRecordLocked(enrollmentID)
}

func (u *evaluationMemoryUOW) getEnrollmentRecordLocked(enrollmentID string) (application.EnrollmentRecord, bool, error) {
	u.store.mu.RLock()
	defer u.store.mu.RUnlock()
	rec, ok := u.store.enrollments[enrollmentID]
	if !ok {
		return application.EnrollmentRecord{}, false, nil
	}
	return cloneEnrollmentRecord(rec), true, nil
}

// Commit overrides the base commit to include evaluation staging and
// freshness validation. All-or-none: state transition, snapshot/marker/
// metadata, and audit events are published atomically.
//
// LOCK ORDER: validateFreshnessLocked re-reads authority under
// authorityState.mu.RLock() while holding store.mu.Lock(). Authority
// mutation methods (SetPartnerEligibility etc.) acquire store.mu.RLock()
// before authorityState.mu.Lock(), ensuring no TOCTOU gap between
// freshness revalidation and publication.
func (u *evaluationMemoryUOW) Commit(ctx context.Context) error {
	if u.closed {
		return errors.New("enrollment evaluation runtime: transaction closed")
	}
	u.closed = true

	u.store.mu.Lock()
	defer u.store.mu.Unlock()

	// Freshness revalidation: re-read current authority values under
	// store.mu and compare revisions against the staged read-set.
	// store.mu prevents concurrent authority mutation during validation
	// because all authority setters also acquire store.mu.
	if u.stagedAuthorized != nil || u.stagedRejected != nil {
		if err := u.validateFreshnessLocked(); err != nil {
			return err
		}
	}

	// Execute base staging (evidence acceptance, etc.) first.
	if u.stagedEvidence != nil {
		write := *u.stagedEvidence
		rec, ok := u.store.enrollments[write.EnrollmentID]
		if !ok || rec.Aggregate == nil || rec.Aggregate.State() != domain.StateChallengeIssued {
			return errors.New("enrollment evaluation runtime: evidence staging state conflict")
		}
		if rec.Challenge.ChallengeVersion != write.ExpectedChallengeVersion {
			return errors.New("enrollment evaluation runtime: evidence staging version mismatch")
		}
		rec.Aggregate, _ = domain.RestoreEnrollment(rec.Aggregate.ID(), domain.StateEvidenceReceived)
		evidence := write.Evidence.Clone()
		rec.AcceptedEvidence = &evidence
		rec.UpdatedAt = write.AcceptedAt

		// M5.9: Store evaluation material on the enrollment record.
		if write.Material != nil && write.Material.Validate() == nil {
			material := write.Material.Clone()
			rec.EvaluationMaterial = &material
		}

		u.store.enrollments[write.EnrollmentID] = cloneEnrollmentRecord(rec)

		u.store.audits = append(u.store.audits, application.AuditEvent{
			Type:             application.AuditEventEvidenceAccepted,
			EnrollmentID:     write.EnrollmentID,
			DeviceID:         rec.DeviceID,
			Operation:        rec.Operation,
			CertificateUsage: rec.CertificateUsage,
			Timestamp:        write.AcceptedAt,
		})
	}

	// Execute evaluation staging.
	if u.stagedAuthorized != nil {
		return u.commitAuthorizedLocked()
	}
	if u.stagedRejected != nil {
		return u.commitRejectedLocked()
	}

	// No evaluation staged; just execute idempotency commits.
	for scope, record := range u.stagedIdemCommits {
		u.store.idemCommitted[scope] = record
	}
	return nil
}

func (u *evaluationMemoryUOW) commitAuthorizedLocked() error {
	sa := u.stagedAuthorized

	rec, ok := u.store.enrollments[sa.enrollmentID]
	if !ok || rec.Aggregate == nil {
		return errors.New("enrollment evaluation runtime: enrollment disappeared during commit")
	}
	if rec.Aggregate.State() != domain.StateEvidenceReceived {
		return errors.New("enrollment evaluation runtime: enrollment state changed during evaluation")
	}

	// Hydrate candidate aggregate from the committed record and Authorize.
	candidate, err := domain.RestoreEnrollment(rec.Aggregate.ID(), rec.Aggregate.State())
	if err != nil {
		return fmt.Errorf("enrollment evaluation runtime: hydrate candidate: %w", err)
	}
	if err := candidate.Authorize(); err != nil {
		return fmt.Errorf("enrollment evaluation runtime: domain transition: %w", err)
	}
	rec.Aggregate = candidate

	rec.AssuranceLevel = string(sa.snapshot.AchievedAssurance)
	rec.UpdatedAt = sa.decidedAt
	u.store.enrollments[sa.enrollmentID] = cloneEnrollmentRecord(rec)

	// Persist decision snapshot.
	u.store.eval.decisionSnapshots[sa.enrollmentID] = sa.snapshot.Clone()

	// Persist ATTESTATION_VERIFIED marker.
	u.store.eval.attestationMarkers[sa.enrollmentID] = sa.marker

	// Stage audit events.
	u.store.audits = append(u.store.audits, sa.event)
	u.store.audits = append(u.store.audits, application.AuditEvent{
		Type:         application.AuditEventAttestationVerified,
		EnrollmentID: sa.enrollmentID,
		Timestamp:    sa.decidedAt,
	})

	// Execute idempotency commits.
	for scope, record := range u.stagedIdemCommits {
		u.store.idemCommitted[scope] = record
	}

	u.stagedAuthorized = nil
	return nil
}

func (u *evaluationMemoryUOW) commitRejectedLocked() error {
	sr := u.stagedRejected

	rec, ok := u.store.enrollments[sr.enrollmentID]
	if !ok || rec.Aggregate == nil {
		return errors.New("enrollment evaluation runtime: enrollment disappeared during commit")
	}
	if rec.Aggregate.State() != domain.StateEvidenceReceived {
		return errors.New("enrollment evaluation runtime: enrollment state changed during evaluation")
	}

	// Apply domain transition.
	if err := rec.Aggregate.Reject(); err != nil {
		return fmt.Errorf("enrollment evaluation runtime: domain reject transition: %w", err)
	}
	rec.UpdatedAt = sr.decidedAt
	u.store.enrollments[sr.enrollmentID] = cloneEnrollmentRecord(rec)

	// Persist denial metadata.
	u.store.eval.denialMetadata[sr.enrollmentID] = sr.metadata

	// Stage audit event.
	u.store.audits = append(u.store.audits, sr.event)

	// Execute idempotency commits.
	for scope, record := range u.stagedIdemCommits {
		u.store.idemCommitted[scope] = record
	}

	u.stagedRejected = nil
	return nil
}

// validateFreshnessLocked re-reads current authority values and compares
// revisions against the staged read-set. It MUST be called while holding
// store.mu.Lock(). Under store.mu, authority cannot change because all
// authority setters also acquire store.mu before authorityState.mu.
func (u *evaluationMemoryUOW) validateFreshnessLocked() error {
	var expected application.EvaluationReadSet

	if u.stagedAuthorized != nil {
		expected = u.stagedAuthorized.readSet
	} else if u.stagedRejected != nil {
		expected = u.stagedRejected.readSet
	} else {
		return nil
	}

	u.eval.authorityState.mu.RLock()
	pe, de, ar, cp, ap, pv := u.readCurrentAuthorityLocked(
		expected.PartnerEligibility.PartnerID,
		expected.DeviceEligibility.DeviceID,
		expected.CertificateUsage,
	)
	u.eval.authorityState.mu.RUnlock()

	// Compare each authoritative fact's revision against the expected value.
	if pe.Revision != expected.PartnerEligibility.Revision {
		return errors.New("enrollment evaluation runtime: partner eligibility changed during evaluation")
	}
	if de.Revision != expected.DeviceEligibility.Revision {
		return errors.New("enrollment evaluation runtime: device eligibility changed during evaluation")
	}
	if ar.Revision != expected.ApprovalRebind.Revision {
		return errors.New("enrollment evaluation runtime: approval/rebind changed during evaluation")
	}
	if cp.Revision != expected.CertificateProfile.Revision {
		return errors.New("enrollment evaluation runtime: certificate profile changed during evaluation")
	}
	if ap.Revision != expected.AssurancePolicy.Revision {
		return errors.New("enrollment evaluation runtime: assurance policy changed during evaluation")
	}
	if pv.Revision != expected.PolicyVersion.Revision {
		return errors.New("enrollment evaluation runtime: policy version changed during evaluation")
	}

	return nil
}

func (u *evaluationMemoryUOW) readCurrentAuthorityLocked(partnerID, deviceID, certificateUsage string) (
	application.PartnerEligibility,
	application.DeviceEligibility,
	application.ApprovalRebind,
	application.CertificateProfile,
	application.AssurancePolicy,
	application.PolicyVersion,
) {
	pe := u.eval.authorityState.partnerEligibility[partnerID]
	de := u.eval.authorityState.deviceEligibility[deviceID]
	ar := u.eval.authorityState.approvalRebind[approvalRebindKey{PartnerID: partnerID, DeviceID: deviceID}]
	cp := u.eval.authorityState.certificateProfile[certProfileKey{DeviceID: deviceID, CertificateUsage: certificateUsage}]
	ap := u.eval.authorityState.assurancePolicy[assurancePolicyKey{PartnerID: partnerID, CertificateUsage: certificateUsage}]
	var pv application.PolicyVersion
	if u.eval.authorityState.policyVersion != nil {
		pv = *u.eval.authorityState.policyVersion
	}
	return pe, de, ar, cp, ap, pv
}

// Rollback releases evaluation staging without publishing.
func (u *evaluationMemoryUOW) Rollback(ctx context.Context) error {
	if u.closed {
		return nil
	}
	u.closed = true
	u.stagedAuthorized = nil
	u.stagedRejected = nil
	return u.memoryUOW.Rollback(ctx)
}

// ---------------------------------------------------------------------------
// Authority state management (for test setup)
// ---------------------------------------------------------------------------

// SetPartnerEligibility installs/updates the current partner eligibility.
// Acquires store.mu.RLock() before authorityState.mu.Lock() to establish
// lock ordering that prevents TOCTOU between freshness-validate and publish.
func (s *MemoryStore) SetPartnerEligibility(partnerID string, eligible bool, revision uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.eval.authorityState.mu.Lock()
	defer s.eval.authorityState.mu.Unlock()
	s.eval.authorityState.partnerEligibility[partnerID] = application.PartnerEligibility{
		PartnerID: partnerID,
		Eligible:  eligible,
		Revision:  revision,
	}
}

// SetDeviceEligibility installs/updates the current device eligibility.
func (s *MemoryStore) SetDeviceEligibility(deviceID string, eligible bool, revision uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.eval.authorityState.mu.Lock()
	defer s.eval.authorityState.mu.Unlock()
	s.eval.authorityState.deviceEligibility[deviceID] = application.DeviceEligibility{
		DeviceID: deviceID,
		Eligible: eligible,
		Revision: revision,
	}
}

// SetApprovalRebind installs/updates the current approval/rebind authority.
func (s *MemoryStore) SetApprovalRebind(partnerID, deviceID, reference string, approved bool, revision uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.eval.authorityState.mu.Lock()
	defer s.eval.authorityState.mu.Unlock()
	s.eval.authorityState.approvalRebind[approvalRebindKey{PartnerID: partnerID, DeviceID: deviceID}] = application.ApprovalRebind{
		PartnerID: partnerID,
		DeviceID:  deviceID,
		Approved:  approved,
		Reference: reference,
		Revision:  revision,
	}
}

// SetCertificateProfile installs/updates the current certificate profile.
func (s *MemoryStore) SetCertificateProfile(deviceID, certificateUsage, profileID, version string, revision uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.eval.authorityState.mu.Lock()
	defer s.eval.authorityState.mu.Unlock()
	s.eval.authorityState.certificateProfile[certProfileKey{DeviceID: deviceID, CertificateUsage: certificateUsage}] = application.CertificateProfile{
		DeviceID:         deviceID,
		CertificateUsage: certificateUsage,
		ProfileID:        profileID,
		Version:          version,
		Revision:         revision,
	}
}

// SetAssurancePolicy installs/updates the current assurance policy.
func (s *MemoryStore) SetAssurancePolicy(partnerID, certificateUsage string, minAssurance application.AssuranceLevel, revision uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.eval.authorityState.mu.Lock()
	defer s.eval.authorityState.mu.Unlock()
	s.eval.authorityState.assurancePolicy[assurancePolicyKey{PartnerID: partnerID, CertificateUsage: certificateUsage}] = application.AssurancePolicy{
		PartnerID:        partnerID,
		CertificateUsage: certificateUsage,
		MinimumAssurance: minAssurance,
		Revision:         revision,
	}
}

// SetPolicyVersion installs/updates the current policy version.
func (s *MemoryStore) SetPolicyVersion(version string, revision uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.eval.authorityState.mu.Lock()
	defer s.eval.authorityState.mu.Unlock()
	s.eval.authorityState.policyVersion = &application.PolicyVersion{
		Version:  version,
		Revision: revision,
	}
}

// ---------------------------------------------------------------------------
// In-memory EvaluationAuthority adapter
// ---------------------------------------------------------------------------

// memoryEvaluationAuthority implements application.EvaluationAuthority
// backed by the same authorityState in MemoryStore.
type memoryEvaluationAuthority struct {
	state *authorityState
}

func (a *memoryEvaluationAuthority) GetPartnerEligibility(ctx context.Context, partnerID string) (application.PartnerEligibility, error) {
	a.state.mu.RLock()
	defer a.state.mu.RUnlock()
	pe, ok := a.state.partnerEligibility[partnerID]
	if !ok {
		return application.PartnerEligibility{}, errors.New("enrollment evaluation runtime: partner not found")
	}
	return pe, nil
}

func (a *memoryEvaluationAuthority) GetDeviceEligibility(ctx context.Context, deviceID string) (application.DeviceEligibility, error) {
	a.state.mu.RLock()
	defer a.state.mu.RUnlock()
	de, ok := a.state.deviceEligibility[deviceID]
	if !ok {
		return application.DeviceEligibility{}, errors.New("enrollment evaluation runtime: device not found")
	}
	return de, nil
}

func (a *memoryEvaluationAuthority) GetApprovalRebind(ctx context.Context, deviceID, partnerID string) (application.ApprovalRebind, error) {
	if strings.TrimSpace(partnerID) == "" || strings.TrimSpace(deviceID) == "" {
		return application.ApprovalRebind{}, errors.New("enrollment evaluation runtime: approval/rebind requires partner and device")
	}
	a.state.mu.RLock()
	defer a.state.mu.RUnlock()
	ar, ok := a.state.approvalRebind[approvalRebindKey{PartnerID: partnerID, DeviceID: deviceID}]
	if !ok {
		return application.ApprovalRebind{}, errors.New("enrollment evaluation runtime: approval/rebind not found for partner+device")
	}
	// Cross-check: stored record must match both requested identities.
	if ar.PartnerID != partnerID || ar.DeviceID != deviceID {
		return application.ApprovalRebind{}, errors.New("enrollment evaluation runtime: approval/rebind binding mismatch")
	}
	return ar, nil
}

func (a *memoryEvaluationAuthority) GetCertificateProfile(ctx context.Context, deviceID, certificateUsage string) (application.CertificateProfile, error) {
	if strings.TrimSpace(deviceID) == "" || strings.TrimSpace(certificateUsage) == "" {
		return application.CertificateProfile{}, errors.New("enrollment evaluation runtime: certificate profile requires device and usage")
	}
	a.state.mu.RLock()
	defer a.state.mu.RUnlock()
	cp, ok := a.state.certificateProfile[certProfileKey{DeviceID: deviceID, CertificateUsage: certificateUsage}]
	if !ok {
		return application.CertificateProfile{}, errors.New("enrollment evaluation runtime: certificate profile not found")
	}
	// Cross-check: stored record must match the requested scoped identity.
	if cp.DeviceID != deviceID || cp.CertificateUsage != certificateUsage {
		return application.CertificateProfile{}, errors.New("enrollment evaluation runtime: certificate profile scope mismatch")
	}
	return cp, nil
}

func (a *memoryEvaluationAuthority) GetAssurancePolicy(ctx context.Context, partnerID, certificateUsage string) (application.AssurancePolicy, error) {
	if strings.TrimSpace(partnerID) == "" || strings.TrimSpace(certificateUsage) == "" {
		return application.AssurancePolicy{}, errors.New("enrollment evaluation runtime: assurance policy requires partner and usage")
	}
	a.state.mu.RLock()
	defer a.state.mu.RUnlock()
	ap, ok := a.state.assurancePolicy[assurancePolicyKey{PartnerID: partnerID, CertificateUsage: certificateUsage}]
	if !ok {
		return application.AssurancePolicy{}, errors.New("enrollment evaluation runtime: assurance policy not found")
	}
	// Cross-check: stored record must match the requested scoped identity.
	if ap.PartnerID != partnerID || ap.CertificateUsage != certificateUsage {
		return application.AssurancePolicy{}, errors.New("enrollment evaluation runtime: assurance policy scope mismatch")
	}
	return ap, nil
}

func (a *memoryEvaluationAuthority) GetPolicyVersion(ctx context.Context) (application.PolicyVersion, error) {
	a.state.mu.RLock()
	defer a.state.mu.RUnlock()
	if a.state.policyVersion == nil {
		return application.PolicyVersion{}, errors.New("enrollment evaluation runtime: policy version not set")
	}
	return *a.state.policyVersion, nil
}

// NewEvaluationAuthority creates an in-memory EvaluationAuthority adapter
// from the MemoryStore's authority state.
func (s *MemoryStore) NewEvaluationAuthority() application.EvaluationAuthority {
	return &memoryEvaluationAuthority{state: s.eval.authorityState}
}

// ---------------------------------------------------------------------------
// Persisted decision artifact read-back (observability / verification)
// ---------------------------------------------------------------------------

// GetDecisionSnapshot returns the persisted positive decision snapshot for an
// enrollment, or false when none exists. The returned value is a copy.
func (s *MemoryStore) GetDecisionSnapshot(enrollmentID string) (application.EvaluationDecisionSnapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap, ok := s.eval.decisionSnapshots[enrollmentID]
	return snap.Clone(), ok
}

// GetDenialMetadata returns the persisted negative decision metadata for an
// enrollment, or false when none exists.
func (s *MemoryStore) GetDenialMetadata(enrollmentID string) (application.EvaluationDenialMetadata, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	md, ok := s.eval.denialMetadata[enrollmentID]
	return md, ok
}

// GetAttestationMarker returns the persisted ATTESTATION_VERIFIED milestone
// for an enrollment, or false when none exists.
func (s *MemoryStore) GetAttestationMarker(enrollmentID string) (application.AttestationVerifiedMarker, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.eval.attestationMarkers[enrollmentID]
	return m, ok
}

// ---------------------------------------------------------------------------
// Compile-time contracts
// ---------------------------------------------------------------------------

var _ application.EvaluationUnitOfWorkManager = (*MemoryStore)(nil)
var _ application.EvaluationUnitOfWork = (*evaluationMemoryUOW)(nil)
