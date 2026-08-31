// Package enrollment contains the enrollment aggregate and its state machine.
//
// The package is pure domain code: no HTTP, no persistence, no generated
// OpenAPI types, no external adapters. Concurrency control, persistence of the
// authorization decision snapshot and CA side effects belong to the future
// application/store boundary, not to this aggregate.
//
// Normative source: Enrollment Protocol Specification v0.2.2.
package enrollment

// EnrollmentID is the opaque, server-issued enrollment identifier
// (Protocol v0.2.2 §9.1). Identifier generation is a server concern; the
// domain treats the value as opaque.
type EnrollmentID string

// Enrollment is the enrollment aggregate. Its state is private: the only way
// to move it is through the transition methods below. There is deliberately no
// SetState or other generic state assignment.
type Enrollment struct {
	id    EnrollmentID
	state State
}

// NewEnrollment creates an enrollment in CHALLENGE_ISSUED, the first
// observable state (Protocol v0.2.2 §9.2: CREATED is not an observable state
// and is not modeled here).
func NewEnrollment(id EnrollmentID) *Enrollment {
	return &Enrollment{id: id, state: StateChallengeIssued}
}

// RestoreEnrollment rebuilds an aggregate from a previously persisted state
// for recovery purposes (Protocol v0.2.2 §9.2 durable AUTHORIZED state; §13
// crash recovery). Unknown state values fail closed with *InvalidStateError.
func RestoreEnrollment(id EnrollmentID, state State) (*Enrollment, error) {
	if !state.Valid() {
		return nil, &InvalidStateError{State: state}
	}
	return &Enrollment{id: id, state: state}, nil
}

// ID returns the enrollment identifier.
func (e *Enrollment) ID() EnrollmentID { return e.id }

// State returns the current state. It is a read-only accessor; there is no
// public way to assign a state.
func (e *Enrollment) State() State { return e.state }

// AcceptEvidence records that valid evidence was accepted for the active
// challenge: CHALLENGE_ISSUED -> EVIDENCE_RECEIVED (Protocol v0.2.2 §10.2, §22).
func (e *Enrollment) AcceptEvidence() error {
	return e.apply(StateEvidenceReceived)
}

// Authorize records the successful evaluation of evidence and policy:
// EVIDENCE_RECEIVED -> AUTHORIZED (Protocol v0.2.2 §22). The caller is
// responsible for having applied the §10.3 validation rules (CSR, JWS PoP,
// TPM evidence, policy) before invoking this transition.
func (e *Enrollment) Authorize() error {
	return e.apply(StateAuthorized)
}

// Reject records a definitive negative Phase-2 evaluation:
// EVIDENCE_RECEIVED -> REJECTED (Protocol v0.2.7 §22).
// REJECTED is terminal: Authorize() cannot succeed afterward, challenge
// refresh cannot reopen it, and no CA progression is possible. This
// transition is guarded; only EVIDENCE_RECEIVED is a valid origin.
func (e *Enrollment) Reject() error {
	return e.apply(StateRejected)
}

// MarkCARequested records the authorization commit point:
// AUTHORIZED -> CA_REQUESTED (Protocol v0.2.2 §11.1, §22).
//
// IMPORTANT: this domain transition models the state change only. The caller
// (future application service) MUST persist the authorization decision
// snapshot atomically BEFORE any CA side effect occurs. This package does not
// persist anything and does not invoke the CA.
func (e *Enrollment) MarkCARequested() error {
	return e.apply(StateCARequested)
}

// MarkCertificateIssued records that the CA returned a certificate and its
// issuance history was persisted: CA_REQUESTED -> CERT_ISSUED (Protocol v0.2.2
// §22; §13: the certificate is recovered from persisted history and is never
// re-issued).
func (e *Enrollment) MarkCertificateIssued() error {
	return e.apply(StateCertIssued)
}

// MarkDelivered records that the post-CA eligibility revalidation succeeded
// and the certificate was made deliverable: CERT_ISSUED -> CERT_DELIVERED
// (Protocol v0.2.2 §11.3, §22). CERT_ISSUED never implies delivery by itself;
// delivery requires this explicit transition.
func (e *Enrollment) MarkDelivered() error {
	return e.apply(StateCertDelivered)
}

// MarkWithheldRevoked records that post-CA eligibility revalidation failed:
// the issued certificate is never deliverable and enters revocation:
// CERT_ISSUED -> CERT_WITHHELD_REVOKED (Protocol v0.2.2 §11.3, §21.2, §22).
// The issued certificate remains in history; no second issuance is created.
func (e *Enrollment) MarkWithheldRevoked() error {
	return e.apply(StateCertWithheldRevoked)
}

// MarkActivated records that a new DeviceMTLS connection using exactly the
// certificate issued by this enrollment was validated and correlated to the
// enrollment/device: CERT_DELIVERED -> DEVICE_ACTIVATED (Protocol v0.2.2
// §12.1, §9.2; SP-17/SP-18: the proof comes from the trusted reverse-proxy
// mTLS hop, never from local store/provider assertions).
func (e *Enrollment) MarkActivated() error {
	return e.apply(StateDeviceActivated)
}

// MarkCompleted records the successful installation report:
// DEVICE_ACTIVATED -> COMPLETED (Protocol v0.2.2 §12.2, §9.2).
func (e *Enrollment) MarkCompleted() error {
	return e.apply(StateCompleted)
}

// apply executes a transition when the state machine allows it. An unknown
// current state fails closed with *InvalidStateError; any other disallowed
// move fails with *TransitionError.
func (e *Enrollment) apply(to State) error {
	if !e.state.Valid() {
		return &InvalidStateError{State: e.state}
	}
	if !canTransition(e.state, to) {
		return &TransitionError{From: e.state, To: to}
	}
	e.state = to
	return nil
}
