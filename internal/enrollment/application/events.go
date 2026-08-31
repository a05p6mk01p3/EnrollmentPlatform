package application

import "time"

const (
	AuditEventEnrollmentCreated  = "ENROLLMENT_CREATED"
	AuditEventEvidenceAccepted   = "EVIDENCE_ACCEPTED"
	AuditEventChallengeRefreshed = "CHALLENGE_REFRESHED"

	// M5.9 Phase-2 evaluation events (Protocol v0.2.7).
	AuditEventIssuanceAuthorized  = "ISSUANCE_AUTHORIZED"
	AuditEventIssuanceDenied      = "ISSUANCE_DENIED"
	AuditEventAttestationVerified = "ATTESTATION_VERIFIED"
)

// AuditEvent contains the minimum protocol fields for the M5.7
// ENROLLMENT_CREATED event. It deliberately carries no token plaintext.
type AuditEvent struct {
	Type             string
	EnrollmentID     string
	DeviceID         string
	Operation        string
	CertificateUsage string
	IdempotencyRef   string
	CorrelationID    string
	Timestamp        time.Time
}
