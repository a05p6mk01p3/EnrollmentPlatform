package application

import "time"

const AuditEventEnrollmentCreated = "ENROLLMENT_CREATED"

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
