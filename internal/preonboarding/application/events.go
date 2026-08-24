package application

import (
	"time"
)

// AuditEventType specifies the type of an authoritative lifecycle audit event.
type AuditEventType string

const (
	// AuditEventApproved is emitted when an admin approves a pre-onboarding request.
	AuditEventApproved AuditEventType = "PREONBOARD_APPROVED"

	// AuditEventRejected is emitted when an admin rejects a pre-onboarding request.
	AuditEventRejected AuditEventType = "PREONBOARD_REJECTED"

	// AuditEventSubmitted is the protocol event for request submission. It is
	// modeled for completeness, but is NOT emitted by M5.5 because production
	// create fails closed before reaching durable success.
	AuditEventSubmitted AuditEventType = "PREONBOARD_SUBMITTED"
)

// AuditEvent represents a structured, authoritative domain event to be staged
// and committed atomically with state mutations.
type AuditEvent struct {
	Type                   AuditEventType `json:"type"`
	ActorPrincipal         string         `json:"actor_principal"`
	PreOnboardingRequestID string         `json:"pre_onboarding_request_id"`
	PartnerID              string         `json:"partner_id"`
	DeviceID               string         `json:"device_id,omitempty"`
	Reason                 string         `json:"reason,omitempty"`
	Timestamp              time.Time      `json:"timestamp"`
	CorrelationID          string         `json:"correlation_id,omitempty"`
}
