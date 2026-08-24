// Package domain contains the pre-onboarding request aggregate, types, and
// state machine.
//
// The package is pure domain code: no HTTP, no persistence, no generated
// OpenAPI types, no external adapters. Concurrency control, persistence, and
// authorization evaluation belong to application and runtime layers.
//
// Normative source: Enrollment Protocol Specification v0.2.3.
package domain

import (
	"errors"
	"strings"
	"time"
)

// ID is the opaque, server-issued pre-onboarding request identifier
// (Protocol v0.2.3 §8.1).
type ID string

// PartnerID is the opaque server-issued partner identifier.
type PartnerID string

// State represents the lifecycle status of a pre-onboarding request.
type State string

const (
	// StatePendingApproval indicates the claimed device proposal was created and
	// is awaiting administrative decision.
	StatePendingApproval State = "PENDING_APPROVAL"

	// StateEnrollmentReady indicates administrative approval was granted and the
	// request is ready for subsequent enrollment.
	StateEnrollmentReady State = "ENROLLMENT_READY"

	// StateRejected indicates the proposal was administratively rejected.
	// REJECTED is a terminal state.
	StateRejected State = "REJECTED"

	// StateExpired indicates the request passed its time-to-live. Expiry is
	// logically derived from expires_at and current clock, or stored.
	StateExpired State = "EXPIRED"

	// StateInvalidated indicates administrative invalidation.
	StateInvalidated State = "INVALIDATED"
)

// Valid reports whether s is one of the recognized lifecycle states.
func (s State) Valid() bool {
	switch s {
	case StatePendingApproval, StateEnrollmentReady, StateRejected, StateExpired, StateInvalidated:
		return true
	default:
		return false
	}
}

// ClaimedDevice holds claimed/non-attested device attributes supplied before
// technical verification.
type ClaimedDevice struct {
	Hostname             string
	SerialNumber         string
	SMBIOSUUID           string
	Manufacturer         string
	Model                string
	TPMPresent           bool
	TPMVendor            string
	EKPublicHash         string
	HardwareBacked       *bool
	PrivateKeyExportable *bool
	Provider             *string
	TPMReady             *bool
}

// Agent describes the client agent platform and version.
type Agent struct {
	Platform string
	Version  string
}

// PreOnboardingRequest is the root aggregate for a pre-onboarding transaction.
// Its internal state is protected: state transitions only occur through domain
// methods that enforce protocol invariants.
type PreOnboardingRequest struct {
	id              ID
	partnerID       PartnerID
	claimedDevice   ClaimedDevice
	agent           Agent
	status          State
	deviceID        *string
	createdAt       time.Time
	expiresAt       time.Time
	resourceVersion int
}

// NewRequest creates a new pre-onboarding request aggregate in PENDING_APPROVAL
// state with initial resource_version = 1.
func NewRequest(id ID, partnerID PartnerID, claimed ClaimedDevice, agent Agent, createdAt, expiresAt time.Time) (*PreOnboardingRequest, error) {
	if strings.TrimSpace(string(id)) == "" {
		return nil, errors.New("domain: request id must not be empty")
	}
	if strings.TrimSpace(string(partnerID)) == "" {
		return nil, errors.New("domain: partner id must not be empty")
	}
	if !expiresAt.After(createdAt) {
		return nil, errors.New("domain: expires_at must be strictly after created_at")
	}
	return &PreOnboardingRequest{
		id:              id,
		partnerID:       partnerID,
		claimedDevice:   claimed,
		agent:           agent,
		status:          StatePendingApproval,
		deviceID:        nil,
		createdAt:       createdAt,
		expiresAt:       expiresAt,
		resourceVersion: 1,
	}, nil
}

// RestoreRequest rebuilds an aggregate from persisted storage for recovery or
// application loading. Unknown states or invalid versions fail closed.
func RestoreRequest(id ID, partnerID PartnerID, claimed ClaimedDevice, agent Agent, status State, deviceID *string, createdAt, expiresAt time.Time, resourceVersion int) (*PreOnboardingRequest, error) {
	if strings.TrimSpace(string(id)) == "" {
		return nil, errors.New("domain: request id must not be empty")
	}
	if strings.TrimSpace(string(partnerID)) == "" {
		return nil, errors.New("domain: partner id must not be empty")
	}
	if !status.Valid() {
		return nil, &InvalidStateError{State: status}
	}
	if resourceVersion < 1 {
		return nil, errors.New("domain: resource_version must be >= 1")
	}
	var devID *string
	if deviceID != nil && *deviceID != "" {
		d := *deviceID
		devID = &d
	}
	return &PreOnboardingRequest{
		id:              id,
		partnerID:       partnerID,
		claimedDevice:   claimed,
		agent:           agent,
		status:          status,
		deviceID:        devID,
		createdAt:       createdAt,
		expiresAt:       expiresAt,
		resourceVersion: resourceVersion,
	}, nil
}

// ID returns the request identifier.
func (r *PreOnboardingRequest) ID() ID { return r.id }

// PartnerID returns the authoritative partner identifier.
func (r *PreOnboardingRequest) PartnerID() PartnerID { return r.partnerID }

// ClaimedDevice returns a copy of claimed device attributes.
func (r *PreOnboardingRequest) ClaimedDevice() ClaimedDevice { return r.claimedDevice }

// Agent returns client agent details.
func (r *PreOnboardingRequest) Agent() Agent { return r.agent }

// Status returns the stored lifecycle state.
func (r *PreOnboardingRequest) Status() State { return r.status }

// DeviceID returns the authoritative logical device ID, if assigned.
func (r *PreOnboardingRequest) DeviceID() *string {
	if r.deviceID == nil {
		return nil
	}
	d := *r.deviceID
	return &d
}

// CreatedAt returns the creation timestamp.
func (r *PreOnboardingRequest) CreatedAt() time.Time { return r.createdAt }

// ExpiresAt returns the expiration timestamp.
func (r *PreOnboardingRequest) ExpiresAt() time.Time { return r.expiresAt }

// ResourceVersion returns the current informational monotonic resource version.
func (r *PreOnboardingRequest) ResourceVersion() int { return r.resourceVersion }

// EffectiveStatus derives the effective lifecycle state at the given time.
// If now >= expiresAt and stored status is PENDING_APPROVAL or ENROLLMENT_READY,
// the effective state is EXPIRED. Stored terminal states (REJECTED, INVALIDATED,
// EXPIRED) are immutable over time.
func (r *PreOnboardingRequest) EffectiveStatus(now time.Time) State {
	if now.After(r.expiresAt) || now.Equal(r.expiresAt) {
		if r.status == StatePendingApproval || r.status == StateEnrollmentReady {
			return StateExpired
		}
	}
	return r.status
}

// IsTerminal reports whether the request is in a terminal state (REJECTED).
func (r *PreOnboardingRequest) IsTerminal() bool {
	return r.status == StateRejected
}

// Approve transitions PENDING_APPROVAL -> ENROLLMENT_READY at time `now`.
// If authoritative logical device_id is absent, it is assigned the provided
// allocatedDeviceID. If an authoritative logical device_id legitimately already
// exists, it is preserved. On successful transition, resource_version increments.
//
// Fails closed if effective status is EXPIRED, stored status is not
// PENDING_APPROVAL, or allocatedDeviceID is empty when no device_id exists.
func (r *PreOnboardingRequest) Approve(now time.Time, allocatedDeviceID string) error {
	eff := r.EffectiveStatus(now)
	if eff == StateExpired {
		return ErrExpired
	}
	if r.status != StatePendingApproval {
		return &StateConflictError{
			CurrentState: r.status,
			Action:       "approve",
			Message:      "cannot approve request not in PENDING_APPROVAL",
		}
	}
	if r.deviceID == nil || *r.deviceID == "" {
		trimmed := strings.TrimSpace(allocatedDeviceID)
		if trimmed == "" {
			return errors.New("domain: allocated device_id must not be empty on approval")
		}
		r.deviceID = &trimmed
	}
	r.status = StateEnrollmentReady
	r.resourceVersion++
	return nil
}

// Reject transitions PENDING_APPROVAL -> REJECTED at time `now`.
// Rejection NEVER allocates or sets a device_id. REJECTED is terminal.
// On successful transition, resource_version increments.
//
// Fails closed if effective status is EXPIRED, or stored status is not
// PENDING_APPROVAL.
func (r *PreOnboardingRequest) Reject(now time.Time, reason string) error {
	eff := r.EffectiveStatus(now)
	if eff == StateExpired {
		return ErrExpired
	}
	if r.status != StatePendingApproval {
		return &StateConflictError{
			CurrentState: r.status,
			Action:       "reject",
			Message:      "cannot reject request not in PENDING_APPROVAL",
		}
	}
	r.status = StateRejected
	r.resourceVersion++
	return nil
}
