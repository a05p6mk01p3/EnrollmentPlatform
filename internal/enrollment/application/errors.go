package application

import "errors"

var (
	// ErrDependencyUnavailable is the fail-safe classification for unavailable,
	// indeterminate, malformed, or otherwise unusable internal dependencies.
	ErrDependencyUnavailable = errors.New("enrollment application: dependency unavailable")

	// ErrAuthenticationRequired means the RequestAccess capability does not
	// possess NEW mutation authority (including already-consumed capabilities
	// presented under a different idempotency operation).
	ErrAuthenticationRequired = errors.New("enrollment application: request access authentication required")

	// ErrNotAuthorized means current request/device/partner/profile policy does
	// not authorize the INITIAL exchange.
	ErrNotAuthorized = errors.New("enrollment application: initial enrollment not authorized")

	// ErrResourceExpired means an authoritative pre-onboarding request or active
	// RequestAccess capability expired before a NEW exchange committed.
	ErrResourceExpired = errors.New("enrollment application: resource expired")

	// ErrIdempotencyConflict maps to the contracted 409 IDEMPOTENCY_CONFLICT.
	ErrIdempotencyConflict = errors.New("enrollment application: idempotency conflict")

	// ErrIdempotencyReplayUnavailable maps to the contracted permanent 409
	// IDEMPOTENCY_REPLAY_UNAVAILABLE recovery posture.
	ErrIdempotencyReplayUnavailable = errors.New("enrollment application: idempotency replay unavailable")

	// ErrStateConflict is returned when the authoritative enrollment/challenge
	// changed before this operation reached its commit boundary.
	ErrStateConflict = errors.New("enrollment application: enrollment state conflict")

	// ErrEvidenceConflict is returned when an already accepted evidence resource
	// is submitted again with a different trusted request fingerprint.
	ErrEvidenceConflict = errors.New("enrollment application: evidence conflict")

	// ErrEvidenceInvalid maps to the contracted 422 EVIDENCE_INVALID.
	ErrEvidenceInvalid = errors.New("enrollment application: evidence invalid")

	// ErrEnrollmentNotFound preserves the controlled 404 outcome for the later
	// HTTP adapter; repository/dependency failures use ErrDependencyUnavailable.
	ErrEnrollmentNotFound = errors.New("enrollment application: enrollment not found")
)

// InProgressError is an internal coordination outcome. It is intentionally not
// a public machine code; HTTP adapters map it fail-closed to the existing
// dependency-unavailable posture.
type InProgressError struct{ Message string }

func (e *InProgressError) Error() string {
	if e == nil || e.Message == "" {
		return "enrollment application: idempotent operation in progress"
	}
	return "enrollment application: " + e.Message
}
