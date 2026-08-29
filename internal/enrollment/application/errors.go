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
