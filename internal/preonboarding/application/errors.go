package application

import (
	"errors"
	"fmt"
)

var (
	// ErrDependencyUnavailable indicates an indispensable dependency or capability is unavailable.
	ErrDependencyUnavailable = errors.New("application: dependency unavailable")

	// ErrIdempotencyConflict indicates a duplicate request with the same Idempotency-Key
	// but mismatched semantic fingerprint.
	ErrIdempotencyConflict          = errors.New("application: idempotency conflict (same key with different fingerprint)")
	ErrIdempotencyReplayUnavailable = errors.New("application: idempotency replay unavailable")

	// ErrPartnerNotAuthorized indicates the administrative principal lacks current server-side
	// authority for the partner.
	ErrPartnerNotAuthorized = errors.New("application: partner not authorized for principal")

	// ErrPartnerIneligible indicates the partner is not currently eligible for approval.
	ErrPartnerIneligible = errors.New("application: partner is not currently eligible for device pre-onboarding approval")

	// ErrNotFound indicates the resource was not found or was concealed due to lack of partner authority.
	ErrNotFound = errors.New("application: resource not found")

	// ErrResourceExpired indicates a public read attempt on an effectively expired resource.
	ErrResourceExpired = errors.New("application: resource is expired")

	// ErrPreconditionFailed indicates the supplied If-Match header does not match current strong ETag.
	ErrPreconditionFailed = errors.New("application: precondition failed (stale If-Match)")

	// ErrStateConflict indicates an invalid lifecycle state transition.
	ErrStateConflict = errors.New("application: state conflict (invalid lifecycle state for operation)")
)

// InProgressError indicates an in-progress reservation exists.
type InProgressError struct {
	Message string
}

func (e *InProgressError) Error() string {
	return fmt.Sprintf("application: operation in progress: %s", e.Message)
}
