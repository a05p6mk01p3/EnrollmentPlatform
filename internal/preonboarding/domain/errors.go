package domain

import (
	"errors"
	"fmt"
)

// Sentinel errors representing pure domain boundary outcomes.
var (
	// ErrExpired indicates an operation was attempted on a request that has
	// expired.
	ErrExpired = errors.New("domain: pre-onboarding request is expired")

	// ErrPreconditionFailed indicates an If-Match precondition check failed
	// against the current strong ETag.
	ErrPreconditionFailed = errors.New("domain: precondition failed (stale or mismatched If-Match)")

	// ErrNotFound indicates the pre-onboarding request aggregate does not exist.
	ErrNotFound = errors.New("domain: pre-onboarding request not found")
)

// InvalidStateError records an unmapped or unrecognized domain state.
type InvalidStateError struct {
	State State
}

func (e *InvalidStateError) Error() string {
	return fmt.Sprintf("domain: invalid or unrecognized state %q", e.State)
}

// StateConflictError records an illegal state transition attempt under current
// domain state.
type StateConflictError struct {
	CurrentState State
	Action       string
	Message      string
}

func (e *StateConflictError) Error() string {
	return fmt.Sprintf("domain: cannot %s in state %q: %s", e.Action, e.CurrentState, e.Message)
}
