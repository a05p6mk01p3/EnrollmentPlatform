package runtime

import (
	"errors"
	"fmt"
)

// Sentinel errors for structural/dependency failures. They are distinct from
// the successful NEW/REPLAY/IN_PROGRESS/CONFLICT classifications: a dependency
// failure is an error, never a successful authoritative classification.
var (
	// ErrNilStore is returned when a mandatory Store dependency is nil or
	// typed-nil.
	ErrNilStore = errors.New("idempotency runtime: store must not be nil or typed-nil")

	// ErrNilProtector is returned when a mandatory Protector dependency is nil
	// or typed-nil.
	ErrNilProtector = errors.New("idempotency runtime: protector must not be nil or typed-nil")

	// ErrUnusableStore is returned when a Store implementation is a zero value
	// with unusable internal state.
	ErrUnusableStore = errors.New("idempotency runtime: store is unusable (zero value or missing internal state)")

	// ErrUnusableService is returned when the Service itself has unusable
	// dependency state.
	ErrUnusableService = errors.New("idempotency runtime: service is unusable (missing dependency)")

	// ErrUnusableProtector is returned when a supplied Protector reports
	// structurally unusable state.
	ErrUnusableProtector = errors.New("idempotency runtime: protector is unusable (zero value or missing internal state)")

	// ErrNilClock is returned when a Service has no usable server-side clock.
	ErrNilClock = errors.New("idempotency runtime: clock must not be nil or typed-nil")

	// ErrMalformedStoreOutput is returned when a Store adapter returns a
	// Reservation/Record whose fields are impossible or contradictory for its
	// declared status. Such output must never surface as execution or replay
	// authority.
	ErrMalformedStoreOutput = errors.New("idempotency runtime: store returned malformed output")

	// ErrRecordExpired is returned when secret recovery targets a record whose
	// idempotency/replay expiry has passed. The capsule is never opened.
	ErrRecordExpired = errors.New("idempotency runtime: idempotency record expired")

	// ErrCapsuleExpired is returned when secret recovery targets an explicitly
	// expired replay capsule. The capsule is never opened.
	ErrCapsuleExpired = errors.New("idempotency runtime: replay capsule expired")

	// ErrCapsuleOutlivesRecord is returned when a protected capsule's expiry
	// would structurally outlive the enclosing record/replay lifetime.
	ErrCapsuleOutlivesRecord = errors.New("idempotency runtime: capsule expiry outlives record expiry")

	// ErrZeroReservationToken is returned when a commit is attempted with a
	// zero reservation token.
	ErrZeroReservationToken = errors.New("idempotency runtime: reservation token must not be zero")

	// ErrReservationNotFound is returned when a commit token is unknown.
	ErrReservationNotFound = errors.New("idempotency runtime: reservation not found")

	// ErrReservationScopeMismatch is returned when a commit token does not
	// belong to the supplied effective scope.
	ErrReservationScopeMismatch = errors.New("idempotency runtime: reservation token does not match effective scope")

	// ErrReservationNotActive is returned when a commit targets a reservation
	// that is not active (already committed, stale, or otherwise consumed).
	ErrReservationNotActive = errors.New("idempotency runtime: reservation is not active")

	// ErrRecoveryUnavailable is returned when protected secret recovery is
	// attempted without the exact same effective scope + same fingerprint +
	// committed REPLAY state.
	ErrRecoveryUnavailable = errors.New("idempotency runtime: secret recovery unavailable for this scope/fingerprint/state")

	// ErrNoCapsule is returned when a committed record carries no protected
	// capsule envelope.
	ErrNoCapsule = errors.New("idempotency runtime: no protected capsule envelope present")

	// ErrEnvelopeOpenFailed wraps a protector Open failure. It is a
	// distinguishable recovery failure, never a remint path.
	ErrEnvelopeOpenFailed = errors.New("idempotency runtime: protected envelope open failed")
)

// RecoveryError distinguishes the possible recovery outcomes with a typed
// reason while preserving any underlying cause.
type RecoveryError struct {
	Reason RecoveryReason
	Cause  error
}

// RecoveryReason is the typed classification of a recovery failure.
type RecoveryReason string

const (
	// RecoveryReasonUnavailable means the exact replay gate was not satisfied.
	RecoveryReasonUnavailable RecoveryReason = "UNAVAILABLE"

	// RecoveryReasonNoCapsule means a committed record has no capsule.
	RecoveryReasonNoCapsule RecoveryReason = "NO_CAPSULE"

	// RecoveryReasonOpenFailed means the protector failed to open the capsule.
	RecoveryReasonOpenFailed RecoveryReason = "OPEN_FAILED"

	// RecoveryReasonRecordExpired means the idempotency record/replay window
	// has expired; the capsule was never opened.
	RecoveryReasonRecordExpired RecoveryReason = "RECORD_EXPIRED"

	// RecoveryReasonCapsuleExpired means the capsule's own expiry metadata has
	// passed; the capsule was never opened.
	RecoveryReasonCapsuleExpired RecoveryReason = "CAPSULE_EXPIRED"
)

func (e *RecoveryError) Error() string {
	msg := "idempotency runtime: secret recovery failed: " + string(e.Reason)
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e *RecoveryError) Unwrap() error { return e.Cause }

// Is reports whether e matches target (via sentinel convenience).
func (e *RecoveryError) Is(target error) bool {
	switch e.Reason {
	case RecoveryReasonUnavailable:
		return target == ErrRecoveryUnavailable
	case RecoveryReasonNoCapsule:
		return target == ErrNoCapsule
	case RecoveryReasonOpenFailed:
		return target == ErrEnvelopeOpenFailed
	case RecoveryReasonRecordExpired:
		return target == ErrRecordExpired
	case RecoveryReasonCapsuleExpired:
		return target == ErrCapsuleExpired
	default:
		return false
	}
}

func newRecoveryError(reason RecoveryReason, cause error) error {
	return &RecoveryError{Reason: reason, Cause: cause}
}

// wrapOpenError wraps a protector Open failure as a distinguishable recovery
// error that preserves the cause for errors.Is/errors.As chains.
func wrapOpenError(cause error) error {
	return &RecoveryError{Reason: RecoveryReasonOpenFailed, Cause: fmt.Errorf("%w: %v", ErrEnvelopeOpenFailed, cause)}
}
