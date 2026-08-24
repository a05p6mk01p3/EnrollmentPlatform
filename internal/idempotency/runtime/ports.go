package runtime

import (
	"context"
	"time"
)

// ReservationStatus is the frozen classification of an atomic reservation
// attempt. The zero value is deliberately not a usable outcome.
type ReservationStatus string

const (
	// ReservationNew means this caller owns the unique active reservation and
	// may later enter the application transaction/side-effect path.
	ReservationNew ReservationStatus = "NEW"

	// ReservationReplay means a committed record exists with the same
	// effective scope and the same fingerprint. No new execution ownership is
	// granted.
	ReservationReplay ReservationStatus = "REPLAY"

	// ReservationInProgress means the same fingerprint is already reserved but
	// not committed. This is an INTERNAL coordination state; it must not be
	// invented into a public HTTP status/error by this milestone.
	ReservationInProgress ReservationStatus = "IN_PROGRESS"

	// ReservationConflict means the same effective scope/key exists with a
	// different fingerprint. No execution ownership is granted. A future
	// HTTP/application adapter maps this to 409 IDEMPOTENCY_CONFLICT.
	ReservationConflict ReservationStatus = "CONFLICT"
)

// Valid reports whether s is one of the frozen statuses.
func (s ReservationStatus) Valid() bool {
	switch s {
	case ReservationNew, ReservationReplay, ReservationInProgress, ReservationConflict:
		return true
	default:
		return false
	}
}

// ReservationToken is the opaque, unforgeable internal reservation identity
// granted to a NEW reservation owner. It is not a client credential and is
// not authenticated; it only proves ownership of one active reservation.
//
// The zero value is unusable. A non-zero token is created by a server-side
// Store (NewReservationToken) or restored from a trusted adapter's persisted
// value (ReservationTokenFromString).
type ReservationToken struct {
	value string
}

// IsZero reports whether the token is the unusable zero value.
func (t ReservationToken) IsZero() bool { return t.value == "" }

// Equal reports exact token equality.
func (t ReservationToken) Equal(other ReservationToken) bool { return t.value == other.value }

// Value returns the exact opaque token value, suitable for trusted adapter
// persistence. It is empty for the zero value. The value is not a credential
// and is not an HTTP/wire format; authority comes from the Store's ownership
// mapping, never from the token's bytes.
func (t ReservationToken) Value() string { return t.value }

// ReserveRequest carries the inputs for an atomic reservation attempt.
type ReserveRequest struct {
	Scope       EffectiveScope
	Fingerprint Fingerprint
	Now         time.Time
	ExpiresAt   time.Time
}

// Reservation is the immutable outcome of a Reserve attempt. Exactly one field
// set is populated per status: Token for NEW, Result for REPLAY. Fingerprint
// carries the authoritative existing fingerprint for diagnostics and for
// REPLAY/CONFLICT classification evidence.
//
// Scope is the authoritative binding to the exact EffectiveScope this result
// belongs to. The Service verifies it against the requested scope before
// exposing any execution or replay authority.
type Reservation struct {
	Scope       EffectiveScope
	Status      ReservationStatus
	Token       ReservationToken
	Result      ResultLocator
	Fingerprint Fingerprint
	ExpiresAt   time.Time
}

// CommitRequest carries the inputs for the reservation-owner-only commit.
type CommitRequest struct {
	Token  ReservationToken
	Scope  EffectiveScope
	Result ResultLocator
	// Capsule is the optional protected Replay Capsule envelope for
	// secret-replay operations. It is copied on commit; the store never
	// retains the caller's slice.
	Capsule *ProtectedEnvelope
}

// RecordStatus is the lifecycle state of an idempotency record.
type RecordStatus string

const (
	// RecordActive means the reservation is reserved but not yet committed.
	RecordActive RecordStatus = "ACTIVE"

	// RecordCommitted means the reservation has been committed to a durable
	// logical result.
	RecordCommitted RecordStatus = "COMMITTED"
)

// Valid reports whether s is one of the frozen record statuses.
func (s RecordStatus) Valid() bool {
	return s == RecordActive || s == RecordCommitted
}

// Record is the immutable public snapshot of an idempotency record. It models
// retention/expiry metadata without freezing final retention values.
//
// Scope is the authoritative binding to the exact EffectiveScope this record
// belongs to. The Service verifies it against the requested scope before
// exposing any execution or replay authority.
type Record struct {
	Scope            EffectiveScope
	Fingerprint      Fingerprint
	Status           RecordStatus
	Result           ResultLocator
	Capsule          *ProtectedEnvelope
	CreatedAt        time.Time
	ExpiresAt        time.Time
	CapsuleExpiresAt time.Time
}

// Clock is the server-controlled time source used for expiry decisions. The
// time used for a security decision is never taken from client authority.
type Clock interface {
	Now() time.Time
}

// RecoverSecretRequest carries the inputs for protected secret recovery. The
// associated data is opaque caller-provided bytes.
//
// M5.4 deliberately does NOT freeze the final operation-specific Associated
// Data schema. Protocol §6.4 has an unresolved controlled-source tension: the
// Replay Capsule applies to REQUEST_ACCESS_TOKEN created by pre-onboarding,
// while its Associated Data language includes enrollment_id even though no
// enrollment exists at pre-onboarding creation time. This milestone does not
// resolve or reinterpret that tension; operation-specific AAD construction is
// deferred to a later milestone with an explicit decision.
//
// It deliberately carries NO time field: recovery expiry is decided with the
// Service's server-controlled clock, never with client-supplied time.
type RecoverSecretRequest struct {
	Scope          EffectiveScope
	Fingerprint    Fingerprint
	AssociatedData []byte
}

// Store is the provider-neutral atomic reservation/coordination port. Future
// PostgreSQL adapters implement this interface without changing the kernel's
// domain semantics. Implementations must be concurrency-safe and must never
// store originator secret plaintext.
//
// Output contract: returned Reservations/Records must be internally
// consistent for their declared status (see ReservationStatus and
// RecordStatus). The Service re-validates every Store output and fails closed
// on impossible or contradictory combinations, so a malformed adapter can
// never hand the caller execution or replay authority.
type Store interface {
	// Reserve atomically classifies an effective scope+fingerprint attempt.
	// A dependency failure is returned as an error and must never be
	// interpreted as a successful classification.
	Reserve(ctx context.Context, req ReserveRequest) (Reservation, error)

	// Commit marks the caller-owned active reservation committed. It fails
	// closed for zero/unknown/mismatched/stale/non-owner reservations.
	Commit(ctx context.Context, req CommitRequest) (Record, error)

	// Lookup returns the current record for an effective scope, or ok=false
	// when no record exists. A dependency failure is returned as an error.
	Lookup(ctx context.Context, scope EffectiveScope) (Record, bool, error)
}

// Protector is the narrow Replay Capsule protection boundary. It seals and
// opens secrets against opaque caller-provided associated data. A protector
// must never log plaintext and must fail closed rather than silently
// disabling protection.
type Protector interface {
	Seal(ctx context.Context, plaintext []byte, associatedData []byte) (*ProtectedEnvelope, error)
	Open(ctx context.Context, envelope *ProtectedEnvelope, associatedData []byte) ([]byte, error)
}
