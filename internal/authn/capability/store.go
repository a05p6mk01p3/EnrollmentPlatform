package capability

import (
	"context"
	"errors"
	"time"
)

// State is the closed lifecycle state of a RequestAccessToken record.
// The zero value is StateUnknown and is explicitly INVALID: authentication
// accepts only explicit StateActive, never an omitted/uninitialized state.
type State uint8

const (
	// StateUnknown is the zero value. It must never authenticate; it marks an
	// omitted or corrupted record.
	StateUnknown State = iota
	// StateActive means the credential is valid for ordinary active
	// authentication (subject to expiry).
	StateActive
	// StateConsumed means the credential was consumed in an atomic exchange.
	// It must never satisfy ordinary active authentication again. The verifier
	// is retained (not deleted) so future idempotent response-loss recovery
	// can recognize it without reactivating it.
	StateConsumed
)

// RequestAccessRecord is the persisted, non-reversible state resolved for a
// RequestAccessToken verifier. It carries no plaintext token, no scopes, no
// partner authority and no authorization result.
type RequestAccessRecord struct {
	PreOnboardingRequestID string
	ExpiresAt              time.Time
	State                  State
}

// EnrollmentAccessRecord is the persisted, non-reversible state resolved for
// an EnrollmentAccessToken verifier. It carries no plaintext token.
type EnrollmentAccessRecord struct {
	EnrollmentID string
	ExpiresAt    time.Time
}

// ErrNotFound reports that no record matches a verifier. It is distinct from
// infrastructure failures, which the store reports as other errors.
var ErrNotFound = errors.New("capability verifier not found")

// ErrDuplicate reports an attempt to seed a verifier that already exists.
// Seeding is creation-only/insert-only: it never overwrites or reactivates an
// existing record (SOL-M4.3-003).
var ErrDuplicate = errors.New("capability verifier already exists")

// Store is the persistence-neutral read port for capability verifiers. It is
// partitioned by CredentialKind through separate lookup methods and through
// the kind-namespaced VerifierKey. Lookups are read-only: authentication never
// mutates lifecycle state.
type Store interface {
	LookupRequestAccess(ctx context.Context, key VerifierKey) (*RequestAccessRecord, error)
	LookupEnrollmentAccess(ctx context.Context, key VerifierKey) (*EnrollmentAccessRecord, error)
}
