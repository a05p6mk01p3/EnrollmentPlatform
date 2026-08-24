package runtime

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"
)

// Service is the M5.4 idempotency/replay-safety coordination boundary. It
// composes a provider-neutral Store with a provider-neutral Protector and
// exposes Reserve/Commit/RecoverSecret.
//
// The zero value is unusable: every method fails closed until a Service is
// constructed with valid dependencies via NewService.
type Service struct {
	store     Store
	protector Protector
	clock     Clock
}

// ServiceOption customizes Service construction.
type ServiceOption func(*Service)

// WithClock replaces the default system clock with a deterministic,
// server-controlled time source. A nil clock is rejected at construction.
func WithClock(c Clock) ServiceOption {
	return func(s *Service) { s.clock = c }
}

// systemClock is the default production clock.
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// isNilLike reports whether v is nil or holds a typed-nil value of a nilable
// kind. It is used to reject typed-nil interfaces that would otherwise
// satisfy a non-nil interface check.
func isNilLike(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

// selfValidator is an optional structural-integrity capability a dependency
// may expose. When present, the Service calls it and rejects a dependency
// that reports itself unusable.
type selfValidator interface {
	Validate() error
}

// structuralDependencyError re-checks a mandatory dependency's own structural
// integrity (when the dependency exposes Validate) and wraps any failure in
// the given unusable sentinel. Dependencies that expose no Validate method
// are accepted (provider neutrality).
func structuralDependencyError(dep any, unusable error) error {
	if isNilLike(dep) {
		return unusable
	}
	v, ok := dep.(selfValidator)
	if !ok {
		return nil
	}
	if err := v.Validate(); err != nil {
		return fmt.Errorf("%w: %v", unusable, err)
	}
	return nil
}

// NewService constructs a Service and rejects nil/typed-nil/unusable
// mandatory dependencies. There is no implicit permissive fallback.
func NewService(store Store, protector Protector, opts ...ServiceOption) (*Service, error) {
	s := &Service{store: store, protector: protector, clock: systemClock{}}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Validate reports whether the Service has usable dependency state. It is the
// explicit structural-integrity check a future composition root can call to
// reject an unusable instance, and it re-checks each dependency's own
// structural validation where the dependency exposes one.
func (s *Service) Validate() error { return s.validate() }

func (s *Service) validate() error {
	if s == nil {
		return ErrUnusableService
	}
	if isNilLike(s.store) {
		return ErrNilStore
	}
	if err := structuralDependencyError(s.store, ErrUnusableStore); err != nil {
		return err
	}
	if isNilLike(s.protector) {
		return ErrNilProtector
	}
	if err := structuralDependencyError(s.protector, ErrUnusableProtector); err != nil {
		return err
	}
	if isNilLike(s.clock) {
		return ErrNilClock
	}
	return nil
}

// Reserve performs an atomic reservation attempt and returns the frozen
// NEW/REPLAY/IN_PROGRESS/CONFLICT classification. A dependency failure is
// returned as an error and is never reinterpreted as a classification.
//
// The Store's returned Reservation is re-validated before it is exposed:
// impossible or contradictory classifications (unknown status, NEW without an
// owner token, ownership or result on non-NEW statuses, fingerprint
// mismatches, a CONFLICT that does not represent a genuinely different
// fingerprint) fail closed with ErrMalformedStoreOutput.
func (s *Service) Reserve(ctx context.Context, req ReserveRequest) (Reservation, error) {
	if err := s.validate(); err != nil {
		return Reservation{}, err
	}
	if err := validateReserveRequest(req); err != nil {
		return Reservation{}, err
	}
	res, err := s.store.Reserve(ctx, req)
	if err != nil {
		return Reservation{}, err
	}
	if err := validateReservationOutput(res, req); err != nil {
		return Reservation{}, err
	}
	return res, nil
}

// Commit commits an active reservation as its owner. It fails closed for
// zero/unknown/mismatched/stale/non-owner reservations and copies the optional
// protected capsule before storing it. The Store's returned record is
// re-validated before it is exposed.
func (s *Service) Commit(ctx context.Context, req CommitRequest) (Record, error) {
	if err := s.validate(); err != nil {
		return Record{}, err
	}
	if err := validateCommitRequest(req); err != nil {
		return Record{}, err
	}
	record, err := s.store.Commit(ctx, req)
	if err != nil {
		return Record{}, err
	}
	if err := validateCommitOutput(record, req); err != nil {
		return Record{}, err
	}
	return record, nil
}

// RecoverSecret attempts protected secret recovery for a committed REPLAY. It
// invokes the protector's Open ONLY after authoritatively establishing the
// exact same effective scope, the exact same fingerprint, committed state, the
// presence of a protected capsule, and — using the server-controlled clock —
// that neither the idempotency record/replay window nor the capsule itself has
// expired. Any other state returns a distinguishable recovery error and never
// reaches Open.
//
// RecoverSecret does NOT authenticate the request and does NOT bypass M4/M5
// authorization or visibility gates; future route adapters must run those
// gates first.
func (s *Service) RecoverSecret(ctx context.Context, req RecoverSecretRequest) ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if req.Scope.IsZero() {
		return nil, newRecoveryError(RecoveryReasonUnavailable, errors.New("effective scope must not be zero"))
	}
	if req.Fingerprint.IsZero() {
		return nil, newRecoveryError(RecoveryReasonUnavailable, errors.New("fingerprint must not be zero"))
	}

	record, found, err := s.store.Lookup(ctx, req.Scope)
	if err != nil {
		// Dependency failure is indeterminate, never a successful replay.
		return nil, err
	}
	if !found {
		return nil, newRecoveryError(RecoveryReasonUnavailable, nil)
	}
	if err := validateRecordOutput(record); err != nil {
		// Malformed provider output must never broaden replay authority.
		return nil, err
	}
	if !record.Scope.Equal(req.Scope) {
		// Provenance: a Lookup result must be bound to the exact requested
		// scope before any secret recovery is attempted. This is checked
		// before Open regardless of fingerprint.
		return nil, newRecoveryError(RecoveryReasonUnavailable,
			fmt.Errorf("%w: lookup returned a record for a different scope", ErrMalformedStoreOutput))
	}
	if record.Status != RecordCommitted {
		return nil, newRecoveryError(RecoveryReasonUnavailable, nil)
	}
	if !record.Fingerprint.Equal(req.Fingerprint) {
		return nil, newRecoveryError(RecoveryReasonUnavailable, nil)
	}

	now := s.clock.Now()
	if !now.Before(record.ExpiresAt) {
		return nil, newRecoveryError(RecoveryReasonRecordExpired,
			fmt.Errorf("%w: record expired at %s", ErrRecordExpired, record.ExpiresAt.Format(time.RFC3339)))
	}

	if record.Capsule == nil {
		return nil, newRecoveryError(RecoveryReasonNoCapsule, nil)
	}
	if !record.CapsuleExpiresAt.IsZero() && !now.Before(record.CapsuleExpiresAt) {
		return nil, newRecoveryError(RecoveryReasonCapsuleExpired,
			fmt.Errorf("%w: capsule expired at %s", ErrCapsuleExpired, record.CapsuleExpiresAt.Format(time.RFC3339)))
	}

	plaintext, err := s.protector.Open(ctx, record.Capsule, req.AssociatedData)
	if err != nil {
		return nil, wrapOpenError(err)
	}
	return plaintext, nil
}

// validateReserveRequest fails closed on malformed authority rather than
// repairing it into validity.
func validateReserveRequest(req ReserveRequest) error {
	if req.Scope.IsZero() {
		return errors.New("idempotency runtime: reserve request effective scope must not be zero")
	}
	if req.Fingerprint.IsZero() {
		return errors.New("idempotency runtime: reserve request fingerprint must not be zero")
	}
	if req.Now.IsZero() {
		return errors.New("idempotency runtime: reserve request now must not be zero")
	}
	if req.ExpiresAt.IsZero() || !req.ExpiresAt.After(req.Now) {
		return errors.New("idempotency runtime: reserve request expires_at must be a future timestamp")
	}
	return nil
}

// validateCommitRequest fails closed on zero token/scope/result or a malformed
// capsule. Capsule presence is not forced here: non-secret operations
// legitimately commit without one, but when present, the capsule must be
// structurally valid.
func validateCommitRequest(req CommitRequest) error {
	if req.Token.IsZero() {
		return ErrZeroReservationToken
	}
	if req.Scope.IsZero() {
		return errors.New("idempotency runtime: commit request effective scope must not be zero")
	}
	if req.Result.IsZero() {
		return errors.New("idempotency runtime: commit request result locator must not be zero")
	}
	if req.Capsule != nil {
		if err := req.Capsule.Validate(); err != nil {
			return fmt.Errorf("idempotency runtime: commit request capsule invalid: %w", err)
		}
	}
	return nil
}

// validateReservationOutput re-validates a Store's Reserve result before the
// Service exposes it. Impossible or contradictory combinations fail closed.
func validateReservationOutput(res Reservation, req ReserveRequest) error {
	// Provenance: the result must be authoritatively bound to the exact
	// requested effective scope. Missing/zero/mismatched scope fails closed
	// as malformed Store output, never as a successful classification.
	if res.Scope.IsZero() || !res.Scope.Equal(req.Scope) {
		return fmt.Errorf("%w: reservation scope does not match requested scope", ErrMalformedStoreOutput)
	}

	switch res.Status {
	case ReservationNew:
		if res.Token.IsZero() {
			return fmt.Errorf("%w: NEW without a non-zero owner token", ErrMalformedStoreOutput)
		}
		if !res.Fingerprint.Equal(req.Fingerprint) {
			return fmt.Errorf("%w: NEW fingerprint does not match requested fingerprint", ErrMalformedStoreOutput)
		}
		if !res.Result.IsZero() {
			return fmt.Errorf("%w: NEW carries a result locator", ErrMalformedStoreOutput)
		}
		if !res.ExpiresAt.Equal(req.ExpiresAt) {
			return fmt.Errorf("%w: NEW expiry does not match requested expiry", ErrMalformedStoreOutput)
		}
	case ReservationReplay:
		if !res.Token.IsZero() {
			return fmt.Errorf("%w: REPLAY carries an owner token", ErrMalformedStoreOutput)
		}
		if res.Result.IsZero() {
			return fmt.Errorf("%w: REPLAY without a valid result locator", ErrMalformedStoreOutput)
		}
		if !res.Fingerprint.Equal(req.Fingerprint) {
			return fmt.Errorf("%w: REPLAY fingerprint does not match requested fingerprint", ErrMalformedStoreOutput)
		}
		if res.ExpiresAt.IsZero() {
			return fmt.Errorf("%w: REPLAY without record expiry metadata", ErrMalformedStoreOutput)
		}
	case ReservationInProgress:
		if !res.Token.IsZero() {
			return fmt.Errorf("%w: IN_PROGRESS carries an owner token", ErrMalformedStoreOutput)
		}
		if !res.Result.IsZero() {
			return fmt.Errorf("%w: IN_PROGRESS carries a result locator", ErrMalformedStoreOutput)
		}
		if !res.Fingerprint.Equal(req.Fingerprint) {
			return fmt.Errorf("%w: IN_PROGRESS fingerprint does not match requested fingerprint", ErrMalformedStoreOutput)
		}
		if res.ExpiresAt.IsZero() {
			return fmt.Errorf("%w: IN_PROGRESS without record expiry metadata", ErrMalformedStoreOutput)
		}
	case ReservationConflict:
		if !res.Token.IsZero() {
			return fmt.Errorf("%w: CONFLICT carries an owner token", ErrMalformedStoreOutput)
		}
		if !res.Result.IsZero() {
			return fmt.Errorf("%w: CONFLICT carries a result locator", ErrMalformedStoreOutput)
		}
		if res.Fingerprint.IsZero() {
			return fmt.Errorf("%w: CONFLICT without an authoritative fingerprint", ErrMalformedStoreOutput)
		}
		if res.Fingerprint.Equal(req.Fingerprint) {
			return fmt.Errorf("%w: CONFLICT does not represent a genuinely different fingerprint", ErrMalformedStoreOutput)
		}
		if res.ExpiresAt.IsZero() {
			return fmt.Errorf("%w: CONFLICT without record expiry metadata", ErrMalformedStoreOutput)
		}
	default:
		return fmt.Errorf("%w: unknown reservation status %q", ErrMalformedStoreOutput, res.Status)
	}
	return nil
}

// validateRecordOutput re-validates a Store's Record before the Service
// consumes it for commit results or replay decisions.
func validateRecordOutput(rec Record) error {
	if rec.Scope.IsZero() {
		return fmt.Errorf("%w: record has zero scope provenance", ErrMalformedStoreOutput)
	}
	if !rec.Status.Valid() {
		return fmt.Errorf("%w: unknown record status %q", ErrMalformedStoreOutput, rec.Status)
	}
	if rec.Fingerprint.IsZero() {
		return fmt.Errorf("%w: record has zero fingerprint", ErrMalformedStoreOutput)
	}
	if rec.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: record has zero expiry", ErrMalformedStoreOutput)
	}

	switch rec.Status {
	case RecordActive:
		if !rec.Result.IsZero() {
			return fmt.Errorf("%w: active record carries a result locator", ErrMalformedStoreOutput)
		}
		if rec.Capsule != nil {
			return fmt.Errorf("%w: active record carries a capsule", ErrMalformedStoreOutput)
		}
		if !rec.CapsuleExpiresAt.IsZero() {
			return fmt.Errorf("%w: active record carries capsule expiry metadata", ErrMalformedStoreOutput)
		}
	case RecordCommitted:
		if rec.Result.IsZero() {
			return fmt.Errorf("%w: committed record has zero result locator", ErrMalformedStoreOutput)
		}
		if rec.Capsule == nil && !rec.CapsuleExpiresAt.IsZero() {
			return fmt.Errorf("%w: capsule expiry metadata without a capsule", ErrMalformedStoreOutput)
		}
		if rec.Capsule != nil {
			if err := rec.Capsule.Validate(); err != nil {
				return fmt.Errorf("%w: committed record has invalid capsule: %v", ErrMalformedStoreOutput, err)
			}
			if !rec.CapsuleExpiresAt.Equal(rec.Capsule.ExpiresAt()) {
				return fmt.Errorf("%w: capsule expiry metadata does not match capsule expiry", ErrMalformedStoreOutput)
			}
			if !rec.CapsuleExpiresAt.IsZero() && rec.CapsuleExpiresAt.After(rec.ExpiresAt) {
				return fmt.Errorf("%w: capsule expiry outlives record expiry", ErrMalformedStoreOutput)
			}
		}
	}
	return nil
}

// validateCommitOutput re-validates a Store's Commit result before the
// Service exposes it: it must be a coherent committed record carrying exactly
// the result the caller asked to commit and bound to the requested scope.
func validateCommitOutput(rec Record, req CommitRequest) error {
	if err := validateRecordOutput(rec); err != nil {
		return err
	}
	if !rec.Scope.Equal(req.Scope) {
		return fmt.Errorf("%w: commit returned a record for a different scope", ErrMalformedStoreOutput)
	}
	if rec.Status != RecordCommitted {
		return fmt.Errorf("%w: commit returned status %q, want %q", ErrMalformedStoreOutput, rec.Status, RecordCommitted)
	}
	if !rec.Result.Equal(req.Result) {
		return fmt.Errorf("%w: commit returned a result different from the committed result", ErrMalformedStoreOutput)
	}
	return nil
}
