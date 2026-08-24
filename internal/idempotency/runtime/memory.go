package runtime

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MemoryStore is a deterministic, concurrency-safe, instance-local in-memory
// reference implementation of the Store port. It exists to prove the frozen
// reservation protocol under test, including high-contention races.
//
// It is a REFERENCE implementation only. Its mutex discipline does NOT define
// future PostgreSQL lock/isolation semantics, and it must not be interpreted
// as production persistence (OPEN-009 remains open).
//
// State is instance-local: there is no package-global mutable map. The zero
// value is unusable; construct one with NewMemoryStore.
type MemoryStore struct {
	mu      sync.Mutex
	records map[EffectiveScope]*memoryRecord
	tokens  map[ReservationToken]EffectiveScope
}

// memoryRecord is the internal immutable-on-read reservation record. It is
// never exposed directly; accessors return copies.
type memoryRecord struct {
	scope            EffectiveScope
	fingerprint      Fingerprint
	status           RecordStatus
	token            ReservationToken
	result           ResultLocator
	capsule          *ProtectedEnvelope
	createdAt        time.Time
	expiresAt        time.Time
	capsuleExpiresAt time.Time
}

// NewMemoryStore constructs a usable in-memory reference store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		records: make(map[EffectiveScope]*memoryRecord),
		tokens:  make(map[ReservationToken]EffectiveScope),
	}
}

// Validate reports whether the store has usable internal state.
func (m *MemoryStore) Validate() error {
	if m == nil || m.records == nil || m.tokens == nil {
		return ErrUnusableStore
	}
	return nil
}

func (m *MemoryStore) validate() error { return m.Validate() }

// Reserve implements the atomic reservation classification. Expiry is modeled
// as metadata only: an expired record is never silently turned into a new
// execution authorization, and a consumed record is never reactivated.
func (m *MemoryStore) Reserve(ctx context.Context, req ReserveRequest) (Reservation, error) {
	if err := m.validate(); err != nil {
		return Reservation{}, err
	}
	if err := validateReserveRequest(req); err != nil {
		return Reservation{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if rec, ok := m.records[req.Scope]; ok {
		switch rec.status {
		case RecordActive:
			if rec.fingerprint.Equal(req.Fingerprint) {
				return Reservation{Scope: rec.scope, Status: ReservationInProgress, Fingerprint: rec.fingerprint, ExpiresAt: rec.expiresAt}, nil
			}
			return Reservation{Scope: rec.scope, Status: ReservationConflict, Fingerprint: rec.fingerprint, ExpiresAt: rec.expiresAt}, nil
		case RecordCommitted:
			if rec.fingerprint.Equal(req.Fingerprint) {
				return Reservation{Scope: rec.scope, Status: ReservationReplay, Result: rec.result, Fingerprint: rec.fingerprint, ExpiresAt: rec.expiresAt}, nil
			}
			return Reservation{Scope: rec.scope, Status: ReservationConflict, Fingerprint: rec.fingerprint, ExpiresAt: rec.expiresAt}, nil
		default:
			return Reservation{}, fmt.Errorf("idempotency runtime: store contains record with unknown status %q for scope", rec.status)
		}
	}

	token, err := NewReservationToken()
	if err != nil {
		return Reservation{}, err
	}

	m.records[req.Scope] = &memoryRecord{
		scope:       req.Scope,
		fingerprint: req.Fingerprint,
		status:      RecordActive,
		token:       token,
		createdAt:   req.Now,
		expiresAt:   req.ExpiresAt,
	}
	m.tokens[token] = req.Scope

	return Reservation{
		Scope:       req.Scope,
		Status:      ReservationNew,
		Token:       token,
		Fingerprint: req.Fingerprint,
		ExpiresAt:   req.ExpiresAt,
	}, nil
}

// Commit marks the caller-owned active reservation committed. Only the active
// owner (holding the exact unforgeable token for the exact scope) may commit.
func (m *MemoryStore) Commit(ctx context.Context, req CommitRequest) (Record, error) {
	if err := m.validate(); err != nil {
		return Record{}, err
	}
	if err := validateCommitRequest(req); err != nil {
		return Record{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if req.Token.IsZero() {
		return Record{}, ErrZeroReservationToken
	}
	scope, ok := m.tokens[req.Token]
	if !ok {
		return Record{}, ErrReservationNotFound
	}
	if !scope.Equal(req.Scope) {
		return Record{}, ErrReservationScopeMismatch
	}

	rec, ok := m.records[scope]
	if !ok {
		return Record{}, ErrReservationNotFound
	}
	if rec.status != RecordActive {
		return Record{}, ErrReservationNotActive
	}
	if !rec.token.Equal(req.Token) {
		return Record{}, ErrReservationNotActive
	}

	// A protected capsule must be structurally valid and its expiry must
	// not outlive the enclosing record/replay lifetime. Validate before
	// persisting so an impossible commit never lands.
	capsule := cloneEnvelope(req.Capsule)
	var capsuleExpiresAt time.Time
	if capsule != nil {
		if err := capsule.Validate(); err != nil {
			return Record{}, fmt.Errorf("idempotency runtime: commit capsule invalid: %w", err)
		}
		capsuleExpiresAt = capsule.ExpiresAt()
		if !capsuleExpiresAt.IsZero() && capsuleExpiresAt.After(rec.expiresAt) {
			return Record{}, fmt.Errorf("%w: capsule expires at %s, record expires at %s",
				ErrCapsuleOutlivesRecord,
				capsuleExpiresAt.Format(time.RFC3339),
				rec.expiresAt.Format(time.RFC3339))
		}
	}

	rec.status = RecordCommitted
	rec.result = req.Result
	rec.capsule = capsule
	rec.capsuleExpiresAt = capsuleExpiresAt
	delete(m.tokens, req.Token)

	return recordToPublic(rec), nil
}

// Lookup returns the current record for an effective scope.
func (m *MemoryStore) Lookup(ctx context.Context, scope EffectiveScope) (Record, bool, error) {
	if err := m.validate(); err != nil {
		return Record{}, false, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	rec, ok := m.records[scope]
	if !ok {
		return Record{}, false, nil
	}
	return recordToPublic(rec), true, nil
}

// recordToPublic copies internal record state into an immutable public
// snapshot. Slices/pointers are copied so callers cannot mutate stored state.
func recordToPublic(rec *memoryRecord) Record {
	if rec == nil {
		return Record{}
	}
	return Record{
		Scope:            rec.scope,
		Fingerprint:      rec.fingerprint,
		Status:           rec.status,
		Result:           rec.result,
		Capsule:          cloneEnvelope(rec.capsule),
		CreatedAt:        rec.createdAt,
		ExpiresAt:        rec.expiresAt,
		CapsuleExpiresAt: rec.capsuleExpiresAt,
	}
}

func cloneEnvelope(e *ProtectedEnvelope) *ProtectedEnvelope {
	if e == nil {
		return nil
	}
	return e.clone()
}
