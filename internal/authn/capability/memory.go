package capability

import (
	"context"
	"fmt"
	"sync"
	"time"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
)

// MemoryStore is a thread-safe in-memory Store for tests and development. It
// stores only non-reversible verifier keys, never plaintext tokens. It is not
// the future PostgreSQL schema (OPEN-009 remains open).
type MemoryStore struct {
	verifier Verifier

	mu         sync.RWMutex
	request    map[VerifierKey]RequestAccessRecord
	enrollment map[VerifierKey]EnrollmentAccessRecord
}

// NewMemoryStore returns an empty in-memory store using the given verifier to
// derive keys at seed time (the plaintext token is discarded immediately).
func NewMemoryStore(v Verifier) *MemoryStore {
	return &MemoryStore{
		verifier:   v,
		request:    map[VerifierKey]RequestAccessRecord{},
		enrollment: map[VerifierKey]EnrollmentAccessRecord{},
	}
}

// SeedRequestAccess derives and stores a RequestAccessToken verifier record,
// discarding the plaintext token. Seeding is creation-only: an existing
// verifier is never overwritten (ErrDuplicate), so a consumed token can never
// be reactivated by re-seeding. The lifecycle state must be an explicit valid
// value (Active or Consumed).
func (s *MemoryStore) SeedRequestAccess(token, requestID string, expiresAt time.Time, state State) error {
	if state != StateActive && state != StateConsumed {
		return fmt.Errorf("capability: invalid request-access lifecycle state %d", state)
	}
	if requestID == "" {
		return fmt.Errorf("capability: request-access seed requires a pre_onboarding_request_id")
	}
	key, err := s.verifier.Derive(authpolicy.CredentialKindRequestAccessToken, token)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.request[key]; exists {
		return ErrDuplicate
	}
	s.request[key] = RequestAccessRecord{PreOnboardingRequestID: requestID, ExpiresAt: expiresAt, State: state}
	return nil
}

// SeedEnrollmentAccess derives and stores an EnrollmentAccessToken verifier
// record, discarding the plaintext token. Seeding is creation-only: an
// existing verifier is never overwritten (ErrDuplicate).
func (s *MemoryStore) SeedEnrollmentAccess(token, enrollmentID string, expiresAt time.Time) error {
	if enrollmentID == "" {
		return fmt.Errorf("capability: enrollment-access seed requires an enrollment_id")
	}
	key, err := s.verifier.Derive(authpolicy.CredentialKindEnrollmentAccessToken, token)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.enrollment[key]; exists {
		return ErrDuplicate
	}
	s.enrollment[key] = EnrollmentAccessRecord{EnrollmentID: enrollmentID, ExpiresAt: expiresAt}
	return nil
}

// LookupRequestAccess resolves a RequestAccessToken verifier. No match returns
// ErrNotFound.
func (s *MemoryStore) LookupRequestAccess(_ context.Context, key VerifierKey) (*RequestAccessRecord, error) {
	s.mu.RLock()
	rec, ok := s.request[key]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	cp := rec
	return &cp, nil
}

// LookupEnrollmentAccess resolves an EnrollmentAccessToken verifier. No match
// returns ErrNotFound.
func (s *MemoryStore) LookupEnrollmentAccess(_ context.Context, key VerifierKey) (*EnrollmentAccessRecord, error) {
	s.mu.RLock()
	rec, ok := s.enrollment[key]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	cp := rec
	return &cp, nil
}
