package runtime

import (
	"errors"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
)

var (
	// ErrEnrollmentAuthorityUnavailable means the committed pre-onboarding /
	// RequestAccess state cannot be resolved into one unambiguous exchange
	// authority snapshot. It is an adapter-integrity outcome, not a public code.
	ErrEnrollmentAuthorityUnavailable = errors.New("runtime: enrollment authority unavailable")
	// ErrEnrollmentAuthorityConsumed means another INITIAL exchange already
	// committed the retained RequestAccess capability.
	ErrEnrollmentAuthorityConsumed = errors.New("runtime: enrollment request access already consumed")
	// ErrEnrollmentAuthorityExpired means the authoritative request/capability
	// is no longer fresh at the commit boundary.
	ErrEnrollmentAuthorityExpired = errors.New("runtime: enrollment authority expired")
	// ErrEnrollmentAuthorityNotAuthorized means the authoritative request is no
	// longer in the ENROLLMENT_READY state required by INITIAL.
	ErrEnrollmentAuthorityNotAuthorized = errors.New("runtime: enrollment authority not authorized")
)

// EnrollmentAuthoritySnapshot is the immutable, non-secret read-set captured
// for an INITIAL exchange. The RequestAccess verifier key is retained only as
// a non-reversible identity; no bearer plaintext crosses this boundary.
type EnrollmentAuthoritySnapshot struct {
	Request          *domain.PreOnboardingRequest
	RequestAccessKey capability.VerifierKey
	RequestAccess    capability.RequestAccessRecord
}

// LoadEnrollmentAuthority atomically resolves the approved pre-onboarding
// request and exactly one retained RequestAccess verifier record bound to it.
// Ambiguous duplicate verifier records fail closed.
func (s *MemoryStore) LoadEnrollmentAuthority(requestID string) (EnrollmentAuthoritySnapshot, bool, error) {
	if s == nil || requestID == "" {
		return EnrollmentAuthoritySnapshot{}, false, ErrEnrollmentAuthorityUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	req, ok := s.requests[domain.ID(requestID)]
	if !ok || req == nil {
		return EnrollmentAuthoritySnapshot{}, false, nil
	}
	key, rec, ok, err := s.requestAccessForRequestLocked(requestID)
	if err != nil {
		return EnrollmentAuthoritySnapshot{}, false, err
	}
	if !ok {
		return EnrollmentAuthoritySnapshot{}, false, nil
	}
	return EnrollmentAuthoritySnapshot{
		Request:          cloneRequest(req),
		RequestAccessKey: key,
		RequestAccess:    rec,
	}, true, nil
}

// ValidateEnrollmentAuthority rechecks the captured INITIAL authority against
// the current committed state using trusted commit time, without mutation.
func (s *MemoryStore) ValidateEnrollmentAuthority(expected EnrollmentAuthoritySnapshot, now time.Time) error {
	if s == nil || now.IsZero() {
		return ErrEnrollmentAuthorityUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.validateEnrollmentAuthorityLocked(expected, now)
}

// CommitEnrollmentAuthority is the single atomic lifecycle/publication boundary
// for the in-memory INITIAL exchange. It revalidates the complete authority
// read-set under the M5.6 authority lock, performs only ACTIVE -> CONSUMED,
// and invokes publish before releasing that lock. publish MUST be a prevalidated,
// non-fallible callback that does not re-enter this MemoryStore. Holding the
// authority lock through publication prevents observers from seeing a consumed
// capability without its corresponding enrollment result. There is no path
// that restores CONSUMED to ACTIVE.
func (s *MemoryStore) CommitEnrollmentAuthority(expected EnrollmentAuthoritySnapshot, now time.Time, publish func()) error {
	if s == nil || now.IsZero() || publish == nil {
		return ErrEnrollmentAuthorityUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateEnrollmentAuthorityLocked(expected, now); err != nil {
		return err
	}
	rec := s.requestAccess[expected.RequestAccessKey]
	rec.State = capability.StateConsumed
	s.requestAccess[expected.RequestAccessKey] = rec
	publish()
	return nil
}

func (s *MemoryStore) validateEnrollmentAuthorityLocked(expected EnrollmentAuthoritySnapshot, now time.Time) error {
	if expected.Request == nil || expected.Request.ID() == "" || expected.RequestAccessKey == "" ||
		expected.RequestAccess.PreOnboardingRequestID != string(expected.Request.ID()) {
		return ErrEnrollmentAuthorityUnavailable
	}

	currentReq, ok := s.requests[expected.Request.ID()]
	if !ok || currentReq == nil {
		return ErrEnrollmentAuthorityUnavailable
	}
	if !sameEnrollmentRequestBinding(currentReq, expected.Request) {
		return ErrEnrollmentAuthorityNotAuthorized
	}
	if currentReq.Status() != domain.StateEnrollmentReady {
		return ErrEnrollmentAuthorityNotAuthorized
	}
	if currentReq.EffectiveStatus(now) == domain.StateExpired {
		return ErrEnrollmentAuthorityExpired
	}

	key, currentRec, ok, err := s.requestAccessForRequestLocked(string(expected.Request.ID()))
	if err != nil || !ok || key != expected.RequestAccessKey {
		return ErrEnrollmentAuthorityUnavailable
	}
	if currentRec.PreOnboardingRequestID != expected.RequestAccess.PreOnboardingRequestID ||
		!currentRec.ExpiresAt.Equal(expected.RequestAccess.ExpiresAt) {
		return ErrEnrollmentAuthorityUnavailable
	}
	switch currentRec.State {
	case capability.StateActive:
		if !now.Before(currentRec.ExpiresAt) {
			return ErrEnrollmentAuthorityExpired
		}
	case capability.StateConsumed:
		return ErrEnrollmentAuthorityConsumed
	default:
		return ErrEnrollmentAuthorityUnavailable
	}
	return nil
}

func (s *MemoryStore) requestAccessForRequestLocked(requestID string) (capability.VerifierKey, capability.RequestAccessRecord, bool, error) {
	var foundKey capability.VerifierKey
	var found capability.RequestAccessRecord
	count := 0
	for key, rec := range s.requestAccess {
		if rec.PreOnboardingRequestID != requestID {
			continue
		}
		count++
		if count > 1 {
			return "", capability.RequestAccessRecord{}, false, ErrEnrollmentAuthorityUnavailable
		}
		foundKey, found = key, rec
	}
	if count == 0 {
		return "", capability.RequestAccessRecord{}, false, nil
	}
	return foundKey, found, true, nil
}

func sameEnrollmentRequestBinding(a, b *domain.PreOnboardingRequest) bool {
	if a == nil || b == nil || a.ID() != b.ID() || a.PartnerID() != b.PartnerID() ||
		a.Status() != b.Status() || a.ResourceVersion() != b.ResourceVersion() ||
		!a.CreatedAt().Equal(b.CreatedAt()) || !a.ExpiresAt().Equal(b.ExpiresAt()) {
		return false
	}
	ad, bd := a.DeviceID(), b.DeviceID()
	if ad == nil || bd == nil {
		return ad == nil && bd == nil
	}
	return *ad == *bd
}
