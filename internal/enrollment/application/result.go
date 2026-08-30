package application

import (
	"errors"
	"strings"
	"time"

	domain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/domain/enrollment"
)

// CreateResultSnapshot is the non-secret committed 201 representation used by
// exact idempotent replay. The EnrollmentAccessToken plaintext is deliberately
// absent; it is recoverable only from the protected Replay Capsule.
type CreateResultSnapshot struct {
	EnrollmentID         string
	Operation            string
	CertificateUsage     string
	DeviceID             string
	State                domain.State
	Challenge            Challenge
	EvidenceRequirements EvidenceRequirements
	Location             string
	CommittedAt          time.Time
}

func (s CreateResultSnapshot) Clone() CreateResultSnapshot {
	s.EvidenceRequirements = s.EvidenceRequirements.Clone()
	return s
}

func (s CreateResultSnapshot) Validate() error {
	if strings.TrimSpace(s.EnrollmentID) == "" || strings.TrimSpace(s.DeviceID) == "" {
		return errors.New("enrollment application: result snapshot requires enrollment_id and device_id")
	}
	if s.Operation != OperationInitial || s.State != domain.StateChallengeIssued {
		return errors.New("enrollment application: result snapshot must represent INITIAL CHALLENGE_ISSUED")
	}
	if strings.TrimSpace(s.CertificateUsage) == "" {
		return errors.New("enrollment application: result snapshot certificate usage is required")
	}
	if s.CommittedAt.IsZero() {
		return errors.New("enrollment application: result snapshot committed_at is required")
	}
	if err := s.Challenge.Validate(s.CommittedAt); err != nil {
		return err
	}
	if err := s.EvidenceRequirements.Validate(); err != nil {
		return err
	}
	want := "/v1/enrollments/" + s.EnrollmentID
	if s.Location != want {
		return errors.New("enrollment application: result snapshot location does not match enrollment_id")
	}
	return nil
}

// CreateInitialResult is the create-enrollment application result. On REPLAY,
// Snapshot is the exact committed non-secret representation and
// EnrollmentAccessToken is the exact original secret recovered from the
// Replay Capsule; no NEW mutation is executed.
type CreateInitialResult struct {
	Snapshot              CreateResultSnapshot
	EnrollmentAccessToken string
	Replay                bool
}

// EvidenceAcceptedResult is the stable 202 result for both the first
// resource acceptance and an exact retry. It contains no request material.
type EvidenceAcceptedResult struct {
	EnrollmentID      string
	State             domain.State
	StatusURL         string
	RetryAfterSeconds int
	Replay            bool
}

func (r EvidenceAcceptedResult) Validate() error {
	if strings.TrimSpace(r.EnrollmentID) == "" || r.State != domain.StateEvidenceReceived {
		return errors.New("enrollment application: invalid evidence accepted result")
	}
	if r.StatusURL != "/v1/enrollments/"+r.EnrollmentID || r.RetryAfterSeconds < 0 {
		return errors.New("enrollment application: invalid evidence status result")
	}
	return nil
}

// ChallengeRefreshResult is the immutable committed 200 representation for a
// challenge refresh. Replays return this exact snapshot and do not mint a
// replacement nonce.
type ChallengeRefreshResult struct {
	EnrollmentID string
	State        domain.State
	Challenge    Challenge
	RefreshedAt  time.Time
}

func (r ChallengeRefreshResult) Clone() ChallengeRefreshResult {
	return r
}

func (r ChallengeRefreshResult) Validate(_ time.Time) error {
	if strings.TrimSpace(r.EnrollmentID) == "" || r.State != domain.StateChallengeIssued || r.RefreshedAt.IsZero() {
		return errors.New("enrollment application: invalid challenge refresh result")
	}
	return r.Challenge.Validate(r.RefreshedAt)
}
