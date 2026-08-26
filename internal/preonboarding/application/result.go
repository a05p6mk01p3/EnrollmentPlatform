package application

import (
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
)

// PreOnboardingCreateResultSnapshot is the immutable, non-secret portion of
// the originating 201 response. The token is recoverable only from its capsule.
type PreOnboardingCreateResultSnapshot struct {
	PreOnboardingRequestID string
	PartnerID              string
	ExpiresAt              time.Time
	Status                 string
	ETag                   string
	Location               string
	CommittedAt            time.Time
}

// ApprovalResultSnapshot captures the immutable outcome of a successful approval.
type ApprovalResultSnapshot struct {
	PreOnboardingRequestID string    `json:"pre_onboarding_request_id"`
	Status                 string    `json:"status"` // ENROLLMENT_READY
	DeviceID               string    `json:"device_id"`
	ResourceVersion        int       `json:"resource_version"`
	ETag                   string    `json:"etag"`
	CommittedAt            time.Time `json:"committed_at"`
}

// RejectionResultSnapshot captures the immutable outcome of a successful rejection.
// Preserves legitimate pre-existing authoritative device_id if one was present.
type RejectionResultSnapshot struct {
	PreOnboardingRequestID string               `json:"pre_onboarding_request_id"`
	PartnerID              string               `json:"partner_id"`
	Status                 string               `json:"status"` // REJECTED
	DeviceID               *string              `json:"device_id,omitempty"`
	ClaimedDevice          domain.ClaimedDevice `json:"claimed_device"`
	CreatedAt              time.Time            `json:"created_at"`
	ExpiresAt              time.Time            `json:"expires_at"`
	ResourceVersion        int                  `json:"resource_version"`
	ETag                   string               `json:"etag"`
	CommittedAt            time.Time            `json:"committed_at"`
}
