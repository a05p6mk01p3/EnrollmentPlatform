package application

import (
	"encoding/json"

	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
)

const ChallengeRefreshRoute = "/v1/enrollments/{id}/challenge:refresh"

type canonicalChallengeRefreshPayload struct {
	ExpectedChallengeVersion int `json:"expected_challenge_version"`
}

// ComputeChallengeRefreshFingerprint implements the contract's simple refresh
// request fingerprint. Correlation IDs and credential material are excluded;
// the authenticated credential binding belongs only to EffectiveScope.
func ComputeChallengeRefreshFingerprint(expectedVersion int) (idempotencyruntime.Fingerprint, error) {
	b, err := json.Marshal(canonicalChallengeRefreshPayload{ExpectedChallengeVersion: expectedVersion})
	if err != nil {
		return idempotencyruntime.Fingerprint{}, err
	}
	return idempotencyruntime.FingerprintRequest(idempotencyruntime.FingerprintVersion1, "POST", ChallengeRefreshRoute, b)
}
