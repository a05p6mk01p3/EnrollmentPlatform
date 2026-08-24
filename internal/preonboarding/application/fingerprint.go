package application

import (
	"encoding/json"
	"fmt"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
)

// canonicalDecisionPayload holds the semantic fields included in decision
// fingerprint generation. Transport noise, correlation IDs, and irrelevant
// headers are excluded.
type canonicalDecisionPayload struct {
	OperationID    string `json:"operation_id"`
	Route          string `json:"route"`
	ResourceID     string `json:"resource_id"`
	IfMatch        string `json:"if_match"`
	ExpectedStatus string `json:"expected_status"`
	Reason         string `json:"reason"`
}

// ComputeDecisionFingerprint produces the deterministic M5.4 Fingerprint for an
// approve or reject command.
func ComputeDecisionFingerprint(opID, routeTemplate, resourceID, ifMatch, expectedStatus, reason string) (runtime.Fingerprint, error) {
	payload := canonicalDecisionPayload{
		OperationID:    opID,
		Route:          routeTemplate,
		ResourceID:     resourceID,
		IfMatch:        ifMatch,
		ExpectedStatus: expectedStatus,
		Reason:         reason,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return runtime.Fingerprint{}, fmt.Errorf("fingerprint: marshal canonical payload: %w", err)
	}
	return runtime.FingerprintRequest(runtime.FingerprintVersion1, "POST", routeTemplate, b)
}
