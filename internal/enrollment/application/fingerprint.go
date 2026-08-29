package application

import (
	"encoding/json"

	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
)

const createEnrollmentRoute = "/v1/enrollments"

// CreateInitialCommand is trusted NEW-operation input after ordinary M4
// RequestAccessToken authentication established an ACTIVE capability binding.
// PreOnboardingRequestID is therefore an opaque server-authenticated binding,
// never a client claim of authority. Exact consumed-capability response-loss
// recovery uses RecoverInitialCommand plus enrollment/recovery.Proof instead.
type CreateInitialCommand struct {
	PreOnboardingRequestID string
	CertificateUsage       string
	IdempotencyKey         string
	CorrelationID          string
}

type canonicalCreatePayload struct {
	Operation        string `json:"operation"`
	CertificateUsage string `json:"certificate_usage"`
}

// ComputeCreateInitialFingerprint excludes credential material, correlation
// ID, and transport noise. Method and canonical route are domain-separated by
// the M5.4 fingerprint kernel itself.
func ComputeCreateInitialFingerprint(cmd CreateInitialCommand) (idempotencyruntime.Fingerprint, error) {
	b, err := json.Marshal(canonicalCreatePayload{Operation: OperationInitial, CertificateUsage: cmd.CertificateUsage})
	if err != nil {
		return idempotencyruntime.Fingerprint{}, err
	}
	return idempotencyruntime.FingerprintRequest(idempotencyruntime.FingerprintVersion1, "POST", createEnrollmentRoute, b)
}
