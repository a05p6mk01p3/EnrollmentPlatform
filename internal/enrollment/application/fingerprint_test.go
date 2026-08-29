package application_test

import (
	"testing"

	application "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/application"
)

func TestCreateInitialFingerprint_ExcludesCorrelationAndBindsUsage(t *testing.T) {
	base := application.CreateInitialCommand{
		PreOnboardingRequestID: "por-A",
		CertificateUsage:       "PARTNER_AUTH",
		IdempotencyKey:         "idem-key-123456",
		CorrelationID:          "corr-A",
	}
	f1, err := application.ComputeCreateInitialFingerprint(base)
	if err != nil {
		t.Fatal(err)
	}
	changedTransport := base
	changedTransport.PreOnboardingRequestID = "por-B"
	changedTransport.IdempotencyKey = "idem-key-654321"
	changedTransport.CorrelationID = "corr-B"
	f2, err := application.ComputeCreateInitialFingerprint(changedTransport)
	if err != nil {
		t.Fatal(err)
	}
	if !f1.Equal(f2) {
		t.Fatal("credential binding/idempotency/correlation transport fields changed the body fingerprint")
	}

	changedBody := base
	changedBody.CertificateUsage = "OTHER_USAGE"
	f3, err := application.ComputeCreateInitialFingerprint(changedBody)
	if err != nil {
		t.Fatal(err)
	}
	if f1.Equal(f3) {
		t.Fatal("certificate_usage mutation did not change the createEnrollment fingerprint")
	}
}
