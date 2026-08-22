package httpapi_test

import (
	"net/http"
	"testing"
)

// BenchmarkEnforcement measures the full pipeline for a valid POST
// /v1/enrollments — the most expensive request-body schema in the contract.
func BenchmarkEnforcement(b *testing.B) {
	h, _ := newTestHandler(b)
	headers := map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := do(b, h, "POST", "/v1/enrollments", validEnrollmentBody, headers)
		if rr.Code != http.StatusCreated {
			b.Fatalf("status = %d, want 201 (body %s)", rr.Code, rr.Body.String())
		}
	}
}

// BenchmarkEnforcementGetTrustBundle measures a bodyless GET through the same
// pipeline (parameter validation only, no body schema work).
func BenchmarkEnforcementGetTrustBundle(b *testing.B) {
	h, _ := newTestHandler(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := do(b, h, "GET", "/v1/pki/trust-bundles/current", "", nil)
		if rr.Code != http.StatusOK {
			b.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
		}
	}
}
