package httpapi_test

import (
	"net/http"
	"testing"
)

// Positive evidence-route regression (M5.8-FIX-004 section 7): with the exact
// canonical v0.1.5 metadata in force, ONLY tpm_evidence.payload and
// agent_assertions are delegated to the application identity boundary.
// Envelope/container duplicates must remain M3 contract errors (400
// INVALID_REQUEST) at the real HTTP boundary.
func TestM58Fix004EnvelopeDuplicatesRemainM3Errors(t *testing.T) {
	t.Run("duplicate tpm_evidence container member", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)
		body := m58EvidenceBodyWithDuplicatedContainer(t, h, jws)
		rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, m58Fix002Auth(h))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status=%d want=400 body=%s", rr.Code, rr.Body.String())
		}
		if code := m58Fix002ErrorCode(t, rr.Body.Bytes()); code != "INVALID_REQUEST" {
			t.Fatalf("error_code=%q want INVALID_REQUEST", code)
		}
	})

	t.Run("duplicate payload container member inside tpm_evidence", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)
		body := `{
			"challenge_version": 1,
			"csr_der_base64": "` + h.helper.csrB64 + `",
			"pop": {"format": "enrollment-pop+jws", "jws": "` + jws + `"},
			"tpm_evidence": {"format": "enrollment-tpm-evidence", "version": "1", "payload": {"a":1}, "payload": {"b":2}}
		}`
		rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, m58Fix002Auth(h))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status=%d want=400 body=%s", rr.Code, rr.Body.String())
		}
		if code := m58Fix002ErrorCode(t, rr.Body.Bytes()); code != "INVALID_REQUEST" {
			t.Fatalf("error_code=%q want INVALID_REQUEST", code)
		}
	})
}

func m58EvidenceBodyWithDuplicatedContainer(t *testing.T, h *m58HTTPHarness, jws string) string {
	t.Helper()
	return `{
		"challenge_version": 1,
		"csr_der_base64": "` + h.helper.csrB64 + `",
		"pop": {"format": "enrollment-pop+jws", "jws": "` + jws + `"},
		"tpm_evidence": {"format": "enrollment-tpm-evidence", "version": "1", "payload": {"a": 1}},
		"tpm_evidence": {"format": "enrollment-tpm-evidence", "version": "1", "payload": {"b": 2}}
	}`
}
