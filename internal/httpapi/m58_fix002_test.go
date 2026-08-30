package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// m58EvidenceBodyWithRaw builds an evidence submission body carrying a fixed
// valid JWS PoP and the caller-supplied RAW JSON text for tpm_evidence.payload
// and, optionally, agent_assertions. The raw JSON strings are spliced verbatim
// so tests can contain duplicate members and original numeric spellings that a
// map/json.Marshal construction could never produce.
func m58EvidenceBodyWithRaw(t *testing.T, h *m58HTTPHarness, jws, tpmPayloadRaw string, agentAssertionsRaw *string) string {
	t.Helper()
	aa := ""
	if agentAssertionsRaw != nil {
		aa = fmt.Sprintf(`,
		"agent_assertions": %s`, *agentAssertionsRaw)
	}
	return fmt.Sprintf(`{
		"challenge_version": 1,
		"csr_der_base64": %q,
		"pop": {"format": "enrollment-pop+jws", "jws": %q},
		"tpm_evidence": {"format": "enrollment-tpm-evidence", "version": "1", "payload": %s}%s
	}`, h.helper.csrB64, jws, tpmPayloadRaw, aa)
}

func m58Fix002Auth(h *m58HTTPHarness) map[string]string {
	return map[string]string{"Authorization": "Bearer " + h.enrollmentToken}
}

func m58Fix002ErrorCode(t *testing.T, body []byte) string {
	t.Helper()
	var p map[string]interface{}
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("response is not JSON: %v (body %s)", err, body)
	}
	code, _ := p["error_code"].(string)
	return code
}

// SOL-M5.8-FIXREV-001 section M: raw-evidence ingress adversarial tests at the
// real HTTP boundary. Duplicate identity-bearing members must be rejected as
// evidence (422 EVIDENCE_INVALID) only after authentication/resource binding;
// an invalid or cross-resource EAT must keep its existing precedence.
func TestM58Fix002RawJSONDuplicateRejection(t *testing.T) {
	t.Run("valid EAT + duplicate root TPM payload member", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)
		body := m58EvidenceBodyWithRaw(t, h, jws, `{"field":"a","field":"b"}`, nil)
		rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, m58Fix002Auth(h))
		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status=%d want=422 body=%s", rr.Code, rr.Body.String())
		}
		if code := m58Fix002ErrorCode(t, rr.Body.Bytes()); code != "EVIDENCE_INVALID" {
			t.Fatalf("error_code=%q want EVIDENCE_INVALID", code)
		}
	})

	t.Run("valid EAT + nested duplicate TPM member", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)
		body := m58EvidenceBodyWithRaw(t, h, jws, `{"nested":{"a":1,"a":2}}`, nil)
		rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, m58Fix002Auth(h))
		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status=%d want=422 body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("valid EAT + duplicate object member inside TPM array", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)
		body := m58EvidenceBodyWithRaw(t, h, jws, `{"arr":[{"x":1,"x":2}]}`, nil)
		rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, m58Fix002Auth(h))
		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status=%d want=422 body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("valid EAT + duplicate agent_assertions member", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)
		aa := `{"tpm_ready":true,"tpm_ready":false}`
		body := m58EvidenceBodyWithRaw(t, h, jws, `{"p":1}`, &aa)
		rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, m58Fix002Auth(h))
		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status=%d want=422 body=%s", rr.Code, rr.Body.String())
		}
		if code := m58Fix002ErrorCode(t, rr.Body.Bytes()); code != "EVIDENCE_INVALID" {
			t.Fatalf("error_code=%q want EVIDENCE_INVALID", code)
		}
	})

	t.Run("invalid EAT + duplicate TPM JSON keeps 401 precedence", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)
		body := m58EvidenceBodyWithRaw(t, h, jws, `{"field":"a","field":"b"}`, nil)
		rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, map[string]string{
			"Authorization": "Bearer not-a-valid-eat-token",
		})
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d want=401 body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("cross-resource EAT + duplicate TPM JSON keeps resource-binding failure", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)
		body := m58EvidenceBodyWithRaw(t, h, jws, `{"field":"a","field":"b"}`, nil)
		rr := h.put("/v1/enrollments/enr-other-id/evidence", body, m58Fix002Auth(h))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d want=401 body=%s", rr.Code, rr.Body.String())
		}
	})
}

// SOL-M5.8-FIXREV-001 section M: EvidenceIdentityV1 raw-JCS identity behavior.
func TestM58Fix002RawJSONIdentitySemantics(t *testing.T) {
	t.Run("agent_assertions absent vs present-empty are distinct identities", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)

		first := m58EvidenceBodyWithRaw(t, h, jws, `{"p":"same"}`, nil)
		rr1 := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", first, m58Fix002Auth(h))
		if rr1.Code != http.StatusAccepted {
			t.Fatalf("first status=%d want=202 body=%s", rr1.Code, rr1.Body.String())
		}

		aa := `{}`
		second := m58EvidenceBodyWithRaw(t, h, jws, `{"p":"same"}`, &aa)
		rr2 := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", second, m58Fix002Auth(h))
		if rr2.Code != http.StatusConflict {
			t.Fatalf("second status=%d want=409 body=%s", rr2.Code, rr2.Body.String())
		}
		if code := m58Fix002ErrorCode(t, rr2.Body.Bytes()); code != "STATE_CONFLICT" {
			t.Fatalf("error_code=%q want STATE_CONFLICT", code)
		}
	})

	t.Run("member ordering and whitespace changes preserve identity", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)

		first := m58EvidenceBodyWithRaw(t, h, jws, `{"a":1,"b":"x"}`, nil)
		rr1 := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", first, m58Fix002Auth(h))
		if rr1.Code != http.StatusAccepted {
			t.Fatalf("first status=%d want=202 body=%s", rr1.Code, rr1.Body.String())
		}

		reordered := m58EvidenceBodyWithRaw(t, h, jws, "{ \"b\" : \"x\" ,\n \"a\" : 1 }", nil)
		rr2 := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", reordered, m58Fix002Auth(h))
		if rr2.Code != http.StatusAccepted {
			t.Fatalf("reordered status=%d want=202 body=%s", rr2.Code, rr2.Body.String())
		}
	})

	t.Run("JCS-equivalent numeric spellings preserve identity", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)

		first := m58EvidenceBodyWithRaw(t, h, jws, `{"n":1.0}`, nil)
		rr1 := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", first, m58Fix002Auth(h))
		if rr1.Code != http.StatusAccepted {
			t.Fatalf("first status=%d want=202 body=%s", rr1.Code, rr1.Body.String())
		}

		equiv := m58EvidenceBodyWithRaw(t, h, jws, `{"n":1e0}`, nil)
		rr2 := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", equiv, m58Fix002Auth(h))
		if rr2.Code != http.StatusAccepted {
			t.Fatalf("equivalent status=%d want=202 body=%s", rr2.Code, rr2.Body.String())
		}
	})

	t.Run("changed TPM value after acceptance is STATE_CONFLICT", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)

		first := m58EvidenceBodyWithRaw(t, h, jws, `{"p":"x"}`, nil)
		rr1 := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", first, m58Fix002Auth(h))
		if rr1.Code != http.StatusAccepted {
			t.Fatalf("first status=%d want=202 body=%s", rr1.Code, rr1.Body.String())
		}

		changed := m58EvidenceBodyWithRaw(t, h, jws, `{"p":"y"}`, nil)
		rr2 := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", changed, m58Fix002Auth(h))
		if rr2.Code != http.StatusConflict {
			t.Fatalf("changed status=%d want=409 body=%s", rr2.Code, rr2.Body.String())
		}
		if code := m58Fix002ErrorCode(t, rr2.Body.Bytes()); code != "STATE_CONFLICT" {
			t.Fatalf("error_code=%q want STATE_CONFLICT", code)
		}
	})

	t.Run("first unresolved evidence after challenge expiry is RESOURCE_EXPIRED", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		// Advance past the challenge lifetime (20m) but keep the EAT valid (1h).
		h.clock.Set(h.clock.Now().Add(30 * time.Minute))
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)
		body := m58EvidenceBodyWithRaw(t, h, jws, `{"p":1}`, nil)
		rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, m58Fix002Auth(h))
		if rr.Code != http.StatusGone {
			t.Fatalf("status=%d want=410 body=%s", rr.Code, rr.Body.String())
		}
		if code := m58Fix002ErrorCode(t, rr.Body.Bytes()); code != "RESOURCE_EXPIRED" {
			t.Fatalf("error_code=%q want RESOURCE_EXPIRED", code)
		}
	})
}
