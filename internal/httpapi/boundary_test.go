package httpapi_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// evidenceHeaders builds the headers for a PUT evidence request (no
// Idempotency-Key: evidence acceptance is resource-idempotent).
func evidenceHeaders() map[string]string {
	return map[string]string{"Content-Type": "application/json"}
}

// evidenceBody builds a schema-valid EvidenceSubmission body with the given
// CSR base64 value.
func evidenceBody(csrBase64 string) string {
	return fmt.Sprintf(`{"challenge_version":1,"csr_der_base64":%q,"pop":{"format":"enrollment-pop+jws","jws":"aaaaaaaa.bbbbbbbb.ccc"},"tpm_evidence":{"format":"enrollment-tpm-evidence","version":"1","payload":{}}}`, csrBase64)
}

// evidenceBodyWithTotalSize builds a schema-valid EvidenceSubmission body
// whose total byte length is exactly total, by padding tpm_evidence.payload
// (an open object per the contract; its specific wire limits remain OPEN-004A).
func evidenceBodyWithTotalSize(t *testing.T, total int) string {
	t.Helper()
	const placeholder = "PADPLACEHOLDER"
	fixed := evidenceBodyWithPayload(placeholder)
	padLen := total - (len(fixed) - len(placeholder))
	if padLen < 0 {
		t.Fatalf("total %d too small for fixed body overhead", total)
	}
	return strings.Replace(fixed, placeholder, strings.Repeat("a", padLen), 1)
}

func evidenceBodyWithPayload(payload string) string {
	return fmt.Sprintf(`{"challenge_version":1,"csr_der_base64":"TUlJQkNTUl9ERVI=","pop":{"format":"enrollment-pop+jws","jws":"aaaaaaaa.bbbbbbbb.ccc"},"tpm_evidence":{"format":"enrollment-tpm-evidence","version":"1","payload":{"pad":%q}}}`, payload)
}

func submitEvidence(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	return do(t, h, "PUT", "/v1/enrollments/enr-123/evidence", body, evidenceHeaders())
}

// SOL-001: the CSR decoded-byte limit (x-max-decoded-bytes: 65536) is
// enforced explicitly, before the strict server interface. 65535 and 65536
// decoded bytes are accepted; 65537 and 65538 (which still satisfy the
// 87384-char encoded maxLength) are rejected with 413 PAYLOAD_TOO_LARGE.
func TestCSRDecodedSizeLimit(t *testing.T) {
	accept := []int{65535, 65536}
	for _, n := range accept {
		t.Run(fmt.Sprintf("accept_%d", n), func(t *testing.T) {
			h, p := newTestHandler(t)
			csr := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'a'}, n))
			rr := submitEvidence(t, h, evidenceBody(csr))
			if rr.Code != http.StatusAccepted {
				t.Fatalf("decoded %d bytes: status = %d, want 202 (body %s)", n, rr.Code, rr.Body.String())
			}
			if p.count("SubmitEnrollmentEvidence") != 1 {
				t.Fatal("handler was not called")
			}
		})
	}

	reject := []int{65537, 65538}
	for _, n := range reject {
		t.Run(fmt.Sprintf("reject_%d", n), func(t *testing.T) {
			h, p := newTestHandler(t)
			csr := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'a'}, n))
			rr := submitEvidence(t, h, evidenceBody(csr))
			if rr.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("decoded %d bytes: status = %d, want 413 (body %s)", n, rr.Code, rr.Body.String())
			}
			if p.total() != 0 {
				t.Fatal("handler ran despite oversized CSR")
			}
			m := problemBody(t, rr)
			if m["error_code"] != "PAYLOAD_TOO_LARGE" {
				t.Fatalf("error_code = %v", m["error_code"])
			}
		})
	}
}

// Invalid base64 in the CSR field is rejected with 400 INVALID_REQUEST
// (syntax error), using the same decoder semantics (base64.StdEncoding) the
// generated server applies to []byte fields.
func TestCSRInvalidBase64(t *testing.T) {
	for _, tc := range []struct {
		name string
		csr  string
	}{
		{"illegal chars", "!!!!"},
		{"unpadded", "TUlJQkNTUl9ERVI"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, p := newTestHandler(t)
			rr := submitEvidence(t, h, evidenceBody(tc.csr))
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", rr.Code, rr.Body.String())
			}
			if p.total() != 0 {
				t.Fatal("handler ran despite invalid base64")
			}
			m := problemBody(t, rr)
			if m["error_code"] != "INVALID_REQUEST" {
				t.Fatalf("error_code = %v", m["error_code"])
			}
		})
	}
}

// SOL-004: the general JSON default limit (256 KiB) caps every JSON body;
// the 4 MiB absolute ceiling stays as backstop. No contract operation may
// currently reach 4 MiB.
func TestGeneralJSONLimitBoundary(t *testing.T) {
	t.Run("256KiB exact accepted", func(t *testing.T) {
		h, p := newTestHandler(t)
		rr := submitEvidence(t, h, evidenceBodyWithTotalSize(t, 262144))
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 (body %s)", rr.Code, rr.Body.String())
		}
		if p.count("SubmitEnrollmentEvidence") != 1 {
			t.Fatal("handler was not called")
		}
	})

	for _, tc := range []struct {
		name string
		size int
	}{
		{"256KiB plus one", 262145},
		{"4MiB exact", 4 << 20},
		{"4MiB plus one", 4<<20 + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, p := newTestHandler(t)
			rr := submitEvidence(t, h, evidenceBodyWithTotalSize(t, tc.size))
			if rr.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413", rr.Code)
			}
			if p.total() != 0 {
				t.Fatal("handler ran despite oversized body")
			}
		})
	}
}

// A truncated stream (Content-Length lies about the actual bytes) is
// rejected with 400.
func TestEarlyEOFRejected(t *testing.T) {
	h, p := newTestHandler(t)
	req := httptest.NewRequest("POST", "/v1/enrollments", nil)
	req.Body = io.NopCloser(strings.NewReader(`{"op`))
	req.ContentLength = 100
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", validIdempotencyKey)
	req.Header.Set("Authorization", "Bearer "+m3TokenForRoute("POST", "/v1/enrollments"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rr.Code, rr.Body.String())
	}
	if p.total() != 0 {
		t.Fatal("handler ran despite truncated body")
	}
}

// SOL-002: operations without a request body accept only an empty body.
func TestBodylessOperationBodyPolicy(t *testing.T) {
	t.Run("content length zero allowed", func(t *testing.T) {
		h, p := newTestHandler(t)
		rr := do(t, h, "GET", "/v1/pki/trust-bundles/current", "", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
		if p.count("GetCurrentTrustBundle") != 1 {
			t.Fatal("handler was not called")
		}
	})

	t.Run("content length positive rejected", func(t *testing.T) {
		h, p := newTestHandler(t)
		rr := do(t, h, "GET", "/v1/pki/trust-bundles/current", "x", nil)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", rr.Code, rr.Body.String())
		}
		if p.total() != 0 {
			t.Fatal("handler ran despite body")
		}
	})

	t.Run("chunked empty allowed", func(t *testing.T) {
		h, p := newTestHandler(t)
		req := httptest.NewRequest("GET", "/v1/pki/trust-bundles/current", nil)
		req.Body = io.NopCloser(strings.NewReader(""))
		req.ContentLength = -1
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
		if p.count("GetCurrentTrustBundle") != 1 {
			t.Fatal("handler was not called")
		}
	})

	t.Run("chunked one byte rejected", func(t *testing.T) {
		h, p := newTestHandler(t)
		req := httptest.NewRequest("GET", "/v1/pki/trust-bundles/current", nil)
		req.Body = io.NopCloser(strings.NewReader("x"))
		req.ContentLength = -1
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
		if p.total() != 0 {
			t.Fatal("handler ran despite body")
		}
	})

	t.Run("chunked large rejected without materializing", func(t *testing.T) {
		h, p := newTestHandler(t)
		req := httptest.NewRequest("GET", "/v1/pki/trust-bundles/current", nil)
		req.Body = io.NopCloser(strings.NewReader(strings.Repeat("a", 1<<20)))
		req.ContentLength = -1
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
		if p.total() != 0 {
			t.Fatal("handler ran despite body")
		}
	})

	t.Run("GET with JSON body rejected", func(t *testing.T) {
		h, p := newTestHandler(t)
		rr := do(t, h, "GET", "/v1/pki/trust-bundles/current", `{"a":1}`, map[string]string{"Content-Type": "application/json"})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", rr.Code, rr.Body.String())
		}
		if p.total() != 0 {
			t.Fatal("handler ran despite JSON body")
		}
	})
}

// SOL-003: Content-Type cardinality. Exactly one unambiguous representation
// is accepted; duplicates, combined values and malformed parameters are 415.
func TestContentTypeCardinality(t *testing.T) {
	t.Run("two different headers", func(t *testing.T) {
		h, p := newTestHandler(t)
		req := httptest.NewRequest("POST", "/v1/enrollments", strings.NewReader(validEnrollmentBody))
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Content-Type", "application/xml")
		req.Header.Set("Idempotency-Key", validIdempotencyKey)
		req.Header.Set("Authorization", "Bearer "+m3TokenForRoute("POST", "/v1/enrollments"))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("status = %d, want 415 (body %s)", rr.Code, rr.Body.String())
		}
		if p.total() != 0 {
			t.Fatal("handler ran with ambiguous Content-Type")
		}
	})

	t.Run("two identical headers", func(t *testing.T) {
		h, p := newTestHandler(t)
		req := httptest.NewRequest("POST", "/v1/enrollments", strings.NewReader(validEnrollmentBody))
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", validIdempotencyKey)
		req.Header.Set("Authorization", "Bearer "+m3TokenForRoute("POST", "/v1/enrollments"))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("status = %d, want 415 (body %s)", rr.Code, rr.Body.String())
		}
		if p.total() != 0 {
			t.Fatal("handler ran with redundant Content-Type")
		}
	})

	t.Run("combined value", func(t *testing.T) {
		h, p := newTestHandler(t)
		rr := do(t, h, "POST", "/v1/enrollments", validEnrollmentBody, map[string]string{
			"Content-Type":    "application/json, application/xml",
			"Idempotency-Key": validIdempotencyKey,
		})
		if rr.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("status = %d, want 415 (body %s)", rr.Code, rr.Body.String())
		}
		if p.total() != 0 {
			t.Fatal("handler ran with combined Content-Type")
		}
	})

	t.Run("malformed parameter", func(t *testing.T) {
		h, p := newTestHandler(t)
		rr := do(t, h, "POST", "/v1/enrollments", validEnrollmentBody, map[string]string{
			"Content-Type":    "application/json; charset",
			"Idempotency-Key": validIdempotencyKey,
		})
		if rr.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("status = %d, want 415 (body %s)", rr.Code, rr.Body.String())
		}
		if p.total() != 0 {
			t.Fatal("handler ran with malformed Content-Type")
		}
	})

	t.Run("uppercase media type accepted", func(t *testing.T) {
		h, p := newTestHandler(t)
		rr := do(t, h, "POST", "/v1/enrollments", validEnrollmentBody, map[string]string{
			"Content-Type":    "APPLICATION/JSON",
			"Idempotency-Key": validIdempotencyKey,
		})
		if rr.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (body %s)", rr.Code, rr.Body.String())
		}
		if p.count("CreateEnrollment") != 1 {
			t.Fatal("handler was not called")
		}
	})
}

// Audit: escaped duplicate member names are detected (the tokenizer resolves
// unicode escapes, so "\u0061" and "a" are the same member).
func TestEscapedDuplicateMemberRejected(t *testing.T) {
	h, p := newTestHandler(t)
	rr := do(t, h, "POST", "/v1/enrollments",
		`{"operation":"INITIAL","\u006fperation":"RENEWAL","certificate_usage":"PARTNER_AUTH"}`, map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
		})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rr.Code, rr.Body.String())
	}
	if p.total() != 0 {
		t.Fatal("handler ran despite escaped duplicate member")
	}
}

// Audit: trailing whitespace after the JSON document is valid.
func TestTrailingWhitespaceAccepted(t *testing.T) {
	h, p := newTestHandler(t)
	rr := do(t, h, "POST", "/v1/enrollments", validEnrollmentBody+"\n\t  ", map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("CreateEnrollment") != 1 {
		t.Fatal("handler was not called")
	}
}

// Parser differential: escaped discriminator values are decoded with the same
// standard JSON semantics the generated strict server uses, so the value we
// validate is the same value the business layer will see.
func TestEscapedValuesDecodedConsistently(t *testing.T) {
	h, p := newTestHandler(t)
	rr := do(t, h, "POST", "/v1/enrollments",
		`{"operation":"INIT\u0049AL","certificate_usage":"PARTNER_AUTH"}`, map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
		})
	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("CreateEnrollment") != 1 {
		t.Fatal("handler was not called")
	}

	// The strict handler receives the decoded value: verify by echoing the
	// body through the probe? The probe does not echo; instead assert that an
	// escaped value failing the const discriminator is rejected.
	h2, p2 := newTestHandler(t)
	rr2 := do(t, h2, "POST", "/v1/enrollments",
		`{"operation":"BOG\u0055S","certificate_usage":"PARTNER_AUTH"}`, map[string]string{
			"Content-Type":    "application/json",
			"Idempotency-Key": validIdempotencyKey,
		})
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rr2.Code, rr2.Body.String())
	}
	if p2.total() != 0 {
		t.Fatal("handler ran despite const-violating escaped value")
	}
}

// Binding errors that occur in the generated wrapper BEFORE the operation
// middleware still produce RFC 9457 responses with a consistent correlation
// ID, and never reach the strict server interface.
func TestBindingErrorIsProblemJSONWithCorrelation(t *testing.T) {
	h, p := newTestHandler(t)
	rr := do(t, h, "GET", "/v1/admin/pre-onboarding-requests?page_size=abc", "", nil)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rr.Code, rr.Body.String())
	}
	if p.total() != 0 {
		t.Fatal("strict server interface was called despite binding error")
	}
	if got := rr.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want application/problem+json", got)
	}
	corr := rr.Header().Get("X-Correlation-ID")
	if corr == "" {
		t.Fatal("missing X-Correlation-ID header")
	}
	m := problemBody(t, rr)
	if m["correlation_id"] != corr {
		t.Fatalf("correlation_id = %v, header = %q", m["correlation_id"], corr)
	}
}

// Audit: the second JSON document after the first is rejected (kept from M3,
// re-asserted here with a JSON array document).
func TestSecondJSONArrayDocumentRejected(t *testing.T) {
	h, p := newTestHandler(t)
	rr := do(t, h, "POST", "/v1/enrollments", validEnrollmentBody+` [1,2]`, map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	if p.total() != 0 {
		t.Fatal("handler ran despite second document")
	}
}
