package httpapi_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
)

// SOL-M5.8-AUDIT-006 A–F: raw HTTP Unicode/I-JSON admission at the real HTTP
// boundary. The malformed bodies are spliced as literal raw JSON text (escaped
// \u sequences), never constructed via json.Marshal, so the decoder really
// receives the malformed surrogate escapes.
func TestM58Fix003UnicodeAdmissionHTTP(t *testing.T) {
	t.Run("A: malformed high+non-low surrogate pair in TPM payload", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)
		body := m58EvidenceBodyWithRaw(t, h, jws, `{"x":"\ud800\u0041"}`, nil)
		rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, m58Fix002Auth(h))
		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status=%d want=422 body=%s", rr.Code, rr.Body.String())
		}
		if code := m58Fix002ErrorCode(t, rr.Body.Bytes()); code != "EVIDENCE_INVALID" {
			t.Fatalf("error_code=%q want EVIDENCE_INVALID", code)
		}
	})

	t.Run("B: lone high surrogate in TPM payload", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)
		body := m58EvidenceBodyWithRaw(t, h, jws, `{"x":"\ud800"}`, nil)
		rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, m58Fix002Auth(h))
		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status=%d want=422 body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("C: lone low surrogate in TPM payload", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)
		body := m58EvidenceBodyWithRaw(t, h, jws, `{"x":"\udc00"}`, nil)
		rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, m58Fix002Auth(h))
		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status=%d want=422 body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("D: valid surrogate pair is admitted", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)
		body := m58EvidenceBodyWithRaw(t, h, jws, `{"x":"\ud83d\ude00"}`, nil)
		rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, m58Fix002Auth(h))
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status=%d want=202 body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("E: malformed surrogate never collides with literal U+FFFD identity", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)

		// Literal U+FFFD is admissible and is accepted first.
		literal := m58EvidenceBodyWithRaw(t, h, jws, `{"x":"\ufffd"}`, nil)
		rr1 := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", literal, m58Fix002Auth(h))
		if rr1.Code != http.StatusAccepted {
			t.Fatalf("literal U+FFFD status=%d want=202 body=%s", rr1.Code, rr1.Body.String())
		}

		// The malformed form must be REJECTED, not replayed as the accepted
		// literal-U+FFFD identity (that would be a 202) and not silently
		// hashed after conversion to U+FFFD.
		malformed := m58EvidenceBodyWithRaw(t, h, jws, `{"x":"\ud800\u0041"}`, nil)
		rr2 := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", malformed, m58Fix002Auth(h))
		if rr2.Code != http.StatusUnprocessableEntity {
			t.Fatalf("malformed status=%d want=422 body=%s", rr2.Code, rr2.Body.String())
		}
	})

	t.Run("F: malformed Unicode inside agent_assertions", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		jws := h.helper.buildJWS(t, h.enrollmentID, h.activeNonce, 1, nil, nil)
		aa := `{"provider":"\ud800\u0041"}`
		body := m58EvidenceBodyWithRaw(t, h, jws, `{"p":1}`, &aa)
		rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, m58Fix002Auth(h))
		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status=%d want=422 body=%s", rr.Code, rr.Body.String())
		}
		if code := m58Fix002ErrorCode(t, rr.Body.Bytes()); code != "EVIDENCE_INVALID" {
			t.Fatalf("error_code=%q want EVIDENCE_INVALID", code)
		}
	})

	t.Run("malformed surrogate inside JWS protected payload is rejected", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		// Build the JWS by hand so the protected payload carries the malformed
		// escape and the ES256 signature still covers the exact bytes.
		hdrJSON := []byte(`{"alg":"ES256","typ":"enrollment-pop+jws"}`)
		hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
		plJSON := []byte(fmt.Sprintf(`{"version":1,"purpose":"enrollment-pop","enrollment_id":%q,"challenge_version":1,"nonce":%q,"csr_sha256":%q,"public_key_sha256":%q,"x":"\ud800\u0041"}`,
			h.enrollmentID, h.activeNonce, h.helper.csrSha256Hex, h.helper.publicKeySha256Hex))
		plB64 := base64.RawURLEncoding.EncodeToString(plJSON)
		digest := sha256.Sum256([]byte(hdrB64 + "." + plB64))
		r, sVal, _ := ecdsa.Sign(rand.Reader, h.helper.priv, digest[:])
		rB := make([]byte, 32)
		sB := make([]byte, 32)
		r.FillBytes(rB)
		sVal.FillBytes(sB)
		sigB64 := base64.RawURLEncoding.EncodeToString(append(rB, sB...))
		jws := hdrB64 + "." + plB64 + "." + sigB64

		body := fmt.Sprintf(`{
			"challenge_version": 1,
			"csr_der_base64": %q,
			"pop": {"format": "enrollment-pop+jws", "jws": %q},
			"tpm_evidence": {"format": "enrollment-tpm-evidence", "version": "1", "payload": {}}
		}`, h.helper.csrB64, jws)

		rr := h.put("/v1/enrollments/"+h.enrollmentID+"/evidence", body, m58Fix002Auth(h))
		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status=%d want=422 body=%s", rr.Code, rr.Body.String())
		}
	})
}

// SOL-M5.8-AUDIT-006 I–J: CR-M5.8-002 regression through HTTP.
func TestM58Fix003RefreshReplayRegression(t *testing.T) {
	t.Run("I: replay returns original 200 after old challenge expiry", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		body := `{"expected_challenge_version": 1}`
		key := "fix003-refresh-replay-001"

		first := h.post("/v1/enrollments/"+h.enrollmentID+"/challenge:refresh", body, map[string]string{
			"Authorization":   "Bearer " + h.enrollmentToken,
			"Idempotency-Key": key,
		})
		if first.Code != http.StatusOK {
			t.Fatalf("first status=%d want=200 body=%s", first.Code, first.Body.String())
		}
		var original openapi.ChallengeRefreshResponse
		if err := json.Unmarshal(first.Body.Bytes(), &original); err != nil {
			t.Fatal(err)
		}

		// Advance past the challenge lifetime (20m) but keep EAT (1h) and the
		// committed idempotency record (1h) valid.
		h.clock.Set(h.clock.Now().Add(30 * time.Minute))

		replay := h.post("/v1/enrollments/"+h.enrollmentID+"/challenge:refresh", body, map[string]string{
			"Authorization":   "Bearer " + h.enrollmentToken,
			"Idempotency-Key": key,
		})
		if replay.Code != http.StatusOK {
			t.Fatalf("replay status=%d want=200 body=%s", replay.Code, replay.Body.String())
		}
		var replayed openapi.ChallengeRefreshResponse
		if err := json.Unmarshal(replay.Body.Bytes(), &replayed); err != nil {
			t.Fatal(err)
		}
		if replayed.Challenge.Nonce != original.Challenge.Nonce ||
			replayed.Challenge.ChallengeVersion != original.Challenge.ChallengeVersion {
			t.Fatalf("replay changed challenge: original=%#v replay=%#v", original.Challenge, replayed.Challenge)
		}
	})

	t.Run("J: expired EAT is 401 before replay", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		body := `{"expected_challenge_version": 1}`
		key := "fix003-refresh-replay-002"

		first := h.post("/v1/enrollments/"+h.enrollmentID+"/challenge:refresh", body, map[string]string{
			"Authorization":   "Bearer " + h.enrollmentToken,
			"Idempotency-Key": key,
		})
		if first.Code != http.StatusOK {
			t.Fatalf("first status=%d want=200 body=%s", first.Code, first.Body.String())
		}

		// Advance past the EAT lifetime (1h): the committed replay record
		// still exists, but authentication must fail first.
		h.clock.Set(h.clock.Now().Add(2 * time.Hour))
		replay := h.post("/v1/enrollments/"+h.enrollmentID+"/challenge:refresh", body, map[string]string{
			"Authorization":   "Bearer " + h.enrollmentToken,
			"Idempotency-Key": key,
		})
		if replay.Code != http.StatusUnauthorized {
			t.Fatalf("expired EAT replay status=%d want=401 body=%s", replay.Code, replay.Body.String())
		}
	})

	t.Run("J: invalid EAT is 401 before replay", func(t *testing.T) {
		h := newM58HTTPHarness(t)
		body := `{"expected_challenge_version": 1}`
		key := "fix003-refresh-replay-003"

		first := h.post("/v1/enrollments/"+h.enrollmentID+"/challenge:refresh", body, map[string]string{
			"Authorization":   "Bearer " + h.enrollmentToken,
			"Idempotency-Key": key,
		})
		if first.Code != http.StatusOK {
			t.Fatalf("first status=%d want=200 body=%s", first.Code, first.Body.String())
		}

		replay := h.post("/v1/enrollments/"+h.enrollmentID+"/challenge:refresh", body, map[string]string{
			"Authorization":   "Bearer not-a-valid-eat-token",
			"Idempotency-Key": key,
		})
		if replay.Code != http.StatusUnauthorized {
			t.Fatalf("invalid EAT replay status=%d want=401 body=%s", replay.Code, replay.Body.String())
		}
	})
}
