package application

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"unicode/utf8"

	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	"github.com/gowebpki/jcs"
)

// EvidenceSubmissionRoute is the canonical OpenAPI route template for evidence submission.
const EvidenceSubmissionRoute = "/v1/enrollments/{id}/evidence"

// EvidenceIdentityDomain is the exact normative domain-separation literal for EvidenceIdentityV1.
const EvidenceIdentityDomain = "enrollment-platform/evidence-identity"

// EvidenceIdentityVersion1 is the only identity version defined by Protocol v0.2.6.
const EvidenceIdentityVersion1 = 1

// EvidenceSubmissionCommand is the application input after HTTP transport decoding.
//
// TpmPayload and AgentAssertions carry the original admitted raw JSON value
// bytes (json.RawMessage) captured at the HTTP boundary before lossy generated
// decoding. This preserves duplicate-member information and the original
// numeric lexical representation so RFC 8785/JCS consumes the admitted bytes
// directly (SOL-M5.8-FIXREV-001). AgentAssertions is nil when the member is
// absent and a zero-length (possibly non-nil empty) RawMessage when the member
// was present but empty ("{}"), so absent and present-empty remain distinct.
type EvidenceSubmissionCommand struct {
	EnrollmentID     string
	ChallengeVersion int
	CsrDerBase64     string
	PopFormat        string
	PopJWS           string
	TpmFormat        string
	TpmVersion       string
	TpmPayload       json.RawMessage
	AgentAssertions  json.RawMessage
}

// encodeMinimalBigEndianUint encodes an unsigned integer into minimal big-endian
// bytes without leading zero octets per Protocol v0.2.6 §6.3 / OpenAPI v0.1.5.
// Zero is encoded as single byte 0x00.
func encodeMinimalBigEndianUint(v uint64) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	i := 0
	for i < len(buf) && buf[i] == 0 {
		i++
	}
	return buf[i:]
}

// validateJSONNoDuplicates verifies that b contains exactly one valid JSON value
// and that no JSON object at any nesting level contains duplicate member names.
func validateJSONNoDuplicates(b []byte) error {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 {
		return errors.New("empty JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()

	type jsonFrame struct {
		isObject    bool
		expectValue bool
		keys        map[string]struct{}
	}
	var stack []jsonFrame
	rootDone := false

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if len(stack) > 0 || !rootDone {
				return errors.New("incomplete JSON document")
			}
			return nil
		}
		if err != nil {
			return err
		}
		if rootDone {
			return errors.New("trailing data after JSON document")
		}

		if len(stack) == 0 {
			if d, ok := tok.(json.Delim); ok {
				if d == '{' {
					stack = append(stack, jsonFrame{isObject: true, keys: map[string]struct{}{}})
					continue
				}
				if d == '[' {
					stack = append(stack, jsonFrame{isObject: false})
					continue
				}
				return errors.New("unexpected delimiter")
			}
			rootDone = true
			continue
		}

		top := &stack[len(stack)-1]
		if top.isObject {
			if top.expectValue {
				if d, ok := tok.(json.Delim); ok {
					if d == '}' {
						return errors.New("object member without value")
					}
					if d == '{' {
						top.expectValue = false
						stack = append(stack, jsonFrame{isObject: true, keys: map[string]struct{}{}})
						continue
					}
					if d == '[' {
						top.expectValue = false
						stack = append(stack, jsonFrame{isObject: false})
						continue
					}
					return errors.New("unexpected delimiter")
				}
				top.expectValue = false
				continue
			}

			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				if len(stack) == 0 {
					rootDone = true
				}
				continue
			}

			key, ok := tok.(string)
			if !ok {
				return errors.New("expected string key")
			}
			if _, exists := top.keys[key]; exists {
				return fmt.Errorf("duplicate JSON member: %q", key)
			}
			top.keys[key] = struct{}{}
			top.expectValue = true
			continue
		}

		// Inside array
		if d, ok := tok.(json.Delim); ok {
			if d == ']' {
				stack = stack[:len(stack)-1]
				if len(stack) == 0 {
					rootDone = true
				}
				continue
			}
			if d == '{' {
				stack = append(stack, jsonFrame{isObject: true, keys: map[string]struct{}{}})
				continue
			}
			if d == '[' {
				stack = append(stack, jsonFrame{isObject: false})
				continue
			}
		}
	}
}

// validateJSONUnicode verifies the RFC 8785/I-JSON Unicode admission rules on
// the ORIGINAL raw JSON bytes, before any lossy Go string conversion:
//
//   - a lone high surrogate escape is rejected;
//   - a lone low surrogate escape is rejected;
//   - a high surrogate must be immediately paired with a low surrogate
//     (\uD800-\uDBFF immediately followed by \uDC00-\uDFFF);
//   - malformed/mismatched escaped surrogate pairs are rejected;
//   - raw UTF-8 inside JSON strings must be valid (including: UTF-8 must not
//     encode a surrogate code point).
//
// This prevents malformed input such as "\ud800\u0041" from being silently
// converted to U+FFFD and hashed as if it were the literal replacement
// character (SOL-M5.8-AUDIT-001). The scanner only inspects string contents; it
// is called after structural JSON validation, so it never judges malformed
// document syntax.
func validateJSONUnicode(b []byte) error {
	i, n := 0, len(b)
	inString := false
	for i < n {
		c := b[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			i++
			continue
		}
		switch {
		case c == '"':
			inString = false
			i++
		case c == '\\':
			if i+1 >= n {
				// Unterminated escape: structural validation owns this case.
				i++
				continue
			}
			if b[i+1] != 'u' {
				i += 2
				continue
			}
			if i+6 > n {
				// Truncated \u escape: structural validation owns this case.
				i += 2
				continue
			}
			v1, ok := parseJSONHex4(b[i+2 : i+6])
			if !ok {
				// Malformed hex escape: structural validation rejects it.
				i += 6
				continue
			}
			if v1 >= 0xD800 && v1 <= 0xDBFF {
				// High surrogate: the immediately following escape must be a
				// low surrogate (\uDC00-\uDFFF).
				if i+12 > n || b[i+6] != '\\' || b[i+7] != 'u' {
					return errors.New("JSON string contains a lone high surrogate")
				}
				v2, ok := parseJSONHex4(b[i+8 : i+12])
				if !ok || v2 < 0xDC00 || v2 > 0xDFFF {
					return errors.New("JSON string contains a high surrogate not paired with a low surrogate")
				}
				i += 12
				continue
			}
			if v1 >= 0xDC00 && v1 <= 0xDFFF {
				return errors.New("JSON string contains a lone low surrogate")
			}
			i += 6
		case c < 0x80:
			i++
		default:
			r, size := utf8.DecodeRune(b[i:])
			if r == utf8.RuneError && size == 1 {
				return errors.New("JSON string contains invalid UTF-8")
			}
			i += size
		}
	}
	return nil
}

// parseJSONHex4 decodes exactly four hexadecimal digits of a \u escape.
func parseJSONHex4(s []byte) (uint16, bool) {
	var v uint16
	for _, c := range s {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= uint16(c - '0')
		case c >= 'a' && c <= 'f':
			v |= uint16(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= uint16(c-'A') + 10
		default:
			return 0, false
		}
	}
	return v, true
}

// ComputeEvidenceIdentityV1 computes the deterministic EvidenceIdentityV1 SHA-256
// over the 10 ordered, domain-separated, uint32 big-endian length-framed components
// defined by Protocol v0.2.6 §6.3 and OpenAPI v0.1.5:
//
//	Component 1:  domain UTF-8 literal "enrollment-platform/evidence-identity"
//	Component 2:  identity_version minimal-big-endian (1 -> 0x01)
//	Component 3:  authoritative route-bound enrollment_id UTF-8
//	Component 4:  challenge_version minimal-big-endian integer
//	Component 5:  csr_der_sha256 raw 32-byte SHA-256 of decoded validated PKCS#10 DER
//	Component 6:  jws_compact exact UTF-8 validated JWS Compact Serialization
//	Component 7:  tpm_evidence.format validated UTF-8
//	Component 8:  tpm_evidence.version validated UTF-8
//	Component 9:  tpm_evidence.payload UTF-8 RFC 8785/JCS opaque JSON object
//	Component 10: agent_assertions zero-length when absent, otherwise UTF-8 RFC 8785/JCS complete object
func ComputeEvidenceIdentityV1(
	enrollmentID string,
	challengeVersion int,
	csrDer []byte,
	jwsCompact string,
	tpmFormat string,
	tpmVersion string,
	tpmPayload []byte,
	agentAssertions json.RawMessage,
) (idempotencyruntime.Fingerprint, []byte, error) {
	if strings.TrimSpace(enrollmentID) == "" {
		return idempotencyruntime.Fingerprint{}, nil, errors.New("evidence identity: enrollment_id is required")
	}
	if challengeVersion < 1 {
		return idempotencyruntime.Fingerprint{}, nil, errors.New("evidence identity: challenge_version must be positive")
	}
	if len(csrDer) == 0 {
		return idempotencyruntime.Fingerprint{}, nil, errors.New("evidence identity: csrDer is required")
	}
	if jwsCompact == "" {
		return idempotencyruntime.Fingerprint{}, nil, errors.New("evidence identity: jwsCompact is required")
	}
	if tpmFormat == "" || tpmVersion == "" {
		return idempotencyruntime.Fingerprint{}, nil, errors.New("evidence identity: tpmFormat and tpmVersion are required")
	}

	// 1. Canonicalize TPM payload with RFC 8785 (JCS).
	if err := validateJSONUnicode(tpmPayload); err != nil {
		return idempotencyruntime.Fingerprint{}, nil, fmt.Errorf("evidence identity: malformed TPM payload Unicode: %w", err)
	}
	if err := validateJSONNoDuplicates(tpmPayload); err != nil {
		return idempotencyruntime.Fingerprint{}, nil, fmt.Errorf("evidence identity: malformed TPM payload JSON: %w", err)
	}
	jcsTpmPayload, err := jcs.Transform(tpmPayload)
	if err != nil {
		return idempotencyruntime.Fingerprint{}, nil, fmt.Errorf("evidence identity: JCS error on TPM payload: %w", err)
	}

	// 2. Canonicalize Agent Assertions if present. The raw admitted bytes are
	// consumed directly; absent (nil) remains a zero-length component while
	// present-empty ("{}") canonicalizes to "{}".
	var jcsAgentAssertions []byte
	if agentAssertions != nil {
		trimmed := bytes.TrimSpace(agentAssertions)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			return idempotencyruntime.Fingerprint{}, nil, errors.New("evidence identity: agent_assertions must be a JSON object")
		}
		if err := validateJSONUnicode(agentAssertions); err != nil {
			return idempotencyruntime.Fingerprint{}, nil, fmt.Errorf("evidence identity: malformed agent assertions Unicode: %w", err)
		}
		if err := validateJSONNoDuplicates(agentAssertions); err != nil {
			return idempotencyruntime.Fingerprint{}, nil, fmt.Errorf("evidence identity: malformed agent assertions JSON: %w", err)
		}
		jcsAgentAssertions, err = jcs.Transform(agentAssertions)
		if err != nil {
			return idempotencyruntime.Fingerprint{}, nil, fmt.Errorf("evidence identity: JCS error on agent assertions: %w", err)
		}
	}

	// 3. Raw 32-byte SHA-256 of validated decoded PKCS#10 DER.
	csrSha256 := sha256.Sum256(csrDer)

	// 4. Assemble the 10 ordered length-framed components.
	var framedBuf bytes.Buffer
	h := sha256.New()
	mw := io.MultiWriter(h, &framedBuf)

	writeFramed := func(data []byte) {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
		mw.Write(lenBuf[:])
		mw.Write(data)
	}

	// Component 1: domain UTF-8 literal
	writeFramed([]byte(EvidenceIdentityDomain))

	// Component 2: identity_version minimal big-endian (1 -> 0x01)
	writeFramed(encodeMinimalBigEndianUint(EvidenceIdentityVersion1))

	// Component 3: authoritative enrollment_id UTF-8
	writeFramed([]byte(enrollmentID))

	// Component 4: challenge_version minimal big-endian
	writeFramed(encodeMinimalBigEndianUint(uint64(challengeVersion)))

	// Component 5: raw 32-byte SHA-256 of decoded validated PKCS#10 DER
	writeFramed(csrSha256[:])

	// Component 6: exact UTF-8 validated JWS Compact bytes
	writeFramed([]byte(jwsCompact))

	// Component 7: tpm_evidence.format UTF-8
	writeFramed([]byte(tpmFormat))

	// Component 8: tpm_evidence.version UTF-8
	writeFramed([]byte(tpmVersion))

	// Component 9: tpm_evidence.payload UTF-8 RFC 8785/JCS
	writeFramed(jcsTpmPayload)

	// Component 10: agent_assertions (zero-length if absent, otherwise JCS bytes)
	writeFramed(jcsAgentAssertions)

	var digest [32]byte
	copy(digest[:], h.Sum(nil))

	fp, err := idempotencyruntime.NewFingerprint(idempotencyruntime.FingerprintVersion1, digest)
	if err != nil {
		return idempotencyruntime.Fingerprint{}, nil, err
	}

	return fp, framedBuf.Bytes(), nil
}

// SubmitEvidence performs deterministic CSR, JWS PoP, and TPM envelope validation
// and derives the trusted EvidenceIdentityV1 before delegating to the atomic
// continuation boundary.
func (s *Service) SubmitEvidence(ctx context.Context, cmd EvidenceSubmissionCommand) (EvidenceAcceptedResult, error) {
	if err := s.Validate(); err != nil {
		return EvidenceAcceptedResult{}, ErrDependencyUnavailable
	}
	if strings.TrimSpace(cmd.EnrollmentID) == "" || cmd.EnrollmentID != strings.TrimSpace(cmd.EnrollmentID) {
		return EvidenceAcceptedResult{}, ErrDependencyUnavailable
	}
	if cmd.ChallengeVersion < 1 {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}

	// 1. CSR Base64 decode and length check under limits.
	// Protocol §6.2: CSR DER limit is 64 KiB (65536 bytes); base64 max length is 87384 chars.
	rawCsrB64 := strings.TrimSpace(cmd.CsrDerBase64)
	if len(rawCsrB64) == 0 || len(rawCsrB64) > 87384 {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	csrDer, err := base64.StdEncoding.DecodeString(rawCsrB64)
	if err != nil {
		csrDer, err = base64.RawStdEncoding.DecodeString(rawCsrB64)
		if err != nil {
			return EvidenceAcceptedResult{}, ErrEvidenceInvalid
		}
	}
	if len(csrDer) == 0 || len(csrDer) > 65536 {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}

	// 2. Parse CSR DER and validate self-signature.
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if err := csr.CheckSignature(); err != nil {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}

	// 3. Allowed key profile: initial profile requires ECDSA P-256.
	// (SOL-M5.8-POST-002: CSR self-signature algorithm is decoupled from public key profile).
	ecdsaPub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || ecdsaPub == nil || ecdsaPub.Curve != elliptic.P256() {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}

	// 4. Compute server-side CSR hash and SubjectPublicKeyInfo hash.
	csrSha256 := sha256.Sum256(csrDer)
	csrSha256Hex := hex.EncodeToString(csrSha256[:])

	spkiDer, err := x509.MarshalPKIXPublicKey(ecdsaPub)
	if err != nil {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	spkiSha256 := sha256.Sum256(spkiDer)
	spkiSha256Hex := hex.EncodeToString(spkiSha256[:])

	// 5. JWS PoP format and compact serialization structure.
	if cmd.PopFormat != PopFormatEnrollmentJWS {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	jwsParts := strings.Split(cmd.PopJWS, ".")
	if len(jwsParts) != 3 {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	headerBytes, err := decodeBase64URL(jwsParts[0])
	if err != nil || len(headerBytes) == 0 {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	payloadBytes, err := decodeBase64URL(jwsParts[1])
	if err != nil || len(payloadBytes) == 0 {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	sigBytes, err := decodeBase64URL(jwsParts[2])
	if err != nil || len(sigBytes) != 64 {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}

	// 6. Protected Header rules:
	// - Must be a JSON object without duplicate member names (SOL-M5.8-POST-003);
	// - Prohibit client-controlled verification authority headers (jwk, jku, x5u, x5c);
	// - Prohibit unknown critical headers (crit);
	// - alg must be exactly "ES256";
	// - typ must be exactly "enrollment-pop+jws".
	if !bytes.HasPrefix(bytes.TrimSpace(headerBytes), []byte("{")) {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if err := validateJSONUnicode(headerBytes); err != nil {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if err := validateJSONNoDuplicates(headerBytes); err != nil {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	var rawHeader map[string]json.RawMessage
	if err := json.Unmarshal(headerBytes, &rawHeader); err != nil {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if _, has := rawHeader["jwk"]; has {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if _, has := rawHeader["jku"]; has {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if _, has := rawHeader["x5u"]; has {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if _, has := rawHeader["x5c"]; has {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if _, has := rawHeader["crit"]; has {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	var hdr struct {
		Alg *string `json:"alg"`
		Typ *string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if hdr.Alg == nil || *hdr.Alg != "ES256" || hdr.Typ == nil || *hdr.Typ != PopFormatEnrollmentJWS {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}

	// 7. Verify JWS ES256 signature using the public key from the CSR.
	r := new(big.Int).SetBytes(sigBytes[:32])
	sVal := new(big.Int).SetBytes(sigBytes[32:])
	if r.Sign() <= 0 || sVal.Sign() <= 0 {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	signingInput := []byte(jwsParts[0] + "." + jwsParts[1])
	sigDigest := sha256.Sum256(signingInput)
	if !ecdsa.Verify(ecdsaPub, sigDigest[:], r, sVal) {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}

	// 8. Protected Payload JSON rules:
	// - Must be a JSON object without duplicate member names (SOL-M5.8-POST-003);
	// - Must satisfy RFC 8785/I-JSON Unicode admission (SOL-M5.8-AUDIT-001);
	// - version == 1;
	// - purpose == "enrollment-pop";
	// - enrollment_id == cmd.EnrollmentID;
	// - challenge_version == cmd.ChallengeVersion;
	// - csr_sha256 == csrSha256Hex;
	// - public_key_sha256 == spkiSha256Hex;
	// - nonce non-empty valid base64url string.
	if !bytes.HasPrefix(bytes.TrimSpace(payloadBytes), []byte("{")) {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if err := validateJSONUnicode(payloadBytes); err != nil {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if err := validateJSONNoDuplicates(payloadBytes); err != nil {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	var popPayload struct {
		Version          *int    `json:"version"`
		Purpose          *string `json:"purpose"`
		EnrollmentID     *string `json:"enrollment_id"`
		ChallengeVersion *int    `json:"challenge_version"`
		Nonce            *string `json:"nonce"`
		CsrSha256        *string `json:"csr_sha256"`
		PublicKeySha256  *string `json:"public_key_sha256"`
	}
	if err := json.Unmarshal(payloadBytes, &popPayload); err != nil {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if popPayload.Version == nil || *popPayload.Version != 1 {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if popPayload.Purpose == nil || *popPayload.Purpose != "enrollment-pop" {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if popPayload.EnrollmentID == nil || *popPayload.EnrollmentID != cmd.EnrollmentID {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if popPayload.ChallengeVersion == nil || *popPayload.ChallengeVersion != cmd.ChallengeVersion {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if popPayload.CsrSha256 == nil || *popPayload.CsrSha256 != csrSha256Hex {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if popPayload.PublicKeySha256 == nil || *popPayload.PublicKeySha256 != spkiSha256Hex {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if popPayload.Nonce == nil || strings.TrimSpace(*popPayload.Nonce) == "" {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if _, err := decodeBase64URL(*popPayload.Nonce); err != nil {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}

	// 9. TPM Evidence Envelope structure check.
	// OPEN-004A remains OPEN: payload is opaque JSON object.
	if cmd.TpmFormat != "enrollment-tpm-evidence" || strings.TrimSpace(cmd.TpmVersion) == "" || len(cmd.TpmPayload) == 0 {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if err := validateJSONUnicode(cmd.TpmPayload); err != nil {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if err := validateJSONNoDuplicates(cmd.TpmPayload); err != nil {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	var tpmPayloadMap map[string]interface{}
	if err := json.Unmarshal(cmd.TpmPayload, &tpmPayloadMap); err != nil || tpmPayloadMap == nil {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}

	// 9a. Agent Assertions raw admission check: when present, the admitted
	// bytes must be a Unicode-clean (RFC 8785/I-JSON), duplicate-free JSON
	// object before JCS. Absent (nil) is handled as a zero-length identity
	// component inside ComputeEvidenceIdentityV1.
	if cmd.AgentAssertions != nil {
		trimmedAA := bytes.TrimSpace(cmd.AgentAssertions)
		if len(trimmedAA) == 0 || trimmedAA[0] != '{' {
			return EvidenceAcceptedResult{}, ErrEvidenceInvalid
		}
		if err := validateJSONUnicode(cmd.AgentAssertions); err != nil {
			return EvidenceAcceptedResult{}, ErrEvidenceInvalid
		}
		if err := validateJSONNoDuplicates(cmd.AgentAssertions); err != nil {
			return EvidenceAcceptedResult{}, ErrEvidenceInvalid
		}
	}

	// 10. Derive canonical EvidenceIdentityV1 (SOL-M5.8-POST-001).
	// All client-controlled RFC 8785/I-JSON admission rules (Unicode, duplicates,
	// object shape, numeric range) were already enforced above with 422
	// EVIDENCE_INVALID; a failure here is therefore an internal/dependency
	// classification, mapped to 503 DEPENDENCY_UNAVAILABLE.
	fp, repBytes, err := ComputeEvidenceIdentityV1(
		cmd.EnrollmentID,
		cmd.ChallengeVersion,
		csrDer,
		cmd.PopJWS,
		cmd.TpmFormat,
		cmd.TpmVersion,
		cmd.TpmPayload,
		cmd.AgentAssertions,
	)
	if err != nil {
		return EvidenceAcceptedResult{}, ErrDependencyUnavailable
	}

	// 11. Atomic acceptance inside transaction-bound UnitOfWork.
	return s.AcceptEvidence(ctx, EvidenceAcceptanceCommand{
		EnrollmentID:             cmd.EnrollmentID,
		ExpectedChallengeVersion: cmd.ChallengeVersion,
		Fingerprint:              fp,
		Representation:           repBytes,
		PopNonce:                 *popPayload.Nonce,
		Material: &EvaluationMaterial{
			CSRSha256:       csrSha256Hex,
			PublicKeySha256: spkiSha256Hex,
			TPMFormat:       cmd.TpmFormat,
			TPMVersion:      cmd.TpmVersion,
			TPMPayload:      cmd.TpmPayload,
			AgentAssertions: cmd.AgentAssertions,
		},
	})
}

func decodeBase64URL(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.URLEncoding.DecodeString(s)
	}
	return b, err
}
