// Package httpapi raw-evidence ingress preservation (SOL-M5.8-FIXREV-001).
//
// The generated OpenAPI strict handler decodes the evidence request body into
// typed Go values; for the opaque TPM payload that decoding is
// map[string]interface{} and for agent_assertions it is a closed struct. Both
// are lossy: duplicate member information is destroyed and raw numeric lexical
// representation passes through generic Go JSON materialization before RFC 8785
// canonicalization.
//
// This file preserves the ORIGINAL admitted raw JSON value bytes for the two
// identity-bearing members — tpm_evidence.payload and agent_assertions — and
// carries them to the business handler via the request context, where they feed
// the duplicate detector and github.com/gowebpki/jcs directly. The generated
// decoder remains authoritative for schema; the raw bytes are supplementary
// trusted admission material only.
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	enrollmentapp "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi/problem"
)

// rawEvidence carries the preserved identity-bearing raw JSON value bytes for
// one evidence submission. tpmPayload holds the exact admitted bytes of
// tpm_evidence.payload. agentAssertions is nil when the member was absent and a
// non-nil RawMessage (possibly empty, e.g. "{}") when it was present, so absent
// and present-empty remain distinguishable (Protocol v0.2.6 §6.3 component 10).
type rawEvidence struct {
	tpmPayload      json.RawMessage
	agentAssertions json.RawMessage
}

type rawEvidenceContextKey struct{}

func withRawEvidence(ctx context.Context, re *rawEvidence) context.Context {
	return context.WithValue(ctx, rawEvidenceContextKey{}, re)
}

func rawEvidenceFrom(ctx context.Context) (*rawEvidence, bool) {
	re, ok := ctx.Value(rawEvidenceContextKey{}).(*rawEvidence)
	return re, ok
}

// rawEvidenceCapture is a narrow, route-scoped middleware that captures the
// already-bounded request body (the M3 enforcer runs immediately before it and
// restores a bounded in-memory copy) and extracts the raw identity-bearing JSON
// values without taking any evidence-semantic decision. It never changes public
// error precedence: the only response it can emit is an internal integrity
// failure, which is unreachable for bodies that passed M3 validation.
func (s *Server) rawEvidenceCapture() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rctx := chi.RouteContext(r.Context())
			if rctx == nil || r.Method != http.MethodPut || rctx.RoutePattern() != enrollmentapp.EvidenceSubmissionRoute {
				next.ServeHTTP(w, r)
				return
			}

			if r.Body == nil || r.Body == http.NoBody {
				problem.WriteInternal(w, r)
				return
			}

			data, err := io.ReadAll(r.Body)
			if err != nil {
				problem.WriteInternal(w, r)
				return
			}

			re, err := extractEvidenceRawValues(data)
			if err != nil || re == nil || len(re.tpmPayload) == 0 {
				// M3 already validated the document and schema, so a failure
				// here is a boundary-integrity defect, not a client error.
				problem.WriteInternal(w, r)
				return
			}

			// Restore the exact bounded bytes for the generated strict handler.
			r.Body = io.NopCloser(bytes.NewReader(data))
			r.ContentLength = int64(len(data))
			r.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(data)), nil
			}

			next.ServeHTTP(w, r.WithContext(withRawEvidence(r.Context(), re)))
		})
	}
}

// extractEvidenceRawValues walks the admitted request JSON with the tokenizer
// and captures the exact raw bytes of tpm_evidence.payload and
// agent_assertions. It fails closed on any duplicate identity-bearing container
// member (tpm_evidence, payload, agent_assertions) rather than silently picking
// one admitted value over another.
func extractEvidenceRawValues(body []byte) (*rawEvidence, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("raw evidence: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("raw evidence: root is not a JSON object")
	}

	out := &rawEvidence{}
	seenTpmEvidence := false
	seenAgentAssertions := false

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("raw evidence: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, errors.New("raw evidence: object member name is not a string")
		}

		switch key {
		case "tpm_evidence":
			if seenTpmEvidence {
				return nil, errors.New("raw evidence: duplicate tpm_evidence member")
			}
			seenTpmEvidence = true
			if err := extractTpmPayload(dec, out); err != nil {
				return nil, err
			}
		case "agent_assertions":
			if seenAgentAssertions {
				return nil, errors.New("raw evidence: duplicate agent_assertions member")
			}
			seenAgentAssertions = true
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return nil, fmt.Errorf("raw evidence: agent_assertions: %w", err)
			}
			out.agentAssertions = raw
		default:
			var discard json.RawMessage
			if err := dec.Decode(&discard); err != nil {
				return nil, fmt.Errorf("raw evidence: %w", err)
			}
		}
	}

	// Consume the closing root delimiter.
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("raw evidence: %w", err)
	}

	return out, nil
}

// extractTpmPayload descends into the tpm_evidence object and captures the raw
// bytes of its payload member. It rejects a duplicate payload member rather
// than treating the raw admission as ambiguous.
func extractTpmPayload(dec *json.Decoder, out *rawEvidence) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("raw evidence: tpm_evidence: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("raw evidence: tpm_evidence is not a JSON object")
	}

	seenPayload := false
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("raw evidence: tpm_evidence: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return errors.New("raw evidence: tpm_evidence member name is not a string")
		}

		if key == "payload" {
			if seenPayload {
				return errors.New("raw evidence: duplicate tpm_evidence.payload member")
			}
			seenPayload = true
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return fmt.Errorf("raw evidence: tpm_evidence.payload: %w", err)
			}
			out.tpmPayload = raw
			continue
		}

		var discard json.RawMessage
		if err := dec.Decode(&discard); err != nil {
			return fmt.Errorf("raw evidence: tpm_evidence: %w", err)
		}
	}

	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("raw evidence: tpm_evidence: %w", err)
	}
	return nil
}
