// Package middleware hosts the handwritten HTTP middleware of the
// Enrollment API: correlation identifiers and OpenAPI contract enforcement.
//
// The middleware runs BEFORE the generated chi router and strict handlers, so
// invalid requests are rejected before any business logic or expensive parsing
// occurs.
package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi/problem"
)

const (
	correlationHeader = "X-Correlation-ID"
	// Length bound per OpenAPI v0.1.1 components/parameters/CorrelationId.
	correlationMaxLen = 4096
)

// Correlation ensures every request carries a valid X-Correlation-ID
// (Protocol v0.2.2 §4.3): provided values are validated and propagated; absent
// values are generated server-side. The value is exposed through the request
// context for downstream layers and is always echoed in the response.
func Correlation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(correlationHeader)

		if id != "" && !validCorrelationID(id) {
			// A provided value must pass format/length validation (Protocol
			// v0.2.2 §4.2). Answer with a fresh server-generated identifier.
			fresh, err := newCorrelationID()
			if err != nil {
				problem.WriteInternal(w, r)
				return
			}
			r = r.WithContext(problem.WithCorrelationID(r.Context(), fresh))
			w.Header().Set(correlationHeader, fresh)
			problem.WriteInvalidRequest(w, r, "X-Correlation-ID header is invalid")
			return
		}

		if id == "" {
			var err error
			if id, err = newCorrelationID(); err != nil {
				problem.WriteInternal(w, r)
				return
			}
		}

		r = r.WithContext(problem.WithCorrelationID(r.Context(), id))
		w.Header().Set(correlationHeader, id)
		next.ServeHTTP(w, r)
	})
}

// newCorrelationID returns a random hex identifier (128 bits of entropy).
func newCorrelationID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// validCorrelationID accepts printable ASCII (0x20..0x7E) of length 1..4096.
// Control characters (including CR/LF) are rejected to keep logs safe.
func validCorrelationID(id string) bool {
	if len(id) == 0 || len(id) > correlationMaxLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x20 || id[i] > 0x7E {
			return false
		}
	}
	return true
}
