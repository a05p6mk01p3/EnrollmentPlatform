// Package problem implements RFC 9457 Problem Details writing for the
// Enrollment API (Protocol v0.2.2 §5; OpenAPI v0.1.1 ProblemDetail schema).
//
// The writer only serializes the fields it is given. It never emits stack
// traces, tokens, credentials, private keys or TPM private material (SP-08).
// It also owns the correlation-id request context, since the writer and the
// correlation middleware both need it.
package problem

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
)

// Type URIs follow the contract examples (OpenAPI v0.1.1 components/responses).
const (
	TypeInvalidRequest               = "https://pki.example/errors/invalid-request"
	TypePayloadTooLarge              = "https://pki.example/errors/payload-too-large"
	TypeUnsupportedMediaType         = "https://pki.example/errors/unsupported-media-type"
	TypeAuthenticationRequired       = "https://pki.example/errors/authentication-required"
	TypeScopeDenied                  = "https://pki.example/errors/scope-denied"
	TypePartnerNotAuthorized         = "https://pki.example/errors/partner-not-authorized"
	TypeResourceNotFound             = "https://pki.example/errors/resource-not-found"
	TypeResourceExpired              = "https://pki.example/errors/resource-expired"
	TypeStateConflict                = "https://pki.example/errors/state-conflict"
	TypeIdempotencyConflict          = "https://pki.example/errors/idempotency-conflict"
	TypeIdempotencyReplayUnavailable = "https://pki.example/errors/idempotency-replay-unavailable"
	TypePreconditionFailed           = "https://pki.example/errors/precondition-failed"
	TypeDependencyUnavailable        = "https://pki.example/errors/dependency-unavailable"
	// TypeInternalError is infrastructure-only (server bug); it is not a
	// contract machine code and must not be relied upon by clients.
	TypeInternalError = "https://pki.example/errors/internal-error"
)

type correlationKey struct{}

// WithCorrelationID stores the correlation identifier in ctx.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationKey{}, id)
}

// CorrelationID returns the correlation identifier stored in ctx, or "".
func CorrelationID(ctx context.Context) string {
	id, _ := ctx.Value(correlationKey{}).(string)
	return id
}

// Problem is an RFC 9457 problem detail plus the protocol's domain extensions
// (error_code, correlation_id, retryable, retry_after_seconds).
type Problem struct {
	Type      string
	Title     string
	Status    int
	Detail    string
	ErrorCode string
	Retryable bool
	// RetryAfterSeconds, when non-nil, is emitted in the body and also as the
	// Retry-After header.
	RetryAfterSeconds *int
	// WWWAuthenticate, when non-empty, is emitted as the WWW-Authenticate
	// header (e.g. "Bearer" for bearer 401 responses; Protocol v0.2.2 §4.2).
	WWWAuthenticate string
}

// Write emits the problem as application/problem+json. instance defaults to
// the request path; correlation_id comes from the request context.
func Write(w http.ResponseWriter, r *http.Request, p Problem) {
	if p.WWWAuthenticate != "" {
		w.Header().Set("WWW-Authenticate", p.WWWAuthenticate)
	}
	corr := CorrelationID(r.Context())
	if corr != "" {
		w.Header().Set("X-Correlation-ID", corr)
	}
	if p.RetryAfterSeconds != nil {
		w.Header().Set("Retry-After", strconv.Itoa(*p.RetryAfterSeconds))
	}

	instance := ""
	if r != nil && r.URL != nil {
		instance = r.URL.Path
	}

	body := struct {
		Type              string `json:"type"`
		Title             string `json:"title"`
		Status            int    `json:"status"`
		Detail            string `json:"detail,omitempty"`
		Instance          string `json:"instance,omitempty"`
		ErrorCode         string `json:"error_code"`
		CorrelationID     string `json:"correlation_id"`
		Retryable         bool   `json:"retryable"`
		RetryAfterSeconds *int   `json:"retry_after_seconds,omitempty"`
	}{
		Type:              p.Type,
		Title:             p.Title,
		Status:            p.Status,
		Detail:            p.Detail,
		Instance:          instance,
		ErrorCode:         p.ErrorCode,
		CorrelationID:     corr,
		Retryable:         p.Retryable,
		RetryAfterSeconds: p.RetryAfterSeconds,
	}

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(body)
}

// WriteInvalidRequest emits 400 INVALID_REQUEST.
func WriteInvalidRequest(w http.ResponseWriter, r *http.Request, detail string) {
	Write(w, r, Problem{
		Type:      TypeInvalidRequest,
		Title:     "Invalid request",
		Status:    http.StatusBadRequest,
		Detail:    detail,
		ErrorCode: "INVALID_REQUEST",
	})
}

// WritePayloadTooLarge emits 413 PAYLOAD_TOO_LARGE.
func WritePayloadTooLarge(w http.ResponseWriter, r *http.Request) {
	Write(w, r, Problem{
		Type:      TypePayloadTooLarge,
		Title:     "Payload too large",
		Status:    http.StatusRequestEntityTooLarge,
		ErrorCode: "PAYLOAD_TOO_LARGE",
	})
}

// WriteUnsupportedMediaType emits 415 UNSUPPORTED_MEDIA_TYPE.
func WriteUnsupportedMediaType(w http.ResponseWriter, r *http.Request) {
	Write(w, r, Problem{
		Type:      TypeUnsupportedMediaType,
		Title:     "Unsupported media type",
		Status:    http.StatusUnsupportedMediaType,
		ErrorCode: "UNSUPPORTED_MEDIA_TYPE",
	})
}

// WriteUnauthorizedBearer emits 401 AUTHENTICATION_REQUIRED with
// WWW-Authenticate: Bearer (Protocol v0.2.2 §4.2).
func WriteUnauthorizedBearer(w http.ResponseWriter, r *http.Request) {
	Write(w, r, Problem{
		Type:            TypeAuthenticationRequired,
		Title:           "Authentication required",
		Status:          http.StatusUnauthorized,
		ErrorCode:       "AUTHENTICATION_REQUIRED",
		WWWAuthenticate: "Bearer",
	})
}

// WriteUnauthorized emits 401 AUTHENTICATION_REQUIRED without a
// WWW-Authenticate header (for authentication failures that are not bearer
// credential challenges).
func WriteUnauthorized(w http.ResponseWriter, r *http.Request) {
	Write(w, r, Problem{
		Type:      TypeAuthenticationRequired,
		Title:     "Authentication required",
		Status:    http.StatusUnauthorized,
		ErrorCode: "AUTHENTICATION_REQUIRED",
	})
}

// WriteScopeDenied emits 403 SCOPE_DENIED (Access denied), the contracted
// response when an authenticated request lacks required domain scope or policy approval.
func WriteScopeDenied(w http.ResponseWriter, r *http.Request) {
	Write(w, r, Problem{
		Type:      TypeScopeDenied,
		Title:     "Access denied",
		Status:    http.StatusForbidden,
		ErrorCode: "SCOPE_DENIED",
	})
}

// WritePartnerNotAuthorized emits 403 PARTNER_NOT_AUTHORIZED, the contracted
// response when the requested partner is not present in the principal's
// current effective partner authorization set.
func WritePartnerNotAuthorized(w http.ResponseWriter, r *http.Request) {
	Write(w, r, Problem{
		Type:      TypePartnerNotAuthorized,
		Title:     "Access denied",
		Status:    http.StatusForbidden,
		ErrorCode: "PARTNER_NOT_AUTHORIZED",
	})
}

// WriteResourceNotFound emits 404 RESOURCE_NOT_FOUND.
func WriteResourceNotFound(w http.ResponseWriter, r *http.Request) {
	Write(w, r, Problem{
		Type:      TypeResourceNotFound,
		Title:     "Resource not found",
		Status:    http.StatusNotFound,
		ErrorCode: "RESOURCE_NOT_FOUND",
	})
}

// WriteResourceExpired emits 410 RESOURCE_EXPIRED.
func WriteResourceExpired(w http.ResponseWriter, r *http.Request) {
	Write(w, r, Problem{
		Type:      TypeResourceExpired,
		Title:     "Resource expired",
		Status:    http.StatusGone,
		ErrorCode: "RESOURCE_EXPIRED",
	})
}

// WritePreconditionFailed emits 412 PRECONDITION_FAILED.
func WritePreconditionFailed(w http.ResponseWriter, r *http.Request, detail string) {
	Write(w, r, Problem{
		Type:      TypePreconditionFailed,
		Title:     "Precondition failed",
		Status:    http.StatusPreconditionFailed,
		Detail:    detail,
		ErrorCode: "PRECONDITION_FAILED",
	})
}

// WriteStateConflict emits 409 STATE_CONFLICT.
func WriteStateConflict(w http.ResponseWriter, r *http.Request, detail string) {
	Write(w, r, Problem{
		Type:      TypeStateConflict,
		Title:     "State conflict",
		Status:    http.StatusConflict,
		Detail:    detail,
		ErrorCode: "STATE_CONFLICT",
	})
}

// WriteIdempotencyConflict emits 409 IDEMPOTENCY_CONFLICT.
func WriteIdempotencyConflict(w http.ResponseWriter, r *http.Request, detail string) {
	Write(w, r, Problem{
		Type:      TypeIdempotencyConflict,
		Title:     "Idempotency conflict",
		Status:    http.StatusConflict,
		Detail:    detail,
		ErrorCode: "IDEMPOTENCY_CONFLICT",
	})
}

// WriteServiceUnavailable emits 503 DEPENDENCY_UNAVAILABLE (retryable), the
// contracted response for a dependency the platform needs but cannot reach.
func WriteServiceUnavailable(w http.ResponseWriter, r *http.Request) {
	Write(w, r, Problem{
		Type:      TypeDependencyUnavailable,
		Title:     "Dependency unavailable",
		Status:    http.StatusServiceUnavailable,
		ErrorCode: "DEPENDENCY_UNAVAILABLE",
		Retryable: true,
	})
}

// WriteInternal emits a generic 500 without internal detail (SP-08).
func WriteInternal(w http.ResponseWriter, r *http.Request) {
	Write(w, r, Problem{
		Type:      TypeInternalError,
		Title:     "Internal server error",
		Status:    http.StatusInternalServerError,
		ErrorCode: "INTERNAL_ERROR",
	})
}
