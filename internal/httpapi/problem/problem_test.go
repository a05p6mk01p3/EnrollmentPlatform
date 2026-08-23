package problem

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newRequest(path string) *http.Request {
	return httptest.NewRequest("POST", path, nil)
}

func TestWriteProblemFullShape(t *testing.T) {
	r := newRequest("/v1/enrollments")
	r = r.WithContext(WithCorrelationID(r.Context(), "corr-42"))
	retry := 3

	rr := httptest.NewRecorder()
	Write(rr, r, Problem{
		Type:              "https://pki.example/errors/rate-limited",
		Title:             "Rate limited",
		Status:            http.StatusTooManyRequests,
		Detail:            "try later",
		ErrorCode:         "RATE_LIMITED",
		Retryable:         true,
		RetryAfterSeconds: &retry,
	})

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := rr.Header().Get("X-Correlation-ID"); got != "corr-42" {
		t.Fatalf("X-Correlation-ID = %q", got)
	}
	if got := rr.Header().Get("Retry-After"); got != "3" {
		t.Fatalf("Retry-After = %q", got)
	}

	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if m["type"] != "https://pki.example/errors/rate-limited" {
		t.Errorf("type = %v", m["type"])
	}
	if m["title"] != "Rate limited" {
		t.Errorf("title = %v", m["title"])
	}
	if m["status"] != float64(429) {
		t.Errorf("status = %v", m["status"])
	}
	if m["detail"] != "try later" {
		t.Errorf("detail = %v", m["detail"])
	}
	if m["instance"] != "/v1/enrollments" {
		t.Errorf("instance = %v", m["instance"])
	}
	if m["error_code"] != "RATE_LIMITED" {
		t.Errorf("error_code = %v", m["error_code"])
	}
	if m["correlation_id"] != "corr-42" {
		t.Errorf("correlation_id = %v", m["correlation_id"])
	}
	if m["retryable"] != true {
		t.Errorf("retryable = %v", m["retryable"])
	}
	if m["retry_after_seconds"] != float64(3) {
		t.Errorf("retry_after_seconds = %v", m["retry_after_seconds"])
	}
}

func TestWriteProblemOmitsEmptyOptionalFields(t *testing.T) {
	r := newRequest("/x")
	r = r.WithContext(WithCorrelationID(r.Context(), "c"))

	rr := httptest.NewRecorder()
	Write(rr, r, Problem{
		Type:      TypeInvalidRequest,
		Title:     "Invalid request",
		Status:    http.StatusBadRequest,
		ErrorCode: "INVALID_REQUEST",
	})

	var raw map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	for _, absent := range []string{"detail", "retry_after_seconds"} {
		if _, ok := raw[absent]; ok {
			t.Errorf("optional field %q must be omitted when empty", absent)
		}
	}
}

func TestWriteUnauthorizedBearer(t *testing.T) {
	r := newRequest("/v1/me/authorizations")
	r = r.WithContext(WithCorrelationID(r.Context(), "c"))

	rr := httptest.NewRecorder()
	WriteUnauthorizedBearer(rr, r)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q, want %q", got, "Bearer")
	}
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if m["error_code"] != "AUTHENTICATION_REQUIRED" {
		t.Fatalf("error_code = %v", m["error_code"])
	}
}

func TestWriteInternalLeaksNoDetail(t *testing.T) {
	r := newRequest("/x")
	r = r.WithContext(WithCorrelationID(r.Context(), "c"))

	rr := httptest.NewRecorder()
	WriteInternal(rr, r)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rr.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if _, ok := m["detail"]; ok {
		t.Fatal("internal errors must not carry detail")
	}
	if m["error_code"] != "INTERNAL_ERROR" {
		t.Fatalf("error_code = %v", m["error_code"])
	}
}

func TestWriteScopeDenied(t *testing.T) {
	r := newRequest("/v1/admin/pre-onboarding-requests")
	r = r.WithContext(WithCorrelationID(r.Context(), "corr-scope-denied"))

	rr := httptest.NewRecorder()
	WriteScopeDenied(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("WWW-Authenticate = %q, want empty", got)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := rr.Header().Get("X-Correlation-ID"); got != "corr-scope-denied" {
		t.Fatalf("X-Correlation-ID = %q", got)
	}

	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if m["type"] != TypeScopeDenied {
		t.Errorf("type = %v, want %s", m["type"], TypeScopeDenied)
	}
	if m["title"] != "Access denied" {
		t.Errorf("title = %v", m["title"])
	}
	if m["status"] != float64(http.StatusForbidden) {
		t.Errorf("status = %v", m["status"])
	}
	if m["error_code"] != "SCOPE_DENIED" {
		t.Errorf("error_code = %v", m["error_code"])
	}
	if m["retryable"] != false {
		t.Errorf("retryable = %v, want false", m["retryable"])
	}
}

func TestCorrelationIDContextRoundTrip(t *testing.T) {
	ctx := WithCorrelationID(context.Background(), "abc-123")
	if got := CorrelationID(ctx); got != "abc-123" {
		t.Fatalf("CorrelationID = %q", got)
	}
	if got := CorrelationID(context.Background()); got != "" {
		t.Fatalf("CorrelationID(empty) = %q, want empty", got)
	}
}
