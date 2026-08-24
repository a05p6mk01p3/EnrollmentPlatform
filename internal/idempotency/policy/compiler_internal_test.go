package policy

import (
	"errors"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
)

func reasonOf(err error) Reason {
	var ce *CompileError
	if !errors.As(err, &ce) {
		return ""
	}
	return ce.Reason
}

func TestDetectIdempotencyKeyUnresolvedParameterFailsClosed(t *testing.T) {
	spec, err := openapi.GetSpec()
	if err != nil {
		t.Fatalf("GetSpec: %v", err)
	}
	op := &openapi3.Operation{
		OperationID: "unresolvedTest",
		Parameters: openapi3.Parameters{
			{Ref: "#/components/parameters/DoesNotExist", Value: nil},
		},
	}
	if _, err := detectIdempotencyKey(nil, op, spec); err == nil {
		t.Fatal("expected error for unresolved parameter reference, got nil")
	} else if got := reasonOf(err); got != ReasonUnresolvedParameter {
		t.Fatalf("reason = %s, want %s", got, ReasonUnresolvedParameter)
	}
}

func TestParseSecretReplayWrongSameSecretType(t *testing.T) {
	op := &openapi3.Operation{
		Extensions: map[string]any{
			"x-idempotent-secret-replay": map[string]any{
				"secretField":           "enrollment_access_token",
				"mechanism":             "encrypted-idempotency-replay-capsule",
				"sameSecretRequired":    "yes",
				"activeVerifierStorage": "non-reversible",
				"capsulePurpose":        "response-loss-recovery-only",
			},
		},
	}
	if _, err := parseSecretReplay(op); err == nil {
		t.Fatal("expected error for non-boolean sameSecretRequired, got nil")
	} else if got := reasonOf(err); got != ReasonMalformedSecretReplay {
		t.Fatalf("reason = %s, want %s", got, ReasonMalformedSecretReplay)
	}
}
