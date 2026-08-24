package policy

import (
	"errors"
	"fmt"
)

// Reason is a typed, machine-checkable classification of a compile failure.
// It is the semantic API of CompileError; tests must match on Reason (via
// errors.As) rather than on human-readable message strings.
type Reason string

const (
	// ReasonMissingOperationID: an operation has a missing, empty, or
	// whitespace-only operationId.
	ReasonMissingOperationID Reason = "missing_operation_id"

	// ReasonDuplicateOperationID: two paths declare the same operationId.
	ReasonDuplicateOperationID Reason = "duplicate_operation_id"

	// ReasonUnresolvedParameter: an operation parameter reference could not be
	// resolved, so its idempotency semantics are unevaluable. The compiler
	// fails closed instead of guessing.
	ReasonUnresolvedParameter Reason = "unresolved_parameter"

	// ReasonMalformedIdempotencyKey: the Idempotency-Key declaration is not
	// the canonical components/parameters reference, is duplicated, or the
	// canonical component is not declared required in the header.
	ReasonMalformedIdempotencyKey Reason = "malformed_idempotency_key"

	// ReasonMalformedSecretReplay: x-idempotent-secret-replay is structurally
	// malformed (not an object, unknown field, missing required field, or
	// wrong-typed field).
	ReasonMalformedSecretReplay Reason = "malformed_secret_replay"

	// ReasonSecretReplayValueMismatch: a declared x-idempotent-secret-replay
	// value contradicts the contracted value and would silently weaken replay
	// protection if accepted.
	ReasonSecretReplayValueMismatch Reason = "secret_replay_value_mismatch"

	// ReasonSecretReplayWithoutIdempotencyKey: an operation declares
	// x-idempotent-secret-replay but does not declare the canonical
	// Idempotency-Key parameter.
	ReasonSecretReplayWithoutIdempotencyKey Reason = "secret_replay_without_idempotency_key"
)

// CompileError is a typed compile failure with the diagnostic context needed
// for startup reporting. It wraps an optional underlying cause.
type CompileError struct {
	Reason      Reason
	OperationID string // empty when not attributable to one operation
	Method      string // empty when not attributable to one operation
	Path        string // empty when not attributable to one operation
	Detail      string // human-readable detail for diagnostics
	Cause       error  // underlying error, if any
}

func (e *CompileError) Error() string {
	loc := ""
	switch {
	case e.OperationID != "":
		loc = "operation " + e.OperationID
	case e.Method != "" && e.Path != "":
		loc = e.Method + " " + e.Path
	case e.Path != "":
		loc = e.Path
	}
	if loc != "" {
		loc = " for " + loc
	}
	msg := "idempotency policy compile error" + loc + ": " + string(e.Reason)
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the underlying cause for errors.Is/errors.As chains.
func (e *CompileError) Unwrap() error { return e.Cause }

// AsReason reports whether err is or wraps a CompileError with the given
// reason. It is a convenience for tests.
func AsReason(err error, reason Reason) bool {
	var ce *CompileError
	if !errors.As(err, &ce) {
		return false
	}
	return ce.Reason == reason
}

// newCompileError builds a CompileError with the given reason and detail.
func newCompileError(reason Reason, detail string) *CompileError {
	return &CompileError{Reason: reason, Detail: detail}
}

// withOperation attaches operation context to a CompileError. It is safe to
// call on a nil *CompileError (returns nil).
func (e *CompileError) withOperation(opID, method, path string) *CompileError {
	if e == nil {
		return nil
	}
	if e.OperationID == "" {
		e.OperationID = opID
	}
	if e.Method == "" {
		e.Method = method
	}
	if e.Path == "" {
		e.Path = path
	}
	return e
}

// fmtCompileError formats a compile error with context, for call sites that
// build a fresh error inline.
func fmtCompileError(reason Reason, opID, method, path, format string, args ...any) error {
	return newCompileError(reason, fmt.Sprintf(format, args...)).withOperation(opID, method, path)
}
