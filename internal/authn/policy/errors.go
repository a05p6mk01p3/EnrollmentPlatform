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
	// ReasonNilSecurity: an operation has no security field at all. For this
	// contract every operation must declare authentication explicitly, so a
	// nil/absent security array is never silently treated as PUBLIC.
	ReasonNilSecurity Reason = "nil_security"

	// ReasonEmptySecurityRequirement: a non-empty security list contains an
	// empty Security Requirement Object (security: [{}]), which is not an
	// accepted substitute for security: [].
	ReasonEmptySecurityRequirement Reason = "empty_security_requirement"

	// ReasonUnknownScheme: a security requirement references a scheme name
	// outside the six contractual credential kinds.
	ReasonUnknownScheme Reason = "unknown_scheme"

	// ReasonUnresolvedScheme: a security requirement references a scheme name
	// that is not declared (or not resolvable) in components/securitySchemes.
	ReasonUnresolvedScheme Reason = "unresolved_scheme"

	// ReasonNonEmptyScopes: a Security Requirement Object carries non-empty
	// scope values, which M4.1 does not implement and must not ignore.
	ReasonNonEmptyScopes Reason = "non_empty_scopes"

	// ReasonConditionalMalformed: the x-security-conditions extension is
	// structurally malformed (not an object, missing/empty discriminator or
	// cases, a non-object case, or a missing requiredSecurityScheme).
	ReasonConditionalMalformed Reason = "conditional_malformed"

	// ReasonConditionalUnknownField: the x-security-conditions extension (or
	// one of its cases) contains an unknown field that could hide a semantic
	// change and is not silently ignored.
	ReasonConditionalUnknownField Reason = "conditional_unknown_field"

	// ReasonConditionalEnforcement: the enforcement field is missing or not
	// the contractually expected value.
	ReasonConditionalEnforcement Reason = "conditional_enforcement"

	// ReasonConditionalDiscriminatorMismatch: the discriminator declared in
	// x-security-conditions does not match the request body schema's
	// discriminator propertyName.
	ReasonConditionalDiscriminatorMismatch Reason = "conditional_discriminator_mismatch"

	// ReasonConditionalCaseMismatch: the set of case names in
	// x-security-conditions does not match the set of discriminator mappings
	// in the request body schema.
	ReasonConditionalCaseMismatch Reason = "conditional_case_mismatch"

	// ReasonConditionalSchemeNotSingletonAlternative: a conditional case
	// mandates a scheme that is not a complete singleton alternative of the
	// operation's base security. Membership inside a larger AND conjunction
	// is not sufficient: the singular requiredSecurityScheme must be
	// satisfiable on its own.
	ReasonConditionalSchemeNotSingletonAlternative Reason = "conditional_scheme_not_singleton_alternative"

	// ReasonSchemeStructureMismatch: a recognized security scheme's declared
	// definition does not match the contracted structure for its
	// CredentialKind (e.g. DeviceMTLS declared as an HTTP bearer scheme). The
	// CredentialKind mapping stays nominal; this only validates structure.
	ReasonSchemeStructureMismatch Reason = "scheme_structure_mismatch"

	// ReasonMissingOperationID: an operation has a missing, empty, or
	// whitespace-only operationId.
	ReasonMissingOperationID Reason = "missing_operation_id"

	// ReasonConditionalMissing: an operation has a discriminated request body
	// and multiple independently satisfiable security alternatives but no
	// x-security-conditions to define the pairing; the policy is ambiguous and
	// fails closed rather than degrading to an unrestricted OR.
	ReasonConditionalMissing Reason = "conditional_missing"

	// ReasonDuplicateOperationID: two paths declare the same operationId.
	ReasonDuplicateOperationID Reason = "duplicate_operation_id"
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
	msg := "authn policy compile error" + loc + ": " + string(e.Reason)
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

// withCause attaches an underlying cause to a CompileError.
func (e *CompileError) withCause(cause error) *CompileError {
	if e == nil {
		return nil
	}
	e.Cause = cause
	return e
}

// fmtCompileError formats a compile error with context, for call sites that
// build a fresh error inline.
func fmtCompileError(reason Reason, opID, method, path, format string, args ...any) error {
	return newCompileError(reason, fmt.Sprintf(format, args...)).withOperation(opID, method, path)
}
