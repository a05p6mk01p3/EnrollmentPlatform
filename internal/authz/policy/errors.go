package policy

import "fmt"

// CompileReason categorizes an authorization policy compilation failure.
type CompileReason string

const (
	ReasonMissingOperationID     CompileReason = "MISSING_OPERATION_ID"
	ReasonDuplicateOperationID   CompileReason = "DUPLICATE_OPERATION_ID"
	ReasonEmptyScope             CompileReason = "EMPTY_SCOPE"
	ReasonDuplicateScope         CompileReason = "DUPLICATE_SCOPE"
	ReasonScopeDivergence        CompileReason = "SCOPE_DIVERGENCE"
	ReasonMalformedDomainAuth    CompileReason = "MALFORMED_DOMAIN_AUTH"
	ReasonUnknownScopeStatus     CompileReason = "UNKNOWN_SCOPE_STATUS"
	ReasonUnknownOpenStatus      CompileReason = "UNKNOWN_OPEN_STATUS"
	ReasonAmbiguousDomainAuth    CompileReason = "AMBIGUOUS_DOMAIN_AUTH"
	ReasonOpenWithRequiredScopes CompileReason = "OPEN_WITH_REQUIRED_SCOPES"
	ReasonMissingRequiredField   CompileReason = "MISSING_REQUIRED_FIELD"
)

// CompileError reports a failure to compile the authorization policy of an
// OpenAPI specification. It is a construction-time error, never an HTTP response.
type CompileError struct {
	Reason      CompileReason
	OperationID string
	Method      string
	Path        string
	Detail      string
}

func (e *CompileError) Error() string {
	if e.OperationID != "" {
		return fmt.Sprintf("authz policy: operation %q (%s %s): [%s] %s", e.OperationID, e.Method, e.Path, e.Reason, e.Detail)
	}
	return fmt.Sprintf("authz policy: [%s] %s", e.Reason, e.Detail)
}

func newCompileError(reason CompileReason, detail string) *CompileError {
	return &CompileError{
		Reason: reason,
		Detail: detail,
	}
}

func fmtCompileError(reason CompileReason, opID, method, path, format string, args ...any) *CompileError {
	return &CompileError{
		Reason:      reason,
		OperationID: opID,
		Method:      method,
		Path:        path,
		Detail:      fmt.Sprintf(format, args...),
	}
}

func (e *CompileError) withOperation(opID, method, path string) *CompileError {
	cp := *e
	cp.OperationID = opID
	cp.Method = method
	cp.Path = path
	return &cp
}
