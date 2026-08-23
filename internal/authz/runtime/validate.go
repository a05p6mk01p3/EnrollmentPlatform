package runtime

import (
	"errors"
	"fmt"

	authzpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authz/policy"
)

// MissingScopeAuthorizerError reports that the compiled policy has confirmed-scope
// operations but no ScopeAuthorizer is registered.
type MissingScopeAuthorizerError struct{}

func (e *MissingScopeAuthorizerError) Error() string {
	return "authz runtime: no scope authorizer registered for confirmed-scope operations"
}

// MissingOpenEvaluatorError reports that the compiled policy has an OPEN
// operation without a registered OpenPolicyEvaluator.
type MissingOpenEvaluatorError struct {
	OperationID string
}

func (e *MissingOpenEvaluatorError) Error() string {
	return fmt.Sprintf("authz runtime: no open policy evaluator registered for operation %q", e.OperationID)
}

// NilEvaluatorError reports that an evaluator is nil or typed-nil.
type NilEvaluatorError struct {
	Component string
}

func (e *NilEvaluatorError) Error() string {
	return fmt.Sprintf("authz runtime: nil or typed-nil evaluator for %s", e.Component)
}

// ValidateRegistry performs startup integrity validation for authorization.
// It verifies that every operation in the compiled policy has the required
// runtime authorization component registered in the Registry.
func ValidateRegistry(compiled *authzpolicy.Policy, registry *Registry) error {
	if compiled == nil {
		return errors.New("authz runtime: nil compiled authorization policy")
	}
	if registry == nil {
		return errors.New("authz runtime: nil authorization registry")
	}

	for _, op := range compiled.Operations() {
		switch op.Kind() {
		case authzpolicy.PolicyKindConfirmedScopes:
			sa, ok := registry.ScopeAuthorizer()
			if !ok || isNilLike(sa) {
				return &MissingScopeAuthorizerError{}
			}
		case authzpolicy.PolicyKindOpen:
			eval, ok := registry.OpenEvaluator(op.OperationID())
			if !ok || isNilLike(eval) {
				return &MissingOpenEvaluatorError{OperationID: op.OperationID()}
			}
		case authzpolicy.PolicyKindNone:
			// No operation-level authorization required in M5.1
		default:
			return fmt.Errorf("authz runtime: unknown policy kind %q for operation %q", op.Kind(), op.OperationID())
		}
	}
	return nil
}
