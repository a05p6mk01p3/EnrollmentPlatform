package runtime

import (
	"errors"
	"fmt"
	"reflect"
)

// Registry manages the ScopeAuthorizer and OpenPolicyEvaluator components
// for the authorization runtime. It is immutable after construction and safe
// for concurrent use.
type Registry struct {
	scopeAuthorizer      ScopeAuthorizer
	openEvaluators       map[string]OpenPolicyEvaluator
	defaultOpenEvaluator OpenPolicyEvaluator
}

// isNilLike reports whether v is nil or holds a typed-nil value of a nilable kind.
func isNilLike(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

// NewRegistry constructs a Registry with the given scope authorizer, default
// open evaluator, and optional per-operation evaluators.
func NewRegistry(scopeAuth ScopeAuthorizer, defaultOpen OpenPolicyEvaluator, perOpOpen map[string]OpenPolicyEvaluator) (*Registry, error) {
	if isNilLike(scopeAuth) {
		return nil, errors.New("authz registry: scope authorizer must not be nil or typed-nil")
	}
	r := &Registry{
		scopeAuthorizer:      scopeAuth,
		openEvaluators:       make(map[string]OpenPolicyEvaluator),
		defaultOpenEvaluator: defaultOpen,
	}
	for opID, eval := range perOpOpen {
		if isNilLike(eval) {
			return nil, fmt.Errorf("authz registry: evaluator for operation %q must not be nil or typed-nil", opID)
		}
		r.openEvaluators[opID] = eval
	}
	return r, nil
}

// ScopeAuthorizer returns the registered ScopeAuthorizer.
func (r *Registry) ScopeAuthorizer() (ScopeAuthorizer, bool) {
	if r == nil || isNilLike(r.scopeAuthorizer) {
		return nil, false
	}
	return r.scopeAuthorizer, true
}

// OpenEvaluator returns the evaluator for an operationId (checking per-operation
// first, then falling back to defaultOpenEvaluator).
func (r *Registry) OpenEvaluator(operationID string) (OpenPolicyEvaluator, bool) {
	if r == nil {
		return nil, false
	}
	if eval, ok := r.openEvaluators[operationID]; ok {
		if isNilLike(eval) {
			return nil, false
		}
		return eval, true
	}
	if !isNilLike(r.defaultOpenEvaluator) {
		return r.defaultOpenEvaluator, true
	}
	return nil, false
}
