package runtime

import (
	"context"

	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	authzpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authz/policy"
)

// ScopeAuthorizationRequest carries the context needed to evaluate confirmed
// domain scopes for an operation.
type ScopeAuthorizationRequest struct {
	OperationID    string
	RequiredScopes []string
	Resource       authruntime.MatchedResource
}

// ScopeAuthorizer evaluates whether the authenticated principal currently
// possesses the confirmed domain scope(s) required by an operation.
//
// Implementations must never log credentials, tokens, or private material,
// and must return DecisionIndeterminate when a required policy dependency
// is unavailable.
type ScopeAuthorizer interface {
	AuthorizeScopes(ctx context.Context, authCtx *authruntime.AuthenticationContext, req ScopeAuthorizationRequest) (Decision, error)
}

// OpenPolicyRequest carries the context needed to evaluate an operation whose
// domain authorization requirements are explicitly OPEN in the OpenAPI contract.
type OpenPolicyRequest struct {
	OperationID string
	Metadata    authzpolicy.OpenMetadata
	Resource    authruntime.MatchedResource
}

// OpenPolicyEvaluator evaluates an operation whose domain authorization
// requirements are explicitly OPEN in the OpenAPI contract.
//
// Implementations must never log credentials, tokens, or private material,
// and must return DecisionIndeterminate when a required policy dependency
// is unavailable.
type OpenPolicyEvaluator interface {
	EvaluateOpenPolicy(ctx context.Context, authCtx *authruntime.AuthenticationContext, req OpenPolicyRequest) (Decision, error)
}
