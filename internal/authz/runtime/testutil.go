package runtime

import (
	"context"

	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
)

// StaticScopeAuthorizer is a deterministic test double for ScopeAuthorizer.
type StaticScopeAuthorizer struct {
	Decide func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req ScopeAuthorizationRequest) (Decision, error)
}

func (a StaticScopeAuthorizer) AuthorizeScopes(ctx context.Context, authCtx *authruntime.AuthenticationContext, req ScopeAuthorizationRequest) (Decision, error) {
	if a.Decide != nil {
		return a.Decide(ctx, authCtx, req)
	}
	return DecisionDenied, nil
}

// StaticOpenEvaluator is a deterministic test double for OpenPolicyEvaluator.
type StaticOpenEvaluator struct {
	Decide func(ctx context.Context, authCtx *authruntime.AuthenticationContext, req OpenPolicyRequest) (Decision, error)
}

func (e StaticOpenEvaluator) EvaluateOpenPolicy(ctx context.Context, authCtx *authruntime.AuthenticationContext, req OpenPolicyRequest) (Decision, error) {
	if e.Decide != nil {
		return e.Decide(ctx, authCtx, req)
	}
	return DecisionDenied, nil
}

// DenyAllScopeAuthorizer returns a ScopeAuthorizer that explicitly denies all scopes.
func DenyAllScopeAuthorizer() ScopeAuthorizer {
	return StaticScopeAuthorizer{
		Decide: func(_ context.Context, _ *authruntime.AuthenticationContext, _ ScopeAuthorizationRequest) (Decision, error) {
			return DecisionDenied, nil
		},
	}
}

// AllowAllScopeAuthorizer returns a ScopeAuthorizer that allows all scopes.
func AllowAllScopeAuthorizer() ScopeAuthorizer {
	return StaticScopeAuthorizer{
		Decide: func(_ context.Context, _ *authruntime.AuthenticationContext, _ ScopeAuthorizationRequest) (Decision, error) {
			return DecisionAllowed, nil
		},
	}
}

// DenyAllOpenEvaluator returns an OpenPolicyEvaluator that explicitly denies all OPEN operations.
func DenyAllOpenEvaluator() OpenPolicyEvaluator {
	return StaticOpenEvaluator{
		Decide: func(_ context.Context, _ *authruntime.AuthenticationContext, _ OpenPolicyRequest) (Decision, error) {
			return DecisionDenied, nil
		},
	}
}

// AllowAllOpenEvaluator returns an OpenPolicyEvaluator that allows all OPEN operations.
func AllowAllOpenEvaluator() OpenPolicyEvaluator {
	return StaticOpenEvaluator{
		Decide: func(_ context.Context, _ *authruntime.AuthenticationContext, _ OpenPolicyRequest) (Decision, error) {
			return DecisionAllowed, nil
		},
	}
}

// DefaultDenyRegistry returns a registry with deny-all ScopeAuthorizer and
// default deny-all OpenPolicyEvaluator.
func DefaultDenyRegistry() *Registry {
	r, _ := NewRegistry(DenyAllScopeAuthorizer(), DenyAllOpenEvaluator(), nil)
	return r
}

// PrincipalScopeAuthorizer evaluates confirmed scopes based on a configured map
// of subject -> granted scopes.
type PrincipalScopeAuthorizer struct {
	Grants map[string][]string
}

func (p *PrincipalScopeAuthorizer) AuthorizeScopes(_ context.Context, authCtx *authruntime.AuthenticationContext, req ScopeAuthorizationRequest) (Decision, error) {
	if authCtx == nil || p == nil || p.Grants == nil {
		return DecisionDenied, nil
	}
	// Extract subject from any OIDC binding
	subject := ""
	for _, b := range authCtx.Bindings() {
		if id, ok := b.OIDCIdentity(); ok && id.Subject != "" {
			subject = id.Subject
			break
		}
	}
	if subject == "" {
		return DecisionDenied, nil
	}
	granted, ok := p.Grants[subject]
	if !ok {
		return DecisionDenied, nil
	}
	// Verify that ALL required scopes are present (AND semantics)
	for _, reqScope := range req.RequiredScopes {
		found := false
		for _, g := range granted {
			if g == reqScope {
				found = true
				break
			}
		}
		if !found {
			return DecisionDenied, nil
		}
	}
	return DecisionAllowed, nil
}
