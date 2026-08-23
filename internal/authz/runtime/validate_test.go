package runtime_test

import (
	"context"
	"errors"
	"testing"

	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	authzpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authz/policy"
	authzruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authz/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
)

type typedNilScopeAuthorizer struct {
	ptr *string
}

func (t *typedNilScopeAuthorizer) AuthorizeScopes(context.Context, *authruntime.AuthenticationContext, authzruntime.ScopeAuthorizationRequest) (authzruntime.Decision, error) {
	return authzruntime.DecisionDenied, nil
}

type typedNilOpenEvaluator struct {
	ptr *string
}

func (t *typedNilOpenEvaluator) EvaluateOpenPolicy(context.Context, *authruntime.AuthenticationContext, authzruntime.OpenPolicyRequest) (authzruntime.Decision, error) {
	return authzruntime.DecisionDenied, nil
}

func TestValidateRegistry(t *testing.T) {
	spec, err := openapi.GetSpec()
	if err != nil {
		t.Fatalf("GetSpec: %v", err)
	}
	compiled, err := authzpolicy.Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	t.Run("nil compiled policy", func(t *testing.T) {
		reg := authzruntime.DefaultDenyRegistry()
		if err := authzruntime.ValidateRegistry(nil, reg); err == nil {
			t.Fatal("expected error on nil compiled policy, got nil")
		}
	})

	t.Run("nil registry", func(t *testing.T) {
		if err := authzruntime.ValidateRegistry(compiled, nil); err == nil {
			t.Fatal("expected error on nil registry, got nil")
		}
	})

	t.Run("valid default deny registry", func(t *testing.T) {
		reg := authzruntime.DefaultDenyRegistry()
		if err := authzruntime.ValidateRegistry(compiled, reg); err != nil {
			t.Fatalf("ValidateRegistry: %v", err)
		}
	})

	t.Run("missing scope authorizer", func(t *testing.T) {
		reg, err := authzruntime.NewRegistry(authzruntime.DenyAllScopeAuthorizer(), authzruntime.DenyAllOpenEvaluator(), nil)
		if err != nil {
			t.Fatal(err)
		}
		// Construct an incomplete registry by omitting scopeAuthorizer
		brokenReg, _ := authzruntime.NewRegistry(authzruntime.DenyAllScopeAuthorizer(), nil, nil)
		// Empty out scopeAuthorizer using unexported field reflection or test registry
		// Since NewRegistry forbids nil scopeAuthorizer, let's test typed-nil
		var typedNil *typedNilScopeAuthorizer
		_, err = authzruntime.NewRegistry(typedNil, nil, nil)
		if err == nil {
			t.Fatal("expected NewRegistry to reject typed-nil scope authorizer")
		}
		_ = reg
		_ = brokenReg
	})

	t.Run("missing open evaluator when default is nil", func(t *testing.T) {
		reg, err := authzruntime.NewRegistry(authzruntime.DenyAllScopeAuthorizer(), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		err = authzruntime.ValidateRegistry(compiled, reg)
		if err == nil {
			t.Fatal("expected error for missing open evaluator, got nil")
		}
		var moe *authzruntime.MissingOpenEvaluatorError
		if !authzruntimeErrorsAs(err, &moe) {
			t.Fatalf("expected MissingOpenEvaluatorError, got: %v", err)
		}
	})

	t.Run("typed-nil open evaluator in perOp map", func(t *testing.T) {
		var typedNil *typedNilOpenEvaluator
		_, err := authzruntime.NewRegistry(authzruntime.DenyAllScopeAuthorizer(), nil, map[string]authzruntime.OpenPolicyEvaluator{
			"adminCreateDeviceRebindRequest": typedNil,
		})
		if err == nil {
			t.Fatal("expected NewRegistry to reject typed-nil evaluator in per-op map")
		}
	})

	t.Run("complete per-operation evaluators without default", func(t *testing.T) {
		perOp := map[string]authzruntime.OpenPolicyEvaluator{
			"adminCreateDeviceRebindRequest":  authzruntime.DenyAllOpenEvaluator(),
			"adminApproveDeviceRebindRequest": authzruntime.DenyAllOpenEvaluator(),
			"adminCreateTemporaryPrincipal":   authzruntime.DenyAllOpenEvaluator(),
			"adminDisableTemporaryPrincipal":  authzruntime.DenyAllOpenEvaluator(),
			"adminGetRevocationRequest":       authzruntime.DenyAllOpenEvaluator(),
			"adminListRevocationCertificates": authzruntime.DenyAllOpenEvaluator(),
		}
		reg, err := authzruntime.NewRegistry(authzruntime.DenyAllScopeAuthorizer(), nil, perOp)
		if err != nil {
			t.Fatal(err)
		}
		if err := authzruntime.ValidateRegistry(compiled, reg); err != nil {
			t.Fatalf("ValidateRegistry: %v", err)
		}
	})
}

func authzruntimeErrorsAs(err error, target any) bool {
	return errors.As(err, target)
}
