package policy_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authz/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
)

func canonicalSpec(t testing.TB) *openapi3.T {
	t.Helper()
	spec, err := openapi.GetSpec()
	if err != nil {
		t.Fatalf("GetSpec: %v", err)
	}
	return spec
}

func TestCompileCanonicalSpec(t *testing.T) {
	spec := canonicalSpec(t)
	p, err := policy.Compile(spec)
	if err != nil {
		t.Fatalf("Compile canonical: %v", err)
	}

	if p.OperationCount() != 20 {
		t.Fatalf("OperationCount = %d, want 20", p.OperationCount())
	}

	// 1. Check confirmed device:approve operations
	deviceApproveOps := []string{
		"adminListPreOnboardingRequests",
		"adminApprovePreOnboardingRequest",
		"adminRejectPreOnboardingRequest",
	}
	for _, opID := range deviceApproveOps {
		op, ok := p.Operation(opID)
		if !ok {
			t.Fatalf("missing operation %q", opID)
		}
		if op.Kind() != policy.PolicyKindConfirmedScopes {
			t.Errorf("op %s: kind = %v, want %v", opID, op.Kind(), policy.PolicyKindConfirmedScopes)
		}
		scopes := op.RequiredScopes()
		if len(scopes) != 1 || scopes[0] != "device:approve" {
			t.Errorf("op %s: scopes = %v, want [device:approve]", opID, scopes)
		}
		if !op.HasScope("device:approve") {
			t.Errorf("op %s: HasScope(device:approve) = false, want true", opID)
		}
		if op.HasScope("certificate:revoke") {
			t.Errorf("op %s: HasScope(certificate:revoke) = true, want false", opID)
		}
	}

	// 2. Check confirmed certificate:revoke operation
	op, ok := p.Operation("adminCreateRevocationRequest")
	if !ok {
		t.Fatal("missing adminCreateRevocationRequest")
	}
	if op.Kind() != policy.PolicyKindConfirmedScopes {
		t.Errorf("adminCreateRevocationRequest: kind = %v, want %v", op.Kind(), policy.PolicyKindConfirmedScopes)
	}
	scopes := op.RequiredScopes()
	if len(scopes) != 1 || scopes[0] != "certificate:revoke" {
		t.Errorf("adminCreateRevocationRequest: scopes = %v, want [certificate:revoke]", scopes)
	}
	if !op.HasScope("certificate:revoke") {
		t.Errorf("adminCreateRevocationRequest: HasScope(certificate:revoke) = false, want true")
	}
	if op.HasScope("device:approve") {
		t.Errorf("adminCreateRevocationRequest: HasScope(device:approve) = true, want false")
	}
	if !op.HighImpact() {
		t.Errorf("adminCreateRevocationRequest: HighImpact = false, want true")
	}
	if op.StepUpPolicy() != "policy-defined" {
		t.Errorf("adminCreateRevocationRequest: StepUpPolicy = %q, want %q", op.StepUpPolicy(), "policy-defined")
	}

	// 3. Check OPEN operations
	openOps := map[string]struct {
		status                policy.OpenStatus
		highImpact            bool
		stepUpPolicy          string
		resourceScope         string
		grantedPrincipalScope string
	}{
		"adminCreateDeviceRebindRequest": {
			status:       policy.OpenStatusScopeName,
			highImpact:   true,
			stepUpPolicy: "policy-defined",
		},
		"adminApproveDeviceRebindRequest": {
			status:       policy.OpenStatusScopeName,
			highImpact:   true,
			stepUpPolicy: "policy-defined",
		},
		"adminCreateTemporaryPrincipal": {
			status:                policy.OpenStatusScopeName,
			highImpact:            true,
			stepUpPolicy:          "policy-defined",
			grantedPrincipalScope: "device:preonboard",
		},
		"adminDisableTemporaryPrincipal": {
			status:       policy.OpenStatusScopeName,
			highImpact:   true,
			stepUpPolicy: "policy-defined",
		},
		"adminGetRevocationRequest": {
			status:        policy.OpenStatusReadScopeName,
			resourceScope: "revocation-request",
		},
		"adminListRevocationCertificates": {
			status:        policy.OpenStatusReadScopeName,
			resourceScope: "revocation-request",
		},
	}

	for opID, expected := range openOps {
		op, ok := p.Operation(opID)
		if !ok {
			t.Fatalf("missing OPEN op %q", opID)
		}
		if op.Kind() != policy.PolicyKindOpen {
			t.Errorf("op %s: kind = %v, want %v", opID, op.Kind(), policy.PolicyKindOpen)
		}
		if len(op.RequiredScopes()) != 0 {
			t.Errorf("op %s: requiredScopes = %v, want empty", opID, op.RequiredScopes())
		}
		meta := op.OpenMetadata()
		if meta == nil {
			t.Fatalf("op %s: OpenMetadata is nil", opID)
		}
		if meta.Status != expected.status {
			t.Errorf("op %s: status = %q, want %q", opID, meta.Status, expected.status)
		}
		if meta.HighImpact != expected.highImpact {
			t.Errorf("op %s: highImpact = %v, want %v", opID, meta.HighImpact, expected.highImpact)
		}
		if meta.StepUpPolicy != expected.stepUpPolicy {
			t.Errorf("op %s: stepUpPolicy = %q, want %q", opID, meta.StepUpPolicy, expected.stepUpPolicy)
		}
		if meta.ResourceScope != expected.resourceScope {
			t.Errorf("op %s: resourceScope = %q, want %q", opID, meta.ResourceScope, expected.resourceScope)
		}
		if meta.GrantedPrincipalScope != expected.grantedPrincipalScope {
			t.Errorf("op %s: grantedPrincipalScope = %q, want %q", opID, meta.GrantedPrincipalScope, expected.grantedPrincipalScope)
		}
	}

	// 4. Check unconstrained (PolicyKindNone) operations
	noneOps := []string{
		"getMyAuthorizations",
		"createPreOnboardingRequest",
		"getPreOnboardingRequest",
		"createEnrollment",
		"getEnrollment",
		"submitEnrollmentEvidence",
		"refreshEnrollmentChallenge",
		"getEnrollmentCertificate",
		"completeEnrollment",
		"getCurrentTrustBundle",
	}
	for _, opID := range noneOps {
		op, ok := p.Operation(opID)
		if !ok {
			t.Fatalf("missing operation %q", opID)
		}
		if op.Kind() != policy.PolicyKindNone {
			t.Errorf("op %s: kind = %v, want %v", opID, op.Kind(), policy.PolicyKindNone)
		}
		if len(op.RequiredScopes()) != 0 {
			t.Errorf("op %s: requiredScopes = %v, want empty", opID, op.RequiredScopes())
		}
		if op.OpenMetadata() != nil {
			t.Errorf("op %s: openMetadata is non-nil", opID)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	t.Run("nil spec", func(t *testing.T) {
		_, err := policy.Compile(nil)
		if err == nil {
			t.Fatal("expected error on nil spec, got nil")
		}
	})

	t.Run("missing operationId", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			me := paths["/v1/me/authorizations"].(map[string]any)
			get := me["get"].(map[string]any)
			delete(get, "operationId")
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonMissingOperationID)
	})

	t.Run("duplicate operationId", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			me := paths["/v1/me/authorizations"].(map[string]any)
			get := me["get"].(map[string]any)
			get["operationId"] = "adminListPreOnboardingRequests" // duplicate
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonDuplicateOperationID)
	})

	t.Run("empty scope string in x-required-scopes", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			req := paths["/v1/admin/pre-onboarding-requests"].(map[string]any)
			get := req["get"].(map[string]any)
			get["x-required-scopes"] = []any{""}
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonEmptyScope)
	})

	t.Run("duplicate scope in x-required-scopes", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			req := paths["/v1/admin/pre-onboarding-requests"].(map[string]any)
			get := req["get"].(map[string]any)
			get["x-required-scopes"] = []any{"device:approve", "device:approve"}
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonDuplicateScope)
	})

	t.Run("scope divergence between x-required-scopes and x-domain-authorization", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			req := paths["/v1/admin/pre-onboarding-requests"].(map[string]any)
			get := req["get"].(map[string]any)
			get["x-required-scopes"] = []any{"certificate:revoke"} // diverged from device:approve
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonScopeDivergence)
	})

	t.Run("unknown scopeStatus", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			req := paths["/v1/admin/pre-onboarding-requests"].(map[string]any)
			get := req["get"].(map[string]any)
			da := get["x-domain-authorization"].(map[string]any)
			da["scopeStatus"] = "INVENTED_STATUS"
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonUnknownScopeStatus)
	})

	t.Run("unknown status in OPEN operation", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			req := paths["/v1/admin/devices/{id}/rebind-requests"].(map[string]any)
			post := req["post"].(map[string]any)
			da := post["x-domain-authorization"].(map[string]any)
			da["status"] = "INVENTED_OPEN_STATUS"
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonUnknownOpenStatus)
	})

	t.Run("OPEN operation declaring requiredScopes", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			req := paths["/v1/admin/devices/{id}/rebind-requests"].(map[string]any)
			post := req["post"].(map[string]any)
			post["x-required-scopes"] = []any{"device:rebind"}
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonOpenWithRequiredScopes)
	})

	t.Run("malformed x-domain-authorization (not an object)", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			req := paths["/v1/admin/pre-onboarding-requests"].(map[string]any)
			get := req["get"].(map[string]any)
			get["x-domain-authorization"] = "invalid"
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonMalformedDomainAuth)
	})

	t.Run("missing required field in x-domain-authorization", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			req := paths["/v1/admin/pre-onboarding-requests"].(map[string]any)
			get := req["get"].(map[string]any)
			da := get["x-domain-authorization"].(map[string]any)
			delete(da, "required")
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonMissingRequiredField)
	})

	t.Run("ambiguous x-domain-authorization (neither scopeStatus nor status)", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			req := paths["/v1/admin/pre-onboarding-requests"].(map[string]any)
			get := req["get"].(map[string]any)
			da := get["x-domain-authorization"].(map[string]any)
			delete(da, "scopeStatus")
			delete(da, "requiredScopes")
		})
		_, err := policy.Compile(spec)
		assertCompileReason(t, err, policy.ReasonAmbiguousDomainAuth)
	})

	t.Run("ambiguous x-domain-authorization (both confirmed scopeStatus and valid OPEN status)", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			req := paths["/v1/admin/pre-onboarding-requests"].(map[string]any)
			get := req["get"].(map[string]any)
			da := get["x-domain-authorization"].(map[string]any)
			// Keep valid confirmed scopeStatus and requiredScopes, but also add valid OPEN status
			da["scopeStatus"] = string(policy.ScopeStatusConfirmed)
			da["requiredScopes"] = []any{"device:approve"}
			da["status"] = string(policy.OpenStatusScopeName)
		})
		compiled, err := policy.Compile(spec)
		if compiled != nil {
			t.Fatalf("compiled policy must be nil on ambiguous metadata, got non-nil: %v", compiled)
		}
		assertCompileReason(t, err, policy.ReasonAmbiguousDomainAuth)
	})

	t.Run("ambiguous x-domain-authorization (confirmed scopeStatus and unknown status)", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			req := paths["/v1/admin/pre-onboarding-requests"].(map[string]any)
			get := req["get"].(map[string]any)
			da := get["x-domain-authorization"].(map[string]any)
			// Valid confirmed scopeStatus with unknown status value
			da["scopeStatus"] = string(policy.ScopeStatusConfirmed)
			da["requiredScopes"] = []any{"device:approve"}
			da["status"] = "FUTURE_UNKNOWN_POLICY_MODE"
		})
		compiled, err := policy.Compile(spec)
		if compiled != nil {
			t.Fatalf("compiled policy must be nil on ambiguous metadata, got non-nil: %v", compiled)
		}
		assertCompileReason(t, err, policy.ReasonAmbiguousDomainAuth)
	})

	t.Run("ambiguous x-domain-authorization (valid confirmed scopeStatus and empty status string)", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			req := paths["/v1/admin/pre-onboarding-requests"].(map[string]any)
			get := req["get"].(map[string]any)
			da := get["x-domain-authorization"].(map[string]any)
			da["scopeStatus"] = string(policy.ScopeStatusConfirmed)
			da["requiredScopes"] = []any{"device:approve"}
			da["status"] = ""
		})
		compiled, err := policy.Compile(spec)
		if compiled != nil {
			t.Fatalf("compiled policy must be nil on ambiguous metadata, got non-nil: %v", compiled)
		}
		assertCompileReason(t, err, policy.ReasonAmbiguousDomainAuth)
	})

	t.Run("ambiguous x-domain-authorization (empty scopeStatus string and valid OPEN status)", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			req := paths["/v1/admin/devices/{id}/rebind-requests"].(map[string]any)
			post := req["post"].(map[string]any)
			da := post["x-domain-authorization"].(map[string]any)
			da["status"] = string(policy.OpenStatusScopeName)
			da["scopeStatus"] = ""
		})
		compiled, err := policy.Compile(spec)
		if compiled != nil {
			t.Fatalf("compiled policy must be nil on ambiguous metadata, got non-nil: %v", compiled)
		}
		assertCompileReason(t, err, policy.ReasonAmbiguousDomainAuth)
	})

	t.Run("single discriminator present with empty scopeStatus", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			req := paths["/v1/admin/pre-onboarding-requests"].(map[string]any)
			get := req["get"].(map[string]any)
			da := get["x-domain-authorization"].(map[string]any)
			da["scopeStatus"] = ""
			delete(da, "status")
		})
		compiled, err := policy.Compile(spec)
		if compiled != nil {
			t.Fatalf("compiled policy must be nil on empty scopeStatus, got non-nil: %v", compiled)
		}
		assertCompileReason(t, err, policy.ReasonMalformedDomainAuth)
	})

	t.Run("single discriminator present with empty status", func(t *testing.T) {
		spec := mutateSpec(t, func(doc map[string]any) {
			paths := doc["paths"].(map[string]any)
			req := paths["/v1/admin/devices/{id}/rebind-requests"].(map[string]any)
			post := req["post"].(map[string]any)
			da := post["x-domain-authorization"].(map[string]any)
			da["status"] = ""
			delete(da, "scopeStatus")
		})
		compiled, err := policy.Compile(spec)
		if compiled != nil {
			t.Fatalf("compiled policy must be nil on empty status, got non-nil: %v", compiled)
		}
		assertCompileReason(t, err, policy.ReasonMalformedDomainAuth)
	})
}

func mutateSpec(t testing.TB, mutate func(doc map[string]any)) *openapi3.T {
	t.Helper()
	spec := canonicalSpec(t)
	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	doc := map[string]any{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal spec: %v", err)
	}
	mutate(doc)
	mutatedData, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal mutated: %v", err)
	}
	mutated, err := openapi3.NewLoader().LoadFromData(mutatedData)
	if err != nil {
		t.Fatalf("load mutated: %v", err)
	}
	return mutated
}

func assertCompileReason(t *testing.T, err error, wantReason policy.CompileReason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected compile error with reason %s, got nil", wantReason)
	}
	var ce *policy.CompileError
	if !errorsAs(err, &ce) {
		t.Fatalf("expected *policy.CompileError, got %T: %v", err, err)
	}
	if ce.Reason != wantReason {
		t.Fatalf("reason = %s, want %s (err: %v)", ce.Reason, wantReason, ce)
	}
}

func errorsAs(err error, target any) bool {
	return errors.As(err, target)
}
