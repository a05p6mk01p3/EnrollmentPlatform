package policy_test

import (
	"testing"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authz/policy"
)

// TestContractParity verifies that the compiled policy precisely matches the
// canonical OpenAPI contract without any deviation or missing operations.
func TestContractParity(t *testing.T) {
	spec := canonicalSpec(t)
	p, err := policy.Compile(spec)
	if err != nil {
		t.Fatalf("Compile canonical: %v", err)
	}

	expectedMatrix := map[string]struct {
		kind                  policy.PolicyKind
		requiredScopes        []string
		status                policy.OpenStatus
		highImpact            bool
		stepUpPolicy          string
		resourceScope         string
		grantedPrincipalScope string
	}{
		// Confirmed administrative operations
		"adminListPreOnboardingRequests": {
			kind:           policy.PolicyKindConfirmedScopes,
			requiredScopes: []string{"device:approve"},
		},
		"adminGetPreOnboardingRequest": {
			kind:           policy.PolicyKindConfirmedScopes,
			requiredScopes: []string{"device:approve"},
		},
		"adminApprovePreOnboardingRequest": {
			kind:           policy.PolicyKindConfirmedScopes,
			requiredScopes: []string{"device:approve"},
		},
		"adminRejectPreOnboardingRequest": {
			kind:           policy.PolicyKindConfirmedScopes,
			requiredScopes: []string{"device:approve"},
		},
		"adminCreateRevocationRequest": {
			kind:           policy.PolicyKindConfirmedScopes,
			requiredScopes: []string{"certificate:revoke"},
			highImpact:     true,
			stepUpPolicy:   "policy-defined",
		},

		// OPEN administrative operations
		"adminCreateDeviceRebindRequest": {
			kind:         policy.PolicyKindOpen,
			status:       policy.OpenStatusScopeName,
			highImpact:   true,
			stepUpPolicy: "policy-defined",
		},
		"adminApproveDeviceRebindRequest": {
			kind:         policy.PolicyKindOpen,
			status:       policy.OpenStatusScopeName,
			highImpact:   true,
			stepUpPolicy: "policy-defined",
		},
		"adminCreateTemporaryPrincipal": {
			kind:                  policy.PolicyKindOpen,
			status:                policy.OpenStatusScopeName,
			highImpact:            true,
			stepUpPolicy:          "policy-defined",
			grantedPrincipalScope: "device:preonboard",
		},
		"adminDisableTemporaryPrincipal": {
			kind:         policy.PolicyKindOpen,
			status:       policy.OpenStatusScopeName,
			highImpact:   true,
			stepUpPolicy: "policy-defined",
		},
		"adminGetRevocationRequest": {
			kind:          policy.PolicyKindOpen,
			status:        policy.OpenStatusReadScopeName,
			resourceScope: "revocation-request",
		},
		"adminListRevocationCertificates": {
			kind:          policy.PolicyKindOpen,
			status:        policy.OpenStatusReadScopeName,
			resourceScope: "revocation-request",
		},

		// Non-admin operations (unconstrained at operation level in M5.1)
		"getMyAuthorizations":        {kind: policy.PolicyKindNone},
		"createPreOnboardingRequest": {kind: policy.PolicyKindNone},
		"getPreOnboardingRequest":    {kind: policy.PolicyKindNone},
		"createEnrollment":           {kind: policy.PolicyKindNone},
		"getEnrollment":              {kind: policy.PolicyKindNone},
		"submitEnrollmentEvidence":   {kind: policy.PolicyKindNone},
		"refreshEnrollmentChallenge": {kind: policy.PolicyKindNone},
		"getEnrollmentCertificate":   {kind: policy.PolicyKindNone},
		"completeEnrollment":         {kind: policy.PolicyKindNone},
		"getCurrentTrustBundle":      {kind: policy.PolicyKindNone},
	}

	if p.OperationCount() != len(expectedMatrix) {
		t.Fatalf("OperationCount = %d, want %d", p.OperationCount(), len(expectedMatrix))
	}

	for opID, expected := range expectedMatrix {
		op, ok := p.Operation(opID)
		if !ok {
			t.Errorf("missing expected operation %q", opID)
			continue
		}

		if op.Kind() != expected.kind {
			t.Errorf("op %s: kind = %v, want %v", opID, op.Kind(), expected.kind)
		}

		scopes := op.RequiredScopes()
		if len(scopes) != len(expected.requiredScopes) {
			t.Errorf("op %s: requiredScopes = %v, want %v", opID, scopes, expected.requiredScopes)
		} else {
			for i := range scopes {
				if scopes[i] != expected.requiredScopes[i] {
					t.Errorf("op %s: requiredScope[%d] = %q, want %q", opID, i, scopes[i], expected.requiredScopes[i])
				}
			}
		}

		if expected.kind == policy.PolicyKindOpen {
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
		} else if expected.kind == policy.PolicyKindConfirmedScopes {
			if expected.highImpact != op.HighImpact() {
				t.Errorf("op %s: highImpact = %v, want %v", opID, op.HighImpact(), expected.highImpact)
			}
			if expected.stepUpPolicy != op.StepUpPolicy() {
				t.Errorf("op %s: stepUpPolicy = %q, want %q", opID, op.StepUpPolicy(), expected.stepUpPolicy)
			}
		}
	}
}
