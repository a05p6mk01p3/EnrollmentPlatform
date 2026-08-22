package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
)

// orReqSpecYAML: non-conditional OR (HumanOIDC OR RequestAccessToken).
const orReqSpecYAML = `openapi: 3.1.0
info: {title: synthetic, version: '1'}
paths:
  /x:
    get:
      operationId: orReqOp
      responses:
        '200': {description: ok}
      security:
        - HumanOIDC: []
        - RequestAccessToken: []
components:
  securitySchemes:
    HumanOIDC: {type: http, scheme: bearer, bearerFormat: JWT}
    RequestAccessToken: {type: http, scheme: bearer, bearerFormat: opaque}
`

// andReqSpecYAML: non-conditional AND (HumanOIDC AND RequestAccessToken).
const andReqSpecYAML = `openapi: 3.1.0
info: {title: synthetic, version: '1'}
paths:
  /x:
    get:
      operationId: andReqOp
      responses:
        '200': {description: ok}
      security:
        - HumanOIDC: []
          RequestAccessToken: []
components:
  securitySchemes:
    HumanOIDC: {type: http, scheme: bearer, bearerFormat: JWT}
    RequestAccessToken: {type: http, scheme: bearer, bearerFormat: opaque}
`

// conditionalCompleteSpecYAML mirrors completeEnrollment's conditional
// security: INSTALLED -> DeviceMTLS, FAILED -> EnrollmentAccessToken.
const conditionalCompleteSpecYAML = `openapi: 3.1.0
info: {title: synthetic, version: '1'}
paths:
  /c:
    post:
      operationId: condCompleteOp
      requestBody:
        required: true
        content:
          application/json:
            schema:
              oneOf:
                - $ref: '#/components/schemas/Installed'
                - $ref: '#/components/schemas/Failed'
              discriminator:
                propertyName: installation_status
                mapping:
                  INSTALLED: '#/components/schemas/Installed'
                  FAILED: '#/components/schemas/Failed'
      responses:
        '200': {description: ok}
      security:
        - DeviceMTLS: []
        - EnrollmentAccessToken: []
      x-security-conditions:
        discriminator: installation_status
        cases:
          INSTALLED:
            requiredSecurityScheme: DeviceMTLS
          FAILED:
            requiredSecurityScheme: EnrollmentAccessToken
        enforcement: MANDATORY_SERVER_POLICY_AND_CONTRACT_TEST
components:
  securitySchemes:
    DeviceMTLS: {type: mutualTLS}
    EnrollmentAccessToken: {type: http, scheme: bearer, bearerFormat: opaque}
  schemas:
    Installed:
      type: object
      required: [installation_status]
      properties:
        installation_status: {type: string, const: INSTALLED}
    Failed:
      type: object
      required: [installation_status]
      properties:
        installation_status: {type: string, const: FAILED}
`

// newBindingAC builds an AuthenticationContext holding the given bindings,
// with satisfied alternatives derived like the real runtime: an alternative is
// satisfied only when every member kind is present in the bindings.
func newBindingAC(op *authpolicy.OperationPolicy, bindings ...*Binding) *AuthenticationContext {
	ac := &AuthenticationContext{
		operationID: op.OperationID(),
		bindings:    map[authpolicy.CredentialKind]Binding{},
	}
	for _, b := range bindings {
		ac.bindings[b.Kind()] = *b
		ac.kinds = append(ac.kinds, b.Kind())
	}
	if op.Conditional() == nil {
		for _, alt := range op.Alternatives() {
			all := true
			for _, k := range alt.Kinds() {
				if _, ok := ac.bindings[k]; !ok {
					all = false
					break
				}
			}
			if all {
				ac.satisfied = append(ac.satisfied, alt)
			}
		}
	}
	return ac
}

// --- SOL-M4.3-002 final: the compiled policy is the authority ---

func TestResourceBindingConditionalRequiresTrustedRequirement(t *testing.T) {
	_, _, op := compileSynthetic(t, conditionalCompleteSpecYAML)
	if op.Conditional() == nil {
		t.Fatal("synthetic spec must be conditional")
	}

	dev := mustBinding(NewDeviceMTLSBinding("dev-1", "cert-1"))
	enr := mustBinding(NewEnrollmentAccessBinding("enr-B"))
	ac := newBindingAC(op, dev, enr)

	t.Run("missing requirement fails closed", func(t *testing.T) {
		got := evaluateResourceBinding(op, ac, nil, false, "enr-A", true)
		if got != resourceBindingIntegrity {
			t.Fatalf("decision = %v, want integrity (no base-OR fallback)", got)
		}
	})

	t.Run("wrong discriminator fails closed", func(t *testing.T) {
		cr := newConditionalRequirement("other_discriminator", "INSTALLED", authpolicy.CredentialKindDeviceMTLS)
		if got := evaluateResourceBinding(op, ac, cr, true, "enr-A", true); got != resourceBindingIntegrity {
			t.Fatalf("decision = %v, want integrity", got)
		}
	})

	t.Run("unknown discriminator value fails closed", func(t *testing.T) {
		cr := newConditionalRequirement("installation_status", "NOT_A_CASE", authpolicy.CredentialKindDeviceMTLS)
		if got := evaluateResourceBinding(op, ac, cr, true, "enr-A", true); got != resourceBindingIntegrity {
			t.Fatalf("decision = %v, want integrity", got)
		}
	})

	t.Run("required kind inconsistent with compiled case fails closed", func(t *testing.T) {
		cr := newConditionalRequirement("installation_status", "INSTALLED", authpolicy.CredentialKindEnrollmentAccessToken)
		if got := evaluateResourceBinding(op, ac, cr, true, "enr-A", true); got != resourceBindingIntegrity {
			t.Fatalf("decision = %v, want integrity", got)
		}
	})

	t.Run("requirement from another operation fails closed", func(t *testing.T) {
		other := *ac
		other.operationID = "someOtherOperation"
		cr := newConditionalRequirement("installation_status", "INSTALLED", authpolicy.CredentialKindDeviceMTLS)
		if got := evaluateResourceBinding(op, &other, cr, true, "enr-A", true); got != resourceBindingIntegrity {
			t.Fatalf("decision = %v, want integrity", got)
		}
	})

	t.Run("INSTALLED ignores mismatched extra capability", func(t *testing.T) {
		cr := newConditionalRequirement("installation_status", "INSTALLED", authpolicy.CredentialKindDeviceMTLS)
		if got := evaluateResourceBinding(op, ac, cr, true, "enr-A", true); got != resourceBindingPass {
			t.Fatalf("decision = %v, want pass", got)
		}
	})

	t.Run("FAILED mismatched required capability is unauthorized", func(t *testing.T) {
		cr := newConditionalRequirement("installation_status", "FAILED", authpolicy.CredentialKindEnrollmentAccessToken)
		if got := evaluateResourceBinding(op, ac, cr, true, "enr-A", true); got != resourceBindingUnauthorized {
			t.Fatalf("decision = %v, want unauthorized", got)
		}
	})

	t.Run("FAILED matching required capability passes", func(t *testing.T) {
		cr := newConditionalRequirement("installation_status", "FAILED", authpolicy.CredentialKindEnrollmentAccessToken)
		if got := evaluateResourceBinding(op, ac, cr, true, "enr-B", true); got != resourceBindingPass {
			t.Fatalf("decision = %v, want pass", got)
		}
	})
}

// TestResourceBindingNonConditionalORAndAND proves the per-satisfied
// alternative semantics for non-conditional operations.
func TestResourceBindingNonConditionalORAndAND(t *testing.T) {
	t.Run("OR alternative independence", func(t *testing.T) {
		_, _, op := compileSynthetic(t, orReqSpecYAML)
		human := mustBinding(NewHumanOIDCBinding("iss", "sub"))
		req := mustBinding(NewRequestAccessBinding("por-B"))
		ac := newBindingAC(op, human, req)

		// Both alternatives satisfied; the capability one is mismatched for
		// por-A. The non-capability alternative must still satisfy the policy.
		if got := evaluateResourceBinding(op, ac, nil, false, "por-A", true); got != resourceBindingPass {
			t.Fatalf("decision = %v, want pass (A must remain valid)", got)
		}

		// Only the mismatched capability alternative satisfied.
		acOnly := newBindingAC(op, req)
		if got := evaluateResourceBinding(op, acOnly, nil, false, "por-A", true); got != resourceBindingUnauthorized {
			t.Fatalf("decision = %v, want unauthorized", got)
		}
		if got := evaluateResourceBinding(op, acOnly, nil, false, "por-B", true); got != resourceBindingPass {
			t.Fatalf("decision = %v, want pass on matching resource", got)
		}
	})

	t.Run("AND capability member must match", func(t *testing.T) {
		_, _, op := compileSynthetic(t, andReqSpecYAML)
		human := mustBinding(NewHumanOIDCBinding("iss", "sub"))
		mismatched := mustBinding(NewRequestAccessBinding("por-B"))
		ac := newBindingAC(op, human, mismatched)

		if got := evaluateResourceBinding(op, ac, nil, false, "por-A", true); got != resourceBindingUnauthorized {
			t.Fatalf("decision = %v, want unauthorized", got)
		}

		matched := mustBinding(NewRequestAccessBinding("por-A"))
		acMatch := newBindingAC(op, human, matched)
		if got := evaluateResourceBinding(op, acMatch, nil, false, "por-A", true); got != resourceBindingPass {
			t.Fatalf("decision = %v, want pass", got)
		}

		// No path resource id: no constraint from the capability member.
		if got := evaluateResourceBinding(op, ac, nil, false, "", false); got != resourceBindingPass {
			t.Fatalf("decision = %v, want pass without path id", got)
		}
	})

	t.Run("unexpected requirement on non-conditional operation fails closed", func(t *testing.T) {
		_, _, op := compileSynthetic(t, orReqSpecYAML)
		human := mustBinding(NewHumanOIDCBinding("iss", "sub"))
		ac := newBindingAC(op, human)
		cr := newConditionalRequirement("operation", "INITIAL", authpolicy.CredentialKindRequestAccessToken)
		if got := evaluateResourceBinding(op, ac, cr, true, "por-A", true); got != resourceBindingIntegrity {
			t.Fatalf("decision = %v, want integrity", got)
		}
	})
}

// TestResourceBindingMiddlewareMissingRequirementFailsClosed proves at the
// middleware level that a conditional operation without a trusted
// ConditionalRequirement fails closed as an internal error (500) and never
// falls back to base-OR validation.
func TestResourceBindingMiddlewareMissingRequirementFailsClosed(t *testing.T) {
	spec := loadYAMLSpec(t, conditionalCompleteSpecYAML)
	pol, err := authpolicy.Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rt, err := NewRuntime(spec, pol, DefaultDenyRegistry(), nil, 262144, 4<<20)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}

	ac := &AuthenticationContext{operationID: "condCompleteOp"}
	req := httptest.NewRequest(http.MethodPost, "/c", nil)
	rctx := chi.NewRouteContext()
	rctx.RoutePatterns = []string{"/c"}
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(WithAuthenticationContext(req.Context(), ac))

	called := false
	handler := rt.ResourceBinding()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if called {
		t.Fatal("next handler was called despite the missing conditional requirement")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (internal fail-closed, no base-OR fallback)", rec.Code)
	}
}

// TestConditionalRequirementImmutableAndRoundTrip proves the typed
// requirement survives the context boundary and exposes no mutable state.
func TestConditionalRequirementImmutableAndRoundTrip(t *testing.T) {
	cr := newConditionalRequirement("installation_status", "INSTALLED", authpolicy.CredentialKindDeviceMTLS)
	if cr.Discriminator() != "installation_status" || cr.DiscriminatorValue() != "INSTALLED" || cr.RequiredKind() != authpolicy.CredentialKindDeviceMTLS {
		t.Fatalf("accessors = (%q, %q, %q)", cr.Discriminator(), cr.DiscriminatorValue(), cr.RequiredKind())
	}
	// The requirement is immutable: there is no setter and the fields are
	// unexported; only value accessors exist.

	ctx := withConditionalRequirement(context.Background(), cr)
	got, ok := conditionalRequirementFrom(ctx)
	if !ok {
		t.Fatal("conditional requirement not found in context")
	}
	if got.Discriminator() != cr.Discriminator() || got.DiscriminatorValue() != cr.DiscriminatorValue() || got.RequiredKind() != cr.RequiredKind() {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if _, ok := conditionalRequirementFrom(context.Background()); ok {
		t.Fatal("fresh context must not carry a conditional requirement")
	}
}
