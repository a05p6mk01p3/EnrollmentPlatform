package middleware

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
)

func loadCanonical(t *testing.T) *openapi3.T {
	t.Helper()
	spec, err := openapi.GetSpec()
	if err != nil {
		t.Fatalf("GetSpec: %v", err)
	}
	return spec
}

// The canonical spec object passed to the enforcer is never mutated: all six
// security schemes, the security requirements of createEnrollment and
// completeEnrollment, and the x-security-conditions metadata remain intact.
func TestNewEnforcerKeepsCanonicalSpecIntact(t *testing.T) {
	canonical := loadCanonical(t)

	enrollmentPost := canonical.Paths.Map()["/v1/enrollments"].Post
	completePost := canonical.Paths.Map()["/v1/enrollments/{id}/complete"].Post

	if _, err := NewEnforcer(canonical, 262144, 4<<20); err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	// Security schemes (6) still present on the canonical object.
	wantSchemes := []string{
		"HumanOIDC", "AdminOIDC", "TemporaryPrincipalToken",
		"RequestAccessToken", "EnrollmentAccessToken", "DeviceMTLS",
	}
	if len(canonical.Components.SecuritySchemes) != len(wantSchemes) {
		t.Fatalf("canonical security schemes = %d, want %d", len(canonical.Components.SecuritySchemes), len(wantSchemes))
	}
	for _, name := range wantSchemes {
		if canonical.Components.SecuritySchemes[name] == nil {
			t.Errorf("canonical spec lost security scheme %q", name)
		}
	}

	// createEnrollment keeps RequestAccessToken + DeviceMTLS.
	if enrollmentPost.Security == nil || len(*enrollmentPost.Security) != 2 {
		t.Fatalf("createEnrollment security = %v, want 2 requirements", enrollmentPost.Security)
	}
	if _, ok := (*enrollmentPost.Security)[0]["RequestAccessToken"]; !ok {
		t.Errorf("createEnrollment lost RequestAccessToken requirement: %v", *enrollmentPost.Security)
	}
	if _, ok := (*enrollmentPost.Security)[1]["DeviceMTLS"]; !ok {
		t.Errorf("createEnrollment lost DeviceMTLS requirement: %v", *enrollmentPost.Security)
	}

	// completeEnrollment keeps DeviceMTLS + EnrollmentAccessToken.
	if completePost.Security == nil || len(*completePost.Security) != 2 {
		t.Fatalf("completeEnrollment security = %v, want 2 requirements", completePost.Security)
	}
	if _, ok := (*completePost.Security)[0]["DeviceMTLS"]; !ok {
		t.Errorf("completeEnrollment lost DeviceMTLS requirement: %v", *completePost.Security)
	}
	if _, ok := (*completePost.Security)[1]["EnrollmentAccessToken"]; !ok {
		t.Errorf("completeEnrollment lost EnrollmentAccessToken requirement: %v", *completePost.Security)
	}

	// x-security-conditions metadata remains present (manual enforcement).
	if enrollmentPost.Extensions["x-security-conditions"] == nil {
		t.Error("canonical spec lost x-security-conditions on createEnrollment")
	}
}

// The validation view is a distinct object with all security requirements
// removed: it never attempts authentication.
func TestValidationViewHasNoSecurity(t *testing.T) {
	canonical := loadCanonical(t)
	e, err := NewEnforcer(canonical, 262144, 4<<20)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	view := e.spec
	if view == canonical {
		t.Fatal("validation view must be a distinct object from the canonical spec")
	}
	if view.Security != nil {
		t.Fatal("validation view must not carry global security requirements")
	}
	for path, pi := range view.Paths.Map() {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			op := pi.GetOperation(method)
			if op == nil {
				continue
			}
			if op.Security != nil {
				t.Errorf("validation view operation %s %s still carries security", method, path)
			}
		}
	}

	// The canonical spec keeps its security on the same operations.
	if canonical.Paths.Map()["/v1/enrollments"].Post.Security == nil {
		t.Fatal("canonical createEnrollment security was stripped")
	}
}

// Body validators are compiled exactly once at startup, one per operation
// with a request body, and they enforce the contract (additionalProperties,
// oneOf, const) without any per-request compilation.
func TestBodyValidatorsCompiledAtStartup(t *testing.T) {
	e, err := NewEnforcer(loadCanonical(t), 262144, 4<<20)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	want := 0
	for _, pi := range e.spec.Paths.Map() {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			if op := pi.GetOperation(method); op != nil && op.RequestBody != nil {
				want++
			}
		}
	}
	if want == 0 {
		t.Fatal("spec has no request bodies; test is meaningless")
	}
	if len(e.bodies) != want {
		t.Fatalf("precompiled body validators = %d, want %d", len(e.bodies), want)
	}

	v := e.bodies[routeKey(http.MethodPost, "/v1/enrollments")]
	if v == nil {
		t.Fatal("createEnrollment body validator missing")
	}
	good := map[string]any{"operation": "INITIAL", "certificate_usage": "PARTNER_AUTH"}
	if err := v.Validate(good); err != nil {
		t.Errorf("valid enrollment body rejected: %v", err)
	}
	if err := v.Validate(good); err != nil {
		t.Errorf("validator not reusable: %v", err)
	}
	badUnknown := map[string]any{"operation": "INITIAL", "certificate_usage": "PARTNER_AUTH", "extra": true}
	if err := v.Validate(badUnknown); err == nil {
		t.Error("body with unknown field accepted")
	}
	badOneOf := map[string]any{"operation": "BOGUS", "certificate_usage": "PARTNER_AUTH"}
	if err := v.Validate(badOneOf); err == nil {
		t.Error("body failing oneOf/const accepted")
	}
}

// An incompatible request-body schema fails construction: the API must not
// start without full enforcement.
func TestNewEnforcerFailsOnIncompatibleBodySchema(t *testing.T) {
	canonical := loadCanonical(t)

	data, err := json.Marshal(canonical)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Inject an invalid regular expression into a schema referenced by the
	// createEnrollment body. kin-openapi would fail at request time; the
	// enforcer must fail at construction time instead.
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	schemas["CertificateUsage"].(map[string]any)["pattern"] = "["

	brokenData, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal broken: %v", err)
	}
	spec, err := openapi3.NewLoader().LoadFromData(brokenData)
	if err != nil {
		t.Fatalf("load broken spec: %v", err)
	}

	if _, err := NewEnforcer(spec, 262144, 4<<20); err == nil {
		t.Fatal("NewEnforcer must fail when a body schema cannot be compiled")
	}
}

// The operation index is derived from the spec document; removing a path from
// the spec removes its entries from the index (no handwritten route table).
func TestRouteIndexDerivedFromSpec(t *testing.T) {
	canonical := loadCanonical(t)

	e, err := NewEnforcer(canonical, 262144, 4<<20)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}

	want := 0
	for _, pi := range canonical.Paths.Map() {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			if pi.GetOperation(method) != nil {
				want++
			}
		}
	}
	if want != 21 {
		t.Fatalf("spec operations = %d, want 21", want)
	}
	if len(e.index) != want {
		t.Fatalf("index entries = %d, want %d", len(e.index), want)
	}

	// A spec copy without /v1/pki/trust-bundles/current yields an index
	// without that entry.
	data, err := json.Marshal(canonical)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	delete(doc["paths"].(map[string]any), "/v1/pki/trust-bundles/current")

	reducedData, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal reduced: %v", err)
	}
	reduced, err := openapi3.NewLoader().LoadFromData(reducedData)
	if err != nil {
		t.Fatalf("load reduced: %v", err)
	}
	e2, err := NewEnforcer(reduced, 262144, 4<<20)
	if err != nil {
		t.Fatalf("NewEnforcer(reduced): %v", err)
	}
	if _, ok := e2.index[routeKey(http.MethodGet, "/v1/pki/trust-bundles/current")]; ok {
		t.Fatal("index must not contain an operation the spec no longer defines")
	}
	if _, ok := e2.index[routeKey(http.MethodGet, "/v1/me/authorizations")]; !ok {
		t.Fatal("index must still contain remaining spec operations")
	}
}
