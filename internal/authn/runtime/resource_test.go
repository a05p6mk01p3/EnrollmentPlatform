package runtime

import (
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-chi/chi/v5"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
)

// TestCanonicalSpecRouteResourceClassification proves the startup-derived
// typed resource classification for the real canonical contract: the resource
// kind comes from the canonical path-parameter component identity, never from
// the path parameter name "id" (every canonical resource path parameter is
// named "id").
func TestCanonicalSpecRouteResourceClassification(t *testing.T) {
	spec, err := openapi.GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := authpolicy.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := NewRuntime(spec, pol, DefaultDenyRegistry(), nil, 262144, 4<<20)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		key  string
		want ResourceKind
	}{
		{"GET /v1/pre-onboarding-requests/{id}", ResourceKindPreOnboardingRequest},
		{"POST /v1/pre-onboarding-requests", ResourceKindUnknown},
		{"POST /v1/enrollments", ResourceKindUnknown},
		{"GET /v1/enrollments/{id}", ResourceKindEnrollment},
		{"PUT /v1/enrollments/{id}/evidence", ResourceKindEnrollment},
		{"POST /v1/enrollments/{id}/challenge:refresh", ResourceKindEnrollment},
		{"GET /v1/enrollments/{id}/certificate", ResourceKindEnrollment},
		{"POST /v1/enrollments/{id}/complete", ResourceKindEnrollment},
		{"POST /v1/admin/devices/{id}/rebind-requests", ResourceKindDevice},
		{"POST /v1/admin/device-rebind-requests/{id}/approve", ResourceKindDeviceRebindRequest},
		{"POST /v1/admin/certificates/{id}/revocations", ResourceKindCertificate},
		{"POST /v1/admin/temporary-principals/{id}/disable", ResourceKindTemporaryPrincipal},
		{"GET /v1/admin/revocation-requests/{id}", ResourceKindRevocationRequest},
	}
	for _, tc := range cases {
		got, ok := rt.byRouteResource[tc.key]
		if !ok {
			t.Fatalf("route %q was not classified at startup", tc.key)
		}
		if got != tc.want {
			t.Fatalf("route %q kind = %v, want %v", tc.key, got, tc.want)
		}
	}
}

// TestCanonicalSpecMatchedResource proves the matched-resource view derived
// from the canonical classification: createEnrollment carries no path
// resource (Present=false), completeEnrollment is an Enrollment resource whose
// value comes from chi's parsed path parameters, and pre-onboarding routes are
// PreOnboardingRequest resources.
func TestCanonicalSpecMatchedResource(t *testing.T) {
	spec, err := openapi.GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := authpolicy.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := NewRuntime(spec, pol, DefaultDenyRegistry(), nil, 262144, 4<<20)
	if err != nil {
		t.Fatal(err)
	}

	newRctx := func(pattern string, params map[string]string) *chi.Context {
		rctx := chi.NewRouteContext()
		rctx.RoutePatterns = []string{pattern}
		for k, v := range params {
			rctx.URLParams.Keys = append(rctx.URLParams.Keys, k)
			rctx.URLParams.Values = append(rctx.URLParams.Values, v)
		}
		return rctx
	}

	t.Run("createEnrollment has no path resource", func(t *testing.T) {
		rctx := newRctx("/v1/enrollments", nil)
		res, ok := rt.matchedResource(http.MethodPost, rctx.RoutePattern(), rctx)
		if !ok {
			t.Fatal("matchedResource failed")
		}
		if res.Present {
			t.Fatalf("createEnrollment matched resource = %+v, want Present=false", res)
		}
	})

	t.Run("completeEnrollment is an Enrollment resource", func(t *testing.T) {
		rctx := newRctx("/v1/enrollments/{id}/complete", map[string]string{"id": "enr-A"})
		res, ok := rt.matchedResource(http.MethodPost, rctx.RoutePattern(), rctx)
		if !ok {
			t.Fatal("matchedResource failed")
		}
		if !res.Present || res.Kind != ResourceKindEnrollment || res.Value != "enr-A" {
			t.Fatalf("matched resource = %+v, want Enrollment enr-A", res)
		}
	})

	t.Run("pre-onboarding route is a PreOnboardingRequest resource", func(t *testing.T) {
		rctx := newRctx("/v1/pre-onboarding-requests/{id}", map[string]string{"id": "por-1"})
		res, ok := rt.matchedResource(http.MethodGet, rctx.RoutePattern(), rctx)
		if !ok {
			t.Fatal("matchedResource failed")
		}
		if !res.Present || res.Kind != ResourceKindPreOnboardingRequest || res.Value != "por-1" {
			t.Fatalf("matched resource = %+v, want PreOnboardingRequest por-1", res)
		}
	})
}

// TestClassifyRouteResourceUnresolvedParameterRefs proves SOL-M4.5-004: ANY
// unresolved ParameterRef encountered during route-resource classification
// fails closed unconditionally. The failure is never conditioned on whether
// the referenced component name is recognized, because without a resolved
// value the parameter's location (path/query/header/cookie) and semantics
// cannot be evaluated.
func TestClassifyRouteResourceUnresolvedParameterRefs(t *testing.T) {
	cases := []struct {
		name string
		op   *openapi3.Operation
	}{
		{
			name: "nil parameter reference",
			op:   &openapi3.Operation{Parameters: openapi3.Parameters{nil}},
		},
		{
			name: "unresolved known component ref",
			op: &openapi3.Operation{Parameters: openapi3.Parameters{
				&openapi3.ParameterRef{Ref: "#/components/parameters/EnrollmentId"},
			}},
		},
		{
			name: "unresolved unknown component ref",
			op: &openapi3.Operation{Parameters: openapi3.Parameters{
				&openapi3.ParameterRef{Ref: "#/components/parameters/MysteryId"},
			}},
		},
		{
			name: "unresolved possibly-header ref",
			op: &openapi3.Operation{Parameters: openapi3.Parameters{
				&openapi3.ParameterRef{Ref: "#/components/parameters/SomeHeaderId"},
			}},
		},
		{
			name: "empty parameter entry",
			op: &openapi3.Operation{Parameters: openapi3.Parameters{
				&openapi3.ParameterRef{},
			}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pi := &openapi3.PathItem{}
			if _, err := classifyRouteResource(pi, tc.op, "/x/{id}"); err == nil {
				t.Fatal("unresolved parameter reference was silently skipped")
			}
		})
	}
}

// TestClassifyRouteResourceResolvedNonPathParamsIgnored proves a RESOLVED
// non-path parameter does not define route resource identity and is safely
// ignored for classification.
func TestClassifyRouteResourceResolvedNonPathParamsIgnored(t *testing.T) {
	pi := &openapi3.PathItem{}
	op := &openapi3.Operation{Parameters: openapi3.Parameters{
		&openapi3.ParameterRef{Value: &openapi3.Parameter{Name: "Idempotency-Key", In: "header"}},
		&openapi3.ParameterRef{Value: &openapi3.Parameter{Name: "X-Correlation-ID", In: "header"}},
	}}
	kind, err := classifyRouteResource(pi, op, "/x")
	if err != nil {
		t.Fatal(err)
	}
	if kind != ResourceKindUnknown {
		t.Fatalf("kind = %v, want unknown", kind)
	}
}

// TestClassifyRouteResourceResolvedNonPathRefParamsIgnored mirrors the
// canonical contract shape: resolved $ref parameters that are not path
// parameters are ignored.
func TestClassifyRouteResourceResolvedNonPathRefParamsIgnored(t *testing.T) {
	pi := &openapi3.PathItem{}
	op := &openapi3.Operation{Parameters: openapi3.Parameters{
		&openapi3.ParameterRef{Ref: "#/components/parameters/CorrelationId", Value: &openapi3.Parameter{Name: "X-Correlation-ID", In: "header"}},
	}}
	kind, err := classifyRouteResource(pi, op, "/x")
	if err != nil {
		t.Fatal(err)
	}
	if kind != ResourceKindUnknown {
		t.Fatalf("kind = %v, want unknown", kind)
	}
}

// TestMatchedResourceIsContextAware proves matchedResource only reads chi's
// parsed route context.
func TestMatchedResourceIsContextAware(t *testing.T) {
	rt := &Runtime{byRouteResource: map[string]ResourceKind{
		"POST /v1/enrollments/{id}/complete": ResourceKindEnrollment,
	}}

	rctx := chi.NewRouteContext()
	rctx.RoutePatterns = []string{"/v1/enrollments/{id}/complete"}
	rctx.URLParams = chi.RouteParams{Keys: []string{"id"}, Values: []string{"enr-B"}}

	res, ok := rt.matchedResource(http.MethodPost, rctx.RoutePattern(), rctx)
	if !ok {
		t.Fatal("matchedResource failed")
	}
	if !res.Present || res.Kind != ResourceKindEnrollment || res.Value != "enr-B" {
		t.Fatalf("matched resource = %+v, want Enrollment enr-B", res)
	}

	// A classified route whose matched value is missing is an integrity
	// failure, not an empty match.
	empty := chi.NewRouteContext()
	empty.RoutePatterns = []string{"/v1/enrollments/{id}/complete"}
	if _, ok := rt.matchedResource(http.MethodPost, empty.RoutePattern(), empty); ok {
		t.Fatal("classified route without matched path parameter was accepted")
	}

	// A request with no route context still behaves safely at the helper
	// level: the value lookup finds nothing.
	if _, ok := rt.matchedResource(http.MethodPost, "/v1/enrollments/{id}/complete", nil); ok {
		t.Fatal("nil route context was accepted for a classified route")
	}
}
