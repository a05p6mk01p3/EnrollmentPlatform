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
func canonicalEvidenceMeta() map[string]interface{} {
	return map[string]interface{}{
		"version":                 float64(1),
		"algorithm":               "SHA-256",
		"encoding":                "ordered-domain-separated-uint32-big-endian-length-framed-components",
		"unsignedIntegerEncoding": "minimal-big-endian-no-leading-zeroes; zero-is-00",
		"components": []interface{}{
			"domain UTF-8 literal enrollment-platform/evidence-identity",
			"identity_version unsigned-big-endian integer 1",
			"authoritative route-bound enrollment_id UTF-8",
			"challenge_version unsigned-big-endian integer",
			"csr_der_sha256 raw 32-byte SHA-256 of decoded validated PKCS#10 DER",
			"jws_compact exact UTF-8 validated JWS Compact Serialization",
			"tpm_evidence.format validated UTF-8",
			"tpm_evidence.version validated UTF-8",
			"tpm_evidence.payload UTF-8 RFC-8785/JCS opaque JSON object",
			"agent_assertions zero-length when absent, otherwise UTF-8 RFC-8785/JCS complete object",
		},
		"jsonCanonicalization": "RFC-8785-JCS-for-identity-only",
		"excludes":             []interface{}{"EnrollmentAccessToken", "Authorization", "X-Correlation-ID", "server-clock", "retry-counters", "transient-server-values", "client-provided-fingerprint"},
		"retry":                "same persisted EvidenceIdentityV1 returns original committed 202; missing/corrupt identity is 503 DEPENDENCY_UNAVAILABLE",
	}
}

func evidenceOperationDoc(evidenceMeta interface{}) map[string]interface{} {
	op := map[string]interface{}{
		"operationId": "submitEnrollmentEvidence",
		"requestBody": map[string]interface{}{
			"required": true,
			"content": map[string]interface{}{
				"application/json": map[string]interface{}{
					"schema": map[string]interface{}{"type": "object"},
				},
			},
		},
		"responses": map[string]interface{}{
			"202": map[string]interface{}{"description": "accepted"},
		},
	}
	if evidenceMeta != nil {
		op["x-evidence-identity"] = evidenceMeta
	}
	return op
}

func evidenceMetadataSpec(t *testing.T, evidenceMeta interface{}) *openapi3.T {
	t.Helper()
	doc := map[string]interface{}{
		"openapi": "3.1.0",
		"info":    map[string]interface{}{"title": "evidence-metadata-test", "version": "1.0.0"},
		"paths": map[string]interface{}{
			"/v1/enrollments/{id}/evidence": map[string]interface{}{
				"parameters": []interface{}{
					map[string]interface{}{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
				},
				"put": evidenceOperationDoc(evidenceMeta),
			},
		},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	spec, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	return spec
}

// evidenceMetadataSpecWithOther builds a spec whose evidence operation carries
// evidenceMeta and whose unrelated operation carries otherMeta (which may be a
// copied x-evidence-identity declaration).
func evidenceMetadataSpecWithOther(t *testing.T, evidenceMeta, otherMeta map[string]interface{}) *openapi3.T {
	t.Helper()
	otherOp := map[string]interface{}{
		"operationId": "someOtherOperation",
		"responses":   map[string]interface{}{"200": map[string]interface{}{"description": "ok"}},
	}
	if otherMeta != nil {
		otherOp["x-evidence-identity"] = otherMeta
	}
	doc := map[string]interface{}{
		"openapi": "3.1.0",
		"info":    map[string]interface{}{"title": "evidence-metadata-test", "version": "1.0.0"},
		"paths": map[string]interface{}{
			"/v1/enrollments/{id}/evidence": map[string]interface{}{
				"parameters": []interface{}{
					map[string]interface{}{"name": "id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
				},
				"put": evidenceOperationDoc(evidenceMeta),
			},
			"/v1/other": map[string]interface{}{"get": otherOp},
		},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	spec, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	return spec
}

func canonicalComponentStrings(meta map[string]interface{}) []interface{} {
	comps := meta["components"].([]interface{})
	return append([]interface{}(nil), comps...)
}

// SOL-M5.8-AUDIT-002 / SOL-M5.8-REAUDIT-001: the full negative metadata
// matrix. Each mutation of the single canonical fixture must fail safe
// (construction error or no skip) and must never enable partial skip behavior.
func TestEvidenceIdentityMetadataNegativeMatrix(t *testing.T) {
	wantPaths := [][]string{{"tpm_evidence", "payload"}, {"agent_assertions"}}

	t.Run("A: valid exact metadata enables intended skip paths", func(t *testing.T) {
		e, err := NewEnforcer(evidenceMetadataSpec(t, canonicalEvidenceMeta()), 262144, 4<<20)
		if err != nil {
			t.Fatalf("NewEnforcer: %v", err)
		}
		if len(e.evidenceSkipPaths) != len(wantPaths) {
			t.Fatalf("skip paths = %v, want exactly %v", e.evidenceSkipPaths, wantPaths)
		}
		for i := range wantPaths {
			if !slicesEqual(e.evidenceSkipPaths[i], wantPaths[i]) {
				t.Fatalf("skip paths = %v, want exactly %v", e.evidenceSkipPaths, wantPaths)
			}
		}
	})

	t.Run("B: metadata absent retains full strict checking", func(t *testing.T) {
		e, err := NewEnforcer(evidenceMetadataSpec(t, nil), 262144, 4<<20)
		if err != nil {
			t.Fatalf("NewEnforcer: %v", err)
		}
		if e.evidenceSkipPaths != nil {
			t.Fatal("absent metadata must not enable skip paths")
		}
	})

	mustFailConstruction := func(name string, meta interface{}) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			if _, err := NewEnforcer(evidenceMetadataSpec(t, meta), 262144, 4<<20); err == nil {
				t.Fatal("NewEnforcer must reject the mutated metadata")
			}
		})
	}

	mustFailConstruction("C: wrong metadata type (string)", "copied-string")
	mustFailConstruction("D: empty metadata object", map[string]interface{}{})
	mustFailConstruction("E: wrong version", withKey(canonicalEvidenceMeta(), "version", float64(2)))
	mustFailConstruction("F: wrong digest algorithm", withKey(canonicalEvidenceMeta(), "algorithm", "SHA-512"))
	mustFailConstruction("G: wrong JCS canonicalization identifier", withKey(canonicalEvidenceMeta(), "jsonCanonicalization", "RFC-8785-JCS-other"))
	mustFailConstruction("H: wrong framing/encoding field", withKey(canonicalEvidenceMeta(), "encoding", "unordered-concatenated-components"))
	mustFailConstruction("I: wrong unsignedIntegerEncoding", withKey(canonicalEvidenceMeta(), "unsignedIntegerEncoding", "varint"))
	mustFailConstruction("J: components array empty", withKey(canonicalEvidenceMeta(), "components", []interface{}{}))
	mustFailConstruction("J2: components field missing", withoutKey(canonicalEvidenceMeta(), "components"))
	mustFailConstruction("K: only the two delegated JCS components (REAUDIT-001)", withKey(canonicalEvidenceMeta(), "components", []interface{}{
		"tpm_evidence.payload UTF-8 RFC-8785/JCS opaque JSON object",
		"agent_assertions zero-length when absent, otherwise UTF-8 RFC-8785/JCS complete object",
	}))

	componentsMissingFirst := canonicalComponentStrings(canonicalEvidenceMeta())[1:]
	mustFailConstruction("L: one non-JCS component missing", withKey(canonicalEvidenceMeta(), "components", componentsMissingFirst))

	compsFirstAltered := canonicalComponentStrings(canonicalEvidenceMeta())
	compsFirstAltered[0] = "domain UTF-8 literal changed-domain"
	mustFailConstruction("M: first component altered", withKey(canonicalEvidenceMeta(), "components", compsFirstAltered))

	compsMiddleAltered := canonicalComponentStrings(canonicalEvidenceMeta())
	compsMiddleAltered[5] = "jws_compact exact UTF-8 validated JWS Compact Serialization CHANGED"
	mustFailConstruction("N: middle component altered", withKey(canonicalEvidenceMeta(), "components", compsMiddleAltered))

	compsLastAltered := canonicalComponentStrings(canonicalEvidenceMeta())
	compsLastAltered[9] = "agent_assertions ALTERED declaration"
	mustFailConstruction("O: last component altered", withKey(canonicalEvidenceMeta(), "components", compsLastAltered))

	compsReordered := canonicalComponentStrings(canonicalEvidenceMeta())
	compsReordered[0], compsReordered[1] = compsReordered[1], compsReordered[0]
	mustFailConstruction("P: components reordered", withKey(canonicalEvidenceMeta(), "components", compsReordered))

	compsExtra := append(canonicalComponentStrings(canonicalEvidenceMeta()), "extra unexpected component")
	mustFailConstruction("Q: extra component appended", withKey(canonicalEvidenceMeta(), "components", compsExtra))

	mustFailConstruction("R: unexpected extra metadata field", withKey(canonicalEvidenceMeta(), "unexpectedField", "surprise"))
	mustFailConstruction("R2: excludes altered", withKey(canonicalEvidenceMeta(), "excludes", []interface{}{"EnrollmentAccessToken"}))
	mustFailConstruction("R3: retry altered", withKey(canonicalEvidenceMeta(), "retry", "different retry semantics"))

	compsTPMPathAltered := canonicalComponentStrings(canonicalEvidenceMeta())
	compsTPMPathAltered[8] = "tpm_evidence.payload_other UTF-8 RFC-8785/JCS opaque JSON object"
	mustFailConstruction("S: TPM JCS component path altered", withKey(canonicalEvidenceMeta(), "components", compsTPMPathAltered))

	compsAAPathAltered := canonicalComponentStrings(canonicalEvidenceMeta())
	compsAAPathAltered[9] = "agent_assertions_other zero-length when absent, otherwise UTF-8 RFC-8785/JCS complete object"
	mustFailConstruction("T: agent_assertions component path altered", withKey(canonicalEvidenceMeta(), "components", compsAAPathAltered))

	compsDup := append(canonicalComponentStrings(canonicalEvidenceMeta()), "agent_assertions zero-length when absent, otherwise UTF-8 RFC-8785/JCS complete object")
	mustFailConstruction("U: duplicate component declaration", withKey(canonicalEvidenceMeta(), "components", compsDup))

	t.Run("V: valid metadata copied to unrelated operation is inert", func(t *testing.T) {
		spec := evidenceMetadataSpecWithOther(t, nil, canonicalEvidenceMeta())
		e, err := NewEnforcer(spec, 262144, 4<<20)
		if err != nil {
			t.Fatalf("NewEnforcer: %v", err)
		}
		if e.evidenceSkipPaths != nil {
			t.Fatal("metadata on an unrelated operation must not enable evidence skips")
		}
		other := &compiledOperation{operation: &openapi3.Operation{OperationID: "someOtherOperation"}}
		if got := e.evidenceOpaquePathsFor(other); got != nil {
			t.Fatal("runtime lookup for an unrelated operation must return nil")
		}
	})
}

// Positive proof against the REAL controlled OpenAPI v0.1.5 spec: the exact
// current metadata must delegate ONLY tpm_evidence.payload and agent_assertions.
func TestCanonicalSpecMetadataDerivesExactSkips(t *testing.T) {
	canonical := loadCanonical(t)
	e, err := NewEnforcer(canonical, 262144, 4<<20)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	want := [][]string{{"tpm_evidence", "payload"}, {"agent_assertions"}}
	if len(e.evidenceSkipPaths) != len(want) {
		t.Fatalf("skip paths = %v, want exactly %v", e.evidenceSkipPaths, want)
	}
	for i := range want {
		if !slicesEqual(e.evidenceSkipPaths[i], want[i]) {
			t.Fatalf("skip paths = %v, want exactly %v", e.evidenceSkipPaths, want)
		}
	}
	op := canonical.Paths.Map()["/v1/enrollments/{id}/evidence"].Put
	if got := e.evidenceOpaquePathsFor(&compiledOperation{operation: op}); len(got) != len(want) {
		t.Fatalf("runtime lookup for evidence operation = %v, want %v", got, want)
	}
	if got := e.evidenceOpaquePathsFor(&compiledOperation{operation: &openapi3.Operation{OperationID: "getEnrollment"}}); got != nil {
		t.Fatal("unrelated operation received evidence skip paths")
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func withoutKey(m map[string]interface{}, key string) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		if k != key {
			out[k] = v
		}
	}
	return out
}

func withKey(m map[string]interface{}, key string, value interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	out[key] = value
	return out
}

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
