package middleware

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/go-chi/chi/v5"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi/problem"
)

// errBodyTooLarge marks a request body that exceeded the hard ceiling.
var errBodyTooLarge = errors.New("request body exceeds the hard ceiling")

// compiledOperation is one operation of the contract, indexed by the route
// pattern of the generated router. The index is derived at startup from the
// spec itself; there is no handwritten route table in this package.
type compiledOperation struct {
	method    string
	template  string
	operation *openapi3.Operation
	pathItem  *openapi3.PathItem
}

// Enforcer applies the OpenAPI v0.1.1 contract to requests before the
// generated strict handler decodes them.
//
// Routing remains the generated router's only source of truth: the enforcer
// runs as an operation middleware of the generated chi server and derives the
// operation from the matched route pattern. If the matched route cannot be
// mapped to a contract operation, the request fails closed.
//
// Authentication is deliberately NOT part of this layer: the enforcer works
// against a private validation view of the spec whose security requirements
// are removed (authn is a future milestone). The canonical spec object is
// never mutated. x-security-conditions and the decoded CSR byte limit remain
// manual.
type Enforcer struct {
	spec         *openapi3.T // validation view (separate from the canonical spec)
	index        map[string]*compiledOperation
	bodies       map[string]jsonSchemaValidator
	decodedRules map[string][]decodedLimitRule
	bodyBytes    int64 // effective JSON body limit: min(general, absolute)
	maxBodyBytes int64 // absolute platform backstop

	// evidenceSkipPaths are the duplicate-detection skip paths for the evidence
	// operation, derived ONCE at startup from the canonical x-evidence-identity
	// extension after structural validation. nil means full M3 strict checking
	// (metadata missing or operation absent). The value never depends on any
	// request material.
	evidenceSkipPaths [][]string
}

// decodedLimitRule enforces a decoded-byte ceiling on one base64 field of an
// operation's request body, derived at startup from the schema's
// x-max-decoded-bytes extension (e.g. csr_der_base64 <= 65536).
type decodedLimitRule struct {
	field string
	limit int64
}

// jsonSchemaValidator is the minimal surface used from a compiled
// santhosh-tekuri/jsonschema/v6 schema.
type jsonSchemaValidator interface {
	Validate(v any) error
}

// NewEnforcer prepares the enforcer from the canonical parsed spec.
//
// Body limits: generalJSONBytes is the default JSON body ceiling derived from
// the contract (x-protocol-limits.general_json_default_bytes, 256 KiB);
// absoluteBodyBytes is the platform-wide hard ceiling (4 MiB) that always
// backstops it. The effective JSON body limit is min(general, absolute).
//
// Construction compiles every request-body schema (and checks every parameter
// schema) against JSON Schema 2020-12, and derives the decoded-byte rules
// (x-max-decoded-bytes). Any incompatibility is a construction error: the API
// must not start with a contract it cannot enforce, and there is no silent
// fallback to different validation semantics at runtime.
func NewEnforcer(canonical *openapi3.T, generalJSONBytes, absoluteBodyBytes int64) (*Enforcer, error) {
	view, err := buildValidationView(canonical)
	if err != nil {
		return nil, err
	}

	compiler, err := prepareJSONSchemaCompiler(canonical)
	if err != nil {
		return nil, err
	}
	if err := checkParamSchemas(compiler, view); err != nil {
		return nil, err
	}
	bodies, err := buildBodyValidators(compiler, view)
	if err != nil {
		return nil, err
	}
	decodedRules, err := deriveDecodedLimitRules(view)
	if err != nil {
		return nil, err
	}

	e := &Enforcer{
		spec:         view,
		index:        map[string]*compiledOperation{},
		bodies:       bodies,
		decodedRules: decodedRules,
		bodyBytes:    minInt64(generalJSONBytes, absoluteBodyBytes),
		maxBodyBytes: absoluteBodyBytes,
	}
	if err := e.deriveEvidenceSkipPaths(view); err != nil {
		return nil, err
	}
	for path, pi := range view.Paths.Map() {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			op := pi.GetOperation(method)
			if op == nil {
				continue
			}
			e.index[routeKey(method, path)] = &compiledOperation{
				method:    strings.ToUpper(method),
				template:  path,
				operation: op,
				pathItem:  pi,
			}
		}
	}
	return e, nil
}

// OperationMiddleware returns the per-operation contract enforcement
// middleware, to be registered in the generated server's ChiServerOptions.
// It runs after the generated router matched a route and before the strict
// handler's JSON decode.
func (e *Enforcer) OperationMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rctx := chi.RouteContext(r.Context())
			if rctx == nil {
				// Outside a routed chi context there is no matched operation.
				// Fail closed: never run the handler without enforcement.
				problem.WriteInternal(w, r)
				return
			}

			cop := e.index[routeKey(r.Method, rctx.RoutePattern())]
			if cop == nil {
				// The generated router matched a route the enforcer cannot
				// map to a contract operation. This is an enforcement
				// integrity failure, not "route outside the contract": fail
				// closed.
				problem.WriteInternal(w, r)
				return
			}

			if cop.operation.RequestBody != nil {
				data, err := captureBody(w, r, e.bodyBytes)
				if err != nil {
					if errors.Is(err, errBodyTooLarge) {
						problem.WritePayloadTooLarge(w, r)
						return
					}
					problem.WriteInvalidRequest(w, r, "request body could not be read")
					return
				}

				if len(data) == 0 {
					if cop.operation.RequestBody.Value.Required {
						problem.WriteInvalidRequest(w, r, "request body is required")
						return
					}
				} else {
					// Content-Type cardinality: exactly one unambiguous
					// representation (SOL-003). Multiple header lines, combined
					// values and malformed parameters are all 415. The original
					// header is never mutated.
					values := r.Header.Values("Content-Type")
					if len(values) != 1 {
						problem.WriteUnsupportedMediaType(w, r)
						return
					}
					mediaType, _, perr := mime.ParseMediaType(values[0])
					if perr != nil || !strings.EqualFold(strings.TrimSpace(mediaType), "application/json") {
						problem.WriteUnsupportedMediaType(w, r)
						return
					}

					if err := validateJSONDocumentSkipping(bytes.NewReader(data), e.evidenceOpaquePathsFor(cop)); err != nil {
						problem.WriteInvalidRequest(w, r, "request body is not a single valid JSON document")
						return
					}

					dec := json.NewDecoder(bytes.NewReader(data))
					dec.UseNumber()
					var value any
					if err := dec.Decode(&value); err != nil {
						problem.WriteInvalidRequest(w, r, "request body could not be decoded")
						return
					}

					// Decoded-byte limits derived from the schema's
					// x-max-decoded-bytes extension (SOL-001): oversize is a
					// payload limit (413), malformed base64 is a syntax error
					// (400). Decoding uses base64.StdEncoding, the same
					// semantics encoding/json applies when the generated strict
					// server decodes the []byte field.
					if rules := e.decodedRules[routeKey(r.Method, rctx.RoutePattern())]; len(rules) > 0 {
						if obj, ok := value.(map[string]any); ok {
							for _, rule := range rules {
								raw, isStr := obj[rule.field].(string)
								if !isStr {
									continue // type/required handled by schema validation
								}
								decoded, derr := base64.StdEncoding.DecodeString(raw)
								if derr != nil {
									problem.WriteInvalidRequest(w, r, "request body contains malformed base64 content")
									return
								}
								if int64(len(decoded)) > rule.limit {
									problem.WritePayloadTooLarge(w, r)
									return
								}
							}
						}
					}

					if err := e.bodies[routeKey(r.Method, rctx.RoutePattern())].Validate(value); err != nil {
						problem.WriteInvalidRequest(w, r, "request body does not satisfy the API contract")
						return
					}
				}
			} else {
				// SOL-002: operations without a request body accept only an
				// empty body; any byte is 400 INVALID_REQUEST. Detection never
				// materializes the stream (single-byte peek at most).
				if r.Body != nil && r.Body != http.NoBody {
					if r.ContentLength > 0 {
						problem.WriteInvalidRequest(w, r, "request body not allowed for this operation")
						return
					}
					buf := make([]byte, 1)
					n, rerr := r.Body.Read(buf)
					if n > 0 {
						problem.WriteInvalidRequest(w, r, "request body not allowed for this operation")
						return
					}
					if rerr != nil && rerr != io.EOF {
						problem.WriteInvalidRequest(w, r, "request body could not be read")
						return
					}
				}
			}

			// Parameters (path/query/header presence, patterns, ranges) are
			// validated by kin-openapi against the validation view; request
			// body validation was already performed with the precompiled
			// schema above.
			input := &openapi3filter.RequestValidationInput{
				Request:    r,
				PathParams: pathParamsFromRoute(rctx),
				Route: &routers.Route{
					Spec:      e.spec,
					Path:      cop.template,
					PathItem:  cop.pathItem,
					Method:    cop.method,
					Operation: cop.operation,
				},
				Options: &openapi3filter.Options{
					ExcludeRequestBody:  true,
					SkipSettingDefaults: true,
				},
			}
			if err := openapi3filter.ValidateRequest(r.Context(), input); err != nil {
				problem.WriteInvalidRequest(w, r, "request does not satisfy the API contract")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// routeKey is the shared key between the generated router's matched pattern
// and the spec-derived index.
func routeKey(method, pathPattern string) string {
	return strings.ToUpper(method) + " " + pathPattern
}

// evidenceOperationID is the canonical operationId of the evidence submission
// operation in the controlled OpenAPI v0.1.5 contract. It is used only to
// locate the operation object inside the spec (never as a route table).
const evidenceOperationID = "submitEnrollmentEvidence"

// evidenceIdentityComponent is one authoritative component declaration of the
// EvidenceIdentityV1 encoding (OpenAPI v0.1.5 x-evidence-identity). jcsPath is
// the root-relative object-member path of the request body sub-tree whose
// duplicate-member detection is delegated to the application identity
// boundary; it is non-nil only for the two JCS-identity-bearing components.
type evidenceIdentityComponent struct {
	declaration string
	jcsPath     []string
}

// canonicalEvidenceIdentityComponents is the complete, ordered component list
// declared by the controlled OpenAPI v0.1.5 contract for EvidenceIdentityV1.
// Component count and order are authoritative and must match exactly.
var canonicalEvidenceIdentityComponents = []evidenceIdentityComponent{
	{declaration: "domain UTF-8 literal enrollment-platform/evidence-identity"},
	{declaration: "identity_version unsigned-big-endian integer 1"},
	{declaration: "authoritative route-bound enrollment_id UTF-8"},
	{declaration: "challenge_version unsigned-big-endian integer"},
	{declaration: "csr_der_sha256 raw 32-byte SHA-256 of decoded validated PKCS#10 DER"},
	{declaration: "jws_compact exact UTF-8 validated JWS Compact Serialization"},
	{declaration: "tpm_evidence.format validated UTF-8"},
	{declaration: "tpm_evidence.version validated UTF-8"},
	{declaration: "tpm_evidence.payload UTF-8 RFC-8785/JCS opaque JSON object", jcsPath: []string{"tpm_evidence", "payload"}},
	{declaration: "agent_assertions zero-length when absent, otherwise UTF-8 RFC-8785/JCS complete object", jcsPath: []string{"agent_assertions"}},
}

// Canonical semantic field values of the authoritative metadata, read from the
// controlled OpenAPI v0.1.5 source.
const (
	canonicalEvidenceIdentityVersion              = float64(1)
	canonicalEvidenceIdentityAlgorithm            = "SHA-256"
	canonicalEvidenceIdentityEncoding             = "ordered-domain-separated-uint32-big-endian-length-framed-components"
	canonicalEvidenceIdentityUnsignedIntEncoding  = "minimal-big-endian-no-leading-zeroes; zero-is-00"
	canonicalEvidenceIdentityJSONCanonicalization = "RFC-8785-JCS-for-identity-only"
	canonicalEvidenceIdentityRetry                = "same persisted EvidenceIdentityV1 returns original committed 202; missing/corrupt identity is 503 DEPENDENCY_UNAVAILABLE"
)

var canonicalEvidenceIdentityExcludes = []string{
	"EnrollmentAccessToken", "Authorization", "X-Correlation-ID", "server-clock",
	"retry-counters", "transient-server-values", "client-provided-fingerprint",
}

// evidenceIdentityMetadata is the strongly typed semantic shape of the
// authoritative x-evidence-identity extension. JSON tags mirror the controlled
// source; unknown fields are rejected at parse time.
type evidenceIdentityMetadata struct {
	Version                 float64  `json:"version"`
	Algorithm               string   `json:"algorithm"`
	Encoding                string   `json:"encoding"`
	UnsignedIntegerEncoding string   `json:"unsignedIntegerEncoding"`
	Components              []string `json:"components"`
	JSONCanonicalization    string   `json:"jsonCanonicalization"`
	Excludes                []string `json:"excludes"`
	Retry                   string   `json:"retry"`
}

// parseEvidenceIdentityMetadata converts the raw extension value into the
// strongly typed semantic shape. A nil raw value means the extension is absent
// and returns (nil, nil). Any structural/type ambiguity fails closed with an
// error.
func parseEvidenceIdentityMetadata(raw interface{}) (*evidenceIdentityMetadata, error) {
	if raw == nil {
		return nil, nil
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("encoding metadata: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var meta evidenceIdentityMetadata
	if err := dec.Decode(&meta); err != nil {
		return nil, fmt.Errorf("decoding metadata: %w", err)
	}
	return &meta, nil
}

// isExactlyCanonical proves that the parsed metadata is the COMPLETE, exact
// semantic declaration of the controlled EvidenceIdentityV1: every
// authority-bearing field matches its canonical value, the component list
// matches count, value and order exactly, and no unexpected component or
// field is present. Partial matches are not sufficient.
func (m *evidenceIdentityMetadata) isExactlyCanonical() bool {
	if m == nil {
		return false
	}
	if m.Version != canonicalEvidenceIdentityVersion {
		return false
	}
	if m.Algorithm != canonicalEvidenceIdentityAlgorithm {
		return false
	}
	if m.Encoding != canonicalEvidenceIdentityEncoding {
		return false
	}
	if m.UnsignedIntegerEncoding != canonicalEvidenceIdentityUnsignedIntEncoding {
		return false
	}
	if m.JSONCanonicalization != canonicalEvidenceIdentityJSONCanonicalization {
		return false
	}
	if !slices.Equal(m.Components, canonicalEvidenceIdentityDeclarations()) {
		return false
	}
	if !equalStringSets(m.Excludes, canonicalEvidenceIdentityExcludes) {
		return false
	}
	if m.Retry != canonicalEvidenceIdentityRetry {
		return false
	}
	return true
}

func canonicalEvidenceIdentityDeclarations() []string {
	out := make([]string, len(canonicalEvidenceIdentityComponents))
	for i, c := range canonicalEvidenceIdentityComponents {
		out[i] = c.declaration
	}
	return out
}

// canonicalEvidenceIdentityJCSPaths returns the root-relative duplicate-
// detection skip paths derived from the validated canonical component list
// (the components whose jcsPath is non-nil). The skip authority is the same
// single validated declaration source, never an independent hard-coded list.
func canonicalEvidenceIdentityJCSPaths() [][]string {
	var paths [][]string
	for _, c := range canonicalEvidenceIdentityComponents {
		if c.jcsPath != nil {
			paths = append(paths, append([]string(nil), c.jcsPath...))
		}
	}
	return paths
}

// equalStringSets compares two string lists as sets with exact multiplicity
// (order-insensitive, duplicate-sensitive).
func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa := append([]string(nil), a...)
	sb := append([]string(nil), b...)
	sort.Strings(sa)
	sort.Strings(sb)
	return slices.Equal(sa, sb)
}

// deriveEvidenceSkipPaths validates, once at startup, the authoritative
// x-evidence-identity extension on the evidence operation and records the
// duplicate-detection skip paths to apply. Fail-safe semantics:
//
//   - operation absent: no skip paths (nothing to derive);
//   - metadata absent: full M3 strict checking remains (no skip paths);
//   - metadata present but not the COMPLETE exact canonical declaration
//     (wrong shape/type/field/version/algorithm/encoding/canonicalization/
//     component count/value/order/duplicates/extras): construction error —
//     the API must not start with internally inconsistent authoritative
//     metadata;
//   - metadata exactly canonical: the skip paths are derived from the
//     validated JCS-bearing component declarations.
//
// Metadata copied onto any OTHER operation never enables skip behavior: the
// derivation only ever inspects the operation whose operationId is
// submitEnrollmentEvidence, and the runtime lookup re-checks the operationId.
func (e *Enforcer) deriveEvidenceSkipPaths(view *openapi3.T) error {
	for _, pi := range view.Paths.Map() {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			op := pi.GetOperation(method)
			if op == nil || op.OperationID != evidenceOperationID {
				continue
			}
			meta, err := parseEvidenceIdentityMetadata(op.Extensions["x-evidence-identity"])
			if err != nil {
				return fmt.Errorf("contract enforcement: malformed x-evidence-identity metadata on submitEnrollmentEvidence: %w", err)
			}
			if meta == nil {
				// Missing metadata: retain full M3 strict checking.
				return nil
			}
			if !meta.isExactlyCanonical() {
				return errors.New("contract enforcement: x-evidence-identity metadata on submitEnrollmentEvidence is not the exact canonical EvidenceIdentityV1 declaration")
			}
			e.evidenceSkipPaths = canonicalEvidenceIdentityJCSPaths()
			return nil
		}
	}
	return nil
}

// evidenceOpaquePathsFor returns the pre-derived skip paths for the evidence
// operation and nil for every other operation. The operationId check makes
// copied metadata on another operation inert; the paths themselves were fixed
// at startup, so no request value can influence skip-path selection.
func (e *Enforcer) evidenceOpaquePathsFor(cop *compiledOperation) [][]string {
	if cop == nil || cop.operation == nil || cop.operation.OperationID != evidenceOperationID {
		return nil
	}
	return e.evidenceSkipPaths
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// pathParamsFromRoute extracts chi's matched URL parameters for the
// parameter validator.
func pathParamsFromRoute(rctx *chi.Context) map[string]string {
	if len(rctx.URLParams.Keys) == 0 {
		return nil
	}
	m := make(map[string]string, len(rctx.URLParams.Keys))
	for i, k := range rctx.URLParams.Keys {
		m[k] = rctx.URLParams.Values[i]
	}
	return m
}

// captureBody reads the request body once, enforcing the hard ceiling, and
// restores it so downstream readers (validator, generated strict handler)
// re-read the same bounded bytes. It protects both Content-Length and
// chunked streams because the limit is enforced on the read itself.
func captureBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}

	r.Body = http.MaxBytesReader(w, r.Body, limit)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, errBodyTooLarge
		}
		return nil, err
	}

	// Restore the body for downstream readers; all subsequent reads come from
	// this bounded in-memory copy.
	r.Body = io.NopCloser(bytes.NewReader(data))
	r.ContentLength = int64(len(data))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	return data, nil
}
