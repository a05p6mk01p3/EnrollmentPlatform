package middleware

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
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

					if err := validateJSONDocument(bytes.NewReader(data)); err != nil {
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
