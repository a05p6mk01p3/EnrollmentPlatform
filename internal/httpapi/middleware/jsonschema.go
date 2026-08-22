package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// specResourceURL is the resource URL under which the canonical spec document
// is registered with the JSON Schema compiler. Fragment-only $refs inside the
// spec (e.g. #/components/schemas/X) resolve against this base.
const specResourceURL = "ep://spec"

// buildValidationView returns a deep copy of the canonical spec with all
// security requirements removed. The canonical spec object is never mutated:
// authentication is a separate future layer and this validation view must not
// attempt it.
//
// The view is rebuilt through the kin-openapi loader (not a plain
// json.Unmarshal) so that internal $refs are re-resolved and every .Value is
// populated.
func buildValidationView(canonical *openapi3.T) (*openapi3.T, error) {
	data, err := json.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("marshaling canonical spec: %w", err)
	}
	view, err := openapi3.NewLoader().LoadFromData(data)
	if err != nil {
		return nil, fmt.Errorf("re-loading validation view: %w", err)
	}

	view.Security = nil
	for _, pi := range view.Paths.Map() {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			if op := pi.GetOperation(method); op != nil {
				op.Security = nil
			}
		}
	}
	return view, nil
}

// prepareJSONSchemaCompiler registers the canonical spec document with a
// JSON Schema 2020-12 compiler. Format assertion is enabled so date-time
// fields in request bodies (e.g. TemporaryPrincipalCreateRequest.expires_at)
// keep the strictness the contract previously had via kin-openapi. Content
// assertion is enabled so contentEncoding: base64 is checked for well-formed
// Base64 (jsonschema/v6 uses base64.StdEncoding — the same semantics
// encoding/json applies to []byte fields). Content assertion does NOT check
// decoded byte counts; that is enforced separately via x-max-decoded-bytes.
func prepareJSONSchemaCompiler(canonical *openapi3.T) (*jsonschema.Compiler, error) {
	doc, err := marshalSpecDocument(canonical)
	if err != nil {
		return nil, err
	}

	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	c.AssertContent()
	if err := c.AddResource(specResourceURL, doc); err != nil {
		return nil, fmt.Errorf("registering spec resource with JSON Schema compiler: %w", err)
	}
	return c, nil
}

// buildBodyValidators precompiles, once at startup, the JSON Schema validator
// for every operation that declares a request body. Compiled schemas are
// immutable and reused by concurrent requests; nothing is compiled per
// request.
func buildBodyValidators(c *jsonschema.Compiler, view *openapi3.T) (map[string]jsonSchemaValidator, error) {
	validators := map[string]jsonSchemaValidator{}
	for path, pi := range view.Paths.Map() {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			op := pi.GetOperation(method)
			if op == nil || op.RequestBody == nil || op.RequestBody.Value == nil {
				continue
			}
			content := op.RequestBody.Value.Content
			if content == nil || content["application/json"] == nil {
				return nil, fmt.Errorf("%s %s: request body without application/json content is not supported", strings.ToUpper(method), path)
			}
			compiled, err := c.Compile(specResourceURL + "#" + bodySchemaPointer(path, method))
			if err != nil {
				return nil, fmt.Errorf("compiling request body schema for %s %s: %w", strings.ToUpper(method), path, err)
			}
			validators[routeKey(method, path)] = compiled
		}
	}
	return validators, nil
}

// checkParamSchemas verifies at startup that every parameter schema in the
// contract compiles under JSON Schema 2020-12. Runtime parameter validation
// (presence, style/explode decoding, patterns) stays with kin-openapi; this
// check guarantees the schemas are 2020-12-compatible, so a future schema the
// engine cannot honor fails at startup instead of silently changing
// semantics.
func checkParamSchemas(c *jsonschema.Compiler, view *openapi3.T) error {
	for path, pi := range view.Paths.Map() {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			op := pi.GetOperation(method)
			if op == nil {
				continue
			}
			for i, pr := range pi.Parameters {
				if err := checkParamSchema(c, pr, pathItemParamPointer(path, i)); err != nil {
					return fmt.Errorf("%s %s: %w", strings.ToUpper(method), path, err)
				}
			}
			for i, pr := range op.Parameters {
				if err := checkParamSchema(c, pr, operationParamPointer(path, method, i)); err != nil {
					return fmt.Errorf("%s %s: %w", strings.ToUpper(method), path, err)
				}
			}
		}
	}
	return nil
}

func checkParamSchema(c *jsonschema.Compiler, pr *openapi3.ParameterRef, inlinePointer string) error {
	if pr == nil || pr.Value == nil || pr.Value.Schema == nil {
		return nil
	}
	loc := inlinePointer
	if pr.Ref != "" {
		loc = pr.Ref + "/schema" // pr.Ref already starts with "#"
	}
	target := specResourceURL
	if strings.HasPrefix(loc, "#") {
		target += loc
	} else {
		target += "#" + loc
	}
	if _, err := c.Compile(target); err != nil {
		return fmt.Errorf("parameter %q schema is not JSON Schema 2020-12 compatible: %w", pr.Value.Name, err)
	}
	return nil
}

// deriveDecodedLimitRules scans, once at startup, the top-level properties of
// every JSON request-body schema for the x-max-decoded-bytes extension and
// registers a decoded-byte ceiling per field and operation (SOL-001). The
// limit value is read from the spec itself; it is never hardcoded a second
// time. Only top-level properties are covered today — the contract currently
// has exactly one such field (csr_der_base64 in EvidenceSubmission).
func deriveDecodedLimitRules(view *openapi3.T) (map[string][]decodedLimitRule, error) {
	rules := map[string][]decodedLimitRule{}
	for path, pi := range view.Paths.Map() {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			op := pi.GetOperation(method)
			if op == nil || op.RequestBody == nil || op.RequestBody.Value == nil {
				continue
			}
			schema := op.RequestBody.Value.Content["application/json"].Schema.Value
			if schema == nil {
				continue
			}
			for name, prop := range schema.Properties {
				if prop == nil || prop.Value == nil {
					continue
				}
				ext := prop.Value.Extensions["x-max-decoded-bytes"]
				if ext == nil {
					continue
				}
				limit, err := extensionInt64(ext)
				if err != nil {
					return nil, fmt.Errorf("%s %s field %q: %w", strings.ToUpper(method), path, name, err)
				}
				rules[routeKey(method, path)] = append(rules[routeKey(method, path)], decodedLimitRule{field: name, limit: limit})
			}
		}
	}
	return rules, nil
}

// extensionInt64 converts a spec extension value to int64. The embedded spec
// arrives through JSON decoding (float64), but defensive support for other
// numeric forms is cheap.
func extensionInt64(v any) (int64, error) {
	switch n := v.(type) {
	case float64:
		return int64(n), nil
	case int:
		return int64(n), nil
	case int64:
		return n, nil
	case json.Number:
		return n.Int64()
	default:
		return 0, fmt.Errorf("x-max-decoded-bytes has unsupported value type %T", v)
	}
}

// marshalSpecDocument converts the canonical parsed spec to its JSON form.
func marshalSpecDocument(spec *openapi3.T) (map[string]any, error) {
	data, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("marshaling spec: %w", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("unmarshaling spec document: %w", err)
	}
	return doc, nil
}

// bodySchemaPointer returns the JSON pointer of the application/json request
// body schema of an operation within the spec document.
func bodySchemaPointer(path, method string) string {
	return "/paths/" + escapePointerSegment(path) + "/" + strings.ToLower(method) +
		"/requestBody/content/application~1json/schema"
}

func operationParamPointer(path, method string, index int) string {
	return "/paths/" + escapePointerSegment(path) + "/" + strings.ToLower(method) +
		"/parameters/" + strconv.Itoa(index) + "/schema"
}

func pathItemParamPointer(path string, index int) string {
	return "/paths/" + escapePointerSegment(path) + "/parameters/" + strconv.Itoa(index) + "/schema"
}

func escapePointerSegment(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	return strings.ReplaceAll(s, "/", "~1")
}
