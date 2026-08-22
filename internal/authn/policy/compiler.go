package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// expectedConditionalEnforcement is the only enforcement value accepted for
// x-security-conditions by the current contract.
const expectedConditionalEnforcement = "MANDATORY_SERVER_POLICY_AND_CONTRACT_TEST"

// knownConditionalFields are the only keys accepted in the top-level
// x-security-conditions object.
var knownConditionalFields = map[string]struct{}{
	"discriminator": {},
	"cases":         {},
	"enforcement":   {},
}

// schemeStructure is the contracted structural shape of a security scheme
// definition for a given CredentialKind. The CredentialKind mapping stays
// nominal (by scheme name); this table only validates that the declared
// definition structure matches the contract, so a structurally incompatible
// mutation (e.g. DeviceMTLS turned into a bearer scheme, or HumanOIDC losing
// its JWT bearerFormat) fails closed at startup (SOL-M4.1-002).
type schemeStructure struct {
	schemeType   string // required OpenAPI "type" (case-sensitive)
	httpScheme   string // required HTTP "scheme" when type is http; compared case-insensitively (RFC 7235)
	bearerFormat string // required bearerFormat (exact match); empty means "no requirement"
}

// contractedSchemeStructures maps each CredentialKind to the structure its
// security-scheme definition must have in the current contract.
var contractedSchemeStructures = map[CredentialKind]schemeStructure{
	CredentialKindHumanOIDC: {schemeType: "http", httpScheme: "bearer", bearerFormat: "JWT"},
	CredentialKindAdminOIDC: {schemeType: "http", httpScheme: "bearer", bearerFormat: "JWT"},
	// TemporaryPrincipalToken: type/scheme are validated; bearerFormat is
	// deliberately NOT validated and its concrete credential mechanism must
	// not be inferred as JWT or opaque (deferred, OPEN-003).
	CredentialKindTemporaryPrincipalToken: {schemeType: "http", httpScheme: "bearer"},
	CredentialKindRequestAccessToken:      {schemeType: "http", httpScheme: "bearer", bearerFormat: "opaque"},
	CredentialKindEnrollmentAccessToken:   {schemeType: "http", httpScheme: "bearer", bearerFormat: "opaque"},
	CredentialKindDeviceMTLS:              {schemeType: "mutualTLS"},
}

// validateSecuritySchemeStructures checks every recognized (six-kind)
// security scheme declared in components against its contracted structure.
// Unrecognized scheme names are not validated here; they are rejected when
// referenced (ReasonUnknownScheme). Unresolved scheme refs are validated at
// reference time (ReasonUnresolvedScheme).
func validateSecuritySchemeStructures(spec *openapi3.T) error {
	if spec == nil || spec.Components == nil {
		return nil
	}
	names := make([]string, 0, len(spec.Components.SecuritySchemes))
	for name := range spec.Components.SecuritySchemes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ssr := spec.Components.SecuritySchemes[name]
		if ssr == nil || ssr.Value == nil {
			continue
		}
		kind, recognized := ParseCredentialKind(name)
		if !recognized {
			continue
		}
		if err := checkSchemeStructure(name, kind, ssr.Value); err != nil {
			return err
		}
	}
	return nil
}

// checkSchemeStructure validates one recognized scheme definition against the
// contracted structure for its kind.
func checkSchemeStructure(name string, kind CredentialKind, ss *openapi3.SecurityScheme) error {
	want := contractedSchemeStructures[kind]
	if ss.Type != want.schemeType {
		return newCompileError(ReasonSchemeStructureMismatch,
			fmt.Sprintf("security scheme %q (%s) has type %q; expected %q", name, kind, ss.Type, want.schemeType))
	}
	if want.httpScheme != "" && !strings.EqualFold(ss.Scheme, want.httpScheme) {
		return newCompileError(ReasonSchemeStructureMismatch,
			fmt.Sprintf("security scheme %q (%s) has http scheme %q; expected %q", name, kind, ss.Scheme, want.httpScheme))
	}
	if want.bearerFormat != "" && ss.BearerFormat != want.bearerFormat {
		return newCompileError(ReasonSchemeStructureMismatch,
			fmt.Sprintf("security scheme %q (%s) has bearerFormat %q; expected %q", name, kind, ss.BearerFormat, want.bearerFormat))
	}
	return nil
}

// httpMethods is the ordered set of HTTP methods a PathItem can carry. The
// current contract uses only get/post/put, but the compiler is written
// against the generic OpenAPI operation surface.
var httpMethods = []string{
	"GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE",
}

// Compile derives the authentication policy for every operation in the
// canonical spec and returns it as an immutable, read-only *Policy.
//
// Compile reads the canonical spec and never mutates it. Any ambiguity,
// unknown scheme, or unsupported metadata is a typed *CompileError; the
// caller (the composition root) must refuse to start when one is returned.
func Compile(spec *openapi3.T) (*Policy, error) {
	if spec == nil {
		return nil, fmt.Errorf("authn policy: cannot compile nil specification")
	}

	if err := validateSecuritySchemeStructures(spec); err != nil {
		return nil, err
	}

	refs := enumerateOperations(spec)

	p := &Policy{
		byID:       make(map[string]*OperationPolicy, len(refs)),
		operations: make([]*OperationPolicy, 0, len(refs)),
	}

	for _, ref := range refs {
		// operationId is the contract's logical key for every operation; a
		// missing, empty, or whitespace-only value must fail closed before any
		// policy is compiled or indexed. Valid operationIds are never
		// rewritten or case-normalized (SOL-M4.1-003).
		if strings.TrimSpace(ref.op.OperationID) == "" {
			return nil, fmtCompileError(ReasonMissingOperationID, ref.op.OperationID, ref.method, ref.path,
				"operation has missing, empty, or whitespace-only operationId")
		}

		op, err := compileOperation(ref, spec)
		if err != nil {
			return nil, err
		}
		if _, dup := p.byID[op.operationID]; dup {
			return nil, fmtCompileError(ReasonDuplicateOperationID, op.operationID, ref.method, ref.path,
				"duplicate operationId %q", op.operationID)
		}
		p.byID[op.operationID] = op
		p.operations = append(p.operations, op)
	}

	// operations were already enumerated in deterministic order and appended
	// in that order; keep the read-only view sorted by operationId so
	// iteration is fully independent of any map ordering.
	sort.Slice(p.operations, func(i, j int) bool {
		return p.operations[i].operationID < p.operations[j].operationID
	})

	return p, nil
}

// operationRef is one operation of the contract, with its path and method for
// diagnostics.
type operationRef struct {
	path   string
	method string
	op     *openapi3.Operation
}

// enumerateOperations returns every operation in the spec in deterministic
// (path, method) order.
func enumerateOperations(spec *openapi3.T) []operationRef {
	var refs []operationRef
	for path, pi := range spec.Paths.Map() {
		for _, m := range httpMethods {
			if op := pi.GetOperation(m); op != nil {
				refs = append(refs, operationRef{path: path, method: strings.ToUpper(m), op: op})
			}
		}
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].path != refs[j].path {
			return refs[i].path < refs[j].path
		}
		return refs[i].method < refs[j].method
	})
	return refs
}

// compileOperation compiles the authentication policy of a single operation.
func compileOperation(ref operationRef, spec *openapi3.T) (*OperationPolicy, error) {
	opID := ref.op.OperationID
	attach := func(err error) error {
		var ce *CompileError
		if errors.As(err, &ce) {
			return ce.withOperation(opID, ref.method, ref.path)
		}
		return err
	}

	alternatives, noAppCred, err := compileSecurity(ref.op, spec)
	if err != nil {
		return nil, attach(err)
	}

	conditional, err := parseConditionalSecurity(ref.op, spec)
	if err != nil {
		return nil, attach(err)
	}

	disc := requestBodyDiscriminator(ref.op)

	if conditional != nil {
		if err := crossCheckConditional(conditional, disc, alternatives, opID, ref.method, ref.path); err != nil {
			return nil, err
		}
	} else if disc != nil && len(alternatives) >= 2 {
		// Structural weakening rule (no handwritten operation table): an
		// operation whose request body is discriminated AND whose base
		// security offers multiple independently satisfiable alternatives
		// MUST declare x-security-conditions to define the discriminator
		// pairing. Without it the policy would degrade to an unrestricted OR
		// that a body-dependent pairing was meant to constrain.
		return nil, fmtCompileError(ReasonConditionalMissing, opID, ref.method, ref.path,
			"discriminated request body (%q) with multiple security alternatives requires x-security-conditions", disc.PropertyName)
	}

	return &OperationPolicy{
		operationID:             opID,
		method:                  ref.method,
		path:                    ref.path,
		noApplicationCredential: noAppCred,
		alternatives:            alternatives,
		conditional:             conditional,
	}, nil
}

// compileSecurity interprets the operation's security field.
//
// security: []  -> noApplicationCredential == true.
// security nil -> typed compile error (never silently PUBLIC).
// security: [{}] -> typed compile error (empty requirement is not an accepted
// substitute for the explicit empty array).
// A referenced scheme must be one of the six contractual kinds AND declared
// in components/securitySchemes. Non-empty scope arrays are rejected: M4.1
// does not implement scopes and must not silently ignore them.
func compileSecurity(op *openapi3.Operation, spec *openapi3.T) ([]Conjunction, bool, error) {
	if op.Security == nil {
		return nil, false, newCompileError(ReasonNilSecurity,
			"operation has no security field; authentication must be declared explicitly")
	}

	if len(*op.Security) == 0 {
		// Explicit empty array: no application credential required.
		return nil, true, nil
	}

	alternatives := make([]Conjunction, 0, len(*op.Security))
	for _, requirement := range *op.Security {
		if len(requirement) == 0 {
			return nil, false, newCompileError(ReasonEmptySecurityRequirement,
				"empty Security Requirement Object ({}) is not an accepted substitute for security: []")
		}
		kinds := make([]CredentialKind, 0, len(requirement))
		for name, scopes := range requirement {
			if len(scopes) > 0 {
				return nil, false, newCompileError(ReasonNonEmptyScopes,
					fmt.Sprintf("security scheme %q carries scopes %v; scopes are not implemented in this milestone", name, scopes))
			}
			kind, ok := ParseCredentialKind(name)
			if !ok {
				return nil, false, newCompileError(ReasonUnknownScheme,
					fmt.Sprintf("security scheme %q is not one of the six contractual credential kinds", name))
			}
			if !isSchemeResolved(spec, name) {
				return nil, false, newCompileError(ReasonUnresolvedScheme,
					fmt.Sprintf("security scheme %q is not declared in components/securitySchemes", name))
			}
			kinds = append(kinds, kind)
		}
		// All schemes listed inside one Security Requirement Object are ANDed.
		alternatives = append(alternatives, newConjunction(kinds...))
	}
	return alternatives, false, nil
}

// isSchemeResolved reports whether a scheme name is declared and resolvable
// in the spec's components.
func isSchemeResolved(spec *openapi3.T, name string) bool {
	if spec == nil || spec.Components == nil {
		return false
	}
	ssr, ok := spec.Components.SecuritySchemes[name]
	return ok && ssr != nil && ssr.Value != nil
}

// parseConditionalSecurity parses and validates the x-security-conditions
// extension. It returns nil when the operation has no such extension.
func parseConditionalSecurity(op *openapi3.Operation, spec *openapi3.T) (*ConditionalSecurity, error) {
	raw := op.Extensions["x-security-conditions"]
	if raw == nil {
		return nil, nil
	}

	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, newCompileError(ReasonConditionalMalformed,
			"x-security-conditions is not an object")
	}

	for field := range obj {
		if _, known := knownConditionalFields[field]; !known {
			return nil, newCompileError(ReasonConditionalUnknownField,
				fmt.Sprintf("x-security-conditions contains unknown field %q", field))
		}
	}

	discriminator, ok := stringField(obj, "discriminator")
	if !ok || discriminator == "" {
		return nil, newCompileError(ReasonConditionalMalformed,
			"x-security-conditions requires a non-empty discriminator")
	}

	enforcement, ok := stringField(obj, "enforcement")
	if !ok {
		return nil, newCompileError(ReasonConditionalEnforcement,
			"x-security-conditions requires an enforcement field")
	}
	if enforcement != expectedConditionalEnforcement {
		return nil, newCompileError(ReasonConditionalEnforcement,
			fmt.Sprintf("unexpected enforcement value %q (expected %q)", enforcement, expectedConditionalEnforcement))
	}

	casesRaw, ok := obj["cases"]
	if !ok {
		return nil, newCompileError(ReasonConditionalMalformed,
			"x-security-conditions requires a cases field")
	}
	casesObj, ok := casesRaw.(map[string]any)
	if !ok {
		return nil, newCompileError(ReasonConditionalMalformed,
			"x-security-conditions cases is not an object")
	}
	if len(casesObj) == 0 {
		return nil, newCompileError(ReasonConditionalMalformed,
			"x-security-conditions cases is empty")
	}

	cases := make([]ConditionalCase, 0, len(casesObj))
	for value, caseRaw := range casesObj {
		caseObj, ok := caseRaw.(map[string]any)
		if !ok {
			return nil, newCompileError(ReasonConditionalMalformed,
				fmt.Sprintf("conditional case %q is not an object", value))
		}
		for field := range caseObj {
			if field != "requiredSecurityScheme" {
				return nil, newCompileError(ReasonConditionalUnknownField,
					fmt.Sprintf("conditional case %q contains unknown field %q", value, field))
			}
		}
		scheme, ok := stringField(caseObj, "requiredSecurityScheme")
		if !ok || scheme == "" {
			return nil, newCompileError(ReasonConditionalMalformed,
				fmt.Sprintf("conditional case %q requires a requiredSecurityScheme", value))
		}
		kind, ok := ParseCredentialKind(scheme)
		if !ok {
			return nil, newCompileError(ReasonUnknownScheme,
				fmt.Sprintf("conditional case %q references unknown scheme %q", value, scheme))
		}
		if !isSchemeResolved(spec, scheme) {
			return nil, newCompileError(ReasonUnresolvedScheme,
				fmt.Sprintf("conditional case %q references scheme %q not declared in components/securitySchemes", value, scheme))
		}
		cases = append(cases, ConditionalCase{
			discriminatorValue: value,
			requirement:        newConjunction(kind),
		})
	}

	sort.Slice(cases, func(i, j int) bool {
		return cases[i].discriminatorValue < cases[j].discriminatorValue
	})

	return &ConditionalSecurity{
		discriminator: discriminator,
		cases:         cases,
	}, nil
}

// crossCheckConditional validates the coherence between the compiled
// conditional security and the request body schema's discriminator, and that
// every conditional case mandates a scheme admitted by the base security.
func crossCheckConditional(cond *ConditionalSecurity, disc *openapi3.Discriminator, alternatives []Conjunction, opID, method, path string) error {
	if disc == nil {
		return fmtCompileError(ReasonConditionalDiscriminatorMismatch, opID, method, path,
			"x-security-conditions discriminator %q but request body schema has no discriminator", cond.discriminator)
	}
	if disc.PropertyName != cond.discriminator {
		return fmtCompileError(ReasonConditionalDiscriminatorMismatch, opID, method, path,
			"x-security-conditions discriminator %q does not match request body discriminator propertyName %q", cond.discriminator, disc.PropertyName)
	}

	// The set of conditional case names must equal the set of discriminator
	// mappings: a removed, renamed, or added case is a semantic regression.
	caseNames := make(map[string]struct{}, len(cond.cases))
	for _, c := range cond.cases {
		caseNames[c.discriminatorValue] = struct{}{}
	}
	mappingNames := make(map[string]struct{}, len(disc.Mapping))
	for name := range disc.Mapping {
		mappingNames[name] = struct{}{}
	}
	if len(caseNames) != len(mappingNames) {
		return fmtCompileError(ReasonConditionalCaseMismatch, opID, method, path,
			"x-security-conditions cases (%d) do not match request body discriminator mappings (%d)", len(caseNames), len(mappingNames))
	}
	for name := range caseNames {
		if _, ok := mappingNames[name]; !ok {
			return fmtCompileError(ReasonConditionalCaseMismatch, opID, method, path,
				"conditional case %q is not present in the request body discriminator mapping", name)
		}
	}

	// Every case's mandated scheme must be satisfiable as a complete singleton
	// alternative of the base security. Membership inside a larger AND
	// conjunction is not sufficient: the singular requiredSecurityScheme
	// expresses exactly one credential kind that must satisfy the case on its
	// own (SOL-M4.1-001).
	for _, c := range cond.cases {
		for _, k := range c.requirement.kinds {
			if !hasSingletonAlternative(alternatives, k) {
				return fmtCompileError(ReasonConditionalSchemeNotSingletonAlternative, opID, method, path,
					"conditional case %q mandates %q, which is not a complete singleton alternative of the operation's base security", c.discriminatorValue, k)
			}
		}
	}

	return nil
}

// hasSingletonAlternative reports whether alternatives contains a conjunction
// consisting of exactly the given kind (a complete singleton alternative).
func hasSingletonAlternative(alternatives []Conjunction, k CredentialKind) bool {
	for _, alt := range alternatives {
		if alt.Len() == 1 && alt.hasKind(k) {
			return true
		}
	}
	return false
}

// requestBodyDiscriminator returns the discriminator of the operation's
// application/json request body schema, or nil when there is none.
func requestBodyDiscriminator(op *openapi3.Operation) *openapi3.Discriminator {
	if op == nil || op.RequestBody == nil || op.RequestBody.Value == nil {
		return nil
	}
	content := op.RequestBody.Value.Content
	if content == nil {
		return nil
	}
	mt := content["application/json"]
	if mt == nil || mt.Schema == nil || mt.Schema.Value == nil {
		return nil
	}
	return mt.Schema.Value.Discriminator
}

// stringField reads a string-valued field from an extension object.
func stringField(obj map[string]any, field string) (string, bool) {
	raw, ok := obj[field]
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	return s, ok
}
