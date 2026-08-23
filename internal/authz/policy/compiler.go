package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// httpMethods is the ordered set of HTTP methods a PathItem can carry.
var httpMethods = []string{
	"GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE",
}

// Compile derives the domain authorization policy for every operation in the
// canonical spec and returns it as an immutable, read-only *Policy.
//
// Compile reads the canonical spec and never mutates it. Any ambiguity,
// unsupported metadata, or scope divergence fails closed with a typed *CompileError.
func Compile(spec *openapi3.T) (*Policy, error) {
	if spec == nil {
		return nil, fmt.Errorf("authz policy: cannot compile nil specification")
	}

	refs := enumerateOperations(spec)

	p := &Policy{
		byID:       make(map[string]*OperationPolicy, len(refs)),
		operations: make([]*OperationPolicy, 0, len(refs)),
	}

	for _, ref := range refs {
		if strings.TrimSpace(ref.op.OperationID) == "" {
			return nil, fmtCompileError(ReasonMissingOperationID, ref.op.OperationID, ref.method, ref.path,
				"operation has missing, empty, or whitespace-only operationId")
		}

		op, err := compileOperation(ref)
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

	sort.Slice(p.operations, func(i, j int) bool {
		return p.operations[i].operationID < p.operations[j].operationID
	})

	return p, nil
}

type operationRef struct {
	path   string
	method string
	op     *openapi3.Operation
}

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

func compileOperation(ref operationRef) (*OperationPolicy, error) {
	opID := ref.op.OperationID
	attach := func(err error) error {
		var ce *CompileError
		if errors.As(err, &ce) {
			return ce.withOperation(opID, ref.method, ref.path)
		}
		return err
	}

	reqScopes, hasReqScopes, err := parseRequiredScopesExtension(ref.op)
	if err != nil {
		return nil, attach(err)
	}

	domainAuth, hasDomainAuth, err := parseDomainAuthExtension(ref.op)
	if err != nil {
		return nil, attach(err)
	}

	if !hasDomainAuth && !hasReqScopes {
		return &OperationPolicy{
			operationID: opID,
			method:      ref.method,
			path:        ref.path,
			kind:        PolicyKindNone,
		}, nil
	}

	if hasDomainAuth {
		if domainAuth.hasScopeStatus && domainAuth.hasStatus {
			return nil, fmtCompileError(ReasonAmbiguousDomainAuth, opID, ref.method, ref.path,
				"x-domain-authorization contains both scopeStatus and status")
		}

		if domainAuth.hasScopeStatus {
			if domainAuth.scopeStatus != ScopeStatusConfirmed {
				return nil, fmtCompileError(ReasonUnknownScopeStatus, opID, ref.method, ref.path,
					"unknown scopeStatus %q (expected %q)", domainAuth.scopeStatus, ScopeStatusConfirmed)
			}
			if len(domainAuth.requiredScopes) == 0 {
				return nil, fmtCompileError(ReasonEmptyScope, opID, ref.method, ref.path,
					"scopeStatus %q requires non-empty requiredScopes", ScopeStatusConfirmed)
			}
			if hasReqScopes {
				if !slicesEqual(reqScopes, domainAuth.requiredScopes) {
					return nil, fmtCompileError(ReasonScopeDivergence, opID, ref.method, ref.path,
						"x-required-scopes %v and x-domain-authorization.requiredScopes %v diverge",
						reqScopes, domainAuth.requiredScopes)
				}
			}
			var meta *OpenMetadata
			if domainAuth.highImpact || domainAuth.stepUpPolicy != "" {
				meta = &OpenMetadata{
					HighImpact:   domainAuth.highImpact,
					StepUpPolicy: domainAuth.stepUpPolicy,
					ScopeStatus:  domainAuth.scopeStatus,
				}
			}
			return &OperationPolicy{
				operationID:    opID,
				method:         ref.method,
				path:           ref.path,
				kind:           PolicyKindConfirmedScopes,
				requiredScopes: domainAuth.requiredScopes,
				openMetadata:   meta,
			}, nil
		}

		if domainAuth.hasStatus {
			if domainAuth.status != OpenStatusScopeName && domainAuth.status != OpenStatusReadScopeName {
				return nil, fmtCompileError(ReasonUnknownOpenStatus, opID, ref.method, ref.path,
					"unknown status %q (expected %q or %q)", domainAuth.status, OpenStatusScopeName, OpenStatusReadScopeName)
			}
			if hasReqScopes || len(domainAuth.requiredScopes) > 0 {
				return nil, fmtCompileError(ReasonOpenWithRequiredScopes, opID, ref.method, ref.path,
					"operation with status %q must not declare confirmed required scopes", domainAuth.status)
			}
			return &OperationPolicy{
				operationID: opID,
				method:      ref.method,
				path:        ref.path,
				kind:        PolicyKindOpen,
				openMetadata: &OpenMetadata{
					Status:                domainAuth.status,
					HighImpact:            domainAuth.highImpact,
					StepUpPolicy:          domainAuth.stepUpPolicy,
					ResourceScope:         domainAuth.resourceScope,
					GrantedPrincipalScope: domainAuth.grantedPrincipalScope,
				},
			}, nil
		}

		return nil, fmtCompileError(ReasonAmbiguousDomainAuth, opID, ref.method, ref.path,
			"x-domain-authorization requires either scopeStatus or status")
	}

	// hasReqScopes is true and hasDomainAuth is false
	return &OperationPolicy{
		operationID:    opID,
		method:         ref.method,
		path:           ref.path,
		kind:           PolicyKindConfirmedScopes,
		requiredScopes: reqScopes,
	}, nil
}

type parsedDomainAuth struct {
	required              bool
	hasScopeStatus        bool
	hasStatus             bool
	scopeStatus           ScopeStatus
	status                OpenStatus
	requiredScopes        []string
	highImpact            bool
	stepUpPolicy          string
	resourceScope         string
	grantedPrincipalScope string
}

func parseDomainAuthExtension(op *openapi3.Operation) (*parsedDomainAuth, bool, error) {
	raw := op.Extensions["x-domain-authorization"]
	if raw == nil {
		return nil, false, nil
	}

	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, false, newCompileError(ReasonMalformedDomainAuth, "x-domain-authorization is not an object")
	}

	reqVal, ok := obj["required"]
	if !ok {
		return nil, false, newCompileError(ReasonMissingRequiredField, "x-domain-authorization missing required field")
	}
	reqBool, ok := reqVal.(bool)
	if !ok {
		return nil, false, newCompileError(ReasonMalformedDomainAuth, "x-domain-authorization required field is not a boolean")
	}
	if !reqBool {
		return nil, false, newCompileError(ReasonMalformedDomainAuth, "x-domain-authorization required field must be true")
	}

	_, hasScopeStatus := obj["scopeStatus"]
	_, hasStatus := obj["status"]

	if hasScopeStatus && hasStatus {
		return nil, false, newCompileError(ReasonAmbiguousDomainAuth, "x-domain-authorization contains both scopeStatus and status")
	}

	res := &parsedDomainAuth{
		required:       true,
		hasScopeStatus: hasScopeStatus,
		hasStatus:      hasStatus,
	}

	if hasScopeStatus {
		ssRaw := obj["scopeStatus"]
		ssStr, ok := ssRaw.(string)
		if !ok || strings.TrimSpace(ssStr) == "" {
			return nil, false, newCompileError(ReasonMalformedDomainAuth, "x-domain-authorization scopeStatus must be a non-empty string")
		}
		res.scopeStatus = ScopeStatus(ssStr)
	}

	if hasStatus {
		stRaw := obj["status"]
		stStr, ok := stRaw.(string)
		if !ok || strings.TrimSpace(stStr) == "" {
			return nil, false, newCompileError(ReasonMalformedDomainAuth, "x-domain-authorization status must be a non-empty string")
		}
		res.status = OpenStatus(stStr)
	}

	if reqScopesRaw, ok := obj["requiredScopes"]; ok {
		scopes, err := parseStringSlice(reqScopesRaw, "x-domain-authorization.requiredScopes")
		if err != nil {
			return nil, false, err
		}
		res.requiredScopes = scopes
	}

	if hiRaw, ok := obj["highImpact"]; ok {
		hiBool, ok := hiRaw.(bool)
		if !ok {
			return nil, false, newCompileError(ReasonMalformedDomainAuth, "x-domain-authorization highImpact must be a boolean")
		}
		res.highImpact = hiBool
	}

	if suRaw, ok := obj["stepUpPolicy"]; ok {
		suStr, ok := suRaw.(string)
		if !ok || strings.TrimSpace(suStr) == "" {
			return nil, false, newCompileError(ReasonMalformedDomainAuth, "x-domain-authorization stepUpPolicy must be a non-empty string")
		}
		res.stepUpPolicy = suStr
	}

	if rsRaw, ok := obj["resourceScope"]; ok {
		rsStr, ok := rsRaw.(string)
		if !ok || strings.TrimSpace(rsStr) == "" {
			return nil, false, newCompileError(ReasonMalformedDomainAuth, "x-domain-authorization resourceScope must be a non-empty string")
		}
		res.resourceScope = rsStr
	}

	if gpsRaw, ok := obj["grantedPrincipalScope"]; ok {
		gpsStr, ok := gpsRaw.(string)
		if !ok || strings.TrimSpace(gpsStr) == "" {
			return nil, false, newCompileError(ReasonMalformedDomainAuth, "x-domain-authorization grantedPrincipalScope must be a non-empty string")
		}
		res.grantedPrincipalScope = gpsStr
	}

	return res, true, nil
}

func parseRequiredScopesExtension(op *openapi3.Operation) ([]string, bool, error) {
	raw := op.Extensions["x-required-scopes"]
	if raw == nil {
		return nil, false, nil
	}
	scopes, err := parseStringSlice(raw, "x-required-scopes")
	if err != nil {
		return nil, false, err
	}
	return scopes, true, nil
}

func parseStringSlice(raw any, fieldName string) ([]string, error) {
	slice, ok := raw.([]any)
	if !ok {
		// Kin-openapi might unmarshal directly to []string in some contexts
		if strSlice, ok := raw.([]string); ok {
			return normalizeStringSlice(strSlice, fieldName)
		}
		return nil, newCompileError(ReasonMalformedDomainAuth, fmt.Sprintf("%s is not an array", fieldName))
	}
	strSlice := make([]string, 0, len(slice))
	for _, item := range slice {
		s, ok := item.(string)
		if !ok {
			return nil, newCompileError(ReasonMalformedDomainAuth, fmt.Sprintf("%s contains non-string element", fieldName))
		}
		strSlice = append(strSlice, s)
	}
	return normalizeStringSlice(strSlice, fieldName)
}

func normalizeStringSlice(slice []string, fieldName string) ([]string, error) {
	if len(slice) == 0 {
		return nil, newCompileError(ReasonEmptyScope, fmt.Sprintf("%s is empty", fieldName))
	}
	seen := make(map[string]struct{}, len(slice))
	out := make([]string, 0, len(slice))
	for _, s := range slice {
		trimmed := strings.TrimSpace(s)
		if trimmed == "" {
			return nil, newCompileError(ReasonEmptyScope, fmt.Sprintf("%s contains empty scope string", fieldName))
		}
		if _, dup := seen[trimmed]; dup {
			return nil, newCompileError(ReasonDuplicateScope, fmt.Sprintf("%s contains duplicate scope %q", fieldName, trimmed))
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out, nil
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
