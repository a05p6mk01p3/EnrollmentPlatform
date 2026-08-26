package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// Canonical contract constants for the idempotency metadata. They are the
// implementation's understanding of the current OpenAPI v0.1.1 contract and
// are validated against the compiled spec, never used as a hand-maintained
// endpoint list.
const (
	canonicalIdempotencyKeyRef  = "#/components/parameters/IdempotencyKey"
	canonicalIdempotencyKeyName = "Idempotency-Key"

	expectedSecretReplayMechanism = "encrypted-idempotency-replay-capsule"
	expectedActiveVerifierStorage = "non-reversible"
	expectedCapsulePurpose        = "response-loss-recovery-only"
)

// knownSecretReplayField reports whether key is one of the exact fields of
// the x-idempotent-secret-replay object. It is a closed switch, not a mutable
// package-level lookup table.
func knownSecretReplayField(key string) bool {
	switch key {
	case "secretField", "mechanism", "sameSecretRequired", "activeVerifierStorage", "capsulePurpose", "originator", "effectiveScope", "aadV1", "aadEncoding", "recovery", "replayAuthority":
		return true
	default:
		return false
	}
}

// orderedHTTPMethods returns the ordered set of HTTP methods a PathItem can
// carry, as a fresh value (no package-level mutable slice).
func orderedHTTPMethods() [8]string {
	return [8]string{
		"GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE",
	}
}

// paramKey identifies a parameter by its (name, location) pair, the key
// OpenAPI uses for operation-level overrides of path-item parameters.
type paramKey struct {
	name string
	in   string
}

// Compile derives the idempotency policy for every operation in the canonical
// spec and returns it as an immutable, read-only *Policy. Only operations that
// effectively declare the canonical Idempotency-Key parameter are included.
//
// Compile reads the canonical spec and never mutates it. Any ambiguity,
// unresolved reference, or unsupported/contradictory metadata is a typed
// *CompileError; the caller (the composition root) must refuse to start when
// one is returned.
func Compile(spec *openapi3.T) (*Policy, error) {
	if spec == nil {
		return nil, fmt.Errorf("idempotency policy: cannot compile nil specification")
	}

	refs := enumerateOperations(spec)

	p := &Policy{
		byID:       make(map[string]*Operation),
		operations: make([]*Operation, 0),
	}

	for _, ref := range refs {
		// operationId is the contract's logical key; a missing/empty value
		// fails closed before any policy is compiled or indexed. Valid
		// operationIds are never rewritten or case-normalized.
		if strings.TrimSpace(ref.op.OperationID) == "" {
			return nil, fmtCompileError(ReasonMissingOperationID, ref.op.OperationID, ref.method, ref.path,
				"operation has missing, empty, or whitespace-only operationId")
		}

		keyRequired, err := detectIdempotencyKey(ref.pi, ref.op, spec)
		if err != nil {
			return nil, attachOperation(err, ref)
		}

		secretReplay, err := parseSecretReplay(ref.op)
		if err != nil {
			return nil, attachOperation(err, ref)
		}

		// Secret replay is only meaningful for an idempotent operation: a
		// capsule can only be recovered after the exact idempotency scope and
		// fingerprint have matched, so declaring one without the other is a
		// contradiction that must fail closed.
		if secretReplay != nil && !keyRequired {
			return nil, fmtCompileError(ReasonSecretReplayWithoutIdempotencyKey, ref.op.OperationID, ref.method, ref.path,
				"x-idempotent-secret-replay declared without the canonical Idempotency-Key parameter")
		}

		if !keyRequired {
			// Non-idempotent operations are not part of this policy.
			continue
		}

		op := &Operation{
			operationID:  ref.op.OperationID,
			method:       ref.method,
			route:        ref.path,
			keyRequired:  true,
			secretReplay: secretReplay,
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

// attachOperation attaches operation context to a CompileError.
func attachOperation(err error, ref operationRef) error {
	var ce *CompileError
	if errors.As(err, &ce) {
		return ce.withOperation(ref.op.OperationID, ref.method, ref.path)
	}
	return err
}

// operationRef is one operation of the contract, with its path item, path,
// and method for diagnostics.
type operationRef struct {
	pi     *openapi3.PathItem
	path   string
	method string
	op     *openapi3.Operation
}

// enumerateOperations returns every operation in the spec in deterministic
// (path, method) order.
func enumerateOperations(spec *openapi3.T) []operationRef {
	var refs []operationRef
	for path, pi := range spec.Paths.Map() {
		for _, m := range orderedHTTPMethods() {
			if op := pi.GetOperation(m); op != nil {
				refs = append(refs, operationRef{pi: pi, path: path, method: strings.ToUpper(m), op: op})
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

// isIdempotencyRelevant reports whether a parameter is a candidate
// Idempotency-Key declaration. Recognition happens BEFORE any location check:
// a parameter is relevant when it references the canonical component OR its
// name equals Idempotency-Key case-insensitively. Once relevant, the exact
// frozen declaration is required; a relevant parameter must never be silently
// ignored.
func isIdempotencyRelevant(pr *openapi3.ParameterRef) bool {
	if pr == nil || pr.Value == nil {
		return false
	}
	if pr.Ref == canonicalIdempotencyKeyRef {
		return true
	}
	return strings.EqualFold(pr.Value.Name, canonicalIdempotencyKeyName)
}

// detectIdempotencyKey reports whether the operation effectively declares the
// canonical Idempotency-Key header parameter, honoring OpenAPI effective
// parameter semantics (path-item parameters apply to every operation;
// operation-level parameters override path-item parameters with the same name
// and location).
//
// A semantically relevant Idempotency-Key declaration must never disappear
// silently: a parameter is recognized as a candidate when it references the
// canonical component OR its name matches the canonical name
// case-insensitively, regardless of its declared location. Any recognized
// candidate that is not exactly the frozen canonical declaration (exact ref,
// exact name, exact in == "header") fails compilation as malformed rather
// than silently downgrading the operation to non-idempotent.
//
// It fails closed on any unresolved parameter reference rather than silently
// treating the operation as non-idempotent.
func detectIdempotencyKey(pi *openapi3.PathItem, op *openapi3.Operation, spec *openapi3.T) (bool, error) {
	if op == nil {
		return false, newCompileError(ReasonUnresolvedParameter, "operation is nil")
	}

	// Build the path-level effective set first. Duplicates within the SAME
	// level are contradictory metadata for idempotency-relevant candidates
	// and fail closed.
	pathParams := make(map[paramKey]*openapi3.ParameterRef)
	if pi != nil {
		pathSeen := make(map[paramKey]struct{}, len(pi.Parameters))
		for _, pr := range pi.Parameters {
			if pr == nil || pr.Value == nil {
				ref := ""
				if pr != nil {
					ref = pr.Ref
				}
				if ref != "" {
					return false, newCompileError(ReasonUnresolvedParameter,
						fmt.Sprintf("unresolved parameter reference %q", ref))
				}
				return false, newCompileError(ReasonUnresolvedParameter,
					"parameter entry has neither a reference nor a resolved value")
			}
			key := paramKey{name: pr.Value.Name, in: pr.Value.In}
			if isIdempotencyRelevant(pr) {
				if _, dup := pathSeen[key]; dup {
					return false, newCompileError(ReasonMalformedIdempotencyKey,
						"duplicate Idempotency-Key parameter declaration in path item")
				}
				pathSeen[key] = struct{}{}
			}
			pathParams[key] = pr
		}
	}

	// Operation-level parameters override path-level entries on the same
	// OpenAPI (name, location) identity. Duplicates within the operation
	// level itself are detected independently of the path-level set.
	effective := make(map[paramKey]*openapi3.ParameterRef, len(pathParams)+len(op.Parameters))
	for key, pr := range pathParams {
		effective[key] = pr
	}

	opSeen := make(map[paramKey]struct{}, len(op.Parameters))
	for _, pr := range op.Parameters {
		if pr == nil || pr.Value == nil {
			ref := ""
			if pr != nil {
				ref = pr.Ref
			}
			if ref != "" {
				return false, newCompileError(ReasonUnresolvedParameter,
					fmt.Sprintf("unresolved parameter reference %q", ref))
			}
			return false, newCompileError(ReasonUnresolvedParameter,
				"parameter entry has neither a reference nor a resolved value")
		}
		key := paramKey{name: pr.Value.Name, in: pr.Value.In}
		if isIdempotencyRelevant(pr) {
			if _, dup := opSeen[key]; dup {
				return false, newCompileError(ReasonMalformedIdempotencyKey,
					"duplicate Idempotency-Key parameter declaration in operation")
			}
			opSeen[key] = struct{}{}
		}
		effective[key] = pr
	}

	found := false
	for _, pr := range effective {
		if !isIdempotencyRelevant(pr) {
			continue
		}

		// The contract declares Idempotency-Key through one canonical
		// component with the exact name and header location. Any other
		// recognized candidate — inline, a different component, a
		// case-variant name, or a non-header location — is a structural
		// divergence that must fail closed rather than silently downgrade the
		// operation to non-idempotent.
		if pr.Ref != canonicalIdempotencyKeyRef || pr.Value.Name != canonicalIdempotencyKeyName || pr.Value.In != "header" {
			return false, newCompileError(ReasonMalformedIdempotencyKey,
				fmt.Sprintf("Idempotency-Key parameter must reference %s with the exact name %s and in header; got ref %q name %q in %q",
					canonicalIdempotencyKeyRef, canonicalIdempotencyKeyName, pr.Ref, pr.Value.Name, pr.Value.In))
		}
		if found {
			return false, newCompileError(ReasonMalformedIdempotencyKey,
				"duplicate Idempotency-Key parameter")
		}
		found = true
	}

	if !found {
		return false, nil
	}

	// The canonical component must remain required; a missing or optional
	// component would silently weaken the idempotency contract.
	comp, ok := spec.Components.Parameters["IdempotencyKey"]
	if !ok || comp == nil || comp.Value == nil {
		return false, newCompileError(ReasonMalformedIdempotencyKey,
			"components/parameters/IdempotencyKey is missing or unresolved")
	}
	if comp.Value.Name != canonicalIdempotencyKeyName || comp.Value.In != "header" {
		return false, newCompileError(ReasonMalformedIdempotencyKey,
			"components/parameters/IdempotencyKey must be a header parameter named Idempotency-Key")
	}
	if !comp.Value.Required {
		return false, newCompileError(ReasonMalformedIdempotencyKey,
			"components/parameters/IdempotencyKey must be declared required")
	}

	return true, nil
}

// parseSecretReplay parses and validates the optional
// x-idempotent-secret-replay extension for one operation. It returns nil when
// the extension is absent.
func parseSecretReplay(op *openapi3.Operation) (*SecretReplay, error) {
	if op == nil {
		return nil, nil
	}
	raw, present := op.Extensions["x-idempotent-secret-replay"]
	if !present {
		return nil, nil
	}

	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, newCompileError(ReasonMalformedSecretReplay,
			"x-idempotent-secret-replay must be an object")
	}

	// Reject unknown fields before accepting any value: an unknown field
	// could change semantics and is never silently ignored.
	for key := range obj {
		if !knownSecretReplayField(key) {
			return nil, newCompileError(ReasonMalformedSecretReplay,
				fmt.Sprintf("x-idempotent-secret-replay contains unknown field %q", key))
		}
	}

	secretField, ok := stringField(obj, "secretField")
	if !ok || secretField == "" {
		return nil, newCompileError(ReasonMalformedSecretReplay,
			"x-idempotent-secret-replay requires a non-empty string secretField")
	}

	mechanism, ok := stringField(obj, "mechanism")
	if !ok || mechanism != expectedSecretReplayMechanism {
		return nil, newCompileError(ReasonSecretReplayValueMismatch,
			fmt.Sprintf("x-idempotent-secret-replay.mechanism must be %q", expectedSecretReplayMechanism))
	}

	sameSecretRequired, ok := boolField(obj, "sameSecretRequired")
	if !ok {
		return nil, newCompileError(ReasonMalformedSecretReplay,
			"x-idempotent-secret-replay.sameSecretRequired must be a boolean")
	}
	// Replay must reproduce the SAME secret; false would permit a replacement
	// minting path that the contract does not allow.
	if !sameSecretRequired {
		return nil, newCompileError(ReasonSecretReplayValueMismatch,
			"x-idempotent-secret-replay.sameSecretRequired must be true")
	}

	activeVerifierStorage, ok := stringField(obj, "activeVerifierStorage")
	if !ok || activeVerifierStorage != expectedActiveVerifierStorage {
		return nil, newCompileError(ReasonSecretReplayValueMismatch,
			fmt.Sprintf("x-idempotent-secret-replay.activeVerifierStorage must be %q", expectedActiveVerifierStorage))
	}

	capsulePurpose, ok := stringField(obj, "capsulePurpose")
	if !ok || capsulePurpose != expectedCapsulePurpose {
		return nil, newCompileError(ReasonSecretReplayValueMismatch,
			fmt.Sprintf("x-idempotent-secret-replay.capsulePurpose must be %q", expectedCapsulePurpose))
	}

	return &SecretReplay{
		SecretField:           secretField,
		Mechanism:             mechanism,
		SameSecretRequired:    sameSecretRequired,
		ActiveVerifierStorage: activeVerifierStorage,
		CapsulePurpose:        capsulePurpose,
	}, nil
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

// boolField reads a bool-valued field from an extension object.
func boolField(obj map[string]any, field string) (bool, bool) {
	raw, ok := obj[field]
	if !ok {
		return false, false
	}
	b, ok := raw.(bool)
	return b, ok
}
