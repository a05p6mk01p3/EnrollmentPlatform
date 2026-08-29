package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-chi/chi/v5"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi/problem"
)

// httpMethods is the ordered set of HTTP methods a PathItem can carry.
var httpMethods = []string{
	http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete,
	http.MethodOptions, http.MethodHead, http.MethodPatch, http.MethodTrace,
}

// errorKind classifies a runtime authentication failure. It carries no
// credential data by construction.
type errorKind int

const (
	// errorKindAuthenticationRequired maps to the contracted 401
	// AUTHENTICATION_REQUIRED response.
	errorKindAuthenticationRequired errorKind = iota
	// errorKindDependencyUnavailable maps to the contracted 503
	// DEPENDENCY_UNAVAILABLE response (missing authenticator, indeterminate
	// authenticator decision).
	errorKindDependencyUnavailable
	// errorKindAmbiguousCredential maps to the internal boundary response:
	// the same bearer signal was accepted by more than one nominal kind,
	// which the platform must treat as a credential-kind separation defect.
	errorKindAmbiguousCredential
	// errorKindInvalidBinding maps to the internal boundary response: an
	// authenticator returned Authenticated without a valid typed binding, or
	// with a binding whose kind does not match the authenticator.
	errorKindInvalidBinding
)

// authnError is an internal runtime failure with no credential content.
type authnError struct {
	kind errorKind
}

func (e *authnError) Error() string {
	switch e.kind {
	case errorKindAuthenticationRequired:
		return "runtime: authentication required"
	case errorKindDependencyUnavailable:
		return "runtime: authentication dependency unavailable"
	case errorKindAmbiguousCredential:
		return "runtime: ambiguous credential classification"
	case errorKindInvalidBinding:
		return "runtime: invalid authenticated binding"
	default:
		return "runtime: authentication failure"
	}
}

// Runtime is the M4.2 authentication runtime boundary. It is immutable after
// construction and safe for concurrent use.
type Runtime struct {
	policy          *authpolicy.Policy
	byRoute         map[string]string       // routeKey -> operationId, derived at startup from the canonical spec
	byRouteResource map[string]ResourceKind // routeKey -> path resource kind, derived at startup from canonical path-parameter component identity
	registry        *Registry
	device          DeviceMTLSSource
	bodyLimit       int64 // effective JSON body limit for Phase B discriminator extraction
}

// NewRuntime prepares the runtime from the canonical spec and the compiled
// M4.1 policy. The method/path -> operationId bridge is derived from the
// canonical spec at startup (no second router, no handwritten table). Every
// spec route must resolve to a compiled policy, otherwise construction fails.
func NewRuntime(canonical *openapi3.T, compiled *authpolicy.Policy, registry *Registry, device DeviceMTLSSource, generalJSONBytes, absoluteBodyBytes int64) (*Runtime, error) {
	if canonical == nil {
		return nil, errors.New("runtime: nil canonical spec")
	}
	if compiled == nil {
		return nil, errors.New("runtime: nil compiled policy")
	}
	if registry == nil {
		registry = DefaultDenyRegistry()
	}

	rt := &Runtime{
		policy:          compiled,
		byRoute:         make(map[string]string),
		byRouteResource: make(map[string]ResourceKind),
		registry:        registry,
		device:          device,
		bodyLimit:       minInt64(generalJSONBytes, absoluteBodyBytes),
	}

	for path, pi := range canonical.Paths.Map() {
		for _, m := range httpMethods {
			op := pi.GetOperation(m)
			if op == nil || strings.TrimSpace(op.OperationID) == "" {
				continue
			}
			key := routeKey(m, path)
			if _, exists := compiled.Operation(op.OperationID); !exists {
				return nil, fmt.Errorf("runtime: spec route %s %s resolves to operationId %q which has no compiled policy", m, path, op.OperationID)
			}
			if prev, dup := rt.byRoute[key]; dup {
				return nil, fmt.Errorf("runtime: duplicate spec route %s (operationIds %q and %q)", key, prev, op.OperationID)
			}
			rt.byRoute[key] = op.OperationID

			// Typed route-resource classification (SOL-M4.5-003): derived from
			// the canonical path-parameter component identity, never from the
			// path parameter name "id".
			kind, err := classifyRouteResource(pi, op, path)
			if err != nil {
				return nil, err
			}
			rt.byRouteResource[key] = kind
		}
	}

	return rt, nil
}

// resolve maps a matched chi route pattern and method to the compiled
// operation policy. ok=false means the route cannot be mapped to a contract
// operation, which the caller must fail closed on.
func (rt *Runtime) resolve(method, routePattern string) (*authpolicy.OperationPolicy, bool) {
	opID, ok := rt.byRoute[routeKey(method, routePattern)]
	if !ok {
		return nil, false
	}
	op, ok := rt.policy.Operation(opID)
	return op, ok
}

// BaseAuthentication is Phase A: it runs after the generated router matched a
// route and before M3 contract enforcement.
func (rt *Runtime) BaseAuthentication() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rctx := chi.RouteContext(r.Context())
			if rctx == nil {
				// Outside a routed chi context there is no matched operation.
				problem.WriteInternal(w, r)
				return
			}

			policy, ok := rt.resolve(r.Method, rctx.RoutePattern())
			if !ok {
				// The generated router matched a route the runtime cannot map
				// to a contract operation: enforcement integrity failure.
				problem.WriteInternal(w, r)
				return
			}

			if policy.NoApplicationCredential() {
				// security: [] — the operation consumes no application
				// credential. No credential inspection, no authenticator
				// invocation, and no failure because of an irrelevant
				// Authorization header.
				next.ServeHTTP(w, r)
				return
			}

			ac, err := rt.authenticate(r, policy)
			if err != nil {
				rt.writeAuthFailure(w, r, policy, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithAuthenticationContext(r.Context(), ac)))
		})
	}
}

// ConditionalAuthentication is Phase B: it runs after M3 contract enforcement
// and before the generated strict handler.
func (rt *Runtime) ConditionalAuthentication() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rctx := chi.RouteContext(r.Context())
			if rctx == nil {
				problem.WriteInternal(w, r)
				return
			}

			policy, ok := rt.resolve(r.Method, rctx.RoutePattern())
			if !ok {
				problem.WriteInternal(w, r)
				return
			}

			cond := policy.Conditional()
			if cond == nil {
				next.ServeHTTP(w, r)
				return
			}

			ac, ok := AuthenticationContextFrom(r.Context())
			if !ok {
				// Phase A must precede Phase B; reaching a conditional
				// operation without a context is a boundary-integrity failure.
				problem.WriteInternal(w, r)
				return
			}

			value, err := rt.extractDiscriminator(w, r, cond.Discriminator())
			if err != nil {
				// The body already passed M3 validation, which constrains the
				// discriminator; any absence/mismatch here is an internal
				// boundary-integrity failure, not a client error.
				problem.WriteInternal(w, r)
				return
			}

			requirement, ok := cond.RequirementFor(value)
			if !ok {
				problem.WriteInternal(w, r)
				return
			}
			kinds := requirement.Kinds()
			if len(kinds) != 1 {
				// M4.1 guarantees a single required kind per case; anything
				// else is a boundary-integrity defect.
				problem.WriteInternal(w, r)
				return
			}
			required := kinds[0]
			if !ac.Has(required) {
				// The authenticated kinds do not satisfy the discriminator
				// case: wrong pairing fails closed. Do not re-authenticate.
				//
				// The WWW-Authenticate challenge is selected from the EFFECTIVE
				// required kind, not from the operation's base policy
				// (SOL-M4.2-001): a bearer-required failure challenges Bearer,
				// a DeviceMTLS-required failure issues no Bearer challenge and
				// invents no mTLS HTTP challenge.
				if isBearerKind(required) {
					problem.WriteUnauthorizedBearer(w, r)
				} else {
					problem.WriteUnauthorized(w, r)
				}
				return
			}

			// Publish the effective conditional requirement so the following
			// resource-binding step validates ONLY the required credential
			// (SOL-M4.3-002). Extra authenticated credentials must not veto.
			// The requirement is re-validated against the compiled policy by
			// the resource-binding step; it is not trusted blindly.
			next.ServeHTTP(w, r.WithContext(withConditionalRequirement(r.Context(), newConditionalRequirement(cond.Discriminator(), value, required))))
		})
	}
}

// ResourceBinding enforces that a capability credential authenticated for one
// resource cannot access a different resource. It runs after Phase B (in the
// composed pipeline) and before the business handler.
//
// Resource validation follows the EFFECTIVE policy, not a universal veto
// (SOL-M4.3-002), and the compiled M4.1 OperationPolicy is the authority
// (SOL-M4.3-002 final):
//
//   - For a conditional operation, Phase B must have published a trusted
//     ConditionalRequirement that exactly agrees with the compiled
//     ConditionalSecurity (discriminator, case, required kind, singleton).
//     A missing, stale, or inconsistent requirement is an internal
//     boundary-integrity failure and never falls back to base-OR
//     validation. Only the effective required credential is
//     resource-validated; extra authenticated capabilities never veto.
//   - For a non-conditional operation, an unexpected conditional
//     requirement is an integrity inconsistency and fails closed. Each
//     satisfied OR alternative is resource-validated independently: an
//     alternative is resource-valid when every capability member's binding
//     matches the route resource, and the operation passes when at least
//     one complete alternative is both authenticated and resource-valid.
//
// It is generic: it consumes the matched chi path parameters, the typed
// capability bindings in the AuthenticationContext and the typed conditional
// requirement, with no handwritten operationId table and no parsing of raw
// URL strings. The domain resource TYPE comes from the startup-derived
// canonical path-parameter component identity (SOL-M4.5-003); the path
// parameter name "id" by itself never determines the resource type.
func (rt *Runtime) ResourceBinding() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ac, ok := AuthenticationContextFrom(r.Context())
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			rctx := chi.RouteContext(r.Context())
			if rctx == nil {
				next.ServeHTTP(w, r)
				return
			}
			policy, ok := rt.resolve(r.Method, rctx.RoutePattern())
			if !ok {
				problem.WriteInternal(w, r)
				return
			}
			resource, ok := rt.matchedResource(r.Method, rctx.RoutePattern(), rctx)
			if !ok {
				// A classified route structurally carries the resource path
				// parameter; its absence at the matched route is an internal
				// boundary-integrity failure.
				problem.WriteInternal(w, r)
				return
			}
			cr, hasCR := conditionalRequirementFrom(r.Context())

			switch evaluateResourceBinding(policy, ac, cr, hasCR, resource) {
			case resourceBindingPass:
				next.ServeHTTP(w, r)
			case resourceBindingUnauthorized:
				// The challenge follows the effective required kind
				// (SOL-M4.2-001): a DeviceMTLS resource mismatch issues no
				// Bearer challenge and invents no mTLS HTTP challenge.
				if effectiveRequiredKindIsDeviceMTLS(cr, hasCR) {
					problem.WriteUnauthorized(w, r)
				} else {
					problem.WriteUnauthorizedBearer(w, r)
				}
			default:
				// Internal boundary-integrity failure: no detail, no fallback
				// to base-OR validation, no guessed credential.
				problem.WriteInternal(w, r)
			}
		})
	}
}

// resourceBindingDecision is the outcome of resource-binding validation.
type resourceBindingDecision int

const (
	resourceBindingPass resourceBindingDecision = iota
	resourceBindingUnauthorized
	resourceBindingIntegrity
)

// evaluateResourceBinding applies the SOL-M4.3-002 final semantics, treating
// the compiled OperationPolicy as the authority.
func evaluateResourceBinding(policy *authpolicy.OperationPolicy, ac *AuthenticationContext, cr *ConditionalRequirement, hasCR bool, resource MatchedResource) resourceBindingDecision {
	if policy.Conditional() != nil {
		// Conditional operation: the trusted Phase-B requirement must exist
		// and agree with the compiled ConditionalSecurity.
		if !hasCR {
			return resourceBindingIntegrity
		}
		kind, ok := validatedRequiredKind(policy, ac, cr)
		if !ok {
			return resourceBindingIntegrity
		}
		if !capabilityResourceMatches(ac, kind, resource) {
			return resourceBindingUnauthorized
		}
		return resourceBindingPass
	}

	// Non-conditional operation: an unexpected requirement is an integrity
	// inconsistency and must not influence evaluation.
	if hasCR {
		return resourceBindingIntegrity
	}
	if !resourceValidForAlternatives(ac, resource) {
		return resourceBindingUnauthorized
	}
	return resourceBindingPass
}

// matchedResource resolves the typed route resource for the matched route:
// the domain resource kind derived at startup from the canonical path
// template and the matched path-parameter value from chi's parsed route
// context (never a raw URL string).
func (rt *Runtime) matchedResource(method, routePattern string, rctx *chi.Context) (MatchedResource, bool) {
	kind := rt.byRouteResource[routeKey(method, routePattern)]
	if kind == ResourceKindUnknown {
		return MatchedResource{Kind: ResourceKindUnknown, Present: false}, true
	}
	value, present := pathParam(rctx, "id")
	if !present || value == "" {
		// A classified route structurally carries the resource path
		// parameter; its absence is an integrity failure, not a client
		// credential rejection.
		return MatchedResource{}, false
	}
	return MatchedResource{Kind: kind, Value: value, Present: true}, true
}

// compiled policy and returns the effective required kind. Any mismatch is an
// integrity failure (ok=false): missing/malformed/stale/inconsistent
// requirements never fall back to base-OR validation.
// validatedRequiredKind checks the conditional requirement against the
// compiled policy and returns the effective required kind. Any mismatch is an
// integrity failure (ok=false): missing/malformed/stale/inconsistent
// requirements never fall back to base-OR validation.
func validatedRequiredKind(policy *authpolicy.OperationPolicy, ac *AuthenticationContext, cr *ConditionalRequirement) (authpolicy.CredentialKind, bool) {
	if ac.OperationID() != policy.OperationID() {
		return "", false
	}
	cond := policy.Conditional()
	if cond == nil {
		return "", false
	}
	if cr.Discriminator() != cond.Discriminator() {
		return "", false
	}
	requirement, ok := cond.RequirementFor(cr.DiscriminatorValue())
	if !ok {
		return "", false
	}
	kinds := requirement.Kinds()
	if len(kinds) != 1 {
		return "", false
	}
	if cr.RequiredKind() != kinds[0] {
		return "", false
	}
	return kinds[0], true
}

// resourceValidForAlternatives evaluates the per-satisfied-alternative
// resource constraints of a non-conditional operation: at least one complete
// alternative must be resource-valid.
func resourceValidForAlternatives(ac *AuthenticationContext, resource MatchedResource) bool {
	for _, alt := range ac.SatisfiedAlternatives() {
		valid := true
		for _, k := range alt.Kinds() {
			if !capabilityResourceMatches(ac, k, resource) {
				valid = false
				break
			}
		}
		if valid {
			return true
		}
	}
	return false
}

// capabilityResourceMatches reports whether the given credential kind's
// binding matches the matched route resource. Each capability/device binding
// is constrained ONLY against the route resource kind it belongs to:
//
//   - RequestAccessToken binds only against a PreOnboardingRequest resource;
//   - EnrollmentAccessToken binds only against an Enrollment resource;
//   - DeviceMTLS.IssuedForEnrollmentID binds only against an Enrollment
//     resource.
//
// A route without a path resource imposes no constraint. A path parameter
// named "id" by itself never determines the domain resource type; the kind
// comes from the startup-derived canonical route classification.
func capabilityResourceMatches(ac *AuthenticationContext, kind authpolicy.CredentialKind, resource MatchedResource) bool {
	switch kind {
	case authpolicy.CredentialKindRequestAccessToken:
		b, ok := ac.Binding(kind)
		if !ok {
			return false
		}
		req, ok := b.RequestAccess()
		if !ok {
			return false
		}
		if !resource.Present {
			return true
		}
		if resource.Kind != ResourceKindPreOnboardingRequest {
			return false
		}
		return req.PreOnboardingRequestID == resource.Value
	case authpolicy.CredentialKindEnrollmentAccessToken:
		b, ok := ac.Binding(kind)
		if !ok {
			return false
		}
		enr, ok := b.EnrollmentAccess()
		if !ok {
			return false
		}
		if !resource.Present {
			return true
		}
		if resource.Kind != ResourceKindEnrollment {
			return false
		}
		return enr.EnrollmentID == resource.Value
	case authpolicy.CredentialKindDeviceMTLS:
		b, ok := ac.Binding(kind)
		if !ok {
			return false
		}
		d, ok := b.DeviceMTLS()
		if !ok {
			return false
		}
		if !resource.Present {
			// Routes without a path enrollment resource (createEnrollment
			// RENEWAL/REKEY) impose no exact-certificate constraint.
			return true
		}
		// The exact certificate/enrollment binding applies ONLY to a route
		// resource structurally known to be an Enrollment.
		if resource.Kind != ResourceKindEnrollment {
			return false
		}
		return d.IssuedForEnrollmentID == resource.Value
	default:
		return true
	}
}

// BearerTokenFromRequest applies the exact strict Authorization syntax used by
// M4 base authentication and returns the opaque bearer token without
// classifying it as any credential kind. M5.7 uses this only after ordinary
// authentication has already failed, so consumed-capability recovery cannot
// become an alternate M4 authenticator.
func BearerTokenFromRequest(r *http.Request) (string, bool, error) {
	if r == nil {
		return "", false, errBearerMalformed
	}
	return extractBearer(r.Header.Values("Authorization"))
}

// authenticate evaluates the base policy against the request's credential
// signals and produces the request-local AuthenticationContext.
func (rt *Runtime) authenticate(r *http.Request, policy *authpolicy.OperationPolicy) (*AuthenticationContext, error) {
	eligible := eligibleKinds(policy)
	if len(eligible) == 0 {
		// An authenticated operation whose policy mandates nothing is a
		// boundary-integrity defect, not a public endpoint.
		return nil, &authnError{kind: errorKindAmbiguousCredential}
	}

	bearerEligible := false
	for _, k := range eligible {
		if isBearerKind(k) {
			bearerEligible = true
			break
		}
	}

	accepted := make(map[authpolicy.CredentialKind]Binding)

	// Strict bearer extraction and nominal-kind classification. The same
	// opaque token is dispatched to every eligible bearer kind's authenticator.
	if bearerEligible {
		token, present, err := extractBearer(r.Header.Values("Authorization"))
		if err != nil {
			return nil, &authnError{kind: errorKindAuthenticationRequired}
		}
		if present {
			bearerSuccesses := 0
			for _, k := range eligible {
				if !isBearerKind(k) {
					continue
				}
				auth, ok := rt.registry.Get(k)
				if !ok {
					// Runtime support for a policy-required kind is missing.
					return nil, &authnError{kind: errorKindDependencyUnavailable}
				}
				res := auth.Authenticate(r.Context(), &Credential{BearerToken: token})
				switch res.Decision {
				case DecisionAuthenticated:
					if err := validateBinding(k, res.Binding); err != nil {
						return nil, &authnError{kind: errorKindInvalidBinding}
					}
					accepted[k] = *res.Binding
					bearerSuccesses++
				case DecisionRejected:
					// definitely not this kind
				default:
					// Indeterminate or unknown: never silently "rejected".
					return nil, &authnError{kind: errorKindDependencyUnavailable}
				}
			}
			if bearerSuccesses > 1 {
				// One physical bearer credential accepted by two distinct
				// nominal kinds: credential-kind ambiguity, fail closed.
				return nil, &authnError{kind: errorKindAmbiguousCredential}
			}
		}
	}

	// DeviceMTLS signal via the abstract source port only.
	if containsKind(eligible, authpolicy.CredentialKindDeviceMTLS) {
		var device *DeviceCredential
		var srcErr error
		if rt.device != nil {
			device, srcErr = rt.device.DeviceCredential(r)
		}
		if srcErr != nil {
			// The trusted-proxy source could not be evaluated (dependency
			// failure): never treat this as "no device credential".
			return nil, &authnError{kind: errorKindDependencyUnavailable}
		}
		if device != nil {
			auth, ok := rt.registry.Get(authpolicy.CredentialKindDeviceMTLS)
			if !ok {
				return nil, &authnError{kind: errorKindDependencyUnavailable}
			}
			res := auth.Authenticate(r.Context(), &Credential{Device: device})
			switch res.Decision {
			case DecisionAuthenticated:
				if err := validateBinding(authpolicy.CredentialKindDeviceMTLS, res.Binding); err != nil {
					return nil, &authnError{kind: errorKindInvalidBinding}
				}
				accepted[authpolicy.CredentialKindDeviceMTLS] = *res.Binding
			case DecisionRejected:
				// no device identity for this request
			default:
				return nil, &authnError{kind: errorKindDependencyUnavailable}
			}
		}
	}

	// OpenAPI OR/AND: at least one complete alternative must authenticate;
	// every kind inside that conjunction must be present.
	satisfied := make([]authpolicy.Conjunction, 0, 1)
	for _, alt := range policy.Alternatives() {
		altKinds := alt.Kinds()
		ok := len(altKinds) > 0
		for _, k := range altKinds {
			if _, present := accepted[k]; !present {
				ok = false
				break
			}
		}
		if ok {
			satisfied = append(satisfied, alt)
		}
	}
	if len(satisfied) == 0 {
		return nil, &authnError{kind: errorKindAuthenticationRequired}
	}

	kinds := make([]authpolicy.CredentialKind, 0, len(accepted))
	for k := range accepted {
		kinds = append(kinds, k)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })

	return &AuthenticationContext{
		operationID: policy.OperationID(),
		kinds:       kinds,
		bindings:    accepted,
		satisfied:   satisfied,
	}, nil
}

// writeAuthFailure maps an internal runtime failure to the contracted problem
// response. No authenticator outcome, credential detail or dependency detail
// is exposed.
func (rt *Runtime) writeAuthFailure(w http.ResponseWriter, r *http.Request, policy *authpolicy.OperationPolicy, err error) {
	var ae *authnError
	if !errors.As(err, &ae) {
		problem.WriteInternal(w, r)
		return
	}
	switch ae.kind {
	case errorKindAuthenticationRequired:
		if policyUsesBearer(policy) {
			problem.WriteUnauthorizedBearer(w, r)
			return
		}
		problem.WriteUnauthorized(w, r)
	case errorKindDependencyUnavailable:
		problem.WriteServiceUnavailable(w, r)
	default:
		problem.WriteInternal(w, r)
	}
}

// extractDiscriminator performs a narrow extraction of ONLY the compiled
// discriminator from the already M3-validated, bounded, restored JSON body,
// and restores the body exactly for the generated strict handler.
func (rt *Runtime) extractDiscriminator(w http.ResponseWriter, r *http.Request, discriminator string) (string, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return "", errors.New("runtime: conditional operation without request body")
	}
	r.Body = http.MaxBytesReader(w, r.Body, rt.bodyLimit)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return "", fmt.Errorf("runtime: reading request body for discriminator: %w", err)
	}
	// Restore the body for downstream readers, mirroring M3's capture.
	r.Body = io.NopCloser(bytes.NewReader(data))
	r.ContentLength = int64(len(data))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return "", fmt.Errorf("runtime: request body is not a JSON object: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return "", errors.New("runtime: request body is not a JSON object")
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return "", fmt.Errorf("runtime: reading discriminator key: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return "", errors.New("runtime: request body key is not a string")
		}
		if key == discriminator {
			var value string
			if err := dec.Decode(&value); err != nil {
				return "", fmt.Errorf("runtime: discriminator %q is not a string: %w", discriminator, err)
			}
			return value, nil
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return "", fmt.Errorf("runtime: skipping request body field: %w", err)
		}
	}
	return "", fmt.Errorf("runtime: discriminator %q absent after contract validation", discriminator)
}

// eligibleKinds is the union of all credential kinds across the policy's
// alternatives. Only these kinds' authenticators are invoked (spec §4).
func eligibleKinds(policy *authpolicy.OperationPolicy) []authpolicy.CredentialKind {
	set := make(map[authpolicy.CredentialKind]struct{})
	for _, alt := range policy.Alternatives() {
		for _, k := range alt.Kinds() {
			set[k] = struct{}{}
		}
	}
	out := make([]authpolicy.CredentialKind, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// policyUsesBearer reports whether the policy can consume a bearer
// credential. It decides whether 401 responses carry WWW-Authenticate: Bearer.
func policyUsesBearer(policy *authpolicy.OperationPolicy) bool {
	for _, k := range eligibleKinds(policy) {
		if isBearerKind(k) {
			return true
		}
	}
	return false
}

// isBearerKind reports whether a kind is carried by the HTTP bearer
// credential syntax. DeviceMTLS is the only non-bearer kind in the contract.
func isBearerKind(k authpolicy.CredentialKind) bool {
	return k != authpolicy.CredentialKindDeviceMTLS
}

func containsKind(kinds []authpolicy.CredentialKind, kind authpolicy.CredentialKind) bool {
	for _, k := range kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// effectiveRequiredKindIsDeviceMTLS reports whether the effective
// conditional requirement mandates DeviceMTLS. It is used only to select the
// WWW-Authenticate challenge for a resource-binding rejection: a DeviceMTLS
// mismatch issues no Bearer challenge.
func effectiveRequiredKindIsDeviceMTLS(cr *ConditionalRequirement, hasCR bool) bool {
	return hasCR && cr != nil && cr.RequiredKind() == authpolicy.CredentialKindDeviceMTLS
}

// validateBinding enforces that a successful authenticator result carries a
// valid, kind-matching, non-empty typed binding. A nil binding, a binding for
// a different CredentialKind, a variant incompatible with the kind, or an
// empty mandatory field is an authenticator defect and fails closed.
func validateBinding(kind authpolicy.CredentialKind, b *Binding) error {
	if b == nil {
		return errors.New("runtime: authenticated result without binding")
	}
	if b.Kind() != kind {
		return fmt.Errorf("runtime: binding kind %q does not match authenticator kind %q", b.Kind(), kind)
	}
	switch kind {
	case authpolicy.CredentialKindHumanOIDC, authpolicy.CredentialKindAdminOIDC:
		o, ok := b.OIDCIdentity()
		if !ok || o.Issuer == "" || o.Subject == "" {
			return fmt.Errorf("runtime: %q binding lacks issuer/subject", kind)
		}
	case authpolicy.CredentialKindRequestAccessToken:
		r, ok := b.RequestAccess()
		if !ok || r.PreOnboardingRequestID == "" {
			return fmt.Errorf("runtime: %q binding lacks pre_onboarding_request_id", kind)
		}
	case authpolicy.CredentialKindEnrollmentAccessToken:
		e, ok := b.EnrollmentAccess()
		if !ok || e.EnrollmentID == "" {
			return fmt.Errorf("runtime: %q binding lacks enrollment_id", kind)
		}
	case authpolicy.CredentialKindTemporaryPrincipalToken:
		tp, ok := b.TemporaryPrincipal()
		if !ok || tp.TemporaryPrincipalID == "" {
			return fmt.Errorf("runtime: %q binding lacks temporary_principal_id", kind)
		}
	case authpolicy.CredentialKindDeviceMTLS:
		d, ok := b.DeviceMTLS()
		if !ok || d.DeviceID == "" || d.CertificateID == "" || d.IssuedForEnrollmentID == "" {
			return fmt.Errorf("runtime: %q binding lacks device_id/certificate_id/issued_for_enrollment_id", kind)
		}
	default:
		return fmt.Errorf("runtime: unknown binding kind %q", kind)
	}
	return nil
}

// routeKey is the shared key between the generated router's matched pattern
// and the spec-derived index (same convention as the M3 enforcer).
func routeKey(method, pathPattern string) string {
	return strings.ToUpper(method) + " " + pathPattern
}

// pathParam returns a matched path parameter value by name from chi's route
// context.
func pathParam(rctx *chi.Context, name string) (string, bool) {
	if rctx == nil {
		return "", false
	}
	for i, k := range rctx.URLParams.Keys {
		if k == name {
			return rctx.URLParams.Values[i], true
		}
	}
	return "", false
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
