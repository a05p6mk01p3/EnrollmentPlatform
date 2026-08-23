package runtime

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-chi/chi/v5"

	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	authzpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authz/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi/problem"
)

// httpMethods is the ordered set of HTTP methods a PathItem can carry.
var httpMethods = []string{
	http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete,
	http.MethodOptions, http.MethodHead, http.MethodPatch, http.MethodTrace,
}

// Runtime is the M5.1 authorization runtime boundary. It consumes the immutable
// policy compiled by internal/authz/policy and enforces operation-level domain
// authorization after M4 authentication and before protected application handlers.
type Runtime struct {
	policy          *authzpolicy.Policy
	registry        *Registry
	byRoute         map[string]string                   // routeKey -> operationId
	byRouteResource map[string]authruntime.ResourceKind // routeKey -> domain resource kind
}

// NewRuntime creates the authorization runtime from the canonical OpenAPI spec,
// compiled authorization policy, and authorization registry.
func NewRuntime(canonical *openapi3.T, compiled *authzpolicy.Policy, registry *Registry) (*Runtime, error) {
	if canonical == nil {
		return nil, errors.New("authz runtime: nil canonical spec")
	}
	if compiled == nil {
		return nil, errors.New("authz runtime: nil compiled authorization policy")
	}
	if registry == nil {
		return nil, errors.New("authz runtime: nil authorization registry")
	}

	rt := &Runtime{
		policy:          compiled,
		registry:        registry,
		byRoute:         make(map[string]string),
		byRouteResource: make(map[string]authruntime.ResourceKind),
	}

	for path, pi := range canonical.Paths.Map() {
		for _, m := range httpMethods {
			op := pi.GetOperation(m)
			if op == nil || strings.TrimSpace(op.OperationID) == "" {
				continue
			}
			key := routeKey(m, path)
			if _, exists := compiled.Operation(op.OperationID); !exists {
				return nil, fmt.Errorf("authz runtime: spec route %s %s resolves to operationId %q which has no compiled policy", m, path, op.OperationID)
			}
			if prev, dup := rt.byRoute[key]; dup {
				return nil, fmt.Errorf("authz runtime: duplicate spec route %s (operationIds %q and %q)", key, prev, op.OperationID)
			}
			rt.byRoute[key] = op.OperationID

			kind, err := authruntime.ClassifyRouteResource(pi, op, path)
			if err != nil {
				return nil, err
			}
			rt.byRouteResource[key] = kind
		}
	}

	return rt, nil
}

// resolve maps a matched chi route pattern and method to the compiled operation policy.
func (rt *Runtime) resolve(method, routePattern string) (*authzpolicy.OperationPolicy, bool) {
	opID, ok := rt.byRoute[routeKey(method, routePattern)]
	if !ok {
		return nil, false
	}
	op, ok := rt.policy.Operation(opID)
	return op, ok
}

// matchedResource extracts the typed domain resource for the matched route.
func (rt *Runtime) matchedResource(method, routePattern string, rctx *chi.Context) (authruntime.MatchedResource, bool) {
	kind := rt.byRouteResource[routeKey(method, routePattern)]
	if kind == authruntime.ResourceKindUnknown {
		return authruntime.MatchedResource{Kind: authruntime.ResourceKindUnknown, Present: false}, true
	}
	value, present := pathParam(rctx, "id")
	if !present || value == "" {
		return authruntime.MatchedResource{}, false
	}
	return authruntime.MatchedResource{Kind: kind, Value: value, Present: true}, true
}

// OperationMiddleware returns the HTTP middleware that enforces operation-level
// domain authorization.
func (rt *Runtime) OperationMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rctx := chi.RouteContext(r.Context())
			if rctx == nil {
				problem.WriteInternal(w, r)
				return
			}

			opPolicy, ok := rt.resolve(r.Method, rctx.RoutePattern())
			if !ok {
				problem.WriteInternal(w, r)
				return
			}

			if opPolicy.Kind() == authzpolicy.PolicyKindNone {
				// No operation-level authorization metadata in M5.1; proceed.
				next.ServeHTTP(w, r)
				return
			}

			ac, ok := authruntime.AuthenticationContextFrom(r.Context())
			if !ok || ac == nil {
				// Protected operations must have been authenticated prior to authorization.
				problem.WriteInternal(w, r)
				return
			}

			resource, ok := rt.matchedResource(r.Method, rctx.RoutePattern(), rctx)
			if !ok {
				// Path parameter was structurally required but missing in route context.
				problem.WriteInternal(w, r)
				return
			}

			switch opPolicy.Kind() {
			case authzpolicy.PolicyKindConfirmedScopes:
				sa, ok := rt.registry.ScopeAuthorizer()
				if !ok || sa == nil {
					problem.WriteServiceUnavailable(w, r)
					return
				}
				decision, err := sa.AuthorizeScopes(r.Context(), ac, ScopeAuthorizationRequest{
					OperationID:    opPolicy.OperationID(),
					RequiredScopes: opPolicy.RequiredScopes(),
					Resource:       resource,
				})
				if err != nil || decision == DecisionIndeterminate {
					problem.WriteServiceUnavailable(w, r)
					return
				}
				if decision == DecisionDenied {
					problem.WriteScopeDenied(w, r)
					return
				}
				if decision == DecisionAllowed {
					next.ServeHTTP(w, r)
					return
				}
				problem.WriteServiceUnavailable(w, r)
				return

			case authzpolicy.PolicyKindOpen:
				meta := opPolicy.OpenMetadata()
				if meta == nil {
					problem.WriteInternal(w, r)
					return
				}
				eval, ok := rt.registry.OpenEvaluator(opPolicy.OperationID())
				if !ok || eval == nil {
					problem.WriteServiceUnavailable(w, r)
					return
				}
				decision, err := eval.EvaluateOpenPolicy(r.Context(), ac, OpenPolicyRequest{
					OperationID: opPolicy.OperationID(),
					Metadata:    *meta,
					Resource:    resource,
				})
				if err != nil || decision == DecisionIndeterminate {
					problem.WriteServiceUnavailable(w, r)
					return
				}
				if decision == DecisionDenied {
					problem.WriteScopeDenied(w, r)
					return
				}
				if decision == DecisionAllowed {
					next.ServeHTTP(w, r)
					return
				}
				problem.WriteServiceUnavailable(w, r)
				return

			default:
				problem.WriteInternal(w, r)
				return
			}
		})
	}
}

func routeKey(method, pathPattern string) string {
	return strings.ToUpper(method) + " " + pathPattern
}

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
