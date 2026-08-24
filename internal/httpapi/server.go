// Package httpapi hosts the handwritten HTTP adapter for the Enrollment API.
//
// The adapter layers the handwritten authentication boundary (M4.2), the
// contract-enforcement middleware (payload ceiling, media type, strict JSON,
// precompiled JSON Schema validation), the authorization boundary (M5.1),
// and the correlation middleware around the generated chi router and strict handlers:
//
//	correlation -> generated chi router (route match)
//	  -> Phase A base authentication (M4.2)
//	    -> contract enforcement (M3, fail-closed)
//	      -> Phase B conditional authentication (M4.2)
//	        -> capability resource binding (M4.3)
//	          -> domain authorization (M5.1)
//	            -> strict handler wrapper -> StrictServerInterface (business handlers)
//
// Concrete credential verification and domain authorization evaluators plug in
// through the respective authn and authz ports.
package httpapi

import (
	"fmt"
	"net/http"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	authzpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authz/policy"
	authzruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authz/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/config"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi/middleware"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi/problem"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
	preonboardingapp "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/resourceownership"
)

// Server is the Enrollment API HTTP adapter and the boundary of the
// composition root.
type Server struct {
	cfg      config.Config
	enforcer *middleware.Enforcer

	// authPolicy is the compiled, immutable authentication policy derived
	// from the canonical spec (M4.1).
	authPolicy *authpolicy.Policy

	// authn is the M4.2 authentication runtime boundary, built from the
	// compiled policy, the authenticator registry and the device-mTLS source.
	authn *authruntime.Runtime

	// authzPolicy is the compiled, immutable authorization policy derived
	// from the canonical spec (M5.1).
	authzPolicy *authzpolicy.Policy

	// authz is the M5.1 authorization runtime boundary.
	authz *authzruntime.Runtime

	// partnerAuth is the M5.2 partner authorization application boundary. It
	// resolves current effective partner authorizations and evaluates
	// partner/scope selection. It is a MANDATORY, explicitly supplied
	// dependency: production currently wires the explicit fail-closed
	// unavailable service while no real partner authorization provider
	// exists. There is no implicit fallback and no permissive default.
	partnerAuth *partnerauth.Service

	// resourceOwnership is the M5.3 resource ownership and visibility boundary.
	// It resolves minimal authoritative resource ownership metadata and
	// evaluates Human visibility for pre-onboarding requests. It is a
	// MANDATORY, explicitly supplied dependency: production currently wires
	// the explicit fail-closed unavailable service while no real resource
	// ownership provider exists. There is no implicit fallback and no
	// permissive default.
	resourceOwnership *resourceownership.Service

	// preonboarding is the M5.5 Pre-Onboarding lifecycle application service.
	preonboarding *preonboardingapp.Service

	// Option inputs, resolved by NewServer.
	authnRegistry             *authruntime.Registry
	authnRegistryExplicit     bool
	deviceSource              authruntime.DeviceMTLSSource
	authzRegistry             *authzruntime.Registry
	authzRegistryExplicit     bool
	partnerAuthExplicit       bool
	resourceOwnershipExplicit bool
	preonboardingExplicit     bool
}

// Option customizes Server construction.
type Option func(*Server)

// WithAuthnRegistry replaces the default deny-by-default authenticator
// registry. The default registry covers every contractual credential kind
// with a fail-closed authenticator; a supplied registry is validated against
// the compiled policy at construction (SOL-M4.6-001), so a registry missing a
// policy-referenced kind fails construction.
func WithAuthnRegistry(registry *authruntime.Registry) Option {
	return func(s *Server) {
		s.authnRegistry = registry
		s.authnRegistryExplicit = true
	}
}

// WithDeviceMTLSSource wires the candidate device-mTLS credential source. The
// concrete trusted-proxy boundary is M4.5. Because the canonical policy
// references DeviceMTLS, construction fails if the source is nil
// (SOL-M4.6-001); there is no silent "DeviceMTLS can never authenticate"
// default on the production path.
func WithDeviceMTLSSource(source authruntime.DeviceMTLSSource) Option {
	return func(s *Server) { s.deviceSource = source }
}

// WithAuthzRegistry replaces the default deny-by-default authorization registry.
// A supplied registry is validated against the compiled authorization policy
// at construction, so a registry missing a required scope authorizer or open
// policy evaluator fails construction.
func WithAuthzRegistry(registry *authzruntime.Registry) Option {
	return func(s *Server) {
		s.authzRegistry = registry
		s.authzRegistryExplicit = true
	}
}

// WithPartnerAuthService wires the M5.2 partner authorization service. It is
// a mandatory dependency: NewServer fails when it is omitted (no implicit
// unavailable/permissive fallback), and a nil or typed-nil service also fails
// construction.
func WithPartnerAuthService(svc *partnerauth.Service) Option {
	return func(s *Server) {
		s.partnerAuth = svc
		s.partnerAuthExplicit = true
	}
}

// WithResourceOwnershipService wires the M5.3 resource ownership and
// visibility service. It is a mandatory dependency: NewServer fails when it is
// omitted (no implicit unavailable/permissive fallback), and a nil or
// typed-nil service also fails construction.
func WithResourceOwnershipService(svc *resourceownership.Service) Option {
	return func(s *Server) {
		s.resourceOwnership = svc
		s.resourceOwnershipExplicit = true
	}
}

// WithPreOnboardingService wires the M5.5 Pre-Onboarding lifecycle application
// service. It is a mandatory dependency: NewServer fails when it is omitted
// (no implicit unavailable/permissive fallback), and a nil or typed-nil
// service also fails construction.
func WithPreOnboardingService(svc *preonboardingapp.Service) Option {
	return func(s *Server) {
		s.preonboarding = svc
		s.preonboardingExplicit = true
	}
}

// NewServer parses the embedded OpenAPI spec and prepares the contract
// enforcement middleware (precompiling all request-body schemas), the M4.2
// authentication runtime, and the M5.1 authorization runtime. Any incompatibility
// between the contract and the JSON Schema 2020-12 engine, any authentication-policy
// compilation error, or any authorization-policy compilation/validation error
// is a construction error: the API must not start without full enforcement.
// No listener is started here.
func NewServer(cfg config.Config, opts ...Option) (*Server, error) {
	canonical, err := openapi.GetSpec()
	if err != nil {
		return nil, fmt.Errorf("loading embedded OpenAPI spec: %w", err)
	}

	// Startup-compile the authentication policy from the canonical spec.
	compiledAuthPolicy, err := authpolicy.Compile(canonical)
	if err != nil {
		return nil, fmt.Errorf("compiling authentication policy: %w", err)
	}

	// Startup-compile the authorization policy from the canonical spec.
	compiledAuthzPolicy, err := authzpolicy.Compile(canonical)
	if err != nil {
		return nil, fmt.Errorf("compiling authorization policy: %w", err)
	}

	s := &Server{
		cfg:         cfg,
		authPolicy:  compiledAuthPolicy,
		authzPolicy: compiledAuthzPolicy,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	registry := s.authnRegistry
	if !s.authnRegistryExplicit && registry == nil {
		registry = authruntime.DefaultDenyRegistry()
	}

	// SOL-M4.6-001: startup integrity is enforced on this production
	// construction path, not in a separate opt-in helper.
	if err := authruntime.ValidateRegistry(compiledAuthPolicy, registry, s.deviceSource); err != nil {
		return nil, fmt.Errorf("validating authentication registry against compiled policy: %w", err)
	}

	rt, err := authruntime.NewRuntime(canonical, compiledAuthPolicy, registry, s.deviceSource, cfg.GeneralJSONDefaultBytes, cfg.AbsoluteRequestBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("preparing authentication runtime: %w", err)
	}
	s.authn = rt

	authzReg := s.authzRegistry
	if !s.authzRegistryExplicit && authzReg == nil {
		authzReg = authzruntime.DefaultDenyRegistry()
	}

	// Startup integrity: validate authorization registry against compiled authz policy.
	if err := authzruntime.ValidateRegistry(compiledAuthzPolicy, authzReg); err != nil {
		return nil, fmt.Errorf("validating authorization registry against compiled policy: %w", err)
	}

	authzRt, err := authzruntime.NewRuntime(canonical, compiledAuthzPolicy, authzReg)
	if err != nil {
		return nil, fmt.Errorf("preparing authorization runtime: %w", err)
	}
	s.authz = authzRt

	// M5.2 partner authorization: mandatory dependency, no implicit fallback.
	// The service must be supplied explicitly (production wires the explicit
	// fail-closed unavailable provider while no real provider exists); a
	// missing or nil service fails construction before any request is served.
	// The service's own structural integrity is revalidated here at the
	// startup boundary: a zero-value &partnerauth.Service{} (non-nil but with
	// unusable resolver state) is rejected instead of being deferred to a
	// request-time DEPENDENCY_UNAVAILABLE.
	if !s.partnerAuthExplicit {
		return nil, fmt.Errorf("validating partner authorization service: no partner authorization service supplied; wire one explicitly with WithPartnerAuthService")
	}
	if s.partnerAuth == nil {
		return nil, fmt.Errorf("validating partner authorization service: nil or typed-nil service")
	}
	if err := s.partnerAuth.Validate(); err != nil {
		return nil, fmt.Errorf("validating partner authorization service: %w", err)
	}

	// M5.3 resource ownership & visibility: mandatory dependency, no implicit
	// fallback. The service must be supplied explicitly (production wires the
	// explicit fail-closed unavailable provider while no real provider
	// exists); a missing or nil service fails construction before any request
	// is served. The service's own structural integrity is revalidated here at
	// the startup boundary: a zero-value &resourceownership.Service{} (non-nil
	// but with unusable resolver state) is rejected instead of being deferred to
	// a request-time DEPENDENCY_UNAVAILABLE.
	if !s.resourceOwnershipExplicit {
		return nil, fmt.Errorf("validating resource ownership service: no resource ownership service supplied; wire one explicitly with WithResourceOwnershipService")
	}
	if s.resourceOwnership == nil {
		return nil, fmt.Errorf("validating resource ownership service: nil or typed-nil service")
	}
	if err := s.resourceOwnership.ValidateWithPartnerAuth(s.partnerAuth); err != nil {
		return nil, fmt.Errorf("validating resource ownership service: %w", err)
	}

	// M5.5 Pre-Onboarding lifecycle: mandatory dependency, no implicit fallback.
	// The service must be supplied explicitly (production wires the explicit
	// fail-closed unavailable provider while no real provider exists); a
	// missing or nil service fails construction before any request is served.
	// The service's own structural integrity is revalidated here at the
	// startup boundary.
	if !s.preonboardingExplicit {
		return nil, fmt.Errorf("validating pre-onboarding service: no pre-onboarding service supplied; wire one explicitly with WithPreOnboardingService")
	}
	if s.preonboarding == nil {
		return nil, fmt.Errorf("validating pre-onboarding service: nil or typed-nil service")
	}
	if err := s.preonboarding.Validate(); err != nil {
		return nil, fmt.Errorf("validating pre-onboarding service: %w", err)
	}

	enforcer, err := middleware.NewEnforcer(canonical, cfg.GeneralJSONDefaultBytes, cfg.AbsoluteRequestBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("preparing contract enforcement: %w", err)
	}
	s.enforcer = enforcer
	return s, nil
}

// Handler wires the complete HTTP pipeline for a strict server
// implementation. The returned handler owns correlation, routing, authentication,
// contract enforcement and domain authorization; the caller is responsible for the listener.
//
// The M5.2 partner authorization, M5.3 resource ownership, and M5.5 pre-onboarding
// boundaries are MANDATORY parts of this composition: the supplied StrictServerInterface is
// wrapped in explicit order:
//
//	wrapResourceOwnership(
//	  wrapPartnerAuth(
//	    wrapPreOnboarding(ssi),
//	  ),
//	)
//
// The wrappers are private (wrapPartnerAuth, wrapResourceOwnership, wrapPreOnboarding)
// and cannot be bypassed through the public surface.
func (s *Server) Handler(ssi openapi.StrictServerInterface) http.Handler {
	strictSI := openapi.NewStrictHandlerWithOptions(s.wrapResourceOwnership(s.wrapPartnerAuth(s.wrapPreOnboarding(ssi))), nil, openapi.StrictHTTPServerOptions{
		// Defense in depth: with enforcement upstream these should not fire,
		// but if the generated decoder or a handler fails, answers stay
		// RFC 9457-shaped.
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			problem.WriteInvalidRequest(w, r, "request body could not be decoded")
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			problem.WriteInternal(w, r)
		},
	})

	router := openapi.HandlerWithOptions(strictSI, openapi.ChiServerOptions{
		Middlewares: []openapi.MiddlewareFunc{
			// The generated chi wrapper builds the chain by wrapping in slice
			// order, so the LAST element of this slice ends up OUTERMOST and
			// runs FIRST. The slice below is therefore ordered to yield the
			// required runtime pipeline:
			//
			//   BaseAuthentication -> M3 contract enforcement
			//     -> ConditionalAuthentication (Phase B, publishes the
			//        effective conditional requirement)
			//       -> capability resource binding (M4.3, follows the
			//          effective policy; SOL-M4.3-002)
			//         -> domain authorization (M5.1, enforces confirmed scopes
			//            and OPEN policy decisions before handlers run)
			//           -> strict handler
			openapi.MiddlewareFunc(s.authz.OperationMiddleware()),
			openapi.MiddlewareFunc(s.authn.ResourceBinding()),
			openapi.MiddlewareFunc(s.authn.ConditionalAuthentication()),
			openapi.MiddlewareFunc(s.enforcer.OperationMiddleware()),
			openapi.MiddlewareFunc(s.authn.BaseAuthentication()),
		},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			problem.WriteInvalidRequest(w, r, "request parameters could not be parsed")
		},
	})

	return middleware.Correlation(router)
}
