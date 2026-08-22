// Package httpapi hosts the handwritten HTTP adapter for the Enrollment API.
//
// The adapter layers the handwritten authentication boundary (M4.2), the
// contract-enforcement middleware (payload ceiling, media type, strict JSON,
// precompiled JSON Schema validation) and the correlation middleware around
// the generated chi router and strict handlers:
//
//	correlation -> generated chi router (route match)
//	  -> Phase A base authentication (M4.2)
//	    -> contract enforcement (M3, fail-closed)
//	      -> Phase B conditional authentication (M4.2)
//	        -> strict handler wrapper -> StrictServerInterface (business handlers)
//
// Concrete credential verification (OIDC/opaque tokens/device mTLS) is
// implemented in later milestones and plugs into the M4.2 authenticator ports.
package httpapi

import (
	"fmt"
	"net/http"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/config"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi/middleware"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi/problem"
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

	// Option inputs, resolved by NewServer.
	authnRegistry *authruntime.Registry
	deviceSource  authruntime.DeviceMTLSSource
}

// Option customizes Server construction.
type Option func(*Server)

// WithAuthnRegistry replaces the default deny-by-default authenticator
// registry. The default registry rejects every credential until the concrete
// authenticators (M4.3+) exist.
func WithAuthnRegistry(registry *authruntime.Registry) Option {
	return func(s *Server) { s.authnRegistry = registry }
}

// WithDeviceMTLSSource wires the candidate device-mTLS credential source.
// The concrete trusted-proxy boundary is M4.5; a nil source (the default)
// means the DeviceMTLS kind can never authenticate (fail closed).
func WithDeviceMTLSSource(source authruntime.DeviceMTLSSource) Option {
	return func(s *Server) { s.deviceSource = source }
}

// NewServer parses the embedded OpenAPI spec and prepares the contract
// enforcement middleware (precompiling all request-body schemas) and the M4.2
// authentication runtime. Any incompatibility between the contract and the
// JSON Schema 2020-12 engine, or any authentication-policy compilation error,
// is a construction error: the API must not start without full enforcement.
// No listener is started here.
func NewServer(cfg config.Config, opts ...Option) (*Server, error) {
	canonical, err := openapi.GetSpec()
	if err != nil {
		return nil, fmt.Errorf("loading embedded OpenAPI spec: %w", err)
	}

	// Startup-compile the authentication policy from the canonical spec. Any
	// ambiguity or unsupported authentication metadata fails construction:
	// the API must not start with a contract whose authentication policy it
	// cannot compile safely.
	compiledAuthPolicy, err := authpolicy.Compile(canonical)
	if err != nil {
		return nil, fmt.Errorf("compiling authentication policy: %w", err)
	}

	s := &Server{cfg: cfg, authPolicy: compiledAuthPolicy}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	registry := s.authnRegistry
	if registry == nil {
		registry = authruntime.DefaultDenyRegistry()
	}
	rt, err := authruntime.NewRuntime(canonical, compiledAuthPolicy, registry, s.deviceSource, cfg.GeneralJSONDefaultBytes, cfg.AbsoluteRequestBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("preparing authentication runtime: %w", err)
	}
	s.authn = rt

	enforcer, err := middleware.NewEnforcer(canonical, cfg.GeneralJSONDefaultBytes, cfg.AbsoluteRequestBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("preparing contract enforcement: %w", err)
	}
	s.enforcer = enforcer
	return s, nil
}

// Handler wires the complete HTTP pipeline for a strict server
// implementation. The returned handler owns correlation, routing and contract
// enforcement; the caller is responsible for the listener.
func (s *Server) Handler(ssi openapi.StrictServerInterface) http.Handler {
	strictSI := openapi.NewStrictHandlerWithOptions(ssi, nil, openapi.StrictHTTPServerOptions{
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
			//         -> strict handler
			//
			// This ordering is pinned by integration tests (authn_test.go and
			// capability_test.go); it is not assumed from documentation.
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
