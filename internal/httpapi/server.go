// Package httpapi hosts the handwritten HTTP adapter for the Enrollment API.
//
// The adapter layers the handwritten contract-enforcement middleware (payload
// ceiling, media type, strict JSON, precompiled JSON Schema validation) and
// the correlation middleware around the generated chi router and strict
// handlers:
//
//	correlation -> generated chi router (route match)
//	  -> operation middleware (contract enforcement, fail-closed)
//	    -> strict handler wrapper -> StrictServerInterface (business handlers)
//
// Business handlers and authentication are implemented in later milestones.
package httpapi

import (
	"fmt"
	"net/http"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
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
	// from the canonical spec. It is startup-compiled but not yet consumed by
	// request handling: the authentication runtime is M4.2. It is kept
	// read-only for that future milestone.
	authPolicy *authpolicy.Policy
}

// NewServer parses the embedded OpenAPI spec and prepares the contract
// enforcement middleware (precompiling all request-body schemas). Any
// incompatibility between the contract and the JSON Schema 2020-12 engine is
// a construction error: the API must not start without full enforcement. No
// listener is started here.
func NewServer(cfg config.Config) (*Server, error) {
	canonical, err := openapi.GetSpec()
	if err != nil {
		return nil, fmt.Errorf("loading embedded OpenAPI spec: %w", err)
	}

	// Startup-compile the authentication policy from the canonical spec. Any
	// ambiguity or unsupported authentication metadata fails construction:
	// the API must not start with a contract whose authentication policy it
	// cannot compile safely. The compiled policy is stored read-only for the
	// M4.2 authentication runtime and is not executed per request here.
	compiledAuthPolicy, err := authpolicy.Compile(canonical)
	if err != nil {
		return nil, fmt.Errorf("compiling authentication policy: %w", err)
	}

	enforcer, err := middleware.NewEnforcer(canonical, cfg.GeneralJSONDefaultBytes, cfg.AbsoluteRequestBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("preparing contract enforcement: %w", err)
	}
	return &Server{cfg: cfg, enforcer: enforcer, authPolicy: compiledAuthPolicy}, nil
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
			openapi.MiddlewareFunc(s.enforcer.OperationMiddleware()),
		},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			problem.WriteInvalidRequest(w, r, "request parameters could not be parsed")
		},
	})

	return middleware.Correlation(router)
}
