// Package httpapi hosts the handwritten HTTP adapter for the Enrollment API.
//
// M1 scope: this package establishes the adapter type only. The generated
// openapi.StrictServerInterface (20 operations) is intentionally NOT implemented
// here yet, so no endpoint is registered and no business behavior is simulated.
package httpapi

import (
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/config"
)

// Server is the Enrollment API HTTP adapter and the boundary of the composition
// root. Handlers and middleware are wired in later milestones.
type Server struct {
	cfg config.Config
}

// NewServer returns an unregistered Server. No HTTP handler is registered until
// the use cases exist; this skeleton does not expose a functional API surface.
func NewServer(cfg config.Config) *Server {
	return &Server{cfg: cfg}
}
