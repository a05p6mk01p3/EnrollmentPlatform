// Command enrollment-api is the Enrollment Platform API service.
//
// Current scope: composition-root skeleton. It loads configuration and prepares
// the HTTP adapter (correlation + contract enforcement + generated router), but
// does not start a listener and does not register business handlers (those
// arrive in later milestones). No business behavior is simulated here.
package main

import (
	"fmt"
	"os"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/config"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/resourceownership"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "enrollment-api: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Composition root: prepare the HTTP adapter (contract enforcement
	// middleware + generated router). No listener is started and no business
	// handler is registered in this milestone.
	//
	// M5.2 partner authorization and M5.3 resource ownership are explicitly
	// wired as unavailable, fail-closed providers while no real providers exist:
	// no request can resolve partner authorization or ownership, and no
	// protected mutation or read can proceed.
	partnerSvc := partnerauth.NewUnavailableService()
	ownershipSvc := resourceownership.NewUnavailableService(partnerSvc)

	server, err := httpapi.NewServer(cfg,
		httpapi.WithPartnerAuthService(partnerSvc),
		httpapi.WithResourceOwnershipService(ownershipSvc),
	)
	if err != nil {
		return err
	}
	_ = server

	fmt.Fprintln(os.Stderr, "enrollment-api: skeleton — HTTP endpoints not yet registered")
	return nil
}
