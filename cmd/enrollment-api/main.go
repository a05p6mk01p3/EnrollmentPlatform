// Command enrollment-api is the Enrollment Platform API service.
//
// Current scope: composition-root skeleton. It loads configuration and prepares
// the HTTP/application boundaries, but does not start a listener. Dependencies
// without an operational provider are wired explicitly fail-closed; no business
// success is simulated by this command.
package main

import (
	"fmt"
	"os"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/config"
	enrollmentapp "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/application"
	enrollmentrecovery "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/recovery"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
	preonboardingapp "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
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

	// Composition root: prepare the HTTP/application boundaries. No listener is
	// started by this command.
	//
	// M5.2 partner authorization, M5.3 resource ownership, M5.5 pre-onboarding,
	// and M5.7 enrollment execution/recovery are explicitly wired as
	// unavailable, fail-closed providers while no real durable transactional
	// providers exist. No protected business operation is simulated here.
	partnerSvc := partnerauth.NewUnavailableService()
	ownershipSvc := resourceownership.NewUnavailableService(partnerSvc)
	preonboardSvc := preonboardingapp.NewUnavailableService()
	enrollmentSvc := enrollmentapp.NewUnavailableService()
	enrollmentRecovery := enrollmentrecovery.NewUnavailableRecognizer()

	server, err := httpapi.NewServer(cfg,
		httpapi.WithPartnerAuthService(partnerSvc),
		httpapi.WithResourceOwnershipService(ownershipSvc),
		httpapi.WithPreOnboardingService(preonboardSvc),
		httpapi.WithEnrollmentService(enrollmentSvc),
		httpapi.WithEnrollmentRecoveryRecognizer(enrollmentRecovery),
	)
	if err != nil {
		return err
	}
	_ = server

	fmt.Fprintln(os.Stderr, "enrollment-api: skeleton — HTTP endpoints not yet registered")
	return nil
}
