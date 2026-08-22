// Command enrollment-api is the Enrollment Platform API service.
//
// M1 scope: composition-root skeleton. It loads configuration and constructs the
// HTTP adapter, but does not start a listener and does not register any endpoint
// (handlers arrive in M2+). No business behavior is simulated here.
package main

import (
	"fmt"
	"os"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/config"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi"
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

	// Composition root: build the HTTP adapter. No listener is started and no
	// handlers are registered in this milestone.
	_ = httpapi.NewServer(cfg)

	fmt.Fprintln(os.Stderr, "enrollment-api: M1 skeleton — no HTTP endpoints registered")
	return nil
}
