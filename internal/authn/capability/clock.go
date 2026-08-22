// Package capability implements concrete authentication for the opaque bearer
// capabilities RequestAccessToken and EnrollmentAccessToken (M4.3).
//
// It provides:
//
//   - a non-reversible verifier abstraction (never the plaintext secret);
//   - a persistence-neutral, lifecycle-aware verifier-store read port;
//   - a RequestAccessToken authenticator (read-only: it never consumes);
//   - an EnrollmentAccessToken authenticator;
//   - a thread-safe in-memory store for tests/development.
//
// Authentication is not authorization. This package establishes only which
// resource a capability was verified against; it decides nothing about
// scopes, partners, eligibility or certificate issuance.
package capability

import "time"

// Clock is an injectable time source for server-side expiry enforcement. No
// hardcoded TTL is used; expiry comes from the record's expires_at and this
// clock.
type Clock interface {
	Now() time.Time
}

// SystemClock uses the process wall clock.
type SystemClock struct{}

// Now returns the current wall-clock time.
func (SystemClock) Now() time.Time { return time.Now() }
