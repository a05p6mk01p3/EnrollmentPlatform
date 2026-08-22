// Package oidc implements the provider-neutral JWT/OIDC verification boundary
// for the HumanOIDC and AdminOIDC credential kinds (M4.4).
//
// It cryptographically verifies signed bearer JWTs against trusted, injected
// provider configuration, validates issuer/audience/algorithm/temporal claims,
// and obtains verification keys through an injected key-source boundary with a
// bounded, issuer-namespaced cache/refresh for safe key rotation.
//
// Authentication is not authorization. An AdminOIDC token that verifies here
// grants no administrative authority; it only establishes the issuer+subject
// authentication identity. Scopes, roles, partner authorization and
// eligibility remain downstream concerns (M5).
//
// This package does NOT implement Keycloak, login, token acquisition, OIDC
// discovery, UserInfo, introspection, or live JWKS HTTP fetching. A real
// network/Keycloak adapter is deferred (M4.6); only the verification boundary
// and deterministic/local key sources exist here.
package oidc

import "time"

// Clock is an injectable, deterministic time source. All JWT temporal
// validation (exp/nbf/iat) uses this clock, never the client wall clock.
type Clock interface {
	Now() time.Time
}

// systemClock uses the process wall clock.
type systemClock struct{}

// Now returns the current wall-clock time.
func (systemClock) Now() time.Time { return time.Now() }
