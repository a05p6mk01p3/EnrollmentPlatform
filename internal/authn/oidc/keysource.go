package oidc

import (
	"context"
	"errors"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// KeySetSource is the external dependency port through which the verifier
// obtains trusted verification keys. It operates only on the trusted
// configured ProviderConfig — never on a token-controlled URL or issuer.
//
// It must distinguish dependency failure (returned error) from a successful
// load that simply does not contain a requested key.
type KeySetSource interface {
	LoadKeys(ctx context.Context, config *ProviderConfig) (jwk.Set, error)
}

// KeySetSourceFunc adapts a function to the KeySetSource port.
type KeySetSourceFunc func(ctx context.Context, config *ProviderConfig) (jwk.Set, error)

// LoadKeys implements KeySetSource.
func (f KeySetSourceFunc) LoadKeys(ctx context.Context, config *ProviderConfig) (jwk.Set, error) {
	return f(ctx, config)
}

// StaticKeySetSource serves a fixed, issuer-namespaced key set. It is a
// deterministic test/local adapter; no network, no Keycloak, no live JWKS.
type StaticKeySetSource struct {
	// KeySets maps an exact trusted issuer to its verification key set.
	KeySets map[string]jwk.Set
}

// ErrKeySourceUnavailable is returned when no key set is configured for a
// provider's issuer.
var ErrKeySourceUnavailable = errors.New("oidc: no key set configured for issuer")

// LoadKeys implements KeySetSource.
func (s StaticKeySetSource) LoadKeys(_ context.Context, config *ProviderConfig) (jwk.Set, error) {
	set, ok := s.KeySets[config.Issuer()]
	if !ok {
		return nil, ErrKeySourceUnavailable
	}
	return set, nil
}
