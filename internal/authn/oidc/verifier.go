package oidc

import (
	"context"
	"errors"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
)

// Verifier verifies signed bearer JWTs against a single trusted provider
// configuration. It is immutable after construction, owns its key cache, and
// is safe for concurrent use.
type Verifier struct {
	config *ProviderConfig
	clock  Clock
	cache  *keyCache
}

// NewVerifier builds a verifier over the given trusted config. The verifier
// OWNS the key cache it uses, which is bound to this config's trusted key
// source, issuer identity and refresh TTL (SOL-M4.4-002): a cache created for
// one provider configuration can never be paired with another. A nil clock
// defaults to the system clock.
func NewVerifier(config *ProviderConfig, clock Clock) *Verifier {
	if clock == nil {
		clock = systemClock{}
	}
	return &Verifier{
		config: config,
		clock:  clock,
		cache:  newKeyCache(config.keySource, config.refreshTTL, clock),
	}
}

// Verify authenticates a bearer JWT against the configured provider and
// returns the outcome. On success it returns a typed OIDC binding carrying
// ONLY the signature-verified issuer and subject. It never embeds the raw JWT
// in a returned error.
func (v *Verifier) Verify(ctx context.Context, token string) runtime.AuthenticationResult {
	if token == "" {
		return runtime.AuthenticationResult{Decision: runtime.DecisionRejected}
	}

	issuer, subject, decision := v.verify(ctx, token)
	if decision != runtime.DecisionAuthenticated {
		return runtime.AuthenticationResult{Decision: decision}
	}

	binding, err := v.newBinding(issuer, subject)
	if err != nil {
		return runtime.AuthenticationResult{Decision: runtime.DecisionIndeterminate}
	}
	return runtime.AuthenticationResult{Decision: runtime.DecisionAuthenticated, Binding: binding}
}

// verify performs header inspection, trusted key resolution, signature
// verification and claim validation, classifying the outcome as
// Authenticated / Rejected / Indeterminate.
func (v *Verifier) verify(ctx context.Context, token string) (string, string, runtime.Decision) {
	// 1. Inspect the JOSE protected header WITHOUT trusting or verifying it.
	alg, kid, ok := v.inspectHeader(token)
	if !ok {
		return "", "", runtime.DecisionRejected
	}

	// 2. Resolve the trusted verification key (cache + at most one refresh).
	snap, err := v.cache.Resolve(ctx, v.config, kid)
	if err != nil {
		if errors.Is(err, errKeyNotFound) {
			return "", "", runtime.DecisionRejected
		}
		return "", "", runtime.DecisionIndeterminate
	}

	// 3. Validate the TRUSTED key's metadata (SOL-M4.4-001): contradictory or
	// malformed trusted metadata makes safe verification impossible and is an
	// infrastructure failure, never an Authenticated result and never a
	// token-controlled decision.
	if !validateKeyMetadata(snap, alg.String()) {
		return "", "", runtime.DecisionIndeterminate
	}

	// 4. Verify the signature using the exact allowed algorithm and the
	// trusted key. Claim validation is deferred to step 5 for explicit,
	// bounded control of issuer/audience/temporal semantics.
	tok, err := jwt.Parse([]byte(token),
		jwt.WithKey(alg, snap.key),
		jwt.WithVerify(true),
		jwt.WithValidate(false),
	)
	if err != nil {
		// Invalid signature, malformed payload, or algorithm/key incompatibility.
		return "", "", runtime.DecisionRejected
	}

	issuer, subject, ok := v.validateClaims(tok)
	if !ok {
		return "", "", runtime.DecisionRejected
	}
	return issuer, subject, runtime.DecisionAuthenticated
}

// inspectHeader parses the protected header, enforces the algorithm allowlist,
// rejects token-controlled key references (jku/x5u/jwk), and returns the
// allowed algorithm (as a JOSE SignatureAlgorithm for verification) and the
// kid.
func (v *Verifier) inspectHeader(token string) (jwa.SignatureAlgorithm, string, bool) {
	msg, err := jws.Parse([]byte(token))
	if err != nil {
		return jwa.SignatureAlgorithm{}, "", false
	}
	sigs := msg.Signatures()
	if len(sigs) != 1 {
		return jwa.SignatureAlgorithm{}, "", false
	}
	hdr := sigs[0].ProtectedHeaders()

	alg, ok := hdr.Algorithm()
	if !ok {
		return jwa.SignatureAlgorithm{}, "", false
	}
	if !v.config.algorithmAllowed(alg.String()) {
		return jwa.SignatureAlgorithm{}, "", false
	}

	// Token-controlled key references are forbidden: the key must come only
	// from the trusted configured key source.
	if _, ok := hdr.JWKSetURL(); ok {
		return jwa.SignatureAlgorithm{}, "", false
	}
	if _, ok := hdr.X509URL(); ok {
		return jwa.SignatureAlgorithm{}, "", false
	}
	if _, ok := hdr.JWK(); ok {
		return jwa.SignatureAlgorithm{}, "", false
	}

	kid, _ := hdr.KeyID()
	return alg, kid, true
}

// validateClaims validates the signature-verified claims against the trusted
// configuration using exact matching and the injected clock with configured
// skew. It returns the verified issuer and subject.
func (v *Verifier) validateClaims(tok jwt.Token) (string, string, bool) {
	issuer, ok := tok.Issuer()
	if !ok || issuer == "" {
		return "", "", false
	}
	if issuer != v.config.issuer {
		return "", "", false
	}

	subject, ok := tok.Subject()
	if !ok || subject == "" {
		return "", "", false
	}

	audiences, ok := tok.Audience()
	if !ok || len(audiences) == 0 {
		return "", "", false
	}
	if !v.config.audienceMatches(audiences) {
		return "", "", false
	}

	now := v.clock.Now()
	skew := v.config.clockSkew

	// exp: required; reject when now >= exp + skew.
	exp, ok := tok.Expiration()
	if !ok {
		return "", "", false
	}
	if !now.Before(exp.Add(skew)) {
		return "", "", false
	}

	// nbf: if present, reject when now + skew < nbf.
	if nbf, ok := tok.NotBefore(); ok {
		if now.Add(skew).Before(nbf) {
			return "", "", false
		}
	}

	// iat: if present, reject clearly future issuance beyond skew.
	if iat, ok := tok.IssuedAt(); ok {
		if iat.After(now.Add(skew)) {
			return "", "", false
		}
	}

	return issuer, subject, true
}

// newBinding builds the typed OIDC binding for the configured credential kind.
func (v *Verifier) newBinding(issuer, subject string) (*runtime.Binding, error) {
	switch v.config.kind {
	case authpolicy.CredentialKindHumanOIDC:
		return runtime.NewHumanOIDCBinding(issuer, subject)
	case authpolicy.CredentialKindAdminOIDC:
		return runtime.NewAdminOIDCBinding(issuer, subject)
	default:
		return nil, errors.New("oidc: unsupported credential kind")
	}
}

// validateKeyMetadata enforces the trusted JWK metadata rules
// (SOL-M4.4-001). Presence is honored explicitly: an ABSENT field is not the
// same as a field that is PRESENT but empty, and present-but-empty trusted
// metadata is a trusted-material failure.
//
//   - alg: absent => acceptable; present, non-empty and exactly equal to the
//     JWT header alg => acceptable; present but empty or conflicting => fail;
//   - use: absent => acceptable; present and exactly "sig" => acceptable;
//     present but empty or any other value (including "enc") => fail;
//   - key_ops: absent => acceptable; present and containing "verify" =>
//     acceptable; present but empty or without "verify" => fail.
//
// All failures are trusted-material inconsistencies and map to an
// Indeterminate outcome — never Authenticated, and the detail is never
// exposed externally.
func validateKeyMetadata(snap *verificationKey, tokenAlg string) bool {
	if snap.algPresent {
		if snap.alg == "" || snap.alg != tokenAlg {
			return false
		}
	}
	if snap.usePresent {
		if snap.use != "sig" {
			return false
		}
	}
	if snap.keyOpsPresent {
		if len(snap.keyOps) == 0 {
			return false
		}
		hasVerify := false
		for _, op := range snap.keyOps {
			if op == "verify" {
				hasVerify = true
				break
			}
		}
		if !hasVerify {
			return false
		}
	}
	return true
}
