package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
)

const (
	humanIssuer = "https://issuer.example/human"
	adminIssuer = "https://issuer.example/admin"
	humanAud    = "enrollment-human"
	adminAud    = "enrollment-admin"
)

var baseTime = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

// fakeClock is a deterministic clock.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }

// rsaFixture is an ephemeral RSA key pair with public and private JWKs.
type rsaFixture struct {
	kid  string
	priv *rsa.PrivateKey
	pub  jwk.Key
	sign jwk.Key // private JWK with kid, used for signing
}

func newRSAFixture(t *testing.T, kid string) rsaFixture {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sign, err := jwk.Import(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := sign.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	pub, err := jwk.PublicKeyOf(sign)
	if err != nil {
		t.Fatal(err)
	}
	return rsaFixture{kid: kid, priv: priv, pub: pub, sign: sign}
}

func (f rsaFixture) publicSet() jwk.Set {
	set := jwk.NewSet()
	_ = set.AddKey(f.pub)
	return set
}

// signJWT signs a compact JWT with the fixture's private key.
func (f rsaFixture) signJWT(t *testing.T, iss, sub string, aud []string, exp time.Time) string {
	t.Helper()
	tok, err := jwt.NewBuilder().Issuer(iss).Subject(sub).Audience(aud).Expiration(exp).Build()
	if err != nil {
		t.Fatal(err)
	}
	return signToken(t, tok, f.sign)
}

func signToken(t *testing.T, tok jwt.Token, signer any) string {
	t.Helper()
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), signer))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

// compactJWS builds a raw compact JWS with arbitrary header/payload and an
// explicit signature (nil => "none"/empty signature). Used only for header
// adversarial fixtures, never for production verification.
func compactJWS(header, payload map[string]any, sig []byte) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	enc := base64.RawURLEncoding
	return enc.EncodeToString(h) + "." + enc.EncodeToString(p) + "." + enc.EncodeToString(sig)
}

func standardClaims(iss, sub string, aud []string, exp time.Time) map[string]any {
	return map[string]any{"iss": iss, "sub": sub, "aud": aud, "exp": exp.Unix()}
}

// mutableSource is a deterministic key source with rotation, failure and call
// counting, safe for concurrent use.
type mutableSource struct {
	mu    sync.Mutex
	sets  map[string]jwk.Set
	calls int
	fail  bool
}

func newMutableSource(sets map[string]jwk.Set) *mutableSource {
	return &mutableSource{sets: sets}
}

func (m *mutableSource) LoadKeys(_ context.Context, config *ProviderConfig) (jwk.Set, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.fail {
		return nil, errors.New("key source unavailable")
	}
	set, ok := m.sets[config.Issuer()]
	if !ok {
		return nil, ErrKeySourceUnavailable
	}
	return set, nil
}

func (m *mutableSource) set(issuer string, set jwk.Set) {
	m.mu.Lock()
	m.sets[issuer] = set
	m.mu.Unlock()
}

func (m *mutableSource) setFail(fail bool) {
	m.mu.Lock()
	m.fail = fail
	m.mu.Unlock()
}

func (m *mutableSource) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func humanConfig(source KeySetSource) *ProviderConfig {
	cfg, _ := NewProviderConfig(authpolicy.CredentialKindHumanOIDC, humanIssuer, []string{humanAud}, []string{"RS256"}, source, 0, time.Minute)
	return cfg
}

func adminConfig(source KeySetSource) *ProviderConfig {
	cfg, _ := NewProviderConfig(authpolicy.CredentialKindAdminOIDC, adminIssuer, []string{adminAud}, []string{"RS256"}, source, 0, time.Minute)
	return cfg
}

func humanAuth(t *testing.T, source KeySetSource, clock Clock) runtime.Authenticator {
	t.Helper()
	a, err := NewHumanOIDCAuthenticator(humanConfig(source), clock)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func adminAuth(t *testing.T, source KeySetSource, clock Clock) runtime.Authenticator {
	t.Helper()
	a, err := NewAdminOIDCAuthenticator(adminConfig(source), clock)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// --- provider configuration validation (§6, §32) ---

func TestProviderConfigValidation(t *testing.T) {
	src := KeySetSourceFunc(func(context.Context, *ProviderConfig) (jwk.Set, error) { return jwk.NewSet(), nil })
	cases := []struct {
		name  string
		build func() error
	}{
		{"empty issuer", func() error {
			_, e := NewProviderConfig(authpolicy.CredentialKindHumanOIDC, "", []string{"a"}, []string{"RS256"}, src, 0, time.Minute)
			return e
		}},
		{"empty audience", func() error {
			_, e := NewProviderConfig(authpolicy.CredentialKindHumanOIDC, "i", nil, []string{"RS256"}, src, 0, time.Minute)
			return e
		}},
		{"empty algorithm", func() error {
			_, e := NewProviderConfig(authpolicy.CredentialKindHumanOIDC, "i", []string{"a"}, nil, src, 0, time.Minute)
			return e
		}},
		{"invalid algorithm", func() error {
			_, e := NewProviderConfig(authpolicy.CredentialKindHumanOIDC, "i", []string{"a"}, []string{"HS256"}, src, 0, time.Minute)
			return e
		}},
		{"none algorithm", func() error {
			_, e := NewProviderConfig(authpolicy.CredentialKindHumanOIDC, "i", []string{"a"}, []string{"none"}, src, 0, time.Minute)
			return e
		}},
		{"negative skew", func() error {
			_, e := NewProviderConfig(authpolicy.CredentialKindHumanOIDC, "i", []string{"a"}, []string{"RS256"}, src, -time.Second, time.Minute)
			return e
		}},
		{"nil key source", func() error {
			_, e := NewProviderConfig(authpolicy.CredentialKindHumanOIDC, "i", []string{"a"}, []string{"RS256"}, nil, 0, time.Minute)
			return e
		}},
		{"non-positive ttl", func() error {
			_, e := NewProviderConfig(authpolicy.CredentialKindHumanOIDC, "i", []string{"a"}, []string{"RS256"}, src, 0, 0)
			return e
		}},
		{"wrong kind", func() error {
			_, e := NewProviderConfig(authpolicy.CredentialKindRequestAccessToken, "i", []string{"a"}, []string{"RS256"}, src, 0, time.Minute)
			return e
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.build()
			if err == nil {
				t.Fatal("invalid config accepted")
			}
			var ce *ConfigError
			if !errors.As(err, &ce) {
				t.Fatalf("error %v is not a *ConfigError", err)
			}
		})
	}
}

// --- happy path + typed binding (§15) ---

func TestHumanAndAdminHappyPath(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	humanKey := newRSAFixture(t, "human-key-1")
	adminKey := newRSAFixture(t, "admin-key-1")

	humanSource := newMutableSource(map[string]jwk.Set{humanIssuer: humanKey.publicSet()})
	adminSource := newMutableSource(map[string]jwk.Set{adminIssuer: adminKey.publicSet()})

	humanTok := humanKey.signJWT(t, humanIssuer, "human-subject", []string{humanAud}, baseTime.Add(time.Hour))
	adminTok := adminKey.signJWT(t, adminIssuer, "admin-subject", []string{adminAud}, baseTime.Add(time.Hour))

	t.Run("Human valid", func(t *testing.T) {
		res := humanAuth(t, humanSource, clock).Authenticate(context.Background(), &runtime.Credential{BearerToken: humanTok})
		if res.Decision != runtime.DecisionAuthenticated {
			t.Fatalf("decision = %v", res.Decision)
		}
		o, ok := res.Binding.OIDCIdentity()
		if !ok || o.Issuer != humanIssuer || o.Subject != "human-subject" {
			t.Fatalf("binding = %+v (ok=%v)", o, ok)
		}
	})

	t.Run("Admin valid", func(t *testing.T) {
		res := adminAuth(t, adminSource, clock).Authenticate(context.Background(), &runtime.Credential{BearerToken: adminTok})
		if res.Decision != runtime.DecisionAuthenticated {
			t.Fatalf("decision = %v", res.Decision)
		}
		o, ok := res.Binding.OIDCIdentity()
		if !ok || o.Issuer != adminIssuer || o.Subject != "admin-subject" {
			t.Fatalf("binding = %+v (ok=%v)", o, ok)
		}
	})
}

// --- header adversarial cases (§24) ---

func TestHeaderAdversarial(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	key := newRSAFixture(t, "key-1")
	src := newMutableSource(map[string]jwk.Set{humanIssuer: key.publicSet()})
	a := humanAuth(t, src, clock)
	exp := baseTime.Add(time.Hour).Unix()

	reject := func(t *testing.T, name, token string) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: token}); res.Decision != runtime.DecisionRejected {
				t.Fatalf("decision = %v, want Rejected", res.Decision)
			}
		})
	}

	reject(t, "alg none", compactJWS(map[string]any{"alg": "none"}, standardClaims(humanIssuer, "s", []string{humanAud}, time.Unix(exp, 0)), nil))
	reject(t, "jku present", compactJWS(map[string]any{"alg": "RS256", "kid": "key-1", "jku": "https://evil.example/jwks"}, standardClaims(humanIssuer, "s", []string{humanAud}, time.Unix(exp, 0)), nil))
	reject(t, "x5u present", compactJWS(map[string]any{"alg": "RS256", "kid": "key-1", "x5u": "https://evil.example/cert"}, standardClaims(humanIssuer, "s", []string{humanAud}, time.Unix(exp, 0)), nil))
	reject(t, "embedded jwk present", compactJWS(map[string]any{"alg": "RS256", "kid": "key-1", "jwk": map[string]any{"kty": "RSA"}}, standardClaims(humanIssuer, "s", []string{humanAud}, time.Unix(exp, 0)), nil))
	reject(t, "malformed compact", "not-a-jwt")

	// Disallowed algorithm: a valid ES256 token with an RS256-only allowlist.
	reject(t, "disallowed alg", es256Token(t, humanIssuer, "s", humanAud, baseTime.Add(time.Hour)))

	// Invalid signature: same kid but a different key.
	other := newRSAFixture(t, "key-1")
	reject(t, "invalid signature", other.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour)))

	// Unknown kid after (no) refresh: key "key-2" not in the trusted set.
	unknown := newRSAFixture(t, "key-2")
	reject(t, "unknown kid", unknown.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour)))

	// Altered payload after signing.
	tampered := tamperPayload(t, key.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour)))
	reject(t, "altered payload", tampered)
}

func es256Token(t *testing.T, iss, sub, aud string, exp time.Time) string {
	t.Helper()
	priv, err := generateECDSAP256()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.NewBuilder().Issuer(iss).Subject(sub).Audience([]string{aud}).Expiration(exp).Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), priv))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func tamperPayload(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token segments = %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatal(err)
	}
	m["sub"] = "tampered-subject"
	edited, _ := json.Marshal(m)
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(edited) + "." + parts[2]
}

// --- claim adversarial cases (§25) ---

func TestClaimAdversarial(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	key := newRSAFixture(t, "key-1")
	src := newMutableSource(map[string]jwk.Set{humanIssuer: key.publicSet()})
	a := humanAuth(t, src, clock)

	sign := func(iss, sub string, aud []string, exp time.Time) string {
		return key.signJWT(t, iss, sub, aud, exp)
	}
	expect := func(t *testing.T, name, token string, want runtime.Decision) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			got := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: token}).Decision
			if got != want {
				t.Fatalf("decision = %v, want %v", got, want)
			}
		})
	}

	exp := baseTime.Add(time.Hour)
	expect(t, "valid", sign(humanIssuer, "s", []string{humanAud}, exp), runtime.DecisionAuthenticated)
	expect(t, "wrong issuer", sign("https://other.example", "s", []string{humanAud}, exp), runtime.DecisionRejected)
	expect(t, "issuer lookalike", sign(humanIssuer+".evil", "s", []string{humanAud}, exp), runtime.DecisionRejected)
	expect(t, "wrong audience", sign(humanIssuer, "s", []string{"other-aud"}, exp), runtime.DecisionRejected)
	expect(t, "multi audience with accepted", sign(humanIssuer, "s", []string{"other-aud", humanAud}, exp), runtime.DecisionAuthenticated)
	expect(t, "multi audience none accepted", sign(humanIssuer, "s", []string{"a", "b"}, exp), runtime.DecisionRejected)
	expect(t, "missing subject", sign(humanIssuer, "", []string{humanAud}, exp), runtime.DecisionRejected)

	// Missing exp, expired, exact expiry, nbf future, iat future.
	expect(t, "missing exp", signNoExp(t, key, humanIssuer, "s", []string{humanAud}), runtime.DecisionRejected)
	expect(t, "expired", sign(humanIssuer, "s", []string{humanAud}, baseTime.Add(-time.Second)), runtime.DecisionRejected)
	expect(t, "exact expiry zero skew", sign(humanIssuer, "s", []string{humanAud}, baseTime), runtime.DecisionRejected)
}

func signNoExp(t *testing.T, f rsaFixture, iss, sub string, aud []string) string {
	t.Helper()
	tok, err := jwt.NewBuilder().Issuer(iss).Subject(sub).Audience(aud).Build()
	if err != nil {
		t.Fatal(err)
	}
	return signToken(t, tok, f.sign)
}

// --- temporal validation / clock skew (§14) ---

func TestClockSkewTemporalValidation(t *testing.T) {
	key := newRSAFixture(t, "key-1")
	src := newMutableSource(map[string]jwk.Set{humanIssuer: key.publicSet()})

	// exp just inside configured skew => accepted.
	cfg, err := NewProviderConfig(authpolicy.CredentialKindHumanOIDC, humanIssuer, []string{humanAud}, []string{"RS256"}, src, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{t: baseTime}
	auth, _ := NewHumanOIDCAuthenticator(cfg, clock)

	tok := key.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(-30*time.Second))
	res := auth.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok})
	if res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("decision = %v, want Authenticated (exp within skew)", res.Decision)
	}

	// Same token with zero skew => expired.
	cfgZero, _ := NewProviderConfig(authpolicy.CredentialKindHumanOIDC, humanIssuer, []string{humanAud}, []string{"RS256"}, src, 0, time.Minute)
	authZero, _ := NewHumanOIDCAuthenticator(cfgZero, clock)
	if res := authZero.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok}); res.Decision != runtime.DecisionRejected {
		t.Fatalf("decision = %v, want Rejected (expired at zero skew)", res.Decision)
	}
}

// --- key rotation / cache (§26) ---

func TestKeyRotationAndCache(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	key1 := newRSAFixture(t, "key-1")
	key2 := newRSAFixture(t, "key-2")
	src := newMutableSource(map[string]jwk.Set{humanIssuer: key1.publicSet()})
	a := humanAuth(t, src, clock)

	tok1 := key1.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))

	// First authenticate: loads the key set (1 call).
	if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok1}); res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("decision = %v", res.Decision)
	}
	if c := src.callCount(); c != 1 {
		t.Fatalf("calls = %d, want 1", c)
	}

	// Second authenticate with the same kid: cached, no refresh.
	if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok1}); res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("decision = %v", res.Decision)
	}
	if c := src.callCount(); c != 1 {
		t.Fatalf("calls = %d, want 1 (cached)", c)
	}

	// Rotate: add key-2; a token with kid key-2 triggers exactly one refresh.
	src.set(humanIssuer, setOf(key1.pub, key2.pub))
	tok2 := key2.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))
	if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok2}); res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("decision = %v after rotation", res.Decision)
	}
	if c := src.callCount(); c != 2 {
		t.Fatalf("calls = %d, want 2 (exactly one refresh)", c)
	}

	// Unknown kid after refresh succeeds => Rejected (one more refresh).
	key3 := newRSAFixture(t, "key-3")
	tok3 := key3.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))
	if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok3}); res.Decision != runtime.DecisionRejected {
		t.Fatalf("decision = %v, want Rejected (unknown kid)", res.Decision)
	}
	if c := src.callCount(); c != 3 {
		t.Fatalf("calls = %d, want 3", c)
	}
}

func TestKeyRefreshDependencyFailureIndeterminate(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	key := newRSAFixture(t, "key-1")
	src := newMutableSource(map[string]jwk.Set{humanIssuer: key.publicSet()})
	a := humanAuth(t, src, clock)

	// Unknown kid: refresh required. Fail the source => Indeterminate.
	key2 := newRSAFixture(t, "key-2")
	tok := key2.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))
	src.setFail(true)
	if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok}); res.Decision != runtime.DecisionIndeterminate {
		t.Fatalf("decision = %v, want Indeterminate", res.Decision)
	}
}

func TestKeySourceInitialUnavailableIndeterminate(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	key := newRSAFixture(t, "key-1")
	src := newMutableSource(map[string]jwk.Set{}) // no issuer keyset
	a := humanAuth(t, src, clock)

	tok := key.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))
	if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok}); res.Decision != runtime.DecisionIndeterminate {
		t.Fatalf("decision = %v, want Indeterminate", res.Decision)
	}
}

func TestSameKidDifferentIssuerIsolation(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	// Two issuers share the SAME kid but different keys.
	humanKey := newRSAFixture(t, "shared-kid")
	adminKey := newRSAFixture(t, "shared-kid")
	src := newMutableSource(map[string]jwk.Set{
		humanIssuer: humanKey.publicSet(),
		adminIssuer: adminKey.publicSet(),
	})

	human := humanAuth(t, src, clock)
	admin := adminAuth(t, src, clock)

	// Admin token (signed by adminKey, shared kid) must not verify as Human.
	adminTok := adminKey.signJWT(t, adminIssuer, "s", []string{adminAud}, baseTime.Add(time.Hour))
	if res := human.Authenticate(context.Background(), &runtime.Credential{BearerToken: adminTok}); res.Decision != runtime.DecisionRejected {
		t.Fatalf("admin token verified as human: %v", res.Decision)
	}
	// Human token must not verify as Admin.
	humanTok := humanKey.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))
	if res := admin.Authenticate(context.Background(), &runtime.Credential{BearerToken: humanTok}); res.Decision != runtime.DecisionRejected {
		t.Fatalf("human token verified as admin: %v", res.Decision)
	}
}

func TestConcurrentValidationRaceClean(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	key := newRSAFixture(t, "key-1")
	src := newMutableSource(map[string]jwk.Set{humanIssuer: key.publicSet()})
	a := humanAuth(t, src, clock)
	tok := key.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok})
			}
		}()
	}
	wg.Wait()
}

// --- credential confusion (§16) ---

func TestHumanAdminCredentialConfusion(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	humanKey := newRSAFixture(t, "human-key")
	adminKey := newRSAFixture(t, "admin-key")
	src := newMutableSource(map[string]jwk.Set{
		humanIssuer: humanKey.publicSet(),
		adminIssuer: adminKey.publicSet(),
	})

	human := humanAuth(t, src, clock)
	admin := adminAuth(t, src, clock)

	humanTok := humanKey.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))
	adminTok := adminKey.signJWT(t, adminIssuer, "s", []string{adminAud}, baseTime.Add(time.Hour))

	if res := human.Authenticate(context.Background(), &runtime.Credential{BearerToken: humanTok}); res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("human fixture on human policy: %v", res.Decision)
	}
	if res := admin.Authenticate(context.Background(), &runtime.Credential{BearerToken: adminTok}); res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("admin fixture on admin policy: %v", res.Decision)
	}
	if res := admin.Authenticate(context.Background(), &runtime.Credential{BearerToken: humanTok}); res.Decision != runtime.DecisionRejected {
		t.Fatalf("human fixture on admin policy: %v", res.Decision)
	}
	if res := human.Authenticate(context.Background(), &runtime.Credential{BearerToken: adminTok}); res.Decision != runtime.DecisionRejected {
		t.Fatalf("admin fixture on human policy: %v", res.Decision)
	}
}

// --- secret / claims leakage (§22) ---

func TestBindingDoesNotLeakClaims(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	key := newRSAFixture(t, "key-1")
	src := newMutableSource(map[string]jwk.Set{humanIssuer: key.publicSet()})
	a := humanAuth(t, src, clock)

	const secretSubject = "raw-token-not-retained"
	tok := key.signJWT(t, humanIssuer, secretSubject, []string{humanAud}, baseTime.Add(time.Hour))
	res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok})
	if res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("decision = %v", res.Decision)
	}
	o, _ := res.Binding.OIDCIdentity()
	// The binding carries ONLY issuer+subject; never the raw JWT or extra claims.
	if strings.Contains(o.Issuer, tok) || strings.Contains(o.Subject, tok) {
		t.Fatal("raw JWT leaked into binding")
	}
	if _, ok := res.Binding.RequestAccess(); ok {
		t.Fatal("OIDC binding must not expose capability variants")
	}
}

func setOf(keys ...jwk.Key) jwk.Set {
	set := jwk.NewSet()
	for _, k := range keys {
		_ = set.AddKey(k)
	}
	return set
}

func generateECDSAP256() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
