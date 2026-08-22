package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
)

func rsaGenerate() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// --- SOL-M4.4-001: trusted JWK metadata enforcement ---

// metadataFixture is a key pair where the public JWK carries explicit
// alg/use/key_ops metadata for trust-boundary tests.
type metadataFixture struct {
	kid  string
	sign jwk.Key // private signing JWK (kid only)
	pub  jwk.Key // public JWK with kid + metadata
}

func newMetadataFixture(t *testing.T, kid, alg, use string, ops []jwk.KeyOperation) metadataFixture {
	t.Helper()
	priv, err := rsaGenerate()
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
	if err := pub.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	if alg != "" {
		if err := pub.Set(jwk.AlgorithmKey, alg); err != nil {
			t.Fatalf("set alg: %v", err)
		}
	}
	if use != "" {
		if err := pub.Set(jwk.KeyUsageKey, use); err != nil {
			t.Fatalf("set use: %v", err)
		}
	}
	if ops != nil {
		if err := pub.Set(jwk.KeyOpsKey, jwk.KeyOperationList(ops)); err != nil {
			t.Fatalf("set key_ops: %v", err)
		}
	}
	return metadataFixture{kid: kid, sign: sign, pub: pub}
}

func (f metadataFixture) token(t *testing.T, iss, sub, aud string) string {
	t.Helper()
	tok, err := jwt.NewBuilder().Issuer(iss).Subject(sub).Audience([]string{aud}).Expiration(baseTime.Add(time.Hour)).Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), f.sign))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func TestTrustedJWKMetadataValidation(t *testing.T) {
	clock := &fakeClock{t: baseTime}

	newAuth := func(t *testing.T, pub jwk.Key) runtime.Authenticator {
		t.Helper()
		set := jwk.NewSet()
		_ = set.AddKey(pub)
		src := newMutableSource(map[string]jwk.Set{humanIssuer: set})
		return humanAuth(t, src, clock)
	}

	verifyOps := []jwk.KeyOperation{jwk.KeyOpVerify}
	signOps := []jwk.KeyOperation{jwk.KeyOpSign}

	cases := []struct {
		name string
		meta metadataFixture
		want runtime.Decision
	}{
		{"alg matches token alg", newMetadataFixture(t, "k1", "RS256", "", nil), runtime.DecisionAuthenticated},
		{"alg absent", newMetadataFixture(t, "k2", "", "", nil), runtime.DecisionAuthenticated},
		{"alg conflicts", newMetadataFixture(t, "k3", "ES256", "", nil), runtime.DecisionIndeterminate},
		{"use=sig", newMetadataFixture(t, "k4", "", "sig", nil), runtime.DecisionAuthenticated},
		{"use absent", newMetadataFixture(t, "k5", "", "", nil), runtime.DecisionAuthenticated},
		{"use=enc", newMetadataFixture(t, "k6", "", "enc", nil), runtime.DecisionIndeterminate},
		{"key_ops includes verify", newMetadataFixture(t, "k7", "", "", verifyOps), runtime.DecisionAuthenticated},
		{"key_ops absent", newMetadataFixture(t, "k8", "", "", nil), runtime.DecisionAuthenticated},
		{"key_ops without verify", newMetadataFixture(t, "k9", "", "", signOps), runtime.DecisionIndeterminate},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAuth(t, tc.meta.pub)
			tok := tc.meta.token(t, humanIssuer, "s", humanAud)
			got := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok}).Decision
			if got != tc.want {
				t.Fatalf("decision = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- SOL-M4.4-002: cache must not cross provider configurations ---

func TestSameIssuerDistinctProviderSourcesIsolated(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	const sameIss = "https://same.example"

	keyA := newRSAFixture(t, "key-a")
	keyB := newRSAFixture(t, "key-b")

	sourceA := newMutableSource(map[string]jwk.Set{sameIss: keyA.publicSet()})
	sourceB := newMutableSource(map[string]jwk.Set{sameIss: keyB.publicSet()})

	cfgA, err := NewProviderConfig(authpolicy.CredentialKindHumanOIDC, sameIss, []string{"aud-A"}, []string{"RS256"}, sourceA, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cfgB, err := NewProviderConfig(authpolicy.CredentialKindAdminOIDC, sameIss, []string{"aud-B"}, []string{"RS256"}, sourceB, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	authA, _ := NewHumanOIDCAuthenticator(cfgA, clock)
	authB, _ := NewAdminOIDCAuthenticator(cfgB, clock)

	// A token signed by A's key, crafted for B's audience. Under a shared
	// issuer-keyed cache this would verify through A's key material; with
	// verifier-owned caches it must be rejected by B (its own source has only
	// key-b).
	forgedForB := keyA.signJWT(t, sameIss, "s", []string{"aud-B"}, baseTime.Add(time.Hour))
	if res := authB.Authenticate(context.Background(), &runtime.Credential{BearerToken: forgedForB}); res.Decision != runtime.DecisionRejected {
		t.Fatalf("key A material accepted by config B: %v", res.Decision)
	}
	if sourceA.callCount() != 0 {
		t.Fatalf("config B consulted config A's key source %d times", sourceA.callCount())
	}
	if sourceB.callCount() != 1 {
		t.Fatalf("config B source calls = %d, want 1", sourceB.callCount())
	}

	// Opposite direction.
	forgedForA := keyB.signJWT(t, sameIss, "s", []string{"aud-A"}, baseTime.Add(time.Hour))
	if res := authA.Authenticate(context.Background(), &runtime.Credential{BearerToken: forgedForA}); res.Decision != runtime.DecisionRejected {
		t.Fatalf("key B material accepted by config A: %v", res.Decision)
	}

	// Sanity: each verifier still authenticates its own tokens.
	ownA := keyA.signJWT(t, sameIss, "s", []string{"aud-A"}, baseTime.Add(time.Hour))
	ownB := keyB.signJWT(t, sameIss, "s", []string{"aud-B"}, baseTime.Add(time.Hour))
	if res := authA.Authenticate(context.Background(), &runtime.Credential{BearerToken: ownA}); res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("config A own token: %v", res.Decision)
	}
	if res := authB.Authenticate(context.Background(), &runtime.Credential{BearerToken: ownB}); res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("config B own token: %v", res.Decision)
	}
}

// --- SOL-M4.4-003: cache owns an immutable key snapshot ---

func TestSourceSetMutationDoesNotAffectCachedSnapshot(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	keyA := newRSAFixture(t, "key-a")
	keyB := newRSAFixture(t, "key-b")
	set := keyA.publicSet()
	src := newMutableSource(map[string]jwk.Set{humanIssuer: set})
	a := humanAuth(t, src, clock)

	tokA := keyA.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))
	tokB := keyB.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))

	// Warm the cache with key A.
	if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tokA}); res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("initial: %v", res.Decision)
	}
	if c := src.callCount(); c != 1 {
		t.Fatalf("calls = %d, want 1", c)
	}

	// External code mutates the SOURCE-OWNED set: key B must not become
	// trusted through aliasing; it must require a controlled refresh.
	if err := set.AddKey(keyB.pub); err != nil {
		t.Fatal(err)
	}
	if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tokB}); res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("rotated token: %v", res.Decision)
	}
	if c := src.callCount(); c != 2 {
		t.Fatalf("calls = %d, want 2 (B visible only after a controlled refresh)", c)
	}
}

func TestSourceKeyReplacementDoesNotAffectCachedSnapshot(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	keyA := newRSAFixture(t, "key-a")
	replacement := newRSAFixture(t, "key-a") // same kid, different key
	set := keyA.publicSet()
	src := newMutableSource(map[string]jwk.Set{humanIssuer: set})
	a := humanAuth(t, src, clock)

	tokA := keyA.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))

	if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tokA}); res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("initial: %v", res.Decision)
	}

	// Replace the source-owned key with a different key under the SAME kid.
	if err := set.RemoveKey(keyA.pub); err != nil {
		t.Fatal(err)
	}
	if err := set.AddKey(replacement.pub); err != nil {
		t.Fatal(err)
	}

	// The cached snapshot must still verify with the ORIGINAL key, without
	// any refresh (the snapshot is owned, not aliased).
	if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tokA}); res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("cached key was mutated through the source alias: %v", res.Decision)
	}
	if c := src.callCount(); c != 1 {
		t.Fatalf("calls = %d, want 1 (no refresh needed)", c)
	}
}

func TestSourceKeyMutationDoesNotAffectCachedSnapshot(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	keyA := newRSAFixture(t, "key-a")
	set := keyA.publicSet()
	src := newMutableSource(map[string]jwk.Set{humanIssuer: set})
	a := humanAuth(t, src, clock)

	tokA := keyA.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))
	if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tokA}); res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("initial: %v", res.Decision)
	}

	// Mutate the individual source-owned JWK after the cache loaded it.
	if err := keyA.pub.Set(jwk.KeyIDKey, "mutated-kid"); err != nil {
		t.Fatal(err)
	}

	// The cached snapshot still carries the original kid and key.
	if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tokA}); res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("cached semantics changed after source key mutation: %v", res.Decision)
	}
	if c := src.callCount(); c != 1 {
		t.Fatalf("calls = %d, want 1", c)
	}
}

func TestConcurrentSourceMutationRaceClean(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	keyA := newRSAFixture(t, "key-a")
	extra := newRSAFixture(t, "key-extra")
	set := keyA.publicSet()
	src := newMutableSource(map[string]jwk.Set{humanIssuer: set})
	a := humanAuth(t, src, clock)

	tokA := keyA.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))
	if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tokA}); res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("initial: %v", res.Decision)
	}

	var wg sync.WaitGroup
	// Readers: cached snapshots (no refresh; TTL valid, kid present).
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tokA})
			}
		}()
	}
	// Writer: mutates the SOURCE-OWNED set concurrently. Because the cache
	// holds an owned snapshot, this must not race with verification.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 50; j++ {
			_ = set.AddKey(extra.pub)
			_ = set.RemoveKey(extra.pub)
		}
	}()
	wg.Wait()
}

// --- SOL-M4.4-004: typed-nil key sources rejected at construction ---

func TestTypedNilKeySourceRejected(t *testing.T) {
	newCfg := func(ks KeySetSource) error {
		_, err := NewProviderConfig(authpolicy.CredentialKindHumanOIDC, humanIssuer, []string{humanAud}, []string{"RS256"}, ks, 0, time.Minute)
		return err
	}

	t.Run("nil interface", func(t *testing.T) {
		if err := newCfg(nil); err == nil {
			t.Fatal("nil interface accepted")
		}
	})

	t.Run("typed-nil KeySetSourceFunc", func(t *testing.T) {
		var f KeySetSourceFunc
		if err := newCfg(f); err == nil {
			t.Fatal("typed-nil func accepted")
		}
	})

	t.Run("typed-nil pointer implementation", func(t *testing.T) {
		var p *StaticKeySetSource
		if err := newCfg(p); err == nil {
			t.Fatal("typed-nil pointer accepted")
		}
	})

	t.Run("valid function source", func(t *testing.T) {
		f := KeySetSourceFunc(func(context.Context, *ProviderConfig) (jwk.Set, error) {
			return jwk.NewSet(), nil
		})
		if err := newCfg(f); err != nil {
			t.Fatalf("valid func source rejected: %v", err)
		}
	})

	t.Run("valid struct source", func(t *testing.T) {
		s := StaticKeySetSource{KeySets: map[string]jwk.Set{}}
		if err := newCfg(s); err != nil {
			t.Fatalf("valid struct source rejected: %v", err)
		}
	})
}

// --- SOL-M4.4-001 remaining: metadata PRESENCE semantics ---

// TestValidateKeyMetadataPresenceSemantics unit-tests the production
// validation logic directly, covering present-but-empty metadata that jwx
// parsing may normalize away before the snapshot boundary. Each case is a
// trusted-material inconsistency => false (Indeterminate), never Rejected.
func TestValidateKeyMetadataPresenceSemantics(t *testing.T) {
	const alg = "RS256"

	cases := []struct {
		name string
		snap verificationKey
		want bool
	}{
		// alg
		{"alg absent", verificationKey{}, true},
		{"alg present matching", verificationKey{alg: alg, algPresent: true}, true},
		{"alg present empty", verificationKey{algPresent: true}, false},
		{"alg conflicting", verificationKey{alg: "ES256", algPresent: true}, false},
		// use
		{"use absent", verificationKey{}, true},
		{"use=sig", verificationKey{use: "sig", usePresent: true}, true},
		{"use present empty", verificationKey{usePresent: true}, false},
		{"use=enc", verificationKey{use: "enc", usePresent: true}, false},
		// key_ops
		{"key_ops absent", verificationKey{}, true},
		{"key_ops includes verify", verificationKey{keyOps: []string{"verify"}, keyOpsPresent: true}, true},
		{"key_ops present empty", verificationKey{keyOpsPresent: true}, false},
		{"key_ops excludes verify", verificationKey{keyOps: []string{"sign"}, keyOpsPresent: true}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validateKeyMetadata(&tc.snap, alg); got != tc.want {
				t.Fatalf("validateKeyMetadata = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- SOL-M4.4-005: nil trusted key set fails closed ---

func TestNilKeySetInitialLoadFailsClosed(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	key := newRSAFixture(t, "key-a")
	nilSetSource := KeySetSourceFunc(func(context.Context, *ProviderConfig) (jwk.Set, error) {
		return nil, nil // (nil, nil) must not panic and must be Indeterminate
	})
	a := humanAuth(t, nilSetSource, clock)

	tok := key.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))
	res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok})
	if res.Decision != runtime.DecisionIndeterminate {
		t.Fatalf("decision = %v, want Indeterminate (no panic)", res.Decision)
	}
}

func TestNilKeySetRefreshFailsClosed(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	key := newRSAFixture(t, "key-a")
	unknown := newRSAFixture(t, "key-unknown")

	// Source returns a valid set first, then (nil, nil) on refresh.
	calls := 0
	src := KeySetSourceFunc(func(context.Context, *ProviderConfig) (jwk.Set, error) {
		calls++
		if calls == 1 {
			return key.publicSet(), nil
		}
		return nil, nil
	})
	a := humanAuth(t, src, clock)

	// Warm the cache with a valid load.
	tokKnown := key.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))
	if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tokKnown}); res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("initial: %v", res.Decision)
	}

	// Unknown kid forces a refresh; the refresh returns (nil, nil) =>
	// Indeterminate, no panic.
	tokUnknown := unknown.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))
	res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tokUnknown})
	if res.Decision != runtime.DecisionIndeterminate {
		t.Fatalf("decision = %v, want Indeterminate (no panic)", res.Decision)
	}
}

// setAlias avoids the embedded-field name shadowing the jwk.Set interface's
// own Set method (Go names an embedded interface field after its type).
type setAlias = jwk.Set

// typedNilSet wraps the jwk.Set interface so that a nil pointer satisfies the
// interface with a TYPED-NIL dynamic value: set != nil, but any method call
// would panic. It exercises the Go interface edge case directly.
type typedNilSet struct {
	setAlias
}

func TestTypedNilKeySetInitialLoadFailsClosed(t *testing.T) {
	// Prove the fixture is the real Go edge case: set != nil but typed-nil.
	var concrete *typedNilSet
	var set jwk.Set = concrete
	if set == nil {
		t.Fatal("fixture must satisfy set != nil to prove the typed-nil edge case")
	}

	clock := &fakeClock{t: baseTime}
	key := newRSAFixture(t, "key-a")
	src := KeySetSourceFunc(func(context.Context, *ProviderConfig) (jwk.Set, error) {
		var c *typedNilSet
		return jwk.Set(c), nil
	})
	a := humanAuth(t, src, clock)

	tok := key.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))
	res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok})
	if res.Decision != runtime.DecisionIndeterminate {
		t.Fatalf("decision = %v, want Indeterminate (no panic)", res.Decision)
	}
}

func TestTypedNilKeySetRefreshFailsClosed(t *testing.T) {
	clock := &fakeClock{t: baseTime}
	key := newRSAFixture(t, "key-a")
	unknown := newRSAFixture(t, "key-unknown")

	calls := 0
	src := KeySetSourceFunc(func(context.Context, *ProviderConfig) (jwk.Set, error) {
		calls++
		if calls == 1 {
			return key.publicSet(), nil
		}
		var c *typedNilSet
		return jwk.Set(c), nil
	})
	a := humanAuth(t, src, clock)

	tokKnown := key.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))
	if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tokKnown}); res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("initial: %v", res.Decision)
	}

	tokUnknown := unknown.signJWT(t, humanIssuer, "s", []string{humanAud}, baseTime.Add(time.Hour))
	res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tokUnknown})
	if res.Decision != runtime.DecisionIndeterminate {
		t.Fatalf("decision = %v, want Indeterminate (no panic)", res.Decision)
	}
}
