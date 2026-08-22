package capability

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
)

// fakeClock is a deterministic injectable clock.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }

func newTestVerifier(t *testing.T) Verifier {
	t.Helper()
	v, err := NewHMACVerifier([]byte("test-key-material"))
	if err != nil {
		t.Fatalf("NewHMACVerifier: %v", err)
	}
	return v
}

// failingStore returns a non-ErrNotFound error for every lookup, simulating a
// verifier/store dependency outage.
type failingStore struct{}

func (failingStore) LookupRequestAccess(context.Context, VerifierKey) (*RequestAccessRecord, error) {
	return nil, errors.New("backend unavailable")
}

func (failingStore) LookupEnrollmentAccess(context.Context, VerifierKey) (*EnrollmentAccessRecord, error) {
	return nil, errors.New("backend unavailable")
}

// --- verifier ---

func TestHMACVerifierKindIsolation(t *testing.T) {
	v := newTestVerifier(t)
	const tok = "same-plaintext-across-kinds"
	reqKey, err := v.Derive(authpolicy.CredentialKindRequestAccessToken, tok)
	if err != nil {
		t.Fatal(err)
	}
	enrKey, err := v.Derive(authpolicy.CredentialKindEnrollmentAccessToken, tok)
	if err != nil {
		t.Fatal(err)
	}
	if reqKey == enrKey {
		t.Fatal("same plaintext collapsed across credential kinds")
	}
	// The verifier key must not reveal the plaintext token.
	if strings.Contains(string(reqKey), tok) {
		t.Fatal("verifier key contains the plaintext token")
	}
	if string(reqKey) == tok {
		t.Fatal("verifier key equals the plaintext token")
	}
}

func TestNewHMACVerifierRejectsEmptyKey(t *testing.T) {
	if _, err := NewHMACVerifier(nil); err == nil {
		t.Fatal("nil key accepted")
	}
	if _, err := NewHMACVerifier([]byte{}); err == nil {
		t.Fatal("empty key accepted")
	}
}

// --- RequestAccessToken authenticator ---

func TestRequestAccessAuthenticator(t *testing.T) {
	const tok = "req-token-active"
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	setup := func(clock Clock, state State, expires time.Time) (*RequestAccessAuthenticator, *MemoryStore) {
		v := newTestVerifier(t)
		store := NewMemoryStore(v)
		if err := store.SeedRequestAccess(tok, "por-A", expires, state); err != nil {
			t.Fatal(err)
		}
		return NewRequestAccessAuthenticator(v, store, clock), store
	}

	t.Run("ACTIVE valid authenticates with binding", func(t *testing.T) {
		a, _ := setup(&fakeClock{t: exp.Add(-time.Second)}, StateActive, exp)
		res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok})
		if res.Decision != runtime.DecisionAuthenticated {
			t.Fatalf("decision = %v, want Authenticated", res.Decision)
		}
		b, ok := res.Binding.RequestAccess()
		if !ok || b.PreOnboardingRequestID != "por-A" {
			t.Fatalf("binding = %+v (ok=%v); want por-A", b, ok)
		}
		// No other variant, no token/verifier in the binding.
		if _, ok := res.Binding.EnrollmentAccess(); ok {
			t.Fatal("request binding must not expose enrollment variant")
		}
		if _, ok := res.Binding.OIDCIdentity(); ok {
			t.Fatal("request binding must not expose OIDC variant")
		}
	})

	t.Run("unknown token rejected", func(t *testing.T) {
		a, _ := setup(&fakeClock{t: exp.Add(-time.Second)}, StateActive, exp)
		res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: "unknown-token"})
		if res.Decision != runtime.DecisionRejected || res.Binding != nil {
			t.Fatalf("unknown token: decision=%v binding=%v", res.Decision, res.Binding)
		}
	})

	t.Run("wrong verifier rejected", func(t *testing.T) {
		v := newTestVerifier(t)
		store := NewMemoryStore(v)
		_ = store.SeedRequestAccess(tok, "por-A", exp, StateActive)
		// A different verifier (different key material) derives a different key.
		other, _ := NewHMACVerifier([]byte("different-key-material"))
		a := NewRequestAccessAuthenticator(other, store, &fakeClock{t: exp.Add(-time.Second)})
		res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok})
		if res.Decision != runtime.DecisionRejected {
			t.Fatalf("wrong verifier: decision = %v, want Rejected", res.Decision)
		}
	})

	t.Run("expiry boundary", func(t *testing.T) {
		t.Run("just before", func(t *testing.T) {
			a, _ := setup(&fakeClock{t: exp.Add(-time.Nanosecond)}, StateActive, exp)
			if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok}); res.Decision != runtime.DecisionAuthenticated {
				t.Fatalf("just before expiry: decision = %v", res.Decision)
			}
		})
		t.Run("exactly at", func(t *testing.T) {
			a, _ := setup(&fakeClock{t: exp}, StateActive, exp)
			if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok}); res.Decision != runtime.DecisionRejected {
				t.Fatalf("exactly at expiry: decision = %v", res.Decision)
			}
		})
		t.Run("after", func(t *testing.T) {
			a, _ := setup(&fakeClock{t: exp.Add(time.Nanosecond)}, StateActive, exp)
			if res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok}); res.Decision != runtime.DecisionRejected {
				t.Fatalf("after expiry: decision = %v", res.Decision)
			}
		})
	})

	t.Run("consumed rejected", func(t *testing.T) {
		a, _ := setup(&fakeClock{t: exp.Add(-time.Second)}, StateConsumed, exp)
		res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok})
		if res.Decision != runtime.DecisionRejected {
			t.Fatalf("consumed: decision = %v, want Rejected", res.Decision)
		}
	})

	t.Run("empty token rejected", func(t *testing.T) {
		a, _ := setup(&fakeClock{t: exp.Add(-time.Second)}, StateActive, exp)
		if res := a.Authenticate(context.Background(), &runtime.Credential{}); res.Decision != runtime.DecisionRejected {
			t.Fatal("empty token was not rejected")
		}
	})
}

// --- EnrollmentAccessToken authenticator ---

func TestEnrollmentAccessAuthenticator(t *testing.T) {
	const tok = "enr-token-active"
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	v := newTestVerifier(t)
	store := NewMemoryStore(v)
	if err := store.SeedEnrollmentAccess(tok, "enr-A", exp); err != nil {
		t.Fatal(err)
	}
	a := NewEnrollmentAccessAuthenticator(v, store, &fakeClock{t: exp.Add(-time.Second)})

	res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok})
	if res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("decision = %v, want Authenticated", res.Decision)
	}
	b, ok := res.Binding.EnrollmentAccess()
	if !ok || b.EnrollmentID != "enr-A" {
		t.Fatalf("binding = %+v (ok=%v); want enr-A", b, ok)
	}

	// unknown + expired + wrong verifier => Rejected.
	if r := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: "nope"}); r.Decision != runtime.DecisionRejected {
		t.Fatal("unknown token not rejected")
	}
	late := NewEnrollmentAccessAuthenticator(v, store, &fakeClock{t: exp})
	if r := late.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok}); r.Decision != runtime.DecisionRejected {
		t.Fatal("expired enrollment token not rejected")
	}
}

// --- kind isolation ---

func TestCrossKindIsolation(t *testing.T) {
	v := newTestVerifier(t)
	store := NewMemoryStore(v)
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	reqTok := "req-token"
	enrTok := "enr-token"
	_ = store.SeedRequestAccess(reqTok, "por-A", exp, StateActive)
	_ = store.SeedEnrollmentAccess(enrTok, "enr-A", exp)

	reqAuth := NewRequestAccessAuthenticator(v, store, &fakeClock{t: exp.Add(-time.Second)})
	enrAuth := NewEnrollmentAccessAuthenticator(v, store, &fakeClock{t: exp.Add(-time.Second)})

	// request token against enrollment authenticator -> reject.
	if r := enrAuth.Authenticate(context.Background(), &runtime.Credential{BearerToken: reqTok}); r.Decision != runtime.DecisionRejected {
		t.Fatal("request token authenticated as enrollment access")
	}
	// enrollment token against request authenticator -> reject.
	if r := reqAuth.Authenticate(context.Background(), &runtime.Credential{BearerToken: enrTok}); r.Decision != runtime.DecisionRejected {
		t.Fatal("enrollment token authenticated as request access")
	}

	// Deliberately seed identical plaintext in both namespaces: kinds must not
	// collapse.
	const same = "same-token-in-both"
	_ = store.SeedRequestAccess(same, "por-A", exp, StateActive)
	_ = store.SeedEnrollmentAccess(same, "enr-A", exp)
	if r := reqAuth.Authenticate(context.Background(), &runtime.Credential{BearerToken: same}); r.Decision != runtime.DecisionAuthenticated {
		t.Fatal("identical token did not authenticate as request access")
	} else if b, _ := r.Binding.RequestAccess(); b.PreOnboardingRequestID != "por-A" {
		t.Fatalf("request binding = %+v", b)
	}
	if r := enrAuth.Authenticate(context.Background(), &runtime.Credential{BearerToken: same}); r.Decision != runtime.DecisionAuthenticated {
		t.Fatal("identical token did not authenticate as enrollment access")
	} else if b, _ := r.Binding.EnrollmentAccess(); b.EnrollmentID != "enr-A" {
		t.Fatalf("enrollment binding = %+v", b)
	}
}

// --- dependency behavior ---

func TestStoreFailureIndeterminate(t *testing.T) {
	v := newTestVerifier(t)
	a := NewRequestAccessAuthenticator(v, failingStore{}, &fakeClock{t: time.Now()})
	res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: "any"})
	if res.Decision != runtime.DecisionIndeterminate {
		t.Fatalf("decision = %v, want Indeterminate", res.Decision)
	}
	if res.Binding != nil {
		t.Fatal("indeterminate result must not carry a binding")
	}

	ea := NewEnrollmentAccessAuthenticator(v, failingStore{}, &fakeClock{t: time.Now()})
	if r := ea.Authenticate(context.Background(), &runtime.Credential{BearerToken: "any"}); r.Decision != runtime.DecisionIndeterminate {
		t.Fatalf("enrollment decision = %v, want Indeterminate", r.Decision)
	}
}

// --- secret safety ---

func TestCapabilityBindingDoesNotRetainToken(t *testing.T) {
	const tok = "req-token-secret-000"
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	v := newTestVerifier(t)
	store := NewMemoryStore(v)
	_ = store.SeedRequestAccess(tok, "por-A", exp, StateActive)
	a := NewRequestAccessAuthenticator(v, store, &fakeClock{t: exp.Add(-time.Second)})

	res := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok})
	if res.Decision != runtime.DecisionAuthenticated {
		t.Fatalf("decision = %v", res.Decision)
	}
	b, _ := res.Binding.RequestAccess()
	if b.PreOnboardingRequestID == tok || strings.Contains(b.PreOnboardingRequestID, tok) {
		t.Fatal("token retained in binding")
	}
	// The store only ever sees the derived key, never the token.
	key, _ := v.Derive(authpolicy.CredentialKindRequestAccessToken, tok)
	if strings.Contains(string(key), tok) {
		t.Fatal("verifier key contains token")
	}
}

// --- concurrency ---

func TestMemoryStoreConcurrent(t *testing.T) {
	const tok = "concurrent-token"
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	v := newTestVerifier(t)
	store := NewMemoryStore(v)
	_ = store.SeedRequestAccess(tok, "por-A", exp, StateActive)
	_ = store.SeedEnrollmentAccess(tok, "enr-A", exp)
	clock := &fakeClock{t: exp.Add(-time.Second)}

	reqAuth := NewRequestAccessAuthenticator(v, store, clock)
	enrAuth := NewEnrollmentAccessAuthenticator(v, store, clock)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = reqAuth.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok})
				_ = enrAuth.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok})
				_, _ = store.LookupRequestAccess(context.Background(), VerifierKey("x"))
				_, _ = store.LookupEnrollmentAccess(context.Background(), VerifierKey("x"))
			}
		}()
	}
	wg.Wait()
}

// --- replay confusion (explicitly out of scope, must be inert) ---

func TestReplayCapsuleMaterialRejected(t *testing.T) {
	v := newTestVerifier(t)
	store := NewMemoryStore(v)
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	_ = store.SeedRequestAccess("real-active-token", "por-A", exp, StateActive)
	a := NewRequestAccessAuthenticator(v, store, &fakeClock{t: exp.Add(-time.Second)})

	// Arbitrary capsule-like material is just an unknown token: Rejected, and
	// never authenticates.
	for _, bogus := range []string{
		"capsule:abcdef123456",
		"replay-capsule-ciphertext",
		"nonce:123",
		"idempotency-key:0123456789abcdef",
	} {
		if r := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: bogus}); r.Decision != runtime.DecisionRejected {
			t.Fatalf("capsule-like material %q was not rejected", bogus)
		}
	}
}

// --- SOL-M4.3-001: zero value must not mean ACTIVE ---

// recordStore returns a fixed record for any request-access lookup, so tests
// can exercise records a persistence adapter could return (including invalid
// lifecycle states).
type recordStore struct {
	rec *RequestAccessRecord
}

func (s recordStore) LookupRequestAccess(context.Context, VerifierKey) (*RequestAccessRecord, error) {
	return s.rec, nil
}

func (s recordStore) LookupEnrollmentAccess(context.Context, VerifierKey) (*EnrollmentAccessRecord, error) {
	return nil, ErrNotFound
}

func TestRequestAccessStateMustBeExplicitlyActive(t *testing.T) {
	v := newTestVerifier(t)
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &fakeClock{t: exp.Add(-time.Second)}

	states := []struct {
		name string
		rec  *RequestAccessRecord
	}{
		{"zero/omitted state", &RequestAccessRecord{PreOnboardingRequestID: "por-A", ExpiresAt: exp}},
		{"explicit StateUnknown", &RequestAccessRecord{PreOnboardingRequestID: "por-A", ExpiresAt: exp, State: StateUnknown}},
		{"unknown numeric value", &RequestAccessRecord{PreOnboardingRequestID: "por-A", ExpiresAt: exp, State: State(99)}},
		{"consumed", &RequestAccessRecord{PreOnboardingRequestID: "por-A", ExpiresAt: exp, State: StateConsumed}},
	}
	for _, tc := range states {
		t.Run(tc.name, func(t *testing.T) {
			a := NewRequestAccessAuthenticator(v, recordStore{rec: tc.rec}, clock)
			if r := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: "any-token"}); r.Decision != runtime.DecisionRejected {
				t.Fatalf("decision = %v, want Rejected (binding=%v)", r.Decision, r.Binding)
			}
		})
	}

	t.Run("explicit Active is eligible", func(t *testing.T) {
		a := NewRequestAccessAuthenticator(v, recordStore{rec: &RequestAccessRecord{
			PreOnboardingRequestID: "por-A", ExpiresAt: exp, State: StateActive,
		}}, clock)
		r := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: "any-token"})
		if r.Decision != runtime.DecisionAuthenticated {
			t.Fatalf("decision = %v, want Authenticated", r.Decision)
		}
	})
}

// --- SOL-M4.3-003: seeding is creation-only / insert-only ---

func TestSeedDoesNotReactivateConsumedToken(t *testing.T) {
	v := newTestVerifier(t)
	store := NewMemoryStore(v)
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	const tok = "consumed-token-reseed"

	if err := store.SeedRequestAccess(tok, "por-A", exp, StateConsumed); err != nil {
		t.Fatal(err)
	}
	// Re-seeding the SAME token as Active must fail and leave the record
	// consumed.
	if err := store.SeedRequestAccess(tok, "por-A", exp, StateActive); err != ErrDuplicate {
		t.Fatalf("re-seed error = %v, want ErrDuplicate", err)
	}

	key, err := v.Derive(authpolicy.CredentialKindRequestAccessToken, tok)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := store.LookupRequestAccess(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != StateConsumed {
		t.Fatalf("state after re-seed = %v, want Consumed (record must not be overwritten)", rec.State)
	}

	// The authenticator still rejects the token.
	a := NewRequestAccessAuthenticator(v, store, &fakeClock{t: exp.Add(-time.Second)})
	if r := a.Authenticate(context.Background(), &runtime.Credential{BearerToken: tok}); r.Decision != runtime.DecisionRejected {
		t.Fatalf("decision = %v, want Rejected (reactivated!)", r.Decision)
	}
}

func TestEnrollmentSeedInsertOnly(t *testing.T) {
	v := newTestVerifier(t)
	store := NewMemoryStore(v)
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	const tok = "enrollment-token"

	if err := store.SeedEnrollmentAccess(tok, "enr-A", exp); err != nil {
		t.Fatal(err)
	}
	if err := store.SeedEnrollmentAccess(tok, "enr-B", exp); err != ErrDuplicate {
		t.Fatalf("re-seed error = %v, want ErrDuplicate", err)
	}
	key, _ := v.Derive(authpolicy.CredentialKindEnrollmentAccessToken, tok)
	rec, err := store.LookupEnrollmentAccess(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if rec.EnrollmentID != "enr-A" {
		t.Fatalf("enrollment after re-seed = %q, want enr-A (record must not be overwritten)", rec.EnrollmentID)
	}
}

func TestSeedRejectsInvalidState(t *testing.T) {
	v := newTestVerifier(t)
	store := NewMemoryStore(v)
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, st := range []State{StateUnknown, State(99)} {
		if err := store.SeedRequestAccess("token", "por-A", exp, st); err == nil {
			t.Fatalf("invalid state %d was accepted at seed time", st)
		}
	}
}

func TestCrossKindNamespacesIndependentSeeds(t *testing.T) {
	v := newTestVerifier(t)
	store := NewMemoryStore(v)
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	const same = "same-plaintext"

	// The same plaintext may be seeded once per kind namespace.
	if err := store.SeedRequestAccess(same, "por-A", exp, StateActive); err != nil {
		t.Fatal(err)
	}
	if err := store.SeedEnrollmentAccess(same, "enr-A", exp); err != nil {
		t.Fatal(err)
	}
	// A second seed WITHIN each namespace still fails.
	if err := store.SeedRequestAccess(same, "por-A", exp, StateActive); err != ErrDuplicate {
		t.Fatalf("second request seed error = %v, want ErrDuplicate", err)
	}
	if err := store.SeedEnrollmentAccess(same, "enr-A", exp); err != ErrDuplicate {
		t.Fatalf("second enrollment seed error = %v, want ErrDuplicate", err)
	}
}
