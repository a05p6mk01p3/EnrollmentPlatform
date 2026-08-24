package runtime_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	authnpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
)

func mustKey(t *testing.T, raw string) runtime.IdempotencyKey {
	t.Helper()
	k, err := runtime.NewIdempotencyKey(raw)
	if err != nil {
		t.Fatalf("NewIdempotencyKey(%q): %v", raw, err)
	}
	return k
}

func mustCredentialScope(t *testing.T, kind authnpolicy.CredentialKind, binding string) runtime.CredentialScope {
	t.Helper()
	c, err := runtime.NewCredentialScope(kind, binding)
	if err != nil {
		t.Fatalf("NewCredentialScope(%q, %q): %v", kind, binding, err)
	}
	return c
}

func mustEffectiveScope(t *testing.T, cred runtime.CredentialScope, method, route string, key runtime.IdempotencyKey) runtime.EffectiveScope {
	t.Helper()
	s, err := runtime.NewEffectiveScope(cred, method, route, key)
	if err != nil {
		t.Fatalf("NewEffectiveScope: %v", err)
	}
	return s
}

func mustFingerprint(t *testing.T, method, route string, canonical []byte) runtime.Fingerprint {
	t.Helper()
	f, err := runtime.FingerprintRequest(runtime.FingerprintVersion1, method, route, canonical)
	if err != nil {
		t.Fatalf("FingerprintRequest: %v", err)
	}
	return f
}

func mustResult(t *testing.T, value string) runtime.ResultLocator {
	t.Helper()
	r, err := runtime.NewResultLocator(value)
	if err != nil {
		t.Fatalf("NewResultLocator(%q): %v", value, err)
	}
	return r
}

// testProtector is a deterministic, test-only protector double. It stores
// plaintext in its own instance-local map keyed by an opaque handle and puts
// only the handle (never the plaintext) into the ProtectedEnvelope. It counts
// Open calls so tests can prove the exact recovery gate.
type testProtector struct {
	mu            sync.Mutex
	sealed        map[string][]byte
	sealCalls     int
	openCalls     int
	failOpen      bool
	lastAD        []byte
	sealExpiresAt time.Time
}

func newTestProtector() *testProtector {
	return &testProtector{sealed: make(map[string][]byte)}
}

func (p *testProtector) Seal(_ context.Context, plaintext []byte, _ []byte) (*runtime.ProtectedEnvelope, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sealCalls++
	handle := fmt.Sprintf("handle-%d", p.sealCalls)
	p.sealed[handle] = append([]byte(nil), plaintext...)
	return runtime.NewProtectedEnvelope([]byte(handle), []byte("nonce"), "test-key", "1", p.sealExpiresAt)
}

func (p *testProtector) Open(_ context.Context, envelope *runtime.ProtectedEnvelope, associatedData []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.openCalls++
	p.lastAD = append([]byte(nil), associatedData...)
	if p.failOpen {
		return nil, errors.New("test protector: open failed")
	}
	if envelope == nil {
		return nil, errors.New("test protector: nil envelope")
	}
	handle := string(envelope.Ciphertext())
	plaintext, ok := p.sealed[handle]
	if !ok {
		return nil, errors.New("test protector: unknown envelope handle")
	}
	return append([]byte(nil), plaintext...), nil
}

func (p *testProtector) OpenCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.openCalls
}

func (p *testProtector) SealCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sealCalls
}

func (p *testProtector) LastAssociatedData() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.lastAD...)
}

func timeZero() time.Time { return time.Time{} }

// fixedClock is a deterministic, server-controlled test clock.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

var errStoreDown = errors.New("test store: dependency down")

// failingStore always fails; it proves dependency failures are never
// interpreted as a successful classification.
type failingStore struct{}

func (failingStore) Reserve(context.Context, runtime.ReserveRequest) (runtime.Reservation, error) {
	return runtime.Reservation{}, errStoreDown
}

func (failingStore) Commit(context.Context, runtime.CommitRequest) (runtime.Record, error) {
	return runtime.Record{}, errStoreDown
}

func (failingStore) Lookup(context.Context, runtime.EffectiveScope) (runtime.Record, bool, error) {
	return runtime.Record{}, false, errStoreDown
}
