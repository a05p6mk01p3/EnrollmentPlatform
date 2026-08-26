package httpapi_test

// M56-POST-003 direct adversarial recovery-path evidence.
//
// Three raw, unclassified dependency errors are injected at their real
// boundaries inside the real M5.6 service (not faked at the application
// result), and the REAL classification chain must map each to the transient
// fail-safe wire outcome: 503 DEPENDENCY_UNAVAILABLE, retryable=true — never
// 409 IDEMPOTENCY_REPLAY_UNAVAILABLE.
//
//  1. Protector.Open returns a raw unknown error (no ErrTransient/ErrPermanent
//     wrapping) — reached through the real CreateOriginator replay branch and
//     M5.4 RecoverSecret.
//  2. ResultStore.GetCreateResult returns a raw backend error (distinct from
//     authoritative not-found) — proves backend query failure is not
//     equivalent to permanent snapshot absence, and that Protector.Open is
//     never reached.
//  3. M5.4 IdempotencyStore.Lookup (the RecoverSecret backing lookup) returns
//     a raw unclassified storage error — the fixture must not pre-convert it.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	preonboardingapp "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	domain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
)

// post003HumanHeaders builds the deterministic authenticated HumanOIDC headers
// for a given idempotency key (same binding/fingerprint on NEW and replay).
func post003HumanHeaders(key string) map[string]string {
	return map[string]string{
		"Authorization":    "Bearer tok-human-oidc",
		"Content-Type":     "application/json",
		"Idempotency-Key":  key,
		"X-Correlation-ID": "corr-post003",
	}
}

// post003State is a snapshot of every durable concern the NEW path publishes.
type post003State struct {
	requests      int
	verifiers     int
	snapshots     int
	idemCommitted int
	audit         int
}

func snapshotPost003State(tc *m56HTTPFixture) post003State {
	return post003State{
		requests:      tc.store.CountRequests(),
		verifiers:     tc.store.CountRequestAccess(),
		snapshots:     tc.store.CountCreateResults(),
		idemCommitted: tc.store.CountIdemCommitted(),
		audit:         tc.recorder.Count(),
	}
}

func assertPost003StateUnchanged(t *testing.T, before, after post003State) {
	t.Helper()
	if before != after {
		t.Fatalf("durable state changed across failed replay: before=%+v after=%+v", before, after)
	}
}

// post003FaultUoW wraps the real UoW and injects raw backend errors at the
// ResultStore or IdempotencyStore boundary. All other concerns delegate to the
// real transactional memory UoW.
type post003FaultUoW struct {
	preonboardingapp.UnitOfWork
	resultStoreErr  error
	lookupErr       error
	resultStoreHits *int
	lookupHits      *int
}

func (u *post003FaultUoW) ResultStore() preonboardingapp.ResultStore {
	if u.resultStoreErr != nil {
		return &post003FaultResultStore{ResultStore: u.UnitOfWork.ResultStore(), err: u.resultStoreErr, hits: u.resultStoreHits}
	}
	return u.UnitOfWork.ResultStore()
}

func (u *post003FaultUoW) IdempotencyStore() runtime.Store {
	if u.lookupErr != nil {
		return &post003FaultIdemStore{Store: u.UnitOfWork.IdempotencyStore(), err: u.lookupErr, hits: u.lookupHits}
	}
	return u.UnitOfWork.IdempotencyStore()
}

type post003FaultResultStore struct {
	preonboardingapp.ResultStore
	err  error
	hits *int
}

// GetCreateResult returns a raw backend error (never authoritative not-found)
// so the test proves the classification boundary distinguishes backend query
// failure from permanent snapshot absence.
func (s *post003FaultResultStore) GetCreateResult(ctx context.Context, loc runtime.ResultLocator) (preonboardingapp.PreOnboardingCreateResultSnapshot, bool, error) {
	if s.hits != nil {
		*s.hits++
	}
	return preonboardingapp.PreOnboardingCreateResultSnapshot{}, false, s.err
}

type post003FaultIdemStore struct {
	runtime.Store
	err  error
	hits *int
}

// Lookup is the M5.4 RecoverSecret backing lookup. It returns the raw
// unclassified error untouched; classification must happen in the real
// application mapping.
func (s *post003FaultIdemStore) Lookup(ctx context.Context, scope runtime.EffectiveScope) (runtime.Record, bool, error) {
	if s.hits != nil {
		*s.hits++
	}
	return runtime.Record{}, false, s.err
}

// assertDependencyUnavailable503 asserts the fail-safe transient wire outcome
// and proves it is NOT the permanent replay-loss outcome.
func assertDependencyUnavailable503(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	m := problemBody(t, rr)
	if m["type"] != "https://pki.example/errors/dependency-unavailable" {
		t.Fatalf("problem type = %v, want dependency-unavailable", m["type"])
	}
	if retryable, ok := m["retryable"].(bool); !ok || !retryable {
		t.Fatalf("retryable = %v, want true", m["retryable"])
	}
	if m["type"] == "https://pki.example/errors/idempotency-replay-unavailable" {
		t.Fatal("raw unknown error was classified as permanent replay loss")
	}
}

// TestM56_POST003_RawUnknownProtectorError proves a raw, unclassified
// Protector.Open failure through the real replay branch maps to the transient
// fail-safe 503 and mints nothing, and that clearing the outage recovers the
// exact original secret.
func TestM56_POST003_RawUnknownProtectorError(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	tc := newM56HTTPFixture(t, now)
	key := "m56-post003-unknown-protector"
	hdr := post003HumanHeaders(key)

	rrNew := doAuth(t, tc.handler, "POST", "/v1/pre-onboarding-requests", m56C1ReqBody, hdr)
	if rrNew.Code != http.StatusCreated {
		t.Fatalf("NEW status = %d, want 201 (body %s)", rrNew.Code, rrNew.Body.String())
	}
	if tc.tokens.calls != 1 {
		t.Fatalf("generator calls after NEW = %d, want 1", tc.tokens.calls)
	}
	var newResp openapi.PreOnboardingCreateResponse
	if err := json.Unmarshal(rrNew.Body.Bytes(), &newResp); err != nil {
		t.Fatal(err)
	}
	before := snapshotPost003State(tc)

	// Raw unknown protector backend failure: no sentinel wrapping at all.
	tc.protector.openErr = errors.New("synthetic protector backend failure")
	rr := doAuth(t, tc.handler, "POST", "/v1/pre-onboarding-requests", m56C1ReqBody, hdr)
	assertDependencyUnavailable503(t, rr)
	if tc.protector.opens != 1 {
		t.Fatalf("protector Open calls = %d, want 1 (replay must reach Protector.Open)", tc.protector.opens)
	}
	if tc.tokens.calls != 1 {
		t.Fatalf("failed replay minted a replacement token: generator calls = %d, want 1", tc.tokens.calls)
	}
	assertPost003StateUnchanged(t, before, snapshotPost003State(tc))

	// Clearing the outage recovers the EXACT original secret — proving the
	// classification was transient, not permanent loss.
	tc.protector.openErr = nil
	rrRecover := doAuth(t, tc.handler, "POST", "/v1/pre-onboarding-requests", m56C1ReqBody, hdr)
	if rrRecover.Code != http.StatusCreated {
		t.Fatalf("recovered retry status = %d, want 201 (body %s)", rrRecover.Code, rrRecover.Body.String())
	}
	var recResp openapi.PreOnboardingCreateResponse
	if err := json.Unmarshal(rrRecover.Body.Bytes(), &recResp); err != nil {
		t.Fatal(err)
	}
	if recResp.RequestAccessToken != newResp.RequestAccessToken {
		t.Fatal("recovered retry returned a replacement secret, want the exact original token")
	}
	if tc.tokens.calls != 1 {
		t.Fatalf("recovery minted a replacement token: generator calls = %d, want 1", tc.tokens.calls)
	}
	assertPost003StateUnchanged(t, before, snapshotPost003State(tc))
}

// TestM56_POST003_RawResultStoreBackendError proves a raw ResultStore backend
// query failure is NOT authoritative snapshot absence: it maps to 503 (not
// 409), never reaches Protector.Open, and mints nothing.
func TestM56_POST003_RawResultStoreBackendError(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	tc := newM56HTTPFixture(t, now)
	key := "m56-post003-resultstore"
	hdr := post003HumanHeaders(key)

	rrNew := doAuth(t, tc.handler, "POST", "/v1/pre-onboarding-requests", m56C1ReqBody, hdr)
	if rrNew.Code != http.StatusCreated {
		t.Fatalf("NEW status = %d, want 201 (body %s)", rrNew.Code, rrNew.Body.String())
	}
	if tc.tokens.calls != 1 {
		t.Fatalf("generator calls after NEW = %d, want 1", tc.tokens.calls)
	}
	before := snapshotPost003State(tc)

	var rsHits int
	tc.uowManagerMock.onBegin = func(uow preonboardingapp.UnitOfWork) preonboardingapp.UnitOfWork {
		return &post003FaultUoW{
			UnitOfWork:      uow,
			resultStoreErr:  errors.New("synthetic result-store outage"),
			resultStoreHits: &rsHits,
		}
	}

	rr := doAuth(t, tc.handler, "POST", "/v1/pre-onboarding-requests", m56C1ReqBody, hdr)
	assertDependencyUnavailable503(t, rr)
	if rsHits != 1 {
		t.Fatalf("GetCreateResult calls = %d, want 1 (failure must originate at the ResultStore boundary)", rsHits)
	}
	if tc.protector.opens != 0 {
		t.Fatalf("protector Open called %d times; ResultStore failure must precede Protector.Open", tc.protector.opens)
	}
	if tc.tokens.calls != 1 {
		t.Fatalf("failed replay minted a replacement token: generator calls = %d, want 1", tc.tokens.calls)
	}
	assertPost003StateUnchanged(t, before, snapshotPost003State(tc))
}

// TestM56_POST003_RawIdempotencyBackendError proves a raw unclassified M5.4
// IdempotencyStore Lookup failure (the RecoverSecret backing lookup) maps to
// the transient fail-safe 503 through the real classification chain, with TP
// quota and every durable concern untouched.
func TestM56_POST003_RawIdempotencyBackendError(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	tc := newM56HTTPFixture(t, now)

	tpID := "test-tp-temporary-principal"
	tc.store.SeedTemporaryPrincipal(&domain.TemporaryPrincipal{
		TemporaryPrincipalID: tpID,
		PartnerID:            "P1",
		Status:               domain.TPStatusActive,
		ExpiresAt:            now.Add(time.Hour),
		MaxSubmissions:       2,
		CommittedSubmissions: 0,
	})

	key := "m56-post003-idempotency"
	headers := map[string]string{
		"Authorization":    "Bearer tok-temporary-principal",
		"Content-Type":     "application/json",
		"Idempotency-Key":  key,
		"X-Correlation-ID": "corr-post003-tp",
	}

	rrNew := doAuth(t, tc.handler, "POST", "/v1/pre-onboarding-requests", m56C1ReqBody, headers)
	if rrNew.Code != http.StatusCreated {
		t.Fatalf("TP NEW status = %d, want 201 (body %s)", rrNew.Code, rrNew.Body.String())
	}
	if tc.tokens.calls != 1 {
		t.Fatalf("generator calls after TP NEW = %d, want 1", tc.tokens.calls)
	}
	before := snapshotPost003State(tc)

	quota := func() int {
		uow, err := tc.store.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer uow.Rollback(context.Background())
		tpRec, ok, err := uow.TemporaryPrincipalStore().Get(context.Background(), tpID)
		if err != nil || !ok {
			t.Fatalf("TP missing after replay failure: ok=%v err=%v", ok, err)
		}
		return tpRec.CommittedSubmissions
	}
	if quota() != 1 {
		t.Fatalf("TP quota after NEW = %d, want 1", quota())
	}

	var lookupHits int
	tc.uowManagerMock.onBegin = func(uow preonboardingapp.UnitOfWork) preonboardingapp.UnitOfWork {
		return &post003FaultUoW{
			UnitOfWork: uow,
			lookupErr:  errors.New("synthetic idempotency store backend failure"),
			lookupHits: &lookupHits,
		}
	}

	rr := doAuth(t, tc.handler, "POST", "/v1/pre-onboarding-requests", m56C1ReqBody, headers)
	assertDependencyUnavailable503(t, rr)
	if lookupHits != 1 {
		t.Fatalf("IdempotencyStore Lookup calls = %d, want 1 (RecoverSecret must reach the lookup boundary)", lookupHits)
	}
	if tc.tokens.calls != 1 {
		t.Fatalf("failed replay minted a replacement token: generator calls = %d, want 1", tc.tokens.calls)
	}
	if quota() != 1 {
		t.Fatalf("TP quota changed across failed replay: %d, want 1", quota())
	}
	assertPost003StateUnchanged(t, before, snapshotPost003State(tc))
}
