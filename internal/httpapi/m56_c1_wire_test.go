package httpapi_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	preonboardingapp "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	domain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/replaycapsule"
)

const m56C1ReqBody = `{"partner_id":"P1","agent":{"platform":"windows","version":"1.0"},"claimed_device":{"hostname":"node-m56-c1"}}`

func TestM56_C1_HTTP_ConflictDistinct(t *testing.T) {
	tc := newM56HTTPFixture(t, time.Now())

	hdr := func(key string) map[string]string {
		return map[string]string{"Authorization": "Bearer tok-human-oidc", "Content-Type": "application/json", "Idempotency-Key": key, "X-Correlation-ID": "corr-c1-conflict"}
	}
	key := "m56-c1-conflict-key"

	rr1 := doAuth(t, tc.handler, "POST", "/v1/pre-onboarding-requests", m56C1ReqBody, hdr(key))
	if rr1.Code != http.StatusCreated {
		t.Fatalf("NEW status = %d, want 201 (body %s)", rr1.Code, rr1.Body.String())
	}

	// Same key, different fingerprint (hostname changed).
	body2 := `{"partner_id":"P1","agent":{"platform":"windows","version":"1.0"},"claimed_device":{"hostname":"node-m56-c1-different"}}`
	rr2 := doAuth(t, tc.handler, "POST", "/v1/pre-onboarding-requests", body2, hdr(key))
	assertProblem(t, rr2, http.StatusConflict, "IDEMPOTENCY_CONFLICT")
	m := problemBody(t, rr2)
	if m["type"] != "https://pki.example/errors/idempotency-conflict" {
		t.Fatalf("conflict type = %v", m["type"])
	}
	if retryable, ok := m["retryable"].(bool); !ok || retryable {
		t.Fatalf("conflict retryable = %v, want false", m["retryable"])
	}
}

func TestM56_C1_HTTP_TransientProtectorOutage503(t *testing.T) {
	tc := newM56HTTPFixture(t, time.Now())

	hdr := func(key string) map[string]string {
		return map[string]string{"Authorization": "Bearer tok-human-oidc", "Content-Type": "application/json", "Idempotency-Key": key, "X-Correlation-ID": "corr-c1-transient"}
	}
	key := "m56-c1-transient-key"
	rr1 := doAuth(t, tc.handler, "POST", "/v1/pre-onboarding-requests", m56C1ReqBody, hdr(key))
	if rr1.Code != http.StatusCreated {
		t.Fatalf("NEW status = %d, want 201 (body %s)", rr1.Code, rr1.Body.String())
	}

	tc.protector.openErr = replaycapsule.ErrTransient
	rr2 := doAuth(t, tc.handler, "POST", "/v1/pre-onboarding-requests", m56C1ReqBody, hdr(key))
	assertProblem(t, rr2, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	m := problemBody(t, rr2)
	if m["type"] != "https://pki.example/errors/dependency-unavailable" {
		t.Fatalf("transient type = %v", m["type"])
	}
	if retryable, ok := m["retryable"].(bool); !ok || !retryable {
		t.Fatalf("transient retryable = %v, want true", m["retryable"])
	}
	if tc.tokens.calls != 1 {
		t.Fatalf("transient outage minted a replacement token: calls=%d, want 1", tc.tokens.calls)
	}

	// A later retry with the outage cleared recovers the original secret.
	tc.protector.openErr = nil
	rr3 := doAuth(t, tc.handler, "POST", "/v1/pre-onboarding-requests", m56C1ReqBody, hdr(key))
	if rr3.Code != http.StatusCreated {
		t.Fatalf("recovered retry status = %d, want 201 (body %s)", rr3.Code, rr3.Body.String())
	}
	if tc.tokens.calls != 1 {
		t.Fatalf("recovery minted a replacement token: calls=%d, want 1", tc.tokens.calls)
	}
}

// seedHTTPCommittedRecord stores a committed create idempotency record with a
// specific replay-capsule failure state, using the real protector to produce
// real cryptographic failure material where applicable.
func seedHTTPCommittedRecord(t *testing.T, tc *m56HTTPFixture, key, resourceID string, capsule *idempotencyruntime.ProtectedEnvelope, capsuleExpiry time.Time) {
	t.Helper()
	ctx := context.Background()
	now := tc.clock.Now()
	cmd := preonboardingapp.CreateOriginatorCommand{
		CreateCommand: preonboardingapp.CreateCommand{
			PartnerID:     "P1",
			ClaimedDevice: domain.ClaimedDevice{Hostname: "node-m56-c1"},
			Agent:         domain.Agent{Platform: "windows", Version: "1.0"},
		},
		CredentialKind:    authpolicy.CredentialKindHumanOIDC,
		CredentialBinding: "test-issuer|test-subject-human",
		IdempotencyKey:    key,
		CorrelationID:     "corr-c1-wire",
	}
	fp, err := preonboardingapp.ComputeCreateFingerprint(cmd)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := idempotencyruntime.NewCredentialScope(authpolicy.CredentialKindHumanOIDC, "test-issuer|test-subject-human")
	if err != nil {
		t.Fatal(err)
	}
	idemKey, err := idempotencyruntime.NewIdempotencyKey(key)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := idempotencyruntime.NewEffectiveScope(cred, "POST", "/v1/pre-onboarding-requests", idemKey)
	if err != nil {
		t.Fatal(err)
	}
	loc, err := idempotencyruntime.NewResultLocator("preonboarding-create:" + resourceID)
	if err != nil {
		t.Fatal(err)
	}

	uow, err := tc.store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.ResultStore().SaveCreateResult(ctx, loc, preonboardingapp.PreOnboardingCreateResultSnapshot{
		PreOnboardingRequestID: resourceID,
		PartnerID:              "P1",
		ExpiresAt:              now.Add(30 * time.Minute),
		Status:                 string(domain.StatePendingApproval),
		ETag:                   "etag-wire",
		Location:               "/v1/pre-onboarding-requests/" + resourceID,
		CommittedAt:            now,
	}); err != nil {
		t.Fatal(err)
	}
	uow.Rollback(ctx)

	rec := idempotencyruntime.Record{
		Scope:            scope,
		Fingerprint:      fp,
		Status:           idempotencyruntime.RecordCommitted,
		Result:           loc,
		ExpiresAt:        now.Add(2 * time.Hour),
		Capsule:          capsule,
		CapsuleExpiresAt: capsuleExpiry,
	}
	tc.store.SeedCommittedIdempotencyRecord(scope, rec)
}

func sealHTTPCapsule(t *testing.T, tc *m56HTTPFixture, resourceID string) (*idempotencyruntime.ProtectedEnvelope, idempotencyruntime.EffectiveScope, idempotencyruntime.Fingerprint) {
	t.Helper()
	cmd := preonboardingapp.CreateOriginatorCommand{
		CreateCommand: preonboardingapp.CreateCommand{
			PartnerID:     "P1",
			ClaimedDevice: domain.ClaimedDevice{Hostname: "node-m56-c1"},
			Agent:         domain.Agent{Platform: "windows", Version: "1.0"},
		},
		CredentialKind:    authpolicy.CredentialKindHumanOIDC,
		CredentialBinding: "test-issuer|test-subject-human",
		IdempotencyKey:    "m56-c1-seal-probe",
	}
	fp, err := preonboardingapp.ComputeCreateFingerprint(cmd)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := idempotencyruntime.NewCredentialScope(authpolicy.CredentialKindHumanOIDC, "test-issuer|test-subject-human")
	if err != nil {
		t.Fatal(err)
	}
	idemKey, err := idempotencyruntime.NewIdempotencyKey(cmd.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := idempotencyruntime.NewEffectiveScope(cred, "POST", "/v1/pre-onboarding-requests", idemKey)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := (replaycapsule.PreOnboardingAAD{ResourceID: resourceID, Scope: scope, Fingerprint: fp}).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	env, err := tc.protector.Seal(context.Background(), []byte("originator-secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	return env, scope, fp
}

// TestM56_C1_HTTP_PermanentClassesWireMatrix exercises every permanent replay
// failure class through the REAL recovery path (real AES-GCM capsule states
// stored in the committed record) and proves the wire outcome:
// 409 IDEMPOTENCY_REPLAY_UNAVAILABLE, retryable=false, no crypto leakage.
func TestM56_C1_HTTP_PermanentClassesWireMatrix(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		seed func(t *testing.T, tc *m56HTTPFixture, key string)
	}{
		{"missing", func(t *testing.T, tc *m56HTTPFixture, key string) {
			seedHTTPCommittedRecord(t, tc, key, "por-wire-missing", nil, time.Time{})
		}},
		{"expired", func(t *testing.T, tc *m56HTTPFixture, key string) {
			env, _, _ := sealHTTPCapsule(t, tc, "por-wire-expired")
			past := now.Add(-time.Minute)
			expired, err := idempotencyruntime.NewProtectedEnvelope(env.Ciphertext(), env.Nonce(), env.KeyID(), env.KeyVersion(), past)
			if err != nil {
				t.Fatal(err)
			}
			seedHTTPCommittedRecord(t, tc, key, "por-wire-expired", expired, past)
		}},
		{"malformed", func(t *testing.T, tc *m56HTTPFixture, key string) {
			env, _, _ := sealHTTPCapsule(t, tc, "por-wire-malformed")
			malformed, err := idempotencyruntime.NewProtectedEnvelope(env.Ciphertext(), env.Nonce(), "wrong-key-id", env.KeyVersion(), env.ExpiresAt())
			if err != nil {
				t.Fatal(err)
			}
			seedHTTPCommittedRecord(t, tc, key, "por-wire-malformed", malformed, malformed.ExpiresAt())
		}},
		{"integrity", func(t *testing.T, tc *m56HTTPFixture, key string) {
			env, _, _ := sealHTTPCapsule(t, tc, "por-wire-integrity")
			ct := env.Ciphertext()
			ct[0] ^= 0xFF
			tampered, err := idempotencyruntime.NewProtectedEnvelope(ct, env.Nonce(), env.KeyID(), env.KeyVersion(), env.ExpiresAt())
			if err != nil {
				t.Fatal(err)
			}
			seedHTTPCommittedRecord(t, tc, key, "por-wire-integrity", tampered, tampered.ExpiresAt())
		}},
		{"wrong_aad", func(t *testing.T, tc *m56HTTPFixture, key string) {
			// Sealed against a different AAD resource id; the replay computes
			// the authoritative AAD, so the real protector rejects the open.
			env, _, _ := sealHTTPCapsule(t, tc, "por-wrong-aad-sealed")
			seedHTTPCommittedRecord(t, tc, key, "por-wire-wrong-aad", env, env.ExpiresAt())
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newM56HTTPFixture(t, now)
			key := "m56-c1-wire-" + tc.name
			tc.seed(t, fx, key)

			rr := doAuth(t, fx.handler, "POST", "/v1/pre-onboarding-requests", m56C1ReqBody, map[string]string{
				"Authorization": "Bearer tok-human-oidc", "Content-Type": "application/json", "Idempotency-Key": key, "X-Correlation-ID": "corr-c1-wire-" + tc.name,
			})
			assertProblem(t, rr, http.StatusConflict, "IDEMPOTENCY_REPLAY_UNAVAILABLE")
			m := problemBody(t, rr)
			if m["type"] != "https://pki.example/errors/idempotency-replay-unavailable" {
				t.Fatalf("replay-unavailable type = %v", m["type"])
			}
			if retryable, ok := m["retryable"].(bool); !ok || retryable {
				t.Fatalf("replay-unavailable retryable = %v, want false", m["retryable"])
			}
			body := rr.Body.String()
			for _, leak := range []string{"aead", "ciphertext", "nonce", "wrong-key-id", "originator-secret", "authentication failed"} {
				if strings.Contains(strings.ToLower(body), strings.ToLower(leak)) {
					t.Fatalf("response leaked crypto material %q: %s", leak, body)
				}
			}
			if fx.tokens.calls != 0 {
				t.Fatalf("permanent replay failure minted a replacement token: calls=%d, want 0", fx.tokens.calls)
			}
		})
	}
}
