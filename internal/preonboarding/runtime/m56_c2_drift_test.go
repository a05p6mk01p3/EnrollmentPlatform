package runtime_test

import (
	"context"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
)

// newDriftHarness builds a HumanOIDC-capable service with
// RequestAccessTokenLifetime (30m) < ReplayCapsuleLifetime (1h) <
// IdempotencyRetention (24h), plus an admin granted partner authority.
func newDriftHarness(t *testing.T, now time.Time) (*application.Service, *c2Harness, application.AdminPrincipal) {
	t.Helper()
	auth := runtime.NewMemoryPartnerAuthorityChecker()
	admin := application.AdminPrincipal{Issuer: "https://auth.example", Subject: "admin-1"}
	auth.GrantPartnerAuthority(admin, "P1")

	recorder := runtime.NewMemoryAuditRecorder()
	store := runtime.NewMemoryStore(recorder)
	tokens := &trackingTokenGenerator{}
	prot := c2RealProtector(t, now)
	h := newC2Harness(t, now, store, recorder, store, &seqID{}, tokens, prot, tokens, auth)
	return h.svc, h, admin
}

func tokenAuthenticates(h *c2Harness, token string) bool {
	a := capability.NewRequestAccessAuthenticator(h.verifier, h.store, h.clock)
	return a.Authenticate(context.Background(), &authruntime.Credential{BearerToken: token}).Decision == authruntime.DecisionAuthenticated
}

func currentRequest(t *testing.T, h *c2Harness, id string) *domain.PreOnboardingRequest {
	t.Helper()
	req, ok := h.store.GetRequest(domain.ID(id))
	if !ok {
		t.Fatalf("request %q missing", id)
	}
	return req
}

func requestAccessRecordExpiry(t *testing.T, h *c2Harness, token string) time.Time {
	t.Helper()
	key, err := h.verifier.Derive(authpolicy.CredentialKindRequestAccessToken, token)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := h.store.LookupRequestAccess(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return rec.ExpiresAt
}

func TestM56_C2_ReplayAfterResourceDrift(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	run := func(t *testing.T, mutate func(t *testing.T, svc *application.Service, admin application.AdminPrincipal, orig application.PreOnboardingCreateResultSnapshot)) {
		svc, h, admin := newDriftHarness(t, now)
		cmd := humanCmd("idem-c2-drift-key")

		res1, err := svc.CreateOriginator(ctx, cmd)
		if err != nil {
			t.Fatal(err)
		}
		orig := res1.Snapshot

		mutate(t, svc, admin, orig)

		// The current resource ETag/state now differs from the create snapshot.
		current := currentRequest(t, h, orig.PreOnboardingRequestID)
		currentETag := domain.ComputeETag(current, now)
		if currentETag == orig.ETag {
			t.Fatalf("mutation did not change the resource ETag (%q)", orig.ETag)
		}

		before := captureReplayState(h.store, h.recorder)

		replayCmd := cmd
		replayCmd.CorrelationID = "corr-c2-drift-replay"
		res2, err := svc.CreateOriginator(ctx, replayCmd)
		if err != nil {
			t.Fatalf("replay failed: %v", err)
		}
		if !res2.Replay {
			t.Fatal("expected REPLAY, got NEW")
		}
		if res2.RequestAccessToken != res1.RequestAccessToken {
			t.Fatalf("replay token = %q, want original %q", res2.RequestAccessToken, res1.RequestAccessToken)
		}
		if res2.Snapshot != orig {
			t.Fatalf("replay snapshot = %+v, want original %+v", res2.Snapshot, orig)
		}
		if res2.Snapshot.ETag != orig.ETag {
			t.Fatalf("replay ETag = %q, want original %q (not current %q)", res2.Snapshot.ETag, orig.ETag, currentETag)
		}
		if res2.Snapshot.Location != orig.Location {
			t.Fatalf("replay Location = %q, want original %q", res2.Snapshot.Location, orig.Location)
		}

		// The underlying resource must be exactly as it was before replay.
		after := currentRequest(t, h, orig.PreOnboardingRequestID)
		if after.Status() != current.Status() || after.ResourceVersion() != current.ResourceVersion() {
			t.Fatalf("replay mutated current resource: status %s->%s version %d->%d", current.Status(), after.Status(), current.ResourceVersion(), after.ResourceVersion())
		}
		if domain.ComputeETag(after, now) != currentETag {
			t.Fatalf("replay changed current resource ETag from %q", currentETag)
		}

		assertReplayStateUnchanged(t, before, captureReplayState(h.store, h.recorder))
		if h.tokens.calls != 1 {
			t.Fatalf("replay minted a token: generator calls = %d, want 1", h.tokens.calls)
		}
	}

	t.Run("after_approve", func(t *testing.T) {
		run(t, func(t *testing.T, svc *application.Service, admin application.AdminPrincipal, orig application.PreOnboardingCreateResultSnapshot) {
			res, err := svc.Approve(ctx, admin, application.ApproveCommand{
				ID:             orig.PreOnboardingRequestID,
				IfMatch:        orig.ETag,
				IdempotencyKey: "idem-c2-approve-key",
				ExpectedStatus: "PENDING_APPROVAL",
				Reason:         "drift approve",
			})
			if err != nil {
				t.Fatalf("approve failed: %v", err)
			}
			if res.Status != domain.StateEnrollmentReady {
				t.Fatalf("approve status = %v, want ENROLLMENT_READY", res.Status)
			}
		})
	})

	t.Run("after_reject", func(t *testing.T) {
		run(t, func(t *testing.T, svc *application.Service, admin application.AdminPrincipal, orig application.PreOnboardingCreateResultSnapshot) {
			res, err := svc.Reject(ctx, admin, application.RejectCommand{
				ID:             orig.PreOnboardingRequestID,
				IfMatch:        orig.ETag,
				IdempotencyKey: "idem-c2-reject-key",
				ExpectedStatus: "PENDING_APPROVAL",
				Reason:         "drift reject",
			})
			if err != nil {
				t.Fatalf("reject failed: %v", err)
			}
			if res.EffectiveStatus != domain.StateRejected {
				t.Fatalf("reject status = %v, want REJECTED", res.EffectiveStatus)
			}
		})
	})
}

// TestM56_C2_ReplayAfterEffectiveExpiry proves replay returns the original
// create snapshot (PENDING_APPROVAL) even after the resource's time-derived
// effective status has become EXPIRED, while the idempotency record and
// Replay Capsule remain recoverable.
func TestM56_C2_ReplayAfterEffectiveExpiry(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	svc, h, _ := newDriftHarness(t, now)
	cmd := humanCmd("idem-c2-expiry-key")
	res1, err := svc.CreateOriginator(ctx, cmd)
	if err != nil {
		t.Fatal(err)
	}
	orig := res1.Snapshot

	// Advance past the 30m resource/token expiry, but before the 1h capsule and
	// 24h idempotency recovery windows.
	h.clock.Advance(45 * time.Minute)

	// The resource is now effectively expired.
	if _, err := svc.GetPublic(ctx, orig.PreOnboardingRequestID); err != application.ErrResourceExpired {
		t.Fatalf("GetPublic error = %v, want ErrResourceExpired", err)
	}

	replayCmd := cmd
	replayCmd.CorrelationID = "corr-c2-expiry-replay"
	res2, err := svc.CreateOriginator(ctx, replayCmd)
	if err != nil {
		t.Fatalf("replay failed: %v", err)
	}
	if !res2.Replay {
		t.Fatal("expected REPLAY, got NEW")
	}
	// Original body/status, not recomputed as EXPIRED.
	if res2.Snapshot != orig {
		t.Fatalf("replay snapshot = %+v, want original %+v", res2.Snapshot, orig)
	}
	if res2.Snapshot.Status != string(domain.StatePendingApproval) {
		t.Fatalf("replay status = %q, want PENDING_APPROVAL (original)", res2.Snapshot.Status)
	}
	// Resource expiry must not have been extended by replay.
	after := currentRequest(t, h, orig.PreOnboardingRequestID)
	if !after.ExpiresAt().Equal(orig.ExpiresAt) {
		t.Fatalf("resource ExpiresAt moved: %v -> %v", orig.ExpiresAt, after.ExpiresAt())
	}
}

// TestM56_C2_ReplayAfterTokenExpiry proves replay returns the exact original
// token string even after that token has expired, without reactivating it,
// extending its verifier expiry, or minting a replacement.
func TestM56_C2_ReplayAfterTokenExpiry(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	svc, h, _ := newDriftHarness(t, now)
	cmd := humanCmd("idem-c2-token-expiry")
	res1, err := svc.CreateOriginator(ctx, cmd)
	if err != nil {
		t.Fatal(err)
	}
	orig := res1.Snapshot
	token := res1.RequestAccessToken

	if !tokenAuthenticates(h, token) {
		t.Fatal("token must authenticate before expiry")
	}
	expiryBefore := requestAccessRecordExpiry(t, h, token)
	if !expiryBefore.Equal(orig.ExpiresAt) {
		t.Fatalf("RequestAccessRecord expiry %v != snapshot ExpiresAt %v", expiryBefore, orig.ExpiresAt)
	}

	// Advance past token/resource expiry, keeping the capsule/idempotency valid.
	h.clock.Advance(45 * time.Minute)

	if tokenAuthenticates(h, token) {
		t.Fatal("token must NOT authenticate after expiry")
	}

	replayCmd := cmd
	replayCmd.CorrelationID = "corr-c2-token-expiry-replay"
	res2, err := svc.CreateOriginator(ctx, replayCmd)
	if err != nil {
		t.Fatalf("replay failed: %v", err)
	}
	if !res2.Replay {
		t.Fatal("expected REPLAY, got NEW")
	}
	if res2.RequestAccessToken != token {
		t.Fatalf("replay returned %q, want exact original %q", res2.RequestAccessToken, token)
	}
	if res2.Snapshot != orig {
		t.Fatalf("replay snapshot = %+v, want original %+v", res2.Snapshot, orig)
	}

	// The returned token must STILL fail authentication after replay.
	if tokenAuthenticates(h, token) {
		t.Fatal("replay must not reactivate the expired token")
	}
	// Verifier expiry must not have moved.
	expiryAfter := requestAccessRecordExpiry(t, h, token)
	if !expiryAfter.Equal(expiryBefore) {
		t.Fatalf("RequestAccessRecord.ExpiresAt moved on replay: %v -> %v", expiryBefore, expiryAfter)
	}
	if h.tokens.calls != 1 {
		t.Fatalf("replay minted a replacement token: generator calls = %d, want 1", h.tokens.calls)
	}
}
