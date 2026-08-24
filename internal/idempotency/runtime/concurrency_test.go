package runtime_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	authnpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
)

func TestConcurrentSameScopeSameFingerprintSingleOwner(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	now := testNow()
	scope := mustEffectiveScope(t,
		mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "issuer-a|subject-a"),
		"POST", "/v1/enrollments", mustKey(t, "0123456789abcdef"))
	fp := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"INITIAL"}`))

	const n = 200
	var newCount int32
	var inProgressCount int32
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			res, err := svc.Reserve(ctx, reserveReq(scope, fp, now))
			if err != nil {
				t.Errorf("Reserve: %v", err)
				return
			}
			switch res.Status {
			case runtime.ReservationNew:
				atomic.AddInt32(&newCount, 1)
			case runtime.ReservationInProgress:
				atomic.AddInt32(&inProgressCount, 1)
			default:
				t.Errorf("unexpected status %s", res.Status)
			}
		}()
	}
	wg.Wait()

	if newCount != 1 {
		t.Fatalf("exactly one NEW owner expected, got %d", newCount)
	}
	if inProgressCount != n-1 {
		t.Fatalf("in-progress count = %d, want %d", inProgressCount, n-1)
	}
}

func TestConcurrentConflictingFingerprintsNeverGrantSecondOwner(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	now := testNow()
	scope := mustEffectiveScope(t,
		mustCredentialScope(t, authnpolicy.CredentialKindHumanOIDC, "issuer-a|subject-a"),
		"POST", "/v1/enrollments", mustKey(t, "0123456789abcdef"))
	fpA := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"INITIAL"}`))
	fpB := mustFingerprint(t, "POST", "/v1/enrollments", []byte(`{"operation":"RENEWAL"}`))

	const half = 100
	var newCount int32
	var conflictCount int32
	var inProgressCount int32
	var wg sync.WaitGroup
	wg.Add(half * 2)

	run := func(fp runtime.Fingerprint) {
		defer wg.Done()
		res, err := svc.Reserve(ctx, reserveReq(scope, fp, now))
		if err != nil {
			t.Errorf("Reserve: %v", err)
			return
		}
		switch res.Status {
		case runtime.ReservationNew:
			atomic.AddInt32(&newCount, 1)
		case runtime.ReservationConflict:
			atomic.AddInt32(&conflictCount, 1)
		case runtime.ReservationInProgress:
			atomic.AddInt32(&inProgressCount, 1)
		default:
			t.Errorf("unexpected status %s", res.Status)
		}
	}

	for i := 0; i < half; i++ {
		go run(fpA)
		go run(fpB)
	}
	wg.Wait()

	if newCount != 1 {
		t.Fatalf("exactly one NEW owner expected, got %d", newCount)
	}
	if conflictCount != half {
		t.Fatalf("conflict count = %d, want %d", conflictCount, half)
	}
	if inProgressCount != half-1 {
		t.Fatalf("in-progress count = %d, want %d", inProgressCount, half-1)
	}
}
