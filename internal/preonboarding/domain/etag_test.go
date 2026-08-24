package domain_test

import (
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
)

func TestComputeETagDeterminism(t *testing.T) {
	now := time.Now()
	expires := now.Add(time.Hour)

	req1, _ := domain.NewRequest("por-1", "P1", domain.ClaimedDevice{Hostname: "host-a"}, domain.Agent{Platform: "windows", Version: "1.0"}, now, expires)
	req2, _ := domain.NewRequest("por-1", "P1", domain.ClaimedDevice{Hostname: "host-a"}, domain.Agent{Platform: "windows", Version: "1.0"}, now, expires)

	etag1 := domain.ComputeETag(req1, now)
	etag2 := domain.ComputeETag(req2, now)

	if etag1 == "" {
		t.Fatal("ComputeETag returned empty string")
	}
	if etag1 != etag2 {
		t.Errorf("ETags must be deterministic for identical representation: %s vs %s", etag1, etag2)
	}

	// ETag is opaque and not equal to raw resource_version
	if etag1 == "1" || etag1 == `"1"` {
		t.Errorf("ETag must be opaque, not raw resource_version: %s", etag1)
	}
}

func TestComputeETagChangesOnMutation(t *testing.T) {
	now := time.Now()
	expires := now.Add(time.Hour)

	req, _ := domain.NewRequest("por-1", "P1", domain.ClaimedDevice{Hostname: "host-a"}, domain.Agent{Platform: "windows", Version: "1.0"}, now, expires)
	etagBefore := domain.ComputeETag(req, now)

	if err := req.Approve(now.Add(time.Minute), "dev-1"); err != nil {
		t.Fatal(err)
	}

	etagAfter := domain.ComputeETag(req, now.Add(time.Minute))
	if etagBefore == etagAfter {
		t.Errorf("ETag must change after approval mutation: before=%s, after=%s", etagBefore, etagAfter)
	}
}

func TestComputeETagChangesOnEffectiveExpiryWithoutPersistedVersionIncrement(t *testing.T) {
	now := time.Now()
	expires := now.Add(10 * time.Minute)

	req, _ := domain.NewRequest("por-1", "P1", domain.ClaimedDevice{Hostname: "host-a"}, domain.Agent{Platform: "windows", Version: "1.0"}, now, expires)

	etagPreExpiry := domain.ComputeETag(req, now.Add(5*time.Minute))
	etagPostExpiry := domain.ComputeETag(req, now.Add(15*time.Minute))

	if etagPreExpiry == etagPostExpiry {
		t.Errorf("ETag must differ across expiration boundary: pre=%s, post=%s", etagPreExpiry, etagPostExpiry)
	}
	// Persisted resource version was not incremented
	if req.ResourceVersion() != 1 {
		t.Errorf("ResourceVersion = %d, want 1", req.ResourceVersion())
	}
}

func TestMatchETag(t *testing.T) {
	current := `"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`

	// Exact match with quotes
	if !domain.MatchETag(current, current) {
		t.Error("expected match for exact quoted ETag")
	}

	// Match without quotes
	if !domain.MatchETag("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", current) {
		t.Error("expected match for unquoted ETag")
	}

	// Mismatched value
	if domain.MatchETag(`"other-etag"`, current) {
		t.Error("did not expect match for different ETag")
	}

	// Weak ETag rejected
	if domain.MatchETag(`W/"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`, current) {
		t.Error("expected weak ETag to be rejected")
	}

	// Wildcard rejected
	if domain.MatchETag("*", current) {
		t.Error("expected wildcard * to be rejected")
	}
}
