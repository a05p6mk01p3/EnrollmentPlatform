package application

import (
	"testing"
	"time"
)

func TestCapsuleExpiry(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

	t.Run("replay shorter than idempotency", func(t *testing.T) {
		got := capsuleExpiry(now, 5*time.Minute, 24*time.Hour)
		want := now.Add(5 * time.Minute)
		if !got.Equal(want) {
			t.Fatalf("capsule expiry = %v, want %v (replay policy)", got, want)
		}
	})

	t.Run("replay longer than idempotency is capped", func(t *testing.T) {
		got := capsuleExpiry(now, 24*time.Hour, time.Hour)
		want := now.Add(time.Hour)
		if !got.Equal(want) {
			t.Fatalf("capsule expiry = %v, want %v (idempotency bound)", got, want)
		}
	})

	t.Run("equal durations", func(t *testing.T) {
		got := capsuleExpiry(now, time.Hour, time.Hour)
		want := now.Add(time.Hour)
		if !got.Equal(want) {
			t.Fatalf("capsule expiry = %v, want %v", got, want)
		}
	})

	t.Run("never consults request access token lifetime", func(t *testing.T) {
		// The helper has no request-access-token parameter by construction: it
		// can only depend on replay and idempotency durations.
		a := capsuleExpiry(now, 10*time.Minute, time.Hour)
		b := capsuleExpiry(now, 10*time.Minute, time.Hour)
		if !a.Equal(b) {
			t.Fatalf("capsule expiry must be deterministic: %v vs %v", a, b)
		}
	})
}
