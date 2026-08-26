package application

import "time"

// capsuleExpiry computes the Replay Capsule expiry, deterministically bounded
// by the enclosing idempotency record expiry.
//
// The candidate capsule expiry is operationTime + replayCapsuleLifetime. It is
// never allowed to outlive the idempotency record (operationTime +
// idempotencyLifetime); when the replay policy asks for a longer window the
// capsule is capped at the idempotency record expiry.
//
// The RequestAccessToken lifetime is deliberately independent: it is neither
// consulted here nor derived from either of the two idempotency/replay
// durations.
func capsuleExpiry(operationTime time.Time, replayCapsuleLifetime, idempotencyLifetime time.Duration) time.Time {
	candidate := operationTime.Add(replayCapsuleLifetime)
	bound := operationTime.Add(idempotencyLifetime)
	if candidate.After(bound) {
		return bound
	}
	return candidate
}
