package application

import "time"

func capsuleExpiry(operationTime time.Time, replayCapsuleLifetime, idempotencyLifetime time.Duration) time.Time {
	candidate := operationTime.Add(replayCapsuleLifetime)
	bound := operationTime.Add(idempotencyLifetime)
	if candidate.After(bound) {
		return bound
	}
	return candidate
}
