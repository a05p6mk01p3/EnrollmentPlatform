package application

import (
	"errors"
	"fmt"
	"testing"

	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/replaycapsule"
)

func TestMapRecovery(t *testing.T) {
	cases := []struct {
		name string
		in   error
		want error
	}{
		{"nil", nil, nil},
		{"no capsule", &idempotencyruntime.RecoveryError{Reason: idempotencyruntime.RecoveryReasonNoCapsule}, ErrIdempotencyReplayUnavailable},
		{"capsule expired", &idempotencyruntime.RecoveryError{Reason: idempotencyruntime.RecoveryReasonCapsuleExpired}, ErrIdempotencyReplayUnavailable},
		{"record expired", &idempotencyruntime.RecoveryError{Reason: idempotencyruntime.RecoveryReasonRecordExpired}, ErrIdempotencyReplayUnavailable},
		{"unavailable", &idempotencyruntime.RecoveryError{Reason: idempotencyruntime.RecoveryReasonUnavailable}, ErrIdempotencyReplayUnavailable},
		{"unknown reason", &idempotencyruntime.RecoveryError{Reason: idempotencyruntime.RecoveryReason("FUTURE_UNKNOWN_REASON")}, ErrDependencyUnavailable},
		{"open failed permanent", &idempotencyruntime.RecoveryError{Reason: idempotencyruntime.RecoveryReasonOpenFailed, Cause: replaycapsule.ErrIntegrityFailure}, ErrIdempotencyReplayUnavailable},
		{"open failed malformed", &idempotencyruntime.RecoveryError{Reason: idempotencyruntime.RecoveryReasonOpenFailed, Cause: replaycapsule.ErrMalformedEnvelope}, ErrIdempotencyReplayUnavailable},
		{"open failed transient", &idempotencyruntime.RecoveryError{Reason: idempotencyruntime.RecoveryReasonOpenFailed, Cause: replaycapsule.ErrTransient}, ErrDependencyUnavailable},
		{"open failed wrapped transient", &idempotencyruntime.RecoveryError{Reason: idempotencyruntime.RecoveryReasonOpenFailed, Cause: fmt.Errorf("%w: %w", idempotencyruntime.ErrEnvelopeOpenFailed, replaycapsule.ErrTransient)}, ErrDependencyUnavailable},
		{"open failed unknown", &idempotencyruntime.RecoveryError{Reason: idempotencyruntime.RecoveryReasonOpenFailed, Cause: errors.New("kms: unexpected outage")}, ErrDependencyUnavailable},
		{"plain transient", replaycapsule.ErrTransient, ErrDependencyUnavailable},
		{"plain permanent", replaycapsule.ErrPermanent, ErrIdempotencyReplayUnavailable},
		{"plain unknown", errors.New("kms: unexpected outage"), ErrDependencyUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapRecovery(tc.in)
			if got == nil && tc.want == nil {
				return
			}
			if !errors.Is(got, tc.want) {
				t.Fatalf("mapRecovery(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
