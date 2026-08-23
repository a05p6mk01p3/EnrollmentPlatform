package resourceownership

import (
	"context"
)

// PreOnboardingOwnershipResolver resolves the authoritative ownership of a
// pre-onboarding request: whether it exists and which partner_id owns it.
//
// A result returned with err == nil is a successful evaluation (either FOUND
// or NOT_FOUND). A non-nil error means authoritative ownership could not be
// determined deterministically (dependency failure, storage error); callers
// MUST fail closed (VisibilityIndeterminate / 503) and must never interpret an
// error as NOT_FOUND.
type PreOnboardingOwnershipResolver interface {
	ResolvePreOnboardingOwnership(ctx context.Context, id string) (OwnershipResult, error)
}
