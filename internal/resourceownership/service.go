package resourceownership

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
)

// Service is the M5.3 resource ownership and visibility application boundary.
// It resolves current effective Human partner authorizations through the
// accepted M5.2 authority (*partnerauth.Service), resolves minimal
// authoritative resource ownership metadata, validates result integrity, and
// evaluates Human visibility.
//
// It is immutable after construction, holds no mutable global state, and does
// not cache authoritative results across requests. Every evaluation is fresh
// for the request it serves.
type Service struct {
	ownership PreOnboardingOwnershipResolver
	humanAuth *partnerauth.Service
}

// NewService constructs a Service. Both dependencies are mandatory: a nil or
// typed-nil dependency, or an invalid *partnerauth.Service, fails construction.
func NewService(ownership PreOnboardingOwnershipResolver, humanAuth *partnerauth.Service) (*Service, error) {
	if isNilLike(ownership) {
		return nil, errors.New("resourceownership: pre-onboarding ownership resolver must not be nil or typed-nil")
	}
	if humanAuth == nil {
		return nil, errors.New("resourceownership: partner authorization service must not be nil")
	}
	if err := humanAuth.Validate(); err != nil {
		return nil, fmt.Errorf("resourceownership: invalid partner authorization service: %w", err)
	}
	return &Service{
		ownership: ownership,
		humanAuth: humanAuth,
	}, nil
}

// Validate reports whether the Service is structurally usable:
// both mandatory dependencies (ownership resolver and partner authorization service)
// must be present, non-nil, and structurally valid.
func (s *Service) Validate() error {
	if s == nil {
		return errors.New("resourceownership: nil service")
	}
	if isNilLike(s.ownership) {
		return errors.New("resourceownership: pre-onboarding ownership resolver missing or typed-nil")
	}
	if s.humanAuth == nil {
		return errors.New("resourceownership: partner authorization service missing")
	}
	if err := s.humanAuth.Validate(); err != nil {
		return fmt.Errorf("resourceownership: invalid partner authorization service: %w", err)
	}
	return nil
}

// ValidateWithPartnerAuth enforces both structural validity of this Service
// and composition provenance: the partner authorization service instance
// wired into M5.3 must be the exact same instance configured in Server.
func (s *Service) ValidateWithPartnerAuth(expected *partnerauth.Service) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if expected == nil {
		return errors.New("resourceownership: expected partner authorization service must not be nil")
	}
	if s.humanAuth != expected {
		return errors.New("resourceownership: partner authorization service instance mismatch with Server.partnerAuth")
	}
	return nil
}

// EvaluateHumanVisibility evaluates whether the authenticated Human principal
// may view the pre-onboarding request identified by requestedResourceID.
//
// When VisibilityAllowed is returned, the second return value is the
// authoritative partner_id of the resource (used by the caller for post-read
// response consistency validation).
//
// Ordering:
//  1. Resolve current Human partner authorizations from M5.2 authority.
//  2. If the current authorization set is validly empty (zero partners), return
//     VisibilityHiddenNotFound immediately without querying ownership.
//  3. Resolve minimal authoritative resource ownership metadata.
//  4. Enforce ownership result integrity.
//  5. If the resource does not exist, return VisibilityHiddenNotFound.
//  6. If the resource's authoritative partner_id is in the caller's current
//     authorization set, return VisibilityAllowed with the partner ID.
//  7. Otherwise (resource exists for an unauthorized partner), return
//     VisibilityHiddenNotFound (404 concealment; no 403 signal).
func (s *Service) EvaluateHumanVisibility(ctx context.Context, principal partnerauth.HumanPrincipal, requestedResourceID string) (VisibilityDecision, string, error) {
	if s == nil || isNilLike(s.ownership) || s.humanAuth == nil {
		return VisibilityIndeterminate, "", ErrOwnershipDependencyUnavailable
	}

	if requestedResourceID == "" {
		return VisibilityIndeterminate, "", fmt.Errorf("resourceownership: empty requested resource_id")
	}
	if requestedResourceID != strings.TrimSpace(requestedResourceID) {
		return VisibilityIndeterminate, "", fmt.Errorf("resourceownership: requested resource_id %q has leading/trailing whitespace", requestedResourceID)
	}

	// 1. Resolve current Human authorizations via M5.2 authority.
	// ResolveMyAuthorizations owns canonical M5.2 authorization-set integrity validation.
	authSet, err := s.humanAuth.ResolveMyAuthorizations(ctx, principal)
	if err != nil {
		return VisibilityIndeterminate, "", err
	}

	// 2. Valid-empty authorization optimization: if caller has zero partners,
	// no partner-owned resource can be visible. Return hidden 404 without
	// querying ownership.
	if len(authSet.Partners) == 0 {
		return VisibilityHiddenNotFound, "", nil
	}

	// 3. Resolve minimal authoritative resource ownership metadata.
	rawResult, err := s.ownership.ResolvePreOnboardingOwnership(ctx, requestedResourceID)
	if err != nil {
		return VisibilityIndeterminate, "", err
	}

	// 4. Enforce ownership result integrity.
	validated, err := ValidateOwnershipResult(requestedResourceID, rawResult)
	if err != nil {
		return VisibilityIndeterminate, "", err
	}

	// 5. Nonexistent resource -> hidden 404.
	if validated.Status == OwnershipStatusNotFound {
		return VisibilityHiddenNotFound, "", nil
	}

	// 6 & 7. Check if resource partner is in caller's current authorization set.
	if validated.Status == OwnershipStatusFound {
		for _, p := range authSet.Partners {
			if p.PartnerID == validated.Ownership.PartnerID {
				return VisibilityAllowed, validated.Ownership.PartnerID, nil
			}
		}
		// Cross-partner: resource exists for another partner -> hidden 404.
		return VisibilityHiddenNotFound, "", nil
	}

	return VisibilityIndeterminate, "", fmt.Errorf("resourceownership: unhandled ownership status %d", validated.Status)
}

// isNilLike reports whether v is nil or holds a typed-nil value of a nilable kind.
func isNilLike(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}
