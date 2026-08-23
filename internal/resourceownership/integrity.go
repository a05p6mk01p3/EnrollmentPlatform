package resourceownership

import (
	"fmt"
	"strings"
)

// ValidateOwnershipResult enforces integrity on a resolved resource ownership
// result and returns the validated result. It fails closed (returns an error)
// for any malformed, contradictory, or ambiguous data.
//
// Authoritative identifiers are preserved with exact identity: resource IDs
// and partner IDs are never trimmed or otherwise normalized, and a value
// carrying leading/trailing whitespace is malformed rather than being
// canonicalized into valid authority.
func ValidateOwnershipResult(requestedID string, raw OwnershipResult) (OwnershipResult, error) {
	if requestedID == "" {
		return OwnershipResult{}, fmt.Errorf("resourceownership: requested resource_id is empty")
	}
	if requestedID != strings.TrimSpace(requestedID) {
		return OwnershipResult{}, fmt.Errorf("resourceownership: requested resource_id %q has leading/trailing whitespace; exact identity is required", requestedID)
	}

	switch raw.Status {
	case OwnershipStatusFound:
		resID := raw.Ownership.ResourceID
		partnerID := raw.Ownership.PartnerID

		if resID == "" {
			return OwnershipResult{}, fmt.Errorf("resourceownership: found ownership result missing resource_id")
		}
		if resID != strings.TrimSpace(resID) {
			return OwnershipResult{}, fmt.Errorf("resourceownership: found resource_id %q has leading/trailing whitespace; exact identity is required", resID)
		}
		if resID != requestedID {
			return OwnershipResult{}, fmt.Errorf("resourceownership: found resource_id %q does not match requested resource_id %q", resID, requestedID)
		}
		if partnerID == "" {
			return OwnershipResult{}, fmt.Errorf("resourceownership: found ownership result missing partner_id")
		}
		if partnerID != strings.TrimSpace(partnerID) {
			return OwnershipResult{}, fmt.Errorf("resourceownership: found partner_id %q has leading/trailing whitespace; exact identity is required", partnerID)
		}

		return OwnershipResult{
			Status: OwnershipStatusFound,
			Ownership: ResourceOwnership{
				ResourceID: resID,
				PartnerID:  partnerID,
			},
		}, nil

	case OwnershipStatusNotFound:
		// Contradiction check: a NOT_FOUND result must not carry ownership metadata.
		if raw.Ownership.ResourceID != "" || raw.Ownership.PartnerID != "" {
			return OwnershipResult{}, fmt.Errorf("resourceownership: contradictory not-found result carries ownership metadata (resource_id=%q, partner_id=%q)", raw.Ownership.ResourceID, raw.Ownership.PartnerID)
		}
		return OwnershipResult{
			Status: OwnershipStatusNotFound,
		}, nil

	default:
		return OwnershipResult{}, fmt.Errorf("resourceownership: unknown or zero ownership status %d", raw.Status)
	}
}
