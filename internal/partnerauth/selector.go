package partnerauth

import "time"

// SelectHumanPreOnboarding evaluates whether the resolved (and integrity-
// validated) human authorizations authorize the requested partner with the
// required partner-scoped permission.
func SelectHumanPreOnboarding(a HumanAuthorizations, requestedPartnerID, requiredScope string) SelectionDecision {
	for _, p := range a.Partners {
		if p.PartnerID == requestedPartnerID {
			if containsScope(p.Scopes, requiredScope) {
				return SelectionAllowed
			}
			return SelectionDeniedScope
		}
	}
	return SelectionDeniedPartner
}

// SelectTemporaryPrincipalPreOnboarding evaluates the Temporary Principal
// partner/scope/local-lifecycle selection sub-gate. It allows only when the
// current local record is ACTIVE, not expired, not disabled, bound to the
// requested partner, and includes the applicable pre-onboarding authority.
//
// This evaluates ONLY the selection sub-gate; it does not consume
// max_submissions/quota and does not establish that the production HTTP path
// may return 201.
func SelectTemporaryPrincipalPreOnboarding(a TemporaryPrincipalAuthorization, requestedPartnerID, requiredScope string, now time.Time) SelectionDecision {
	if a.Status != TemporaryPrincipalStatusActive {
		// Disabled or not-active local state: not currently authorized.
		return SelectionDeniedPartner
	}
	if a.ExpiresAt == nil {
		// Cannot establish "not expired": fail closed.
		return SelectionIndeterminate
	}
	if !now.Before(*a.ExpiresAt) {
		// Expired local authorization.
		return SelectionDeniedPartner
	}
	if a.PartnerID != requestedPartnerID {
		return SelectionDeniedPartner
	}
	if !containsScope(a.Scopes, requiredScope) {
		return SelectionDeniedScope
	}
	return SelectionAllowed
}

func containsScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}
