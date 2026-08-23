package partnerauth

import (
	"fmt"
	"sort"
	"strings"
)

// validateHumanAuthorizations enforces authorization-set integrity on a
// resolved human authorization result and returns the validated set. It
// fails closed (returns an error) for any malformed or ambiguous data.
//
// Authoritative identifiers are preserved with exact identity: partner IDs
// and scope names are never trimmed or otherwise normalized, and a value
// carrying leading/trailing whitespace is malformed rather than being
// canonicalized into valid authority. Harmless identical duplication (exact
// duplicate partner entries, exact duplicate scopes) is de-duplicated and
// scopes are sorted deterministically; neither operation can broaden
// authority.
//
// A non-identical duplicate partner entry (same partner_id, different scopes)
// is ambiguous and fails closed rather than being merged.
func validateHumanAuthorizations(a HumanAuthorizations) (HumanAuthorizations, error) {
	if strings.TrimSpace(a.PrincipalID) == "" {
		return HumanAuthorizations{}, fmt.Errorf("partnerauth: resolved human authorizations missing principal_id")
	}

	type normalizedPartner struct {
		displayName string
		scopes      []string
	}
	seen := make(map[string]normalizedPartner, len(a.Partners))
	order := make([]string, 0, len(a.Partners))

	for i, p := range a.Partners {
		if p.PartnerID == "" {
			return HumanAuthorizations{}, fmt.Errorf("partnerauth: resolved human authorization entry %d missing partner_id", i)
		}
		if p.PartnerID != strings.TrimSpace(p.PartnerID) {
			return HumanAuthorizations{}, fmt.Errorf("partnerauth: resolved human authorization entry %d partner_id %q has leading/trailing whitespace; exact identity is required", i, p.PartnerID)
		}
		scopes, err := validateScopes(p.Scopes)
		if err != nil {
			return HumanAuthorizations{}, fmt.Errorf("partnerauth: resolved human authorization entry %q: %w", p.PartnerID, err)
		}
		if prev, dup := seen[p.PartnerID]; dup {
			if !equalScopes(prev.scopes, scopes) {
				return HumanAuthorizations{}, fmt.Errorf("partnerauth: contradictory duplicate entries for partner %q", p.PartnerID)
			}
			// Identical duplication is harmless: collapse to one.
			continue
		}
		seen[p.PartnerID] = normalizedPartner{displayName: p.DisplayName, scopes: scopes}
		order = append(order, p.PartnerID)
	}

	partners := make([]PartnerAuthorization, 0, len(order))
	for _, id := range order {
		np := seen[id]
		partners = append(partners, PartnerAuthorization{
			PartnerID:   id,
			DisplayName: np.displayName,
			Scopes:      np.scopes,
		})
	}

	return HumanAuthorizations{PrincipalID: a.PrincipalID, Partners: partners}, nil
}

// validateScopes validates scope names without transforming their identity:
// every name must be non-empty and must not carry leading/trailing whitespace
// (a padded name is malformed, never canonicalized into authority). Exact
// duplicates are de-duplicated and the set is sorted deterministically; both
// operations preserve exact identity and cannot broaden authority. An empty
// input validates to nil (no scopes).
func validateScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		if s == "" {
			return nil, fmt.Errorf("scope name must be non-empty")
		}
		if s != strings.TrimSpace(s) {
			return nil, fmt.Errorf("scope name %q has leading/trailing whitespace; exact identity is required", s)
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

func equalScopes(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// validateTemporaryPrincipalAuthorization enforces integrity on a resolved
// Temporary Principal authorization record. It fails closed on any malformed
// or ambiguous data. Partner IDs and scope names preserve exact identity: a
// padded value is malformed, never canonicalized into authority.
func validateTemporaryPrincipalAuthorization(expected TemporaryPrincipalID, a TemporaryPrincipalAuthorization) (TemporaryPrincipalAuthorization, error) {
	if strings.TrimSpace(a.TemporaryPrincipalID) == "" || a.TemporaryPrincipalID != string(expected) {
		return TemporaryPrincipalAuthorization{}, fmt.Errorf("partnerauth: resolved temporary principal record id %q does not match authenticated id %q", a.TemporaryPrincipalID, expected)
	}
	if a.PartnerID == "" {
		return TemporaryPrincipalAuthorization{}, fmt.Errorf("partnerauth: resolved temporary principal authorization missing partner_id")
	}
	if a.PartnerID != strings.TrimSpace(a.PartnerID) {
		return TemporaryPrincipalAuthorization{}, fmt.Errorf("partnerauth: resolved temporary principal partner_id %q has leading/trailing whitespace; exact identity is required", a.PartnerID)
	}
	scopes, err := validateScopes(a.Scopes)
	if err != nil {
		return TemporaryPrincipalAuthorization{}, fmt.Errorf("partnerauth: resolved temporary principal scopes: %w", err)
	}
	if a.Status != TemporaryPrincipalStatusActive && a.Status != TemporaryPrincipalStatusDisabled {
		return TemporaryPrincipalAuthorization{}, fmt.Errorf("partnerauth: resolved temporary principal has unknown status %q", a.Status)
	}
	if a.ExpiresAt == nil {
		return TemporaryPrincipalAuthorization{}, fmt.Errorf("partnerauth: resolved temporary principal authorization missing expires_at")
	}
	return TemporaryPrincipalAuthorization{
		TemporaryPrincipalID: a.TemporaryPrincipalID,
		PartnerID:            a.PartnerID,
		Scopes:               scopes,
		Status:               a.Status,
		ExpiresAt:            a.ExpiresAt,
	}, nil
}
