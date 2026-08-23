package partnerauth

// SelectionDecision is the typed outcome of partner/scope selection.
//
// The zero value is SelectionIndeterminate: fail closed by default, so a naive
// or buggy selector can never allow by accident.
type SelectionDecision int

const (
	// SelectionIndeterminate means the effective authorization could not be
	// established deterministically (dependency unavailable, malformed or
	// ambiguous provider result). Callers fail closed.
	SelectionIndeterminate SelectionDecision = iota

	// SelectionDeniedPartner means the requested partner is not present in the
	// current effective authorization set (or, for a Temporary Principal, its
	// local authorization is not currently effective for that partner).
	SelectionDeniedPartner

	// SelectionDeniedScope means the requested partner is present but does not
	// include the required partner-scoped permission.
	SelectionDeniedScope

	// SelectionAllowed means the requested partner is authorized with the
	// required partner-scoped permission.
	SelectionAllowed
)

func (d SelectionDecision) String() string {
	switch d {
	case SelectionIndeterminate:
		return "INDETERMINATE"
	case SelectionDeniedPartner:
		return "DENY_PARTNER"
	case SelectionDeniedScope:
		return "DENY_SCOPE"
	case SelectionAllowed:
		return "ALLOW"
	default:
		return "UNKNOWN"
	}
}
