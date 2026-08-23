package runtime

// Decision is the explicit typed outcome of an authorization evaluation.
// The zero value is DecisionDenied: fail closed by default.
type Decision int

const (
	// DecisionDenied means the principal is explicitly not authorized.
	DecisionDenied Decision = iota

	// DecisionAllowed means the principal is explicitly authorized.
	DecisionAllowed

	// DecisionIndeterminate means the evaluator could not reach a decision
	// (e.g. dependency unavailable, internal error, or unresolvable state).
	// The runtime fails closed and never treats this as allowed.
	DecisionIndeterminate
)

func (d Decision) String() string {
	switch d {
	case DecisionDenied:
		return "DENIED"
	case DecisionAllowed:
		return "ALLOWED"
	case DecisionIndeterminate:
		return "INDETERMINATE"
	default:
		return "UNKNOWN"
	}
}
