package enrollment

import "fmt"

// TransitionError reports an attempted state transition that the enrollment
// state machine does not allow. The application layer can distinguish it via
// errors.As without parsing message text.
type TransitionError struct {
	From State
	To   State
}

func (e *TransitionError) Error() string {
	return fmt.Sprintf("enrollment: invalid state transition %s -> %s", e.From, e.To)
}

// InvalidStateError reports a state value that is not part of the normative
// state set (Protocol v0.2.2 §9.2). It is always a fail-closed condition.
type InvalidStateError struct {
	State State
}

func (e *InvalidStateError) Error() string {
	return fmt.Sprintf("enrollment: invalid state %q", string(e.State))
}
