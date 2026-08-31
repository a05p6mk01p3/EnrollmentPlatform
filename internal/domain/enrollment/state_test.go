package enrollment

import "testing"

// allStates lists every normative state (Protocol v0.2.2 §9.2).
var allStates = []State{
	StateChallengeIssued,
	StateEvidenceReceived,
	StateAuthorized,
	StateCARequested,
	StateCertIssued,
	StateCertDelivered,
	StateDeviceActivated,
	StateCompleted,
	StateRejected,
	StateExpired,
	StateCAFailed,
	StateInstallFailed,
	StateAborted,
	StateCertWithheldRevoked,
}

func TestStateValidity(t *testing.T) {
	for _, s := range allStates {
		if !s.Valid() {
			t.Errorf("State %s must be valid", s)
		}
		if s.String() != string(s) {
			t.Errorf("State %s String() = %q", s, s.String())
		}
	}

	// CREATED and ATTESTATION_VERIFIED are intentionally NOT states
	// (Protocol v0.2.2 §9.2).
	invalid := []State{"", "BOGUS", "CREATED", "ATTESTATION_VERIFIED", "challenge_issued", "Challenge_Issued"}
	for _, s := range invalid {
		if s.Valid() {
			t.Errorf("State %q must be invalid (fail closed)", s)
		}
		if s.IsTerminal() {
			t.Errorf("invalid state %q must not be terminal", s)
		}
	}
}

func TestTerminalStates(t *testing.T) {
	terminal := map[State]bool{}
	for _, s := range terminalStatesList {
		terminal[s] = true
	}
	if len(terminalStatesList) != 7 {
		t.Fatalf("expected 7 terminal states, got %d", len(terminalStatesList))
	}
	for _, s := range allStates {
		if got, want := s.IsTerminal(), terminal[s]; got != want {
			t.Errorf("State %s IsTerminal() = %v, want %v", s, got, want)
		}
	}
}

// TestTransitionMatrix locks canTransition to the documented matrix
// (Protocol v0.2.2 §22 and §9.2), including fail-closed behavior for unknown
// states and the absence of outgoing edges from terminal states.
func TestTransitionMatrix(t *testing.T) {
	expected := map[State][]State{
		StateChallengeIssued:  {StateEvidenceReceived},
		StateEvidenceReceived: {StateAuthorized, StateRejected},
		StateAuthorized:       {StateCARequested},
		StateCARequested:      {StateCertIssued},
		StateCertIssued:       {StateCertDelivered, StateCertWithheldRevoked},
		StateCertDelivered:    {StateDeviceActivated},
		StateDeviceActivated:  {StateCompleted},
		// No outgoing edges from any terminal state.
	}

	for _, from := range allStates {
		allowed := map[State]bool{}
		for _, to := range expected[from] {
			allowed[to] = true
		}
		for _, to := range allStates {
			if got, want := canTransition(from, to), allowed[to]; got != want {
				t.Errorf("canTransition(%s, %s) = %v, want %v", from, to, got, want)
			}
		}
	}

	// Unknown source states fail closed against every target.
	for _, from := range []State{"", "BOGUS", "CREATED"} {
		for _, to := range allStates {
			if canTransition(from, to) {
				t.Errorf("canTransition(%q, %s) must be false", from, to)
			}
		}
	}
}

// TestTerminalStatesHaveNoOutgoingEdges cross-checks the matrix for terminal
// states (Protocol v0.2.2 §9.2).
func TestTerminalStatesHaveNoOutgoingEdges(t *testing.T) {
	for _, from := range terminalStatesList {
		for _, to := range allStates {
			if canTransition(from, to) {
				t.Errorf("terminal state %s must not transition to %s", from, to)
			}
		}
	}
}
