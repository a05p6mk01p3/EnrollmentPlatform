package enrollment

// State is the closed set of normative enrollment states defined by the
// Enrollment Protocol Specification v0.2.2 §9.2.
//
// ATTESTATION_VERIFIED and CREATED are intentionally NOT states of this type:
// the first is an internal milestone/event and the second is not observable
// (Protocol v0.2.2 §9.2).
type State string

const (
	// Main sequence (Protocol v0.2.2 §9.2).
	StateChallengeIssued  State = "CHALLENGE_ISSUED"
	StateEvidenceReceived State = "EVIDENCE_RECEIVED"
	StateAuthorized       State = "AUTHORIZED"
	StateCARequested      State = "CA_REQUESTED"
	StateCertIssued       State = "CERT_ISSUED"
	StateCertDelivered    State = "CERT_DELIVERED"
	StateDeviceActivated  State = "DEVICE_ACTIVATED"
	StateCompleted        State = "COMPLETED"

	// Terminal/error states (Protocol v0.2.2 §9.2).
	StateRejected            State = "REJECTED"
	StateExpired             State = "EXPIRED"
	StateCAFailed            State = "CA_FAILED"
	StateInstallFailed       State = "INSTALL_FAILED"
	StateAborted             State = "ABORTED"
	StateCertWithheldRevoked State = "CERT_WITHHELD_REVOKED"
)

// terminalStates are the states from which no transition is allowed
// (Protocol v0.2.2 §9.2).
var terminalStates = map[State]struct{}{
	StateCompleted:           {},
	StateRejected:            {},
	StateExpired:             {},
	StateCAFailed:            {},
	StateInstallFailed:       {},
	StateAborted:             {},
	StateCertWithheldRevoked: {},
}

// Valid reports whether s is one of the normative states. Any other value is
// invalid and must fail closed (Protocol v0.2.2 §9.2).
func (s State) Valid() bool {
	switch s {
	case StateChallengeIssued,
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
		StateCertWithheldRevoked:
		return true
	default:
		return false
	}
}

// IsTerminal reports whether s is a terminal/error state from which no
// transition is allowed (Protocol v0.2.2 §9.2).
func (s State) IsTerminal() bool {
	_, ok := terminalStates[s]
	return ok
}

// String returns the state as its protocol wire value.
func (s State) String() string { return string(s) }

// canTransition reports whether the state machine allows moving from -> to.
//
// Transition matrix per Protocol v0.2.2 §22 "Transicoes e pre-condicoes
// essenciais" and the §9.2 sequence. Unknown and terminal states have no
// outgoing edges (fail closed).
func canTransition(from, to State) bool {
	switch from {
	case StateChallengeIssued:
		return to == StateEvidenceReceived
	case StateEvidenceReceived:
		return to == StateAuthorized || to == StateRejected
	case StateAuthorized:
		return to == StateCARequested
	case StateCARequested:
		return to == StateCertIssued
	case StateCertIssued:
		return to == StateCertDelivered || to == StateCertWithheldRevoked
	case StateCertDelivered:
		return to == StateDeviceActivated
	case StateDeviceActivated:
		return to == StateCompleted
	default:
		return false
	}
}
