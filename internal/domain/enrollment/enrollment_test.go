package enrollment

import (
	"errors"
	"reflect"
	"sort"
	"testing"
)

// mutation is one public transition method of Enrollment.
type mutation struct {
	name string
	run  func(*Enrollment) error
}

// mutations lists every public transition method, in main-sequence order.
var mutations = []mutation{
	{"AcceptEvidence", func(e *Enrollment) error { return e.AcceptEvidence() }},
	{"Authorize", func(e *Enrollment) error { return e.Authorize() }},
	{"Reject", func(e *Enrollment) error { return e.Reject() }},
	{"MarkCARequested", func(e *Enrollment) error { return e.MarkCARequested() }},
	{"MarkCertificateIssued", func(e *Enrollment) error { return e.MarkCertificateIssued() }},
	{"MarkDelivered", func(e *Enrollment) error { return e.MarkDelivered() }},
	{"MarkWithheldRevoked", func(e *Enrollment) error { return e.MarkWithheldRevoked() }},
	{"MarkActivated", func(e *Enrollment) error { return e.MarkActivated() }},
	{"MarkCompleted", func(e *Enrollment) error { return e.MarkCompleted() }},
}

// happyPathSteps is the §9.2 main sequence without the withhold branch.
var happyPathSteps = []mutation{
	{"AcceptEvidence", func(e *Enrollment) error { return e.AcceptEvidence() }},
	{"Authorize", func(e *Enrollment) error { return e.Authorize() }},
	{"MarkCARequested", func(e *Enrollment) error { return e.MarkCARequested() }},
	{"MarkCertificateIssued", func(e *Enrollment) error { return e.MarkCertificateIssued() }},
	{"MarkDelivered", func(e *Enrollment) error { return e.MarkDelivered() }},
	{"MarkActivated", func(e *Enrollment) error { return e.MarkActivated() }},
	{"MarkCompleted", func(e *Enrollment) error { return e.MarkCompleted() }},
}

// terminalStatesList mirrors Protocol v0.2.2 §9.2 terminal/error states.
var terminalStatesList = []State{
	StateCompleted,
	StateRejected,
	StateExpired,
	StateCAFailed,
	StateInstallFailed,
	StateAborted,
	StateCertWithheldRevoked,
}

func restored(t *testing.T, state State) *Enrollment {
	t.Helper()
	e, err := RestoreEnrollment(EnrollmentID("enr-test"), state)
	if err != nil {
		t.Fatalf("RestoreEnrollment(%s) failed: %v", state, err)
	}
	return e
}

func requireTransitionError(t *testing.T, err error) *TransitionError {
	t.Helper()
	var te *TransitionError
	if !errors.As(err, &te) {
		t.Fatalf("want *TransitionError, got %T (%v)", err, err)
	}
	return te
}

// A. Full main sequence (Protocol v0.2.2 §9.2).
func TestHappyPathSequence(t *testing.T) {
	e := NewEnrollment(EnrollmentID("enr-1"))
	if got := e.State(); got != StateChallengeIssued {
		t.Fatalf("initial state = %s, want %s", got, StateChallengeIssued)
	}

	want := []State{
		StateEvidenceReceived,
		StateAuthorized,
		StateCARequested,
		StateCertIssued,
		StateCertDelivered,
		StateDeviceActivated,
		StateCompleted,
	}
	for i, m := range happyPathSteps {
		if err := m.run(e); err != nil {
			t.Fatalf("step %d (%s): %v", i, m.name, err)
		}
		if got := e.State(); got != want[i] {
			t.Fatalf("step %d (%s): state = %s, want %s", i, m.name, got, want[i])
		}
	}
}

// B. Each valid step individually, from a restored source state
// (Protocol v0.2.2 §22 transition table).
func TestIndividualValidSteps(t *testing.T) {
	cases := []struct {
		name   string
		from   State
		method func(*Enrollment) error
		to     State
		proto  string
	}{
		{"challenge to evidence", StateChallengeIssued, (*Enrollment).AcceptEvidence, StateEvidenceReceived, "§10.2, §22"},
		{"evidence to authorized", StateEvidenceReceived, (*Enrollment).Authorize, StateAuthorized, "§22"},
		{"authorized to ca requested", StateAuthorized, (*Enrollment).MarkCARequested, StateCARequested, "§11.1, §22"},
		{"ca requested to cert issued", StateCARequested, (*Enrollment).MarkCertificateIssued, StateCertIssued, "§22"},
		{"cert issued to delivered", StateCertIssued, (*Enrollment).MarkDelivered, StateCertDelivered, "§11.3, §22"},
		{"cert issued to withheld revoked", StateCertIssued, (*Enrollment).MarkWithheldRevoked, StateCertWithheldRevoked, "§11.3, §21.2, §22"},
		{"delivered to activated", StateCertDelivered, (*Enrollment).MarkActivated, StateDeviceActivated, "§12.1, §9.2"},
		{"activated to completed", StateDeviceActivated, (*Enrollment).MarkCompleted, StateCompleted, "§12.2, §9.2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := restored(t, tc.from)
			if err := tc.method(e); err != nil {
				t.Fatalf("transition from %s: %v (protocol %s)", tc.from, err, tc.proto)
			}
			if got := e.State(); got != tc.to {
				t.Fatalf("state = %s, want %s", got, tc.to)
			}
		})
	}
}

// C. Invalid jumps must fail with *TransitionError and leave the state
// unchanged. (Protocol v0.2.2 §9.2, §22: no skips in the main sequence.)
func TestInvalidJumpsRejected(t *testing.T) {
	cases := []struct {
		name   string
		from   State
		method func(*Enrollment) error
	}{
		{"challenge->authorize", StateChallengeIssued, (*Enrollment).Authorize},
		{"challenge->caRequested", StateChallengeIssued, (*Enrollment).MarkCARequested},
		{"challenge->certIssued", StateChallengeIssued, (*Enrollment).MarkCertificateIssued},
		{"challenge->delivered", StateChallengeIssued, (*Enrollment).MarkDelivered},
		{"challenge->withheld", StateChallengeIssued, (*Enrollment).MarkWithheldRevoked},
		{"challenge->activated", StateChallengeIssued, (*Enrollment).MarkActivated},
		{"challenge->completed", StateChallengeIssued, (*Enrollment).MarkCompleted},
		{"evidence->acceptAgain", StateEvidenceReceived, (*Enrollment).AcceptEvidence},
		{"evidence->caRequested", StateEvidenceReceived, (*Enrollment).MarkCARequested},
		{"evidence->certIssued", StateEvidenceReceived, (*Enrollment).MarkCertificateIssued},
		{"evidence->delivered", StateEvidenceReceived, (*Enrollment).MarkDelivered},
		{"evidence->activated", StateEvidenceReceived, (*Enrollment).MarkActivated},
		{"evidence->completed", StateEvidenceReceived, (*Enrollment).MarkCompleted},
		{"authorized->evidence", StateAuthorized, (*Enrollment).AcceptEvidence},
		{"authorized->authorizeAgain", StateAuthorized, (*Enrollment).Authorize},
		{"authorized->certIssued", StateAuthorized, (*Enrollment).MarkCertificateIssued},
		{"authorized->delivered", StateAuthorized, (*Enrollment).MarkDelivered},
		{"authorized->activated", StateAuthorized, (*Enrollment).MarkActivated},
		{"authorized->completed", StateAuthorized, (*Enrollment).MarkCompleted},
		{"caRequested->delivered", StateCARequested, (*Enrollment).MarkDelivered},
		{"caRequested->withheld", StateCARequested, (*Enrollment).MarkWithheldRevoked},
		{"caRequested->activated", StateCARequested, (*Enrollment).MarkActivated},
		{"caRequested->completed", StateCARequested, (*Enrollment).MarkCompleted},
		{"certIssued->authorize", StateCertIssued, (*Enrollment).Authorize},
		{"certIssued->caRequested", StateCertIssued, (*Enrollment).MarkCARequested},
		{"certIssued->activated", StateCertIssued, (*Enrollment).MarkActivated},
		{"certIssued->completed", StateCertIssued, (*Enrollment).MarkCompleted},
		{"delivered->completedDirect", StateCertDelivered, (*Enrollment).MarkCompleted},
		{"delivered->deliveredAgain", StateCertDelivered, (*Enrollment).MarkDelivered},
		{"delivered->withheld", StateCertDelivered, (*Enrollment).MarkWithheldRevoked},
		{"activated->activatedAgain", StateDeviceActivated, (*Enrollment).MarkActivated},
		{"activated->delivered", StateDeviceActivated, (*Enrollment).MarkDelivered},
		{"activated->withheld", StateDeviceActivated, (*Enrollment).MarkWithheldRevoked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := restored(t, tc.from)
			err := tc.method(e)
			te := requireTransitionError(t, err)
			if te.From != tc.from {
				t.Fatalf("TransitionError.From = %s, want %s", te.From, tc.from)
			}
			if got := e.State(); got != tc.from {
				t.Fatalf("state changed after rejected transition: %s, want %s", got, tc.from)
			}
		})
	}
}

// D. No transition may start from a terminal state (Protocol v0.2.2 §9.2).
func TestNoTransitionFromTerminalState(t *testing.T) {
	for _, from := range terminalStatesList {
		for _, m := range mutations {
			t.Run(from.String()+"/"+m.name, func(t *testing.T) {
				e := restored(t, from)
				err := m.run(e)
				te := requireTransitionError(t, err)
				if te.From != from {
					t.Fatalf("TransitionError.From = %s, want %s", te.From, from)
				}
				if got := e.State(); got != from {
					t.Fatalf("state changed from terminal: %s, want %s", got, from)
				}
			})
		}
	}
}

// E. COMPLETED is terminal.
func TestCompletedIsTerminal(t *testing.T) {
	if !StateCompleted.IsTerminal() {
		t.Fatal("COMPLETED must be terminal")
	}
	e := restored(t, StateCompleted)
	for _, m := range mutations {
		if err := m.run(e); err == nil {
			t.Fatalf("transition %s from COMPLETED must fail", m.name)
		} else {
			requireTransitionError(t, err)
		}
		if got := e.State(); got != StateCompleted {
			t.Fatalf("state left COMPLETED: %s", got)
		}
	}
}

// F. CERT_ISSUED never implies CERT_DELIVERED (Protocol v0.2.2 §11.3).
func TestCertIssuedDoesNotImplyDelivered(t *testing.T) {
	e := restored(t, StateCARequested)
	if err := e.MarkCertificateIssued(); err != nil {
		t.Fatalf("MarkCertificateIssued: %v", err)
	}
	if got := e.State(); got != StateCertIssued {
		t.Fatalf("state = %s, want %s", got, StateCertIssued)
	}
	if got := e.State(); got == StateCertDelivered {
		t.Fatal("CERT_ISSUED must not become CERT_DELIVERED automatically")
	}
	// Delivery requires the explicit post-CA revalidation transition.
	if err := e.MarkDelivered(); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}
	if got := e.State(); got != StateCertDelivered {
		t.Fatalf("state = %s, want %s", got, StateCertDelivered)
	}
}

// G. CERT_ISSUED branches: explicit delivery or explicit withhold-revocation
// (Protocol v0.2.2 §11.3, §21.2, §22).
func TestCertIssuedBranches(t *testing.T) {
	t.Run("deliver", func(t *testing.T) {
		e := restored(t, StateCertIssued)
		if err := e.MarkDelivered(); err != nil {
			t.Fatalf("MarkDelivered: %v", err)
		}
		if got := e.State(); got != StateCertDelivered {
			t.Fatalf("state = %s, want %s", got, StateCertDelivered)
		}
	})

	t.Run("withhold-revoke", func(t *testing.T) {
		e := restored(t, StateCertIssued)
		if err := e.MarkWithheldRevoked(); err != nil {
			t.Fatalf("MarkWithheldRevoked: %v", err)
		}
		if got := e.State(); got != StateCertWithheldRevoked {
			t.Fatalf("state = %s, want %s", got, StateCertWithheldRevoked)
		}
		// Withheld is terminal: it can never become deliverable afterwards.
		err := e.MarkDelivered()
		requireTransitionError(t, err)
		if got := e.State(); got != StateCertWithheldRevoked {
			t.Fatalf("state left CERT_WITHHELD_REVOKED: %s", got)
		}
	})
}

// H. EVIDENCE_RECEIVED -> CA_REQUESTED must fail: AUTHORIZED is the mandatory
// boundary before any CA side effect (Protocol v0.2.2 §11.1; AGENTS.md §3).
func TestEvidenceReceivedToCARequestedRejected(t *testing.T) {
	e := restored(t, StateEvidenceReceived)
	err := e.MarkCARequested()
	te := requireTransitionError(t, err)
	if te.From != StateEvidenceReceived || te.To != StateCARequested {
		t.Fatalf("TransitionError = %+v, want From=EVIDENCE_RECEIVED To=CA_REQUESTED", te)
	}
	if got := e.State(); got != StateEvidenceReceived {
		t.Fatalf("state = %s, want %s", got, StateEvidenceReceived)
	}
}

// I. CA_REQUESTED cannot go back to AUTHORIZED; only CA success moves it
// forward (Protocol v0.2.2 §11.1, §22).
func TestCARequestedCannotReturnToAuthorized(t *testing.T) {
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			e := restored(t, StateCARequested)
			err := m.run(e)
			if err == nil {
				if m.name != "MarkCertificateIssued" {
					t.Fatalf("unexpected transition %s succeeded from CA_REQUESTED", m.name)
				}
				if got := e.State(); got != StateCertIssued {
					t.Fatalf("state = %s, want %s", got, StateCertIssued)
				}
			} else {
				requireTransitionError(t, err)
				if got := e.State(); got != StateCARequested {
					t.Fatalf("state changed after rejected transition: %s, want %s", got, StateCARequested)
				}
			}
			if got := e.State(); got == StateAuthorized {
				t.Fatal("CA_REQUESTED must never return to AUTHORIZED")
			}
		})
	}
}

// J. Unknown/invalid state values fail closed.
func TestUnknownStateFailsClosed(t *testing.T) {
	for _, bad := range []State{"", "BOGUS", "CREATED", "ATTESTATION_VERIFIED", "challenge_issued"} {
		e, err := RestoreEnrollment(EnrollmentID("enr-x"), bad)
		if e != nil {
			t.Fatalf("RestoreEnrollment(%q) returned non-nil enrollment", bad)
		}
		var ise *InvalidStateError
		if !errors.As(err, &ise) {
			t.Fatalf("RestoreEnrollment(%q) error = %T (%v), want *InvalidStateError", bad, err, err)
		}
		if ise.State != bad {
			t.Fatalf("InvalidStateError.State = %q, want %q", ise.State, bad)
		}
	}
}

// K. No public API allows arbitrary state assignment: Enrollment exposes no
// fields, and its exported method set is exactly the transition API.
func TestNoArbitraryStateAssignment(t *testing.T) {
	typ := reflect.TypeOf(Enrollment{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.IsExported() {
			t.Errorf("Enrollment must not expose exported field %q", f.Name)
		}
	}

	got := exportedMethodNames(reflect.TypeOf(&Enrollment{}))
	want := []string{
		"AcceptEvidence",
		"Authorize",
		"ID",
		"MarkActivated",
		"MarkCARequested",
		"MarkCertificateIssued",
		"MarkCompleted",
		"MarkDelivered",
		"MarkWithheldRevoked",
		"Reject",
		"State",
	}
	if len(got) != len(want) {
		t.Fatalf("exported methods = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("exported methods = %v, want %v", got, want)
		}
	}
}

func exportedMethodNames(t reflect.Type) []string {
	var names []string
	for i := 0; i < t.NumMethod(); i++ {
		names = append(names, t.Method(i).Name)
	}
	sort.Strings(names)
	return names
}

// All normative states are restorable for persistence/recovery hydration
// (Protocol v0.2.2 §9.2, §13).
func TestRestoreEnrollmentAllKnownStates(t *testing.T) {
	all := []State{
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
	for _, s := range all {
		e, err := RestoreEnrollment(EnrollmentID("enr-h"), s)
		if err != nil {
			t.Fatalf("RestoreEnrollment(%s): %v", s, err)
		}
		if got := e.State(); got != s {
			t.Fatalf("State() = %s, want %s", got, s)
		}
	}
}

// NewEnrollment starts in CHALLENGE_ISSUED with the provided ID.
func TestNewEnrollmentInitialState(t *testing.T) {
	e := NewEnrollment(EnrollmentID("enr-9"))
	if got := e.ID(); got != EnrollmentID("enr-9") {
		t.Fatalf("ID() = %q", got)
	}
	if got := e.State(); got != StateChallengeIssued {
		t.Fatalf("State() = %s, want %s", got, StateChallengeIssued)
	}
	if e.State().IsTerminal() {
		t.Fatal("CHALLENGE_ISSUED must not be terminal")
	}
}

// Transition errors carry structured From/To without message parsing.
func TestTransitionErrorsAreTyped(t *testing.T) {
	e := restored(t, StateChallengeIssued)
	err := e.MarkCompleted()
	te := requireTransitionError(t, err)
	if te.From != StateChallengeIssued || te.To != StateCompleted {
		t.Fatalf("TransitionError = %+v", te)
	}
}

// L. REJECTED is terminal (Protocol v0.2.7 §22).
func TestRejectedIsTerminal(t *testing.T) {
	e := restored(t, StateRejected)
	if !e.State().IsTerminal() {
		t.Fatal("REJECTED must be terminal")
	}
	// No outgoing transitions.
	for _, m := range mutations {
		err := m.run(e)
		if err == nil {
			t.Fatalf("transition %s succeeded from REJECTED", m.name)
		}
		requireTransitionError(t, err)
		if got := e.State(); got != StateRejected {
			t.Fatalf("state changed after rejected transition from REJECTED: %s, want REJECTED", got)
		}
	}
}

// M. Reject is only valid from EVIDENCE_RECEIVED (Protocol v0.2.7 §22).
func TestRejectValidOrigin(t *testing.T) {
	e := restored(t, StateEvidenceReceived)
	if err := e.Reject(); err != nil {
		t.Fatalf("Reject from EVIDENCE_RECEIVED: %v", err)
	}
	if got := e.State(); got != StateRejected {
		t.Fatalf("state after Reject = %s, want REJECTED", got)
	}
}

// N. Reject from non-EVIDENCE_RECEIVED origins must fail.
func TestRejectForbiddenOrigins(t *testing.T) {
	forbidden := []State{
		StateChallengeIssued,
		StateAuthorized,
		StateCARequested,
		StateCertIssued,
		StateCertDelivered,
		StateDeviceActivated,
		StateCompleted,
		StateExpired,
		StateCAFailed,
		StateInstallFailed,
		StateAborted,
		StateCertWithheldRevoked,
		StateRejected, // already terminal
	}
	for _, from := range forbidden {
		e := restored(t, from)
		err := e.Reject()
		if err == nil {
			t.Fatalf("Reject from %s must fail", from)
		}
		requireTransitionError(t, err)
		if got := e.State(); got != from {
			t.Fatalf("state changed after rejected Reject from %s: %s", from, got)
		}
	}
}

// O. Authorize cannot succeed after rejection.
func TestAuthorizeAfterRejectFails(t *testing.T) {
	e := restored(t, StateEvidenceReceived)
	if err := e.Reject(); err != nil {
		t.Fatal(err)
	}
	err := e.Authorize()
	if err == nil {
		t.Fatal("Authorize after Reject must fail")
	}
	requireTransitionError(t, err)
	if got := e.State(); got != StateRejected {
		t.Fatalf("state = %s, want REJECTED", got)
	}
}

// P. No CA progression from REJECTED.
func TestNoCAProgressionAfterReject(t *testing.T) {
	e := restored(t, StateEvidenceReceived)
	if err := e.Reject(); err != nil {
		t.Fatal(err)
	}
	for _, m := range []struct {
		name string
		fn   func(*Enrollment) error
	}{
		{"MarkCARequested", (*Enrollment).MarkCARequested},
		{"MarkCertificateIssued", (*Enrollment).MarkCertificateIssued},
		{"MarkDelivered", (*Enrollment).MarkDelivered},
	} {
		err := m.fn(e)
		if err == nil {
			t.Fatalf("%s after Reject must fail", m.name)
		}
		requireTransitionError(t, err)
		if got := e.State(); got != StateRejected {
			t.Fatalf("state changed after %s from REJECTED: %s", m.name, got)
		}
	}
}
