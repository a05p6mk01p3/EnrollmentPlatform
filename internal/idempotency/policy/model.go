// Package policy compiles the idempotency metadata declared in the canonical
// OpenAPI specification into an immutable, read-only, validated representation
// for the idempotency/replay-safety runtime (M5.4).
//
// It answers exactly one question: "which operations are idempotent, and which
// of those carry secret-replay protection metadata?" It does NOT reserve,
// commit, replay, seal, open, authenticate, authorize, or mutate anything.
//
// The compiled policy is derived only from the canonical spec returned by
// openapi.GetSpec(). The canonical spec object is never mutated.
package policy

// SecretReplay is the compiled x-idempotent-secret-replay metadata for an
// originator operation. All fields are immutable value strings/bool and are
// preserved exactly as declared by the OpenAPI contract.
type SecretReplay struct {
	// SecretField names the response field carrying the originator secret
	// that may be replayed only through the protected Replay Capsule.
	SecretField string

	// Mechanism is the contracted replay protection mechanism.
	Mechanism string

	// SameSecretRequired records whether replay must reproduce the exact
	// original secret rather than minting a replacement.
	SameSecretRequired bool

	// ActiveVerifierStorage records the contracted storage posture for the
	// active token verifier (non-reversible for the current contract).
	ActiveVerifierStorage string

	// CapsulePurpose records the contracted purpose of the Replay Capsule.
	CapsulePurpose string
}

// Operation is the compiled idempotency policy for a single operation. It is
// immutable and safe for concurrent reads.
type Operation struct {
	operationID  string
	method       string
	route        string
	keyRequired  bool
	secretReplay *SecretReplay
}

// OperationID returns the operation's unique operationId.
func (p *Operation) OperationID() string { return p.operationID }

// Method returns the canonical uppercase HTTP method (for diagnostics).
func (p *Operation) Method() string { return p.method }

// Route returns the canonical OpenAPI route template (for diagnostics and
// effective-scope construction by a future route adapter).
func (p *Operation) Route() string { return p.route }

// KeyRequired reports whether the canonical contract declares the
// Idempotency-Key parameter as required on this operation.
func (p *Operation) KeyRequired() bool { return p.keyRequired }

// IsSecretReplay reports whether the operation carries
// x-idempotent-secret-replay metadata.
func (p *Operation) IsSecretReplay() bool { return p.secretReplay != nil }

// SecretReplayMetadata returns a copy of the secret-replay metadata, or
// ok=false when the operation carries none.
func (p *Operation) SecretReplayMetadata() (SecretReplay, bool) {
	if p.secretReplay == nil {
		return SecretReplay{}, false
	}
	return *p.secretReplay, true
}

// Policy is the compiled, immutable, read-only idempotency policy for all
// operations, indexed by operationId. It is safe for concurrent reads and
// exposes no mutable state.
type Policy struct {
	byID       map[string]*Operation
	operations []*Operation // sorted by operationId
}

// Operation returns the compiled policy for an operationId, or ok=false.
func (p *Policy) Operation(operationID string) (*Operation, bool) {
	op, ok := p.byID[operationID]
	return op, ok
}

// Operations returns a defensive copy of all compiled policies in
// deterministic (operationId-sorted) order. Only idempotent operations are
// included; non-idempotent operations are not part of this policy.
func (p *Policy) Operations() []*Operation {
	return append([]*Operation(nil), p.operations...)
}

// OperationCount returns the number of compiled idempotent operations.
func (p *Policy) OperationCount() int { return len(p.operations) }

// SecretReplayCount returns the number of compiled operations carrying
// x-idempotent-secret-replay metadata.
func (p *Policy) SecretReplayCount() int {
	n := 0
	for _, op := range p.operations {
		if op.IsSecretReplay() {
			n++
		}
	}
	return n
}
