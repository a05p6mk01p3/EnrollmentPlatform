package runtime

import (
	"errors"
	"fmt"
	"sort"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
)

// MissingAuthenticatorError reports a CredentialKind referenced by the
// compiled authentication policy that has no runtime component registered.
// For bearer kinds the missing component is the scheme-specific Authenticator;
// for DeviceMTLS it is either the Authenticator or the trusted-proxy
// DeviceMTLSSource (M4.5): without the source the DeviceMTLS kind can never
// authenticate, so the boundary is absent rather than merely unreachable.
//
// It is a construction-time integrity error, not an HTTP error type. It never
// carries credential material.
type MissingAuthenticatorError struct {
	Kind authpolicy.CredentialKind
}

func (e *MissingAuthenticatorError) Error() string {
	return fmt.Sprintf("runtime: no authenticator registered for credential kind %q", e.Kind)
}

// ValidateRegistry is the M4.6 startup integrity check. It verifies that
// every CredentialKind referenced by the compiled policy — across every base
// security alternative and every conditional x-security-conditions case — has
// a registered runtime component.
//
//   - A referenced bearer kind must have an Authenticator in the registry.
//   - A referenced DeviceMTLS kind must have an Authenticator AND a non-nil
//     DeviceMTLSSource; without the trusted-proxy source the kind can never
//     authenticate and its absence must be an explicit error, never a silent
//     fallback to another credential mechanism.
//
// A component is considered present only when it is interface-non-nil AND its
// underlying concrete value is non-nil (SOL-M4.6-003): a typed-nil
// Authenticator or DeviceMTLSSource is treated exactly like an absent
// component. This check does not rely on NewRegistry having rejected bad
// entries; it re-validates independently at the startup boundary.
//
// An intentionally unavailable mechanism — for example, a mechanism whose
// bootstrap/verification lies outside the current protocol — is represented by
// an explicit fail-closed adapter that is still REGISTERED (so the branch is
// present and validation passes); genuine absence of the entry itself is what
// this check rejects. The distinction is what prevents a "scheme mentioned by
// the contract but silently absent at runtime" path.
func ValidateRegistry(compiled *authpolicy.Policy, registry *Registry, device DeviceMTLSSource) error {
	if compiled == nil {
		return errors.New("runtime: nil compiled authentication policy")
	}
	if registry == nil {
		return errors.New("runtime: nil authenticator registry")
	}

	for _, kind := range referencedKinds(compiled) {
		a, ok := registry.Get(kind)
		if !ok || isNilLike(a) {
			return &MissingAuthenticatorError{Kind: kind}
		}
		if kind == authpolicy.CredentialKindDeviceMTLS && isNilLike(device) {
			return &MissingAuthenticatorError{Kind: kind}
		}
	}
	return nil
}

// referencedKinds is the union of every CredentialKind the compiled policy can
// require, in deterministic order. It walks both the base alternatives and the
// conditional cases: even though the current compiler guarantees conditional
// cases are singleton alternatives of the base security, the union keeps the
// validation correct if that guarantee ever changes.
func referencedKinds(compiled *authpolicy.Policy) []authpolicy.CredentialKind {
	set := make(map[authpolicy.CredentialKind]struct{})
	for _, op := range compiled.Operations() {
		for _, alt := range op.Alternatives() {
			for _, k := range alt.Kinds() {
				set[k] = struct{}{}
			}
		}
		if cond := op.Conditional(); cond != nil {
			for _, c := range cond.Cases() {
				for _, k := range c.Requirement().Kinds() {
					set[k] = struct{}{}
				}
			}
		}
	}
	out := make([]authpolicy.CredentialKind, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
