// Package recovery provides the narrow read-only recognition boundary for a
// consumed RequestAccessToken used in exact createEnrollment response-loss
// recovery. It is deliberately separate from ordinary M4 authentication,
// which continues to reject consumed capabilities.
package recovery

import (
	"context"
	"errors"
	"reflect"
	"strings"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
)

var (
	// ErrNotRecognized means the presented credential is not a retained
	// consumed RequestAccess capability. It grants no authentication or replay
	// authority by itself.
	ErrNotRecognized = errors.New("enrollment recovery: consumed request access not recognized")

	// ErrDependencyUnavailable means verifier/store state is indeterminate.
	ErrDependencyUnavailable = errors.New("enrollment recovery: dependency unavailable")
)

// Proof is a typed, non-secret recognition result. Its fields are private so
// unrelated code cannot construct a non-zero proof without this package.
// Proof establishes possession/binding only; exact idempotency scope,
// fingerprint, current authorization, and Replay Capsule checks remain the
// responsibility of the enrollment application operation.
type Proof struct {
	requestID string
	key       capability.VerifierKey
}

func (p Proof) RequestID() string { return p.requestID }
func (p Proof) IsZero() bool      { return p.requestID == "" || p.key == "" }

// Matches verifies that this proof still names the exact retained verifier
// record resolved by the application UoW. It exposes no verifier bytes and
// prevents a request-id-only proof from surviving an unexpected verifier
// replacement between recognition and recovery execution.
func (p Proof) Matches(requestID string, key capability.VerifierKey) bool {
	return !p.IsZero() && p.requestID == requestID && p.key == key
}

// Recognizer verifies possession of a retained CONSUMED RequestAccessToken
// using the same non-reversible verifier namespace as M4, but it does not
// authenticate the token for ordinary use and performs no lifecycle mutation.
type Recognizer struct {
	verifier capability.Verifier
	store    capability.Store
}

func NewRecognizer(verifier capability.Verifier, store capability.Store) (*Recognizer, error) {
	if nilLike(verifier) || nilLike(store) {
		return nil, ErrDependencyUnavailable
	}
	return &Recognizer{verifier: verifier, store: store}, nil
}

// Validate checks that the recognition boundary is structurally wired. It does
// not perform a credential lookup and therefore has no request-time side effect.
func (r *Recognizer) Validate() error {
	if r == nil || nilLike(r.verifier) || nilLike(r.store) {
		return ErrDependencyUnavailable
	}
	return nil
}

// Recognize returns a Proof only for an exact retained CONSUMED verifier
// record. Expiry of the original RequestAccessToken is intentionally not a
// rejection here: Protocol §6.3 permits recovery of an operation committed
// before credential expiry while its idempotency/capsule recovery window is
// still valid. The enrollment application enforces those recovery windows.
func (r *Recognizer) Recognize(ctx context.Context, bearer string) (Proof, error) {
	if r == nil || r.verifier == nil || r.store == nil {
		return Proof{}, ErrDependencyUnavailable
	}
	if strings.TrimSpace(bearer) == "" {
		return Proof{}, ErrNotRecognized
	}
	key, err := r.verifier.Derive(authpolicy.CredentialKindRequestAccessToken, bearer)
	if err != nil {
		return Proof{}, ErrDependencyUnavailable
	}
	rec, err := r.store.LookupRequestAccess(ctx, key)
	if errors.Is(err, capability.ErrNotFound) {
		return Proof{}, ErrNotRecognized
	}
	if err != nil {
		return Proof{}, ErrDependencyUnavailable
	}
	if rec == nil || rec.State != capability.StateConsumed {
		return Proof{}, ErrNotRecognized
	}
	if strings.TrimSpace(rec.PreOnboardingRequestID) == "" {
		return Proof{}, ErrDependencyUnavailable
	}
	return Proof{requestID: rec.PreOnboardingRequestID, key: key}, nil
}

func nilLike(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}
