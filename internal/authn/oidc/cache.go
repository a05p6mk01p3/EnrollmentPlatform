package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Sentinel errors distinguishing key-resolution outcomes. They carry no key
// material or token content.
var (
	// errKeyNotFound means the trusted key set was successfully loaded but
	// does not contain a compatible verification key for the requested kid.
	// It maps to a Rejected (401) outcome.
	errKeyNotFound = errors.New("oidc: no compatible verification key")

	// errAmbiguousKeys means the trusted key set is malformed or ambiguous in
	// a way that prevents safe verification (duplicate kid, no kid with
	// multiple keys, or an empty set). It maps to an Indeterminate (503)
	// outcome.
	errAmbiguousKeys = errors.New("oidc: ambiguous or malformed verification key set")
)

// errMalformedKeySet marks trusted key material that is malformed/unusable
// (including a nil set returned with a nil error). It maps to Indeterminate.
var errMalformedKeySet = errors.New("oidc: malformed trusted key material")

// verificationKey is an OWNED, immutable snapshot of the trusted key material
// needed for verification. It aliases nothing from the key source: the key
// itself is a serialization/parse deep copy and the metadata is copied into
// plain values at snapshot time. Nothing outside the cache ever receives a
// mutable reference to it.
//
// Metadata PRESENCE is preserved explicitly (SOL-M4.4-001): an absent field
// is never collapsed into the same representation as a field that is present
// but empty.
type verificationKey struct {
	kid           string // JWK kid ("" when absent)
	alg           string // JWK alg metadata
	algPresent    bool
	use           string // JWK use metadata
	usePresent    bool
	keyOps        []string // JWK key_ops metadata
	keyOpsPresent bool
	key           jwk.Key // owned, detached public verification key
}

// snapshotKey deep-copies a trusted JWK into an owned verificationKey. It
// strips private material (only public verification material belongs here)
// and re-parses the serialized key so no alias to the source-owned object
// remains.
func snapshotKey(key jwk.Key) (verificationKey, error) {
	pub, err := jwk.PublicKeyOf(key)
	if err != nil {
		return verificationKey{}, err
	}
	data, err := json.Marshal(pub)
	if err != nil {
		return verificationKey{}, err
	}
	detached, err := jwk.ParseKey(data)
	if err != nil {
		return verificationKey{}, err
	}

	snap := verificationKey{key: detached}
	if kid, ok := key.KeyID(); ok {
		snap.kid = kid
	}
	if alg, ok := key.Algorithm(); ok {
		snap.algPresent = true
		snap.alg = alg.String()
	}
	if use, ok := key.KeyUsage(); ok {
		snap.usePresent = true
		snap.use = use
	}
	if ops, ok := key.KeyOps(); ok {
		snap.keyOpsPresent = true
		snap.keyOps = make([]string, 0, len(ops))
		for _, op := range ops {
			snap.keyOps = append(snap.keyOps, string(op))
		}
	}
	return snap, nil
}

// snapshotSet converts a freshly loaded trusted key set into owned immutable
// snapshots. A nil or TYPED-NIL set returned with a nil error is malformed
// trusted material and fails closed (SOL-M4.4-005) — the guard runs before any
// method call on the set, so a typed-nil interface (e.g. a nil pointer
// implementation) can never panic.
func snapshotSet(set jwk.Set) ([]verificationKey, error) {
	if isNilInterfaceValue(set) {
		return nil, errMalformedKeySet
	}
	out := make([]verificationKey, 0, set.Len())
	for i := 0; i < set.Len(); i++ {
		key, _ := set.Key(i)
		snap, err := snapshotKey(key)
		if err != nil {
			return nil, err
		}
		out = append(out, snap)
	}
	return out, nil
}

// keyCache is a provider-neutral, bounded, issuer-namespaced key snapshot
// cache with at-most-one-refresh semantics per resolve.
//
// Ownership (SOL-M4.4-002): a keyCache is created by a Verifier and bound to
// exactly one immutable ProviderConfig/KeySetSource. It is not exported and
// cannot be shared across provider configurations, so trusted key material
// can never cross a provider-configuration boundary merely because issuer
// strings match.
//
// Snapshot isolation (SOL-M4.4-003): cached state consists only of owned
// verificationKey snapshots; mutations of the source-owned jwk.Set/jwk.Key
// after LoadKeys returns cannot change trusted state.
//
// The cache is race-safe and coalesces concurrent loads behind a single lock
// (no uncontrolled refresh storm).
type keyCache struct {
	source KeySetSource
	ttl    time.Duration
	clock  Clock

	mu      sync.Mutex
	entries map[string]*cacheEntry // keyed by trusted issuer
}

// cacheEntry is a cached key snapshot and its load time.
type cacheEntry struct {
	keys     []verificationKey
	loadedAt time.Time
}

// newKeyCache builds a key cache over the given source, TTL and clock. A nil
// clock defaults to the system clock. Unexported: only a Verifier constructs
// its own cache.
func newKeyCache(source KeySetSource, ttl time.Duration, clock Clock) *keyCache {
	if clock == nil {
		clock = systemClock{}
	}
	return &keyCache{
		source:  source,
		ttl:     ttl,
		clock:   clock,
		entries: map[string]*cacheEntry{},
	}
}

// Resolve returns the owned verification-key snapshot for the given kid, using
// the cached snapshot when valid and otherwise performing exactly one
// controlled refresh.
//
// Outcomes:
//   - cached key found -> returned without any refresh;
//   - kid missing from cache -> exactly one refresh, then key selected;
//   - refresh succeeds but kid still missing -> errKeyNotFound (Rejected);
//   - refresh dependency fails -> the source error (Indeterminate);
//   - ambiguous/malformed key set -> errAmbiguousKeys (Indeterminate).
func (c *keyCache) Resolve(ctx context.Context, config *ProviderConfig, kid string) (*verificationKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.entries[config.Issuer()]; ok && c.clock.Now().Before(entry.loadedAt.Add(c.ttl)) {
		if key, err := selectSnapshot(entry.keys, kid); err == nil {
			return key, nil
		}
		// Kid not present in the fresh cache (or ambiguous): fall through to
		// exactly one controlled refresh below.
	}

	set, err := c.source.LoadKeys(ctx, config)
	if err != nil {
		return nil, err
	}
	snapshots, err := snapshotSet(set)
	if err != nil {
		return nil, err
	}
	c.entries[config.Issuer()] = &cacheEntry{keys: snapshots, loadedAt: c.clock.Now()}
	return selectSnapshot(snapshots, kid)
}

// selectSnapshot deterministically selects a single verification-key snapshot
// by kid from an owned, immutable snapshot slice. Selection is bounded and
// fail-closed:
//   - a single snapshot matching the kid is returned;
//   - duplicate matching kids, an empty set, or no-kid with multiple keys are
//     ambiguous (errAmbiguousKeys);
//   - a kid with no matching key is errKeyNotFound.
func selectSnapshot(keys []verificationKey, kid string) (*verificationKey, error) {
	if kid == "" {
		switch len(keys) {
		case 0:
			return nil, errAmbiguousKeys
		case 1:
			return &keys[0], nil
		default:
			return nil, errAmbiguousKeys
		}
	}

	var matches []*verificationKey
	for i := range keys {
		if keys[i].kid == kid {
			matches = append(matches, &keys[i])
		}
	}
	if len(matches) == 0 {
		return nil, errKeyNotFound
	}
	if len(matches) > 1 {
		return nil, errAmbiguousKeys
	}
	return matches[0], nil
}
