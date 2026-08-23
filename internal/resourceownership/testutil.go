package resourceownership

import (
	"context"
	"sync"
)

// StaticPreOnboardingOwnershipResolver is a deterministic test double for
// PreOnboardingOwnershipResolver.
type StaticPreOnboardingOwnershipResolver struct {
	Resolve func(ctx context.Context, id string) (OwnershipResult, error)
}

// ResolvePreOnboardingOwnership invokes Resolve, or returns NOT_FOUND if nil.
func (s StaticPreOnboardingOwnershipResolver) ResolvePreOnboardingOwnership(ctx context.Context, id string) (OwnershipResult, error) {
	if s.Resolve == nil {
		return OwnershipNotFound(), nil
	}
	return s.Resolve(ctx, id)
}

// SpyPreOnboardingOwnershipResolver records every lookup call and returns
// configured results.
type SpyPreOnboardingOwnershipResolver struct {
	mu    sync.Mutex
	calls map[string]int
	fn    func(ctx context.Context, id string) (OwnershipResult, error)
}

// NewSpyPreOnboardingOwnershipResolver constructs a thread-safe spy resolver.
func NewSpyPreOnboardingOwnershipResolver(fn func(ctx context.Context, id string) (OwnershipResult, error)) *SpyPreOnboardingOwnershipResolver {
	return &SpyPreOnboardingOwnershipResolver{
		calls: make(map[string]int),
		fn:    fn,
	}
}

// ResolvePreOnboardingOwnership records the call and delegates to fn.
func (s *SpyPreOnboardingOwnershipResolver) ResolvePreOnboardingOwnership(ctx context.Context, id string) (OwnershipResult, error) {
	s.mu.Lock()
	if s.calls == nil {
		s.calls = make(map[string]int)
	}
	s.calls[id]++
	s.mu.Unlock()

	if s.fn != nil {
		return s.fn(ctx, id)
	}
	return OwnershipNotFound(), nil
}

// Count returns the total number of calls for a specific resource ID.
func (s *SpyPreOnboardingOwnershipResolver) Count(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[id]
}

// Total returns the total number of calls across all resource IDs.
func (s *SpyPreOnboardingOwnershipResolver) Total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		n += c
	}
	return n
}
