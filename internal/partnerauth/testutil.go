package partnerauth

import "context"

// StaticHumanResolver adapts a function to HumanAuthorizationResolver.
type StaticHumanResolver struct {
	Resolve func(ctx context.Context, principal HumanPrincipal) (HumanAuthorizations, error)
}

// ResolveHumanAuthorizations calls the configured function, failing closed
// (dependency unavailable) when none is set.
func (r StaticHumanResolver) ResolveHumanAuthorizations(ctx context.Context, principal HumanPrincipal) (HumanAuthorizations, error) {
	if r.Resolve != nil {
		return r.Resolve(ctx, principal)
	}
	return HumanAuthorizations{}, ErrDependencyUnavailable
}

// StaticTemporaryPrincipalResolver adapts a function to
// TemporaryPrincipalAuthorizationResolver.
type StaticTemporaryPrincipalResolver struct {
	Resolve func(ctx context.Context, id TemporaryPrincipalID) (TemporaryPrincipalAuthorization, error)
}

// ResolveTemporaryPrincipal calls the configured function, failing closed
// (dependency unavailable) when none is set.
func (r StaticTemporaryPrincipalResolver) ResolveTemporaryPrincipal(ctx context.Context, id TemporaryPrincipalID) (TemporaryPrincipalAuthorization, error) {
	if r.Resolve != nil {
		return r.Resolve(ctx, id)
	}
	return TemporaryPrincipalAuthorization{}, ErrDependencyUnavailable
}
