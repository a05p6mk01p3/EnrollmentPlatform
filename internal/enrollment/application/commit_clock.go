package application

import "context"

type commitClockContextKey struct{}

// ContextWithCommitClock carries the trusted server-controlled clock to the
// UoW commit boundary so commit-time freshness checks cannot use client time.
func ContextWithCommitClock(ctx context.Context, clock Clock) context.Context {
	return context.WithValue(ctx, commitClockContextKey{}, clock)
}

// CommitClockFromContext is for UnitOfWork adapters implementing commit-time
// freshness. A missing clock must make time-sensitive commit validation fail
// closed.
func CommitClockFromContext(ctx context.Context) Clock {
	clock, _ := ctx.Value(commitClockContextKey{}).(Clock)
	return clock
}
