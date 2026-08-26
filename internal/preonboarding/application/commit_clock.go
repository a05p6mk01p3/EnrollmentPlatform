package application

import "context"

// commitClockContextKey is the private carrier for the trusted server-controlled
// clock that a transaction adapter must use for commit-time freshness
// decisions. It is unexported so only the application injects it; adapters read
// it through CommitClockFromContext.
type commitClockContextKey struct{}

// ContextWithCommitClock returns ctx carrying the trusted server-controlled
// clock used for commit-time freshness evaluation. A nil clock is ignored.
//
// The commit-time clock is deliberately a narrow, adapter-local mechanism: the
// application owns the trusted time source and injects it for the commit
// boundary, while a future durable adapter may instead use a transaction
// timestamp or database NOW() without changing this contract.
func ContextWithCommitClock(ctx context.Context, clock Clock) context.Context {
	if clock == nil {
		return ctx
	}
	return context.WithValue(ctx, commitClockContextKey{}, clock)
}

// CommitClockFromContext returns the trusted commit-time clock injected by the
// application, or nil when absent. Adapters must not substitute uncontrolled
// wall-clock time for a missing injected clock while evaluating a
// time-sensitive commit precondition; they should fail closed instead.
func CommitClockFromContext(ctx context.Context) Clock {
	if ctx == nil {
		return nil
	}
	clock, _ := ctx.Value(commitClockContextKey{}).(Clock)
	return clock
}
