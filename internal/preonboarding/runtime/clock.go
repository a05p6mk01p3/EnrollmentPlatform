package runtime

import (
	"errors"
	"sync"
	"time"
)

// SystemClock is the real system clock.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

func (SystemClock) Validate() error { return nil }

// MockClock is a deterministic, concurrency-safe clock for testing.
type MockClock struct {
	mu  sync.RWMutex
	now time.Time
}

// Validate checks the structural integrity of MockClock.
func (c *MockClock) Validate() error {
	if c == nil {
		return errors.New("runtime: nil mock clock")
	}
	return nil
}

// NewMockClock creates a MockClock initialized to t.
func NewMockClock(t time.Time) *MockClock {
	return &MockClock{now: t}
}

// Now returns the current mock time.
func (c *MockClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

// Set sets the mock time to t.
func (c *MockClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// Advance advances the mock time by d.
func (c *MockClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
