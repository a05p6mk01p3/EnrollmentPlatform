package runtime

import (
	"sync"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
)

// MemoryAuditRecorder is a thread-safe in-memory recorder of committed audit events.
type MemoryAuditRecorder struct {
	mu     sync.RWMutex
	events []application.AuditEvent
}

// NewMemoryAuditRecorder creates an empty audit recorder.
func NewMemoryAuditRecorder() *MemoryAuditRecorder {
	return &MemoryAuditRecorder{
		events: make([]application.AuditEvent, 0),
	}
}

// Record appends committed events to the recorder.
func (r *MemoryAuditRecorder) Record(events []application.AuditEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, events...)
}

// Events returns a snapshot of all committed audit events.
func (r *MemoryAuditRecorder) Events() []application.AuditEvent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cp := make([]application.AuditEvent, len(r.events))
	copy(cp, r.events)
	return cp
}

// Count returns the number of committed audit events.
func (r *MemoryAuditRecorder) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.events)
}

// CountByType returns the count of committed audit events matching the given type.
func (r *MemoryAuditRecorder) CountByType(t application.AuditEventType) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, e := range r.events {
		if e.Type == t {
			n++
		}
	}
	return n
}
