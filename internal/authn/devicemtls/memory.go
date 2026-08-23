package devicemtls

import (
	"context"
	"sync"
)

// CertificateState is the authentication acceptability state of a stored
// certificate record. The zero value is CertificateStateUnknown and fails
// closed: only an explicit CertificateStateActive is acceptable.
type CertificateState int

const (
	CertificateStateUnknown CertificateState = iota
	CertificateStateActive
	CertificateStateInactive
)

// CertificateRecord is an insertion-only server-side certificate record used
// by the in-memory test adapter. It is NOT a future database schema
// (OPEN-009). Multiple historical certificates may belong to one device; a
// new renewal/rekey certificate receives a distinct CertificateID and is never
// an overwrite of an earlier one.
type CertificateRecord struct {
	CertificateID         string
	DeviceID              string
	IssuedForEnrollmentID string
	FingerprintSHA256     string
	Serial                string
	State                 CertificateState
}

// MemoryCertificateRegistry is a thread-safe, insertion-only, deterministic
// in-memory certificate registry (test adapter). It never overwrites an
// existing identity and never collapses one device to one certificate.
type MemoryCertificateRegistry struct {
	mu            sync.RWMutex
	records       map[string]CertificateRecord
	byFingerprint map[string]string // fingerprint -> CertificateID
	bySerial      map[string]string // serial -> CertificateID
}

// NewMemoryCertificateRegistry constructs an empty registry.
func NewMemoryCertificateRegistry() *MemoryCertificateRegistry {
	return &MemoryCertificateRegistry{
		records:       map[string]CertificateRecord{},
		byFingerprint: map[string]string{},
		bySerial:      map[string]string{},
	}
}

// Seed inserts a record. It rejects empty IDs/selectors, a zero/unknown or
// otherwise invalid state, and duplicate identity selectors (certificate id,
// fingerprint, serial). There is deliberately no unrestricted upsert that
// could silently rewrite certificate identity/history.
func (r *MemoryCertificateRegistry) Seed(rec CertificateRecord) error {
	if rec.CertificateID == "" {
		return &ConfigError{Component: "certificate record", Reason: "empty certificate id"}
	}
	if rec.DeviceID == "" {
		return &ConfigError{Component: "certificate record", Reason: "empty device id"}
	}
	if rec.IssuedForEnrollmentID == "" {
		return &ConfigError{Component: "certificate record", Reason: "empty issued-for-enrollment id"}
	}
	if rec.FingerprintSHA256 == "" {
		return &ConfigError{Component: "certificate record", Reason: "empty fingerprint"}
	}
	if rec.Serial == "" {
		return &ConfigError{Component: "certificate record", Reason: "empty serial"}
	}
	if rec.State == CertificateStateUnknown {
		return &ConfigError{Component: "certificate record", Reason: "zero/unknown state (must be explicitly active or inactive)"}
	}
	if rec.State != CertificateStateActive && rec.State != CertificateStateInactive {
		return &ConfigError{Component: "certificate record", Reason: "invalid state"}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.records[rec.CertificateID]; dup {
		return &ConfigError{Component: "certificate record", Reason: "duplicate certificate id"}
	}
	if _, dup := r.byFingerprint[rec.FingerprintSHA256]; dup {
		return &ConfigError{Component: "certificate record", Reason: "duplicate fingerprint"}
	}
	if _, dup := r.bySerial[rec.Serial]; dup {
		return &ConfigError{Component: "certificate record", Reason: "duplicate serial"}
	}
	r.records[rec.CertificateID] = rec
	r.byFingerprint[rec.FingerprintSHA256] = rec.CertificateID
	r.bySerial[rec.Serial] = rec.CertificateID
	return nil
}

// ResolveDeviceCertificate resolves metadata to a record.
func (r *MemoryCertificateRegistry) ResolveDeviceCertificate(ctx context.Context, md DeviceCertificateMetadata) (ResolvedDeviceCertificate, Verdict) {
	if r == nil {
		return ResolvedDeviceCertificate{}, VerdictIndeterminate
	}
	if ctx != nil && ctx.Err() != nil {
		return ResolvedDeviceCertificate{}, VerdictIndeterminate
	}
	if !md.Verified {
		return ResolvedDeviceCertificate{}, VerdictRejected
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	byFP, fpOK := r.byFingerprint[md.FingerprintSHA256]
	bySN, snOK := r.bySerial[md.Serial]
	switch {
	case !fpOK || !snOK:
		// Unknown certificate (no fingerprint match, no serial match).
		return ResolvedDeviceCertificate{}, VerdictRejected
	case byFP != bySN:
		// Fingerprint from one certificate, serial from another.
		return ResolvedDeviceCertificate{}, VerdictRejected
	}

	rec := r.records[byFP]
	// A structurally incomplete trusted record prevents safe resolution.
	if rec.CertificateID == "" || rec.DeviceID == "" || rec.IssuedForEnrollmentID == "" {
		return ResolvedDeviceCertificate{}, VerdictIndeterminate
	}
	if rec.State != CertificateStateActive {
		return ResolvedDeviceCertificate{}, VerdictRejected
	}

	return ResolvedDeviceCertificate{
		CertificateID:         rec.CertificateID,
		DeviceID:              rec.DeviceID,
		IssuedForEnrollmentID: rec.IssuedForEnrollmentID,
	}, VerdictTrusted
}
