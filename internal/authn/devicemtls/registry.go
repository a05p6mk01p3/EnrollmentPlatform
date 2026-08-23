package devicemtls

import "context"

// ResolvedDeviceCertificate is the server-side resolved certificate identity.
// All IDs come only from the certificate registry; none come from the client
// or the proxy metadata, and no plaintext/private-key material is present.
type ResolvedDeviceCertificate struct {
	CertificateID         string
	DeviceID              string
	IssuedForEnrollmentID string
}

// CertificateRegistry resolves protected certificate metadata to the
// authoritative server-side certificate record and its device/enrollment
// relationships. It is persistence-neutral (PostgreSQL remains OPEN-009).
type CertificateRegistry interface {
	// ResolveDeviceCertificate resolves the presented certificate evidence to
	// the authoritative server-side record.
	//
	//   - VerdictTrusted: resolved; the returned record is valid.
	//   - VerdictRejected: unknown/mismatched/unacceptable certificate.
	//   - VerdictIndeterminate: registry unavailable, ambiguous trusted state
	//     or malformed record preventing safe resolution.
	ResolveDeviceCertificate(ctx context.Context, md DeviceCertificateMetadata) (ResolvedDeviceCertificate, Verdict)
}
