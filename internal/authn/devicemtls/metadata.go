package devicemtls

import "net/http"

// DeviceCertificateMetadata is the protected certificate evidence extracted
// from the authenticated proxy hop. It carries NO authority identifiers
// (device_id/certificate_id/enrollment_id/partner_id/scope/authorization):
// those are resolved server-side by the certificate registry, never trusted
// from proxy metadata.
type DeviceCertificateMetadata struct {
	Verified          bool
	FingerprintSHA256 string
	Serial            string
}

// CertificateMetadataSource extracts protected device-certificate metadata
// from a request whose proxy hop has already authenticated.
//
// A VerdictTrusted result carries a complete, positively-verified metadata
// triple. VerdictRejected means no usable metadata (absent/incomplete/
// duplicate/malformed/unverified). VerdictIndeterminate means the source
// itself could not be evaluated.
type CertificateMetadataSource interface {
	Metadata(r *http.Request) (DeviceCertificateMetadata, Verdict)
}
