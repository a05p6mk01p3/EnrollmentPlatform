package devicemtls

import (
	"net/http"
	"strings"
	"unicode"
)

// HeaderMetadataConfig configures the protected-metadata header adapter.
// Concrete header names are deployment configuration, NOT normative protocol
// constants (Protocol v0.2.2 gives example names only).
type HeaderMetadataConfig struct {
	VerifiedHeader    string
	FingerprintHeader string
	SerialHeader      string
	VerifiedValue     string
}

// HeaderMetadataSource reads protected device-certificate metadata from
// configured HTTP headers with strict cardinality. It is one concrete
// CertificateMetadataSource; the header names are supplied at construction.
type HeaderMetadataSource struct {
	verifiedHeader    string
	fingerprintHeader string
	serialHeader      string
	verifiedValue     string
}

// NewHeaderMetadataSource validates the header configuration and constructs
// the adapter. Names must be non-empty, valid HTTP field names, and pairwise
// distinct AFTER canonical HTTP header normalization (HTTP field names are
// case-insensitive). The positive verified marker must be non-empty.
// Malformed configuration fails closed. Canonicalized names are stored once
// so extraction uses one representation consistently.
func NewHeaderMetadataSource(cfg HeaderMetadataConfig) (*HeaderMetadataSource, error) {
	verified, err := canonicalHeaderName("verified", cfg.VerifiedHeader)
	if err != nil {
		return nil, err
	}
	fingerprint, err := canonicalHeaderName("fingerprint", cfg.FingerprintHeader)
	if err != nil {
		return nil, err
	}
	serial, err := canonicalHeaderName("serial", cfg.SerialHeader)
	if err != nil {
		return nil, err
	}
	if verified == fingerprint || verified == serial || fingerprint == serial {
		return nil, &ConfigError{Component: "metadata header names", Reason: "collision after HTTP canonicalization"}
	}
	if cfg.VerifiedValue == "" {
		return nil, &ConfigError{Component: "verified value", Reason: "empty"}
	}
	return &HeaderMetadataSource{
		verifiedHeader:    verified,
		fingerprintHeader: fingerprint,
		serialHeader:      serial,
		verifiedValue:     cfg.VerifiedValue,
	}, nil
}

// canonicalHeaderName validates one configured header name and returns its
// canonical HTTP form (case-insensitive comparison semantics).
func canonicalHeaderName(role, raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", &ConfigError{Component: role + " header name", Reason: "empty"}
	}
	canonical := http.CanonicalHeaderKey(name)
	if !isHTTPFieldName(canonical) {
		return "", &ConfigError{Component: role + " header name", Reason: "not a valid HTTP field name"}
	}
	return canonical, nil
}

// isHTTPFieldName reports whether name consists only of RFC 9110 tchar
// characters (a syntactically valid HTTP field name).
func isHTTPFieldName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if !isHTTPTokenChar(r) {
			return false
		}
	}
	return true
}

func isHTTPTokenChar(r rune) bool {
	if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
		return true
	}
	switch r {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// Metadata extracts and validates the protected metadata with strict
// cardinality. It returns VerdictTrusted only when all three fields are
// present, single-valued, and the verified marker is exactly the configured
// positive value.
func (s *HeaderMetadataSource) Metadata(r *http.Request) (DeviceCertificateMetadata, Verdict) {
	if s == nil || r == nil {
		return DeviceCertificateMetadata{}, VerdictRejected
	}

	verified, ok := s.singleValue(r, s.verifiedHeader)
	if !ok || verified != s.verifiedValue {
		// The "device certificate verified" signal must be explicit and
		// positive; a false/absent/other marker is Rejected. Presence of
		// fingerprint/serial alone never counts as verification.
		return DeviceCertificateMetadata{}, VerdictRejected
	}

	fp, ok := s.singleValue(r, s.fingerprintHeader)
	if !ok {
		return DeviceCertificateMetadata{}, VerdictRejected
	}
	serial, ok := s.singleValue(r, s.serialHeader)
	if !ok {
		return DeviceCertificateMetadata{}, VerdictRejected
	}

	return DeviceCertificateMetadata{
		Verified:          true,
		FingerprintSHA256: fp,
		Serial:            serial,
	}, VerdictTrusted
}

// singleValue enforces strict cardinality for one protected metadata field:
// exactly one value, non-empty, no comma-combined values, no control
// characters and no embedded whitespace. It never silently trims or merges.
func (s *HeaderMetadataSource) singleValue(r *http.Request, name string) (string, bool) {
	values := r.Header.Values(name)
	if len(values) != 1 {
		return "", false
	}
	v := values[0]
	if !validMetadataValue(v) {
		return "", false
	}
	return v, true
}

// validMetadataValue reports whether a single header value is a structurally
// acceptable metadata token. It performs no protocol-wide normalization of
// the fingerprint/serial encoding (that wire encoding is not frozen).
func validMetadataValue(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		if r == ',' || r < 0x20 || r == 0x7f || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}
