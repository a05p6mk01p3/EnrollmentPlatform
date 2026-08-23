package devicemtls

import (
	"net/http"

	runtime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
)

// Source is the M4.5 DeviceMTLS trusted-proxy source. It orchestrates the
// flow:
//
//	proxy trust verification -> protected certificate metadata
//	  -> server-side certificate resolution -> typed device credential
//
// It implements runtime.DeviceMTLSSource.
type Source struct {
	verifier ProxyTrustVerifier
	metadata CertificateMetadataSource
	registry CertificateRegistry
}

// NewSource constructs the source. nil/typed-nil components are construction
// errors; there is no accept-all default.
func NewSource(verifier ProxyTrustVerifier, metadata CertificateMetadataSource, registry CertificateRegistry) (*Source, error) {
	if isNilInterfaceValue(verifier) {
		return nil, &ConfigError{Component: "proxy trust verifier", Reason: "nil"}
	}
	if isNilInterfaceValue(metadata) {
		return nil, &ConfigError{Component: "certificate metadata source", Reason: "nil"}
	}
	if isNilInterfaceValue(registry) {
		return nil, &ConfigError{Component: "certificate registry", Reason: "nil"}
	}
	return &Source{verifier: verifier, metadata: metadata, registry: registry}, nil
}

// DeviceCredential implements runtime.DeviceMTLSSource.
//
//   - (nil, nil): the request presented no acceptable DeviceMTLS credential
//     (the runtime classifies this as Rejected).
//   - (credential, nil): the device identity was resolved server-side.
//   - (nil, error): a trusted dependency could not be evaluated (the runtime
//     classifies this as Indeterminate).
//
// Ordering is mandatory: the proxy service hop is authenticated before any
// device-certificate metadata is read, so an untrusted request never triggers
// certificate/device identity resolution.
func (s *Source) DeviceCredential(r *http.Request) (*runtime.DeviceCredential, error) {
	if s == nil {
		return nil, ErrTrustedMaterialUnavailable
	}

	switch s.verifier.Verify(r) {
	case VerdictTrusted:
	case VerdictRejected:
		return nil, nil
	default:
		return nil, ErrTrustedMaterialUnavailable
	}

	md, verdict := s.metadata.Metadata(r)
	switch verdict {
	case VerdictTrusted:
	case VerdictRejected:
		return nil, nil
	default:
		return nil, ErrTrustedMaterialUnavailable
	}

	cert, verdict := s.registry.ResolveDeviceCertificate(r.Context(), md)
	switch verdict {
	case VerdictTrusted:
	case VerdictRejected:
		return nil, nil
	default:
		return nil, ErrTrustedMaterialUnavailable
	}

	return &runtime.DeviceCredential{
		DeviceID:              cert.DeviceID,
		CertificateID:         cert.CertificateID,
		IssuedForEnrollmentID: cert.IssuedForEnrollmentID,
	}, nil
}
