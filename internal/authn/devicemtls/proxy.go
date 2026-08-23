package devicemtls

import (
	"bytes"
	"crypto/x509"
	"net/http"
)

// ProxyServiceIdentityMatcher decides whether an authenticated TLS leaf
// certificate is the expected Reverse Proxy service identity.
//
// Match returns true for the expected identity, false for a definitive
// mismatch, and a non-nil error when the matcher cannot evaluate (treated as
// Indeterminate). The concrete identity policy is supplied at deployment; this
// package invents no DNS/URI/SPIFFE/CN/fingerprint representation.
type ProxyServiceIdentityMatcher interface {
	Match(cert *x509.Certificate) (bool, error)
}

// ProxyTrustVerifier evaluates the internal HTTP request transport to decide
// whether it arrived over an authenticated connection from the expected
// Reverse Proxy service.
type ProxyTrustVerifier interface {
	Verify(r *http.Request) Verdict
}

// TLSProxyTrustVerifier authenticates the Proxy -> API mTLS hop from the
// request's *tls.ConnectionState. It never treats r.TLS peer certificates as
// device certificates; r.TLS is used only to authenticate the proxy service.
type TLSProxyTrustVerifier struct {
	matcher ProxyServiceIdentityMatcher
}

// NewTLSProxyTrustVerifier constructs the verifier with an exact service
// identity matcher. A nil/typed-nil matcher is a construction error; there is
// no accept-all default.
func NewTLSProxyTrustVerifier(matcher ProxyServiceIdentityMatcher) (*TLSProxyTrustVerifier, error) {
	if isNilInterfaceValue(matcher) {
		return nil, &ConfigError{Component: "proxy service identity matcher", Reason: "nil"}
	}
	return &TLSProxyTrustVerifier{matcher: matcher}, nil
}

// Verify evaluates the request transport.
//
// Required, in order: r.TLS must exist; the TLS handshake must be complete;
// a client certificate must exist; the chain must have been cryptographically
// verified (VerifiedChains, not PeerCertificates alone); the authenticated
// peer must be the leaf of a verified chain; and the leaf must match the
// configured proxy service identity. "Any valid client certificate" is never
// enough.
func (v *TLSProxyTrustVerifier) Verify(r *http.Request) Verdict {
	if v == nil || v.matcher == nil || r == nil || r.TLS == nil {
		return VerdictRejected
	}
	cs := r.TLS
	if !cs.HandshakeComplete {
		return VerdictRejected
	}
	if len(cs.PeerCertificates) == 0 {
		return VerdictRejected
	}
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return VerdictRejected
	}
	leaf := cs.PeerCertificates[0]
	chainLeaf := cs.VerifiedChains[0][0]
	if leaf == nil || chainLeaf == nil {
		return VerdictRejected
	}
	// The authenticated peer must be the leaf of a verified chain; a spoofed
	// PeerCertificates entry that is not the verified leaf is rejected.
	if !leaf.Equal(chainLeaf) {
		return VerdictRejected
	}
	ok, err := v.matcher.Match(leaf)
	if err != nil {
		return VerdictIndeterminate
	}
	if !ok {
		return VerdictRejected
	}
	return VerdictTrusted
}

// ExactCertificateMatcher is an exact (DER-equality) proxy service identity
// matcher. It pins trust to one specific proxy leaf certificate and is a
// concrete, deployment-supplied policy; it invents no protocol-mandated
// identity representation.
//
// The matcher OWNS an immutable snapshot of the expected certificate's raw
// DER; it never retains the caller-owned *x509.Certificate pointer, never
// consults caller-owned certificate fields after construction, and never
// exposes the owned snapshot mutably.
type ExactCertificateMatcher struct {
	expectedDER []byte
}

// NewExactCertificateMatcher constructs a matcher for exactly one expected
// proxy leaf certificate. A nil certificate or a certificate without raw DER
// is a construction error. The raw DER is defensively copied into
// matcher-owned storage, so later mutation of the caller's certificate cannot
// change the trusted identity.
func NewExactCertificateMatcher(expected *x509.Certificate) (*ExactCertificateMatcher, error) {
	if expected == nil {
		return nil, &ConfigError{Component: "expected proxy certificate", Reason: "nil"}
	}
	if len(expected.Raw) == 0 {
		return nil, &ConfigError{Component: "expected proxy certificate", Reason: "missing raw DER"}
	}
	return &ExactCertificateMatcher{expectedDER: append([]byte(nil), expected.Raw...)}, nil
}

// Match reports whether cert's raw DER equals the matcher-owned expected DER
// snapshot. A nil presented certificate is rejected.
func (m *ExactCertificateMatcher) Match(cert *x509.Certificate) (bool, error) {
	if m == nil || len(m.expectedDER) == 0 {
		return false, &ConfigError{Component: "expected proxy certificate", Reason: "missing"}
	}
	if cert == nil {
		return false, nil
	}
	return bytes.Equal(cert.Raw, m.expectedDER), nil
}
