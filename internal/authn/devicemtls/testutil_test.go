package devicemtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"testing"
	"time"
)

// generateCert produces a fresh self-signed leaf certificate usable as a
// proxy service identity in tests.
func generateCert(t *testing.T) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "proxy.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// trustedTLSState builds a completed, verified client-mTLS connection state
// whose peer leaf is cert.
func trustedTLSState(cert *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{cert},
		VerifiedChains:    [][]*x509.Certificate{{cert}},
	}
}

// requestWithTLS builds a request carrying the given TLS connection state.
func requestWithTLS(cs *tls.ConnectionState) *http.Request {
	r := &http.Request{Header: http.Header{}}
	r.TLS = cs
	return r
}

// --- function-type test doubles ---

type verifierFunc func(r *http.Request) Verdict

func (f verifierFunc) Verify(r *http.Request) Verdict {
	if f == nil {
		return VerdictRejected
	}
	return f(r)
}

type metadataFunc func(r *http.Request) (DeviceCertificateMetadata, Verdict)

func (f metadataFunc) Metadata(r *http.Request) (DeviceCertificateMetadata, Verdict) {
	if f == nil {
		return DeviceCertificateMetadata{}, VerdictRejected
	}
	return f(r)
}

type registryFunc func(ctx context.Context, md DeviceCertificateMetadata) (ResolvedDeviceCertificate, Verdict)

func (f registryFunc) ResolveDeviceCertificate(ctx context.Context, md DeviceCertificateMetadata) (ResolvedDeviceCertificate, Verdict) {
	if f == nil {
		return ResolvedDeviceCertificate{}, VerdictIndeterminate
	}
	return f(ctx, md)
}

// matcherFunc implements ProxyServiceIdentityMatcher.
type matcherFunc func(cert *x509.Certificate) (bool, error)

func (f matcherFunc) Match(cert *x509.Certificate) (bool, error) {
	return f(cert)
}

// ptrMatcher implements ProxyServiceIdentityMatcher with a pointer receiver so
// typed-nil pointer rejection can be exercised.
type ptrMatcher struct {
	ok bool
}

func (m *ptrMatcher) Match(*x509.Certificate) (bool, error) {
	if m == nil {
		return false, nil
	}
	return m.ok, nil
}
