package devicemtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"sync"
	"testing"
)

func TestNewTLSProxyTrustVerifierRejectsNilAndTypedNil(t *testing.T) {
	if _, err := NewTLSProxyTrustVerifier(nil); err == nil {
		t.Fatal("nil matcher was accepted")
	}

	var f matcherFunc = nil
	if _, err := NewTLSProxyTrustVerifier(f); err == nil {
		t.Fatal("typed-nil func matcher was accepted")
	}

	var p *ptrMatcher = nil
	if _, err := NewTLSProxyTrustVerifier(p); err == nil {
		t.Fatal("typed-nil pointer matcher was accepted")
	}
}

func TestTLSProxyTrustVerifierVerify(t *testing.T) {
	expected := generateCert(t)
	other := generateCert(t)

	matcher, err := NewExactCertificateMatcher(expected)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewTLSProxyTrustVerifier(matcher)
	if err != nil {
		t.Fatal(err)
	}

	handshakeIncomplete := &tls.ConnectionState{
		HandshakeComplete: false,
		PeerCertificates:  []*x509.Certificate{expected},
		VerifiedChains:    [][]*x509.Certificate{{expected}},
	}
	noPeer := &tls.ConnectionState{HandshakeComplete: true}
	noVerified := &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{expected},
	}
	peerMismatchesVerified := &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{expected},
		VerifiedChains:    [][]*x509.Certificate{{other}},
	}

	cases := []struct {
		name string
		req  *http.Request
		want Verdict
	}{
		{"nil request", nil, VerdictRejected},
		{"nil TLS", requestWithTLS(nil), VerdictRejected},
		{"handshake incomplete", requestWithTLS(handshakeIncomplete), VerdictRejected},
		{"no peer certificates", requestWithTLS(noPeer), VerdictRejected},
		{"peer but no verified chains", requestWithTLS(noVerified), VerdictRejected},
		{"peer not the verified leaf", requestWithTLS(peerMismatchesVerified), VerdictRejected},
		{"verified chain but wrong identity", requestWithTLS(trustedTLSState(other)), VerdictRejected},
		{"exact expected identity", requestWithTLS(trustedTLSState(expected)), VerdictTrusted},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := v.Verify(tc.req); got != tc.want {
				t.Fatalf("Verify = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTLSProxyTrustVerifierMatcherErrorIsIndeterminate(t *testing.T) {
	expected := generateCert(t)
	v, err := NewTLSProxyTrustVerifier(matcherFunc(func(*x509.Certificate) (bool, error) {
		return false, errors.New("matcher unavailable")
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Verify(requestWithTLS(trustedTLSState(expected))); got != VerdictIndeterminate {
		t.Fatalf("Verify = %v, want indeterminate", got)
	}
}

func TestExactCertificateMatcher(t *testing.T) {
	if _, err := NewExactCertificateMatcher(nil); err == nil {
		t.Fatal("nil expected certificate was accepted")
	}
	a := generateCert(t)
	b := generateCert(t)
	m, err := NewExactCertificateMatcher(a)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.Match(a); !ok {
		t.Fatal("exact certificate did not match")
	}
	if ok, _ := m.Match(b); ok {
		t.Fatal("different certificate matched")
	}
	if ok, err := m.Match(nil); ok || err != nil {
		t.Fatalf("nil certificate match = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestExactCertificateMatcherRejectsEmptyDER(t *testing.T) {
	bare := &x509.Certificate{}
	if _, err := NewExactCertificateMatcher(bare); err == nil {
		t.Fatal("certificate without raw DER was accepted")
	}
}

// TestExactCertificateMatcherOwnsDER proves the matcher keeps its own
// immutable DER snapshot: mutating the caller-owned certificate after
// construction (including overwriting its Raw with another certificate's
// DER) cannot change the trusted identity.
func TestExactCertificateMatcherOwnsDER(t *testing.T) {
	certA := generateCert(t)
	certB := generateCert(t)

	// Owned snapshot of Cert-A's original DER for a fresh presented leaf.
	origA := append([]byte(nil), certA.Raw...)

	m, err := NewExactCertificateMatcher(certA)
	if err != nil {
		t.Fatal(err)
	}

	// Mutate the caller-owned Cert-A after construction: replace its Raw
	// with Cert-B's DER (simulating a caller/source mutating its object).
	certA.Raw = append([]byte(nil), certB.Raw...)
	certA.RawTBSCertificate = certB.RawTBSCertificate
	certA.RawSubjectPublicKeyInfo = certB.RawSubjectPublicKeyInfo

	presentedA, err := x509.ParseCertificate(origA)
	if err != nil {
		t.Fatal(err)
	}

	// The matcher must still trust ONLY the original Cert-A DER.
	if ok, _ := m.Match(presentedA); !ok {
		t.Fatal("original Cert-A DER no longer trusted after caller mutation")
	}
	if ok, _ := m.Match(certB); ok {
		t.Fatal("Cert-B matched after caller mutation")
	}
	// The mutated caller-owned Cert-A (now carrying Cert-B's Raw) must not
	// match either.
	if ok, _ := m.Match(certA); ok {
		t.Fatal("mutated caller-owned certificate matched")
	}
}

// TestExactCertificateMatcherConcurrentMatch proves Match is race-safe for
// concurrent calls with distinct presented certificates (run under -race).
func TestExactCertificateMatcherConcurrentMatch(t *testing.T) {
	expected := generateCert(t)
	other := generateCert(t)
	m, err := NewExactCertificateMatcher(expected)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			c := expected
			if g%2 == 1 {
				c = other
			}
			ok, err := m.Match(c)
			if err != nil {
				t.Errorf("Match error: %v", err)
				return
			}
			if g%2 == 0 && !ok {
				t.Error("expected certificate did not match")
			}
			if g%2 == 1 && ok {
				t.Error("other certificate matched")
			}
		}(g)
	}
	wg.Wait()
}
