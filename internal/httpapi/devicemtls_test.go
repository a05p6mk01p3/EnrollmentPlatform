package httpapi_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	devicemtls "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/devicemtls"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
)

// Example protected-metadata header names. These are NOT normative; they are
// deployment configuration supplied at construction (Protocol v0.2.2 names
// are examples only).
const (
	dmVerifiedHeader    = "X-Enrollment-Client-Cert-Verified"
	dmFingerprintHeader = "X-Enrollment-Client-Cert-Fingerprint-SHA256"
	dmSerialHeader      = "X-Enrollment-Client-Cert-Serial"
	dmVerifiedValue     = "SUCCESS"
)

func dmHeaderConfig() devicemtls.HeaderMetadataConfig {
	return devicemtls.HeaderMetadataConfig{
		VerifiedHeader:    dmVerifiedHeader,
		FingerprintHeader: dmFingerprintHeader,
		SerialHeader:      dmSerialHeader,
		VerifiedValue:     dmVerifiedValue,
	}
}

func dmSeedRecord(deviceID, certID, enrollmentID, fp, sn string) devicemtls.CertificateRecord {
	return devicemtls.CertificateRecord{
		CertificateID:         certID,
		DeviceID:              deviceID,
		IssuedForEnrollmentID: enrollmentID,
		FingerprintSHA256:     fp,
		Serial:                sn,
		State:                 devicemtls.CertificateStateActive,
	}
}

func dmMetadataHeaders(fp, sn string) map[string]string {
	return map[string]string{
		dmVerifiedHeader:    dmVerifiedValue,
		dmFingerprintHeader: fp,
		dmSerialHeader:      sn,
	}
}

func genProxyCert(t *testing.T) *x509.Certificate {
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

func proxyTLS(cert *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{cert},
		VerifiedChains:    [][]*x509.Certificate{{cert}},
	}
}

// newDeviceMTSetup builds a full real DeviceMTLS source (exact-certificate
// proxy verifier + header metadata source + seeded in-memory registry) and
// returns the source and the trusted proxy certificate.
func newDeviceMTSetup(t *testing.T, records ...devicemtls.CertificateRecord) (*devicemtls.Source, *x509.Certificate) {
	t.Helper()
	proxyCert := genProxyCert(t)
	matcher, err := devicemtls.NewExactCertificateMatcher(proxyCert)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := devicemtls.NewTLSProxyTrustVerifier(matcher)
	if err != nil {
		t.Fatal(err)
	}
	headerSrc, err := devicemtls.NewHeaderMetadataSource(dmHeaderConfig())
	if err != nil {
		t.Fatal(err)
	}
	reg := devicemtls.NewMemoryCertificateRegistry()
	for _, rec := range records {
		if err := reg.Seed(rec); err != nil {
			t.Fatal(err)
		}
	}
	src, err := devicemtls.NewSource(verifier, headerSrc, reg)
	if err != nil {
		t.Fatal(err)
	}
	return src, proxyCert
}

func doDeviceMTLS(h http.Handler, method, path, body string, cs *tls.ConnectionState, headers map[string]string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	req.TLS = cs
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func completeInstalledHeaders() map[string]string {
	return map[string]string{
		"Content-Type":    "application/json",
		"Idempotency-Key": validIdempotencyKey,
	}
}

func deviceBindingOf(t *testing.T, ac *authruntime.AuthenticationContext) authruntime.DeviceMTLSBinding {
	t.Helper()
	b, ok := ac.Binding(authpolicy.CredentialKindDeviceMTLS)
	if !ok {
		t.Fatal("no DeviceMTLS binding in context")
	}
	d, ok := b.DeviceMTLS()
	if !ok {
		t.Fatal("binding is not DeviceMTLS")
	}
	return d
}

func TestDeviceMTLSCompleteInstalledSuccess(t *testing.T) {
	src, proxyCert := newDeviceMTSetup(t,
		dmSeedRecord("dev-D", "cert-A", "enr-A", "fp-A", "sn-A"),
		dmSeedRecord("dev-D", "cert-B", "enr-B", "fp-B", "sn-B"),
	)
	h, p := newAuthTestHandler(t, registry(t, devicemtls.NewAuthenticator()), src)

	headers := completeInstalledHeaders()
	for k, v := range dmMetadataHeaders("fp-A", "sn-A") {
		headers[k] = v
	}
	rr := doDeviceMTLS(h, "POST", "/v1/enrollments/enr-A/complete", `{"installation_status":"INSTALLED"}`, proxyTLS(proxyCert), headers)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}
	if p.count("CompleteEnrollment") != 1 {
		t.Fatal("CompleteEnrollment was not reached")
	}
}

func TestDeviceMTLSExactCertificateRequired(t *testing.T) {
	src, proxyCert := newDeviceMTSetup(t,
		dmSeedRecord("dev-D", "cert-A", "enr-A", "fp-A", "sn-A"),
		dmSeedRecord("dev-D", "cert-B", "enr-B", "fp-B", "sn-B"),
	)
	h, p := newAuthTestHandler(t, registry(t, devicemtls.NewAuthenticator()), src)

	// Same device D, but the presented certificate was issued for enrollment B
	// while the route is enrollment A: device-id equality is insufficient.
	headers := completeInstalledHeaders()
	for k, v := range dmMetadataHeaders("fp-B", "sn-B") {
		headers[k] = v
	}
	rr := doDeviceMTLS(h, "POST", "/v1/enrollments/enr-A/complete", `{"installation_status":"INSTALLED"}`, proxyTLS(proxyCert), headers)
	assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("WWW-Authenticate = %q; want empty (DeviceMTLS mismatch issues no Bearer challenge)", got)
	}
	assertNoHandlerCall(t, &p.probeSSI)
}

func TestDeviceMTLSProxyTrustRequired(t *testing.T) {
	src, proxyCert := newDeviceMTSetup(t, dmSeedRecord("dev-D", "cert-A", "enr-A", "fp-A", "sn-A"))
	// EnrollmentAccessToken is the bearer alternative; it authenticates so the
	// request reaches Phase B where INSTALLED requires DeviceMTLS.
	h, p := newAuthTestHandler(t, registry(t,
		acceptOnly(authpolicy.CredentialKindEnrollmentAccessToken, tokEnroll),
		devicemtls.NewAuthenticator(),
	), src)

	base := completeInstalledHeaders()
	base["Authorization"] = "Bearer " + tokEnroll
	headers := func(fp, sn string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range dmMetadataHeaders(fp, sn) {
			m[k] = v
		}
		return m
	}
	body := `{"installation_status":"INSTALLED"}`

	t.Run("no proxy TLS rejected", func(t *testing.T) {
		rr := doDeviceMTLS(h, "POST", "/v1/enrollments/enr-A/complete", body, nil, headers("fp-A", "sn-A"))
		assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		if got := rr.Header().Get("WWW-Authenticate"); got != "" {
			t.Fatalf("WWW-Authenticate = %q; want empty", got)
		}
		assertNoHandlerCall(t, &p.probeSSI)
	})

	t.Run("unverified proxy chain rejected", func(t *testing.T) {
		cs := &tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{proxyCert}}
		rr := doDeviceMTLS(h, "POST", "/v1/enrollments/enr-A/complete", body, cs, headers("fp-A", "sn-A"))
		assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		assertNoHandlerCall(t, &p.probeSSI)
	})

	t.Run("wrong proxy identity rejected", func(t *testing.T) {
		rr := doDeviceMTLS(h, "POST", "/v1/enrollments/enr-A/complete", body, proxyTLS(genProxyCert(t)), headers("fp-A", "sn-A"))
		assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		assertNoHandlerCall(t, &p.probeSSI)
	})
}

// errMatcher is a proxy identity matcher that reports an internal failure
// (Indeterminate), used to exercise the 503 mapping.
type errMatcher struct{}

func (errMatcher) Match(*x509.Certificate) (bool, error) {
	return false, errors.New("matcher unavailable")
}

// indeterminateRegistry reports the registry as unavailable (Indeterminate).
type indeterminateRegistry struct{}

func (indeterminateRegistry) ResolveDeviceCertificate(context.Context, devicemtls.DeviceCertificateMetadata) (devicemtls.ResolvedDeviceCertificate, devicemtls.Verdict) {
	return devicemtls.ResolvedDeviceCertificate{}, devicemtls.VerdictIndeterminate
}

func TestDeviceMTLSDependencyUnavailable(t *testing.T) {
	t.Run("proxy matcher failure -> 503", func(t *testing.T) {
		verifier, err := devicemtls.NewTLSProxyTrustVerifier(errMatcher{})
		if err != nil {
			t.Fatal(err)
		}
		headerSrc, _ := devicemtls.NewHeaderMetadataSource(dmHeaderConfig())
		reg := devicemtls.NewMemoryCertificateRegistry()
		if err := reg.Seed(dmSeedRecord("dev-D", "cert-A", "enr-A", "fp-A", "sn-A")); err != nil {
			t.Fatal(err)
		}
		src, err := devicemtls.NewSource(verifier, headerSrc, reg)
		if err != nil {
			t.Fatal(err)
		}
		h, p := newAuthTestHandler(t, registry(t, devicemtls.NewAuthenticator()), src)

		headers := completeInstalledHeaders()
		for k, v := range dmMetadataHeaders("fp-A", "sn-A") {
			headers[k] = v
		}
		rr := doDeviceMTLS(h, "POST", "/v1/enrollments/enr-A/complete", `{"installation_status":"INSTALLED"}`, proxyTLS(genProxyCert(t)), headers)
		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
		assertNoHandlerCall(t, &p.probeSSI)
	})

	t.Run("certificate registry unavailable -> 503", func(t *testing.T) {
		proxyCert := genProxyCert(t)
		matcher, _ := devicemtls.NewExactCertificateMatcher(proxyCert)
		verifier, _ := devicemtls.NewTLSProxyTrustVerifier(matcher)
		headerSrc, _ := devicemtls.NewHeaderMetadataSource(dmHeaderConfig())
		src, err := devicemtls.NewSource(verifier, headerSrc, indeterminateRegistry{})
		if err != nil {
			t.Fatal(err)
		}
		h, p := newAuthTestHandler(t, registry(t, devicemtls.NewAuthenticator()), src)

		headers := completeInstalledHeaders()
		for k, v := range dmMetadataHeaders("fp-A", "sn-A") {
			headers[k] = v
		}
		rr := doDeviceMTLS(h, "POST", "/v1/enrollments/enr-A/complete", `{"installation_status":"INSTALLED"}`, proxyTLS(proxyCert), headers)
		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
		assertNoHandlerCall(t, &p.probeSSI)
	})
}

// fixedBearerAuthenticator authenticates exactly one bearer token to a fixed
// typed binding, independent of the route path parameter.
type fixedBearerAuthenticator struct {
	kind    authpolicy.CredentialKind
	token   string
	binding *authruntime.Binding
}

func (a fixedBearerAuthenticator) Kind() authpolicy.CredentialKind { return a.kind }

func (a fixedBearerAuthenticator) Authenticate(_ context.Context, c *authruntime.Credential) authruntime.AuthenticationResult {
	if c == nil || c.BearerToken != a.token {
		return authruntime.AuthenticationResult{Decision: authruntime.DecisionRejected}
	}
	return authruntime.AuthenticationResult{Decision: authruntime.DecisionAuthenticated, Binding: a.binding}
}

func mustEnrollmentAccess(t *testing.T, id string) *authruntime.Binding {
	t.Helper()
	b, err := authruntime.NewEnrollmentAccessBinding(id)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDeviceMTLSExtraCredentialDoesNotVeto(t *testing.T) {
	t.Run("INSTALLED DeviceMTLS-A plus extra EnrollmentAccessToken-B", func(t *testing.T) {
		src, proxyCert := newDeviceMTSetup(t, dmSeedRecord("dev-D", "cert-A", "enr-A", "fp-A", "sn-A"))
		h, p := newAuthTestHandler(t, registry(t,
			devicemtls.NewAuthenticator(),
			fixedBearerAuthenticator{kind: authpolicy.CredentialKindEnrollmentAccessToken, token: "tok-B", binding: mustEnrollmentAccess(t, "enr-B")},
		), src)

		headers := completeInstalledHeaders()
		headers["Authorization"] = "Bearer tok-B"
		for k, v := range dmMetadataHeaders("fp-A", "sn-A") {
			headers[k] = v
		}
		rr := doDeviceMTLS(h, "POST", "/v1/enrollments/enr-A/complete", `{"installation_status":"INSTALLED"}`, proxyTLS(proxyCert), headers)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
		}
		if p.count("CompleteEnrollment") != 1 {
			t.Fatal("CompleteEnrollment was not reached")
		}
	})

	t.Run("FAILED EnrollmentAccessToken-A plus extra DeviceMTLS-B", func(t *testing.T) {
		src, proxyCert := newDeviceMTSetup(t, dmSeedRecord("dev-D", "cert-B", "enr-B", "fp-B", "sn-B"))
		h, p := newAuthTestHandler(t, registry(t,
			devicemtls.NewAuthenticator(),
			fixedBearerAuthenticator{kind: authpolicy.CredentialKindEnrollmentAccessToken, token: "tok-A", binding: mustEnrollmentAccess(t, "enr-A")},
		), src)

		headers := completeInstalledHeaders()
		headers["Authorization"] = "Bearer tok-A"
		for k, v := range dmMetadataHeaders("fp-B", "sn-B") {
			headers[k] = v
		}
		rr := doDeviceMTLS(h, "POST", "/v1/enrollments/enr-A/complete", `{"installation_status":"FAILED","error_code":"AGENT_INSTALL_FAILED"}`, proxyTLS(proxyCert), headers)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
		}
		if p.count("CompleteEnrollment") != 1 {
			t.Fatal("CompleteEnrollment was not reached")
		}
	})
}

func TestDeviceMTLSRenewalRekey(t *testing.T) {
	src, proxyCert := newDeviceMTSetup(t, dmSeedRecord("dev-D", "cert-A", "enr-A", "fp-A", "sn-A"))

	for _, op := range []string{"RENEWAL", "REKEY"} {
		t.Run(op, func(t *testing.T) {
			h, p := newAuthTestHandler(t, registry(t, devicemtls.NewAuthenticator()), src)
			body := fmt.Sprintf(`{"operation":%q,"certificate_usage":"PARTNER_AUTH"}`, op)
			headers := completeInstalledHeaders()
			for k, v := range dmMetadataHeaders("fp-A", "sn-A") {
				headers[k] = v
			}
			rr := doDeviceMTLS(h, "POST", "/v1/enrollments", body, proxyTLS(proxyCert), headers)
			if rr.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201 (body %s)", rr.Code, rr.Body.String())
			}
			if p.count("CreateEnrollment") != 1 {
				t.Fatal("CreateEnrollment was not reached")
			}
		})
	}
}

func TestDeviceMTLSClientAuthorityHeadersIgnored(t *testing.T) {
	src, proxyCert := newDeviceMTSetup(t, dmSeedRecord("dev-SERVER", "cert-A", "enr-A", "fp-A", "sn-A"))
	h, p := newAuthTestHandler(t, registry(t, devicemtls.NewAuthenticator()), src)

	headers := completeInstalledHeaders()
	// Client-supplied authority identifiers must never override server-side
	// resolution; they are simply not trusted by the metadata adapter.
	headers["X-Enrollment-Device-ID"] = "dev-ATTACKER"
	headers["X-Enrollment-Certificate-ID"] = "cert-ATTACKER"
	headers["X-Enrollment-Partner-ID"] = "partner-ATTACKER"
	for k, v := range dmMetadataHeaders("fp-A", "sn-A") {
		headers[k] = v
	}

	rr := doDeviceMTLS(h, "POST", "/v1/enrollments/enr-A/complete", `{"installation_status":"INSTALLED"}`, proxyTLS(proxyCert), headers)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
	}

	ctxs := p.contextSnapshot()
	if len(ctxs) == 0 {
		t.Fatal("no authentication context recorded")
	}
	d := deviceBindingOf(t, ctxs[len(ctxs)-1])
	if d.DeviceID != "dev-SERVER" || d.CertificateID != "cert-A" || d.IssuedForEnrollmentID != "enr-A" {
		t.Fatalf("device binding = %+v; want server-resolved ids only", d)
	}
	// The typed binding carries only the three server-resolved IDs; it has no
	// fingerprint/serial/header field to leak by construction.
}
