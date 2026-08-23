package devicemtls

import (
	"context"
	"net/http"
	"testing"
)

func TestNewSourceRejectsNilAndTypedNil(t *testing.T) {
	// nil interface values.
	if _, err := NewSource(nil, metadataFunc(nil), registryFunc(nil)); err == nil {
		t.Fatal("nil verifier was accepted")
	}
	if _, err := NewSource(verifierFunc(nil), nil, registryFunc(nil)); err == nil {
		t.Fatal("nil metadata source was accepted")
	}
	if _, err := NewSource(verifierFunc(nil), metadataFunc(nil), nil); err == nil {
		t.Fatal("nil registry was accepted")
	}

	// typed-nil function values.
	if _, err := NewSource(verifierFunc(nil), metadataFunc(nil), registryFunc(nil)); err == nil {
		t.Fatal("typed-nil func components were accepted")
	}

	// typed-nil pointer registry.
	var reg *MemoryCertificateRegistry = nil
	if _, err := NewSource(verifierFunc(nil), metadataFunc(nil), reg); err == nil {
		t.Fatal("typed-nil pointer registry was accepted")
	}
}

func TestSourceDeviceCredentialOrchestration(t *testing.T) {
	trustedMD := DeviceCertificateMetadata{Verified: true, FingerprintSHA256: "fp-A", Serial: "sn-A"}
	resolved := ResolvedDeviceCertificate{CertificateID: "cert-A", DeviceID: "dev-D", IssuedForEnrollmentID: "enr-A"}

	newSrc := func(v verifierFunc, m metadataFunc, g registryFunc) *Source {
		t.Helper()
		s, err := NewSource(v, m, g)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	t.Run("full success resolves server-side ids", func(t *testing.T) {
		s := newSrc(
			verifierFunc(func(*http.Request) Verdict { return VerdictTrusted }),
			metadataFunc(func(*http.Request) (DeviceCertificateMetadata, Verdict) { return trustedMD, VerdictTrusted }),
			registryFunc(func(context.Context, DeviceCertificateMetadata) (ResolvedDeviceCertificate, Verdict) {
				return resolved, VerdictTrusted
			}),
		)
		cred, err := s.DeviceCredential(requestWithTLS(trustedTLSState(generateCert(t))))
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if cred == nil || cred.DeviceID != "dev-D" || cred.CertificateID != "cert-A" || cred.IssuedForEnrollmentID != "enr-A" {
			t.Fatalf("credential = %+v", cred)
		}
	})

	t.Run("proxy rejected yields nil credential and no error", func(t *testing.T) {
		s := newSrc(
			verifierFunc(func(*http.Request) Verdict { return VerdictRejected }),
			metadataFunc(func(*http.Request) (DeviceCertificateMetadata, Verdict) { return trustedMD, VerdictTrusted }),
			registryFunc(func(context.Context, DeviceCertificateMetadata) (ResolvedDeviceCertificate, Verdict) {
				return resolved, VerdictTrusted
			}),
		)
		cred, err := s.DeviceCredential(requestWithTLS(trustedTLSState(generateCert(t))))
		if err != nil || cred != nil {
			t.Fatalf("cred, err = (%v, %v), want (nil, nil)", cred, err)
		}
	})

	t.Run("proxy indeterminate yields error", func(t *testing.T) {
		s := newSrc(
			verifierFunc(func(*http.Request) Verdict { return VerdictIndeterminate }),
			metadataFunc(func(*http.Request) (DeviceCertificateMetadata, Verdict) { return trustedMD, VerdictTrusted }),
			registryFunc(func(context.Context, DeviceCertificateMetadata) (ResolvedDeviceCertificate, Verdict) {
				return resolved, VerdictTrusted
			}),
		)
		cred, err := s.DeviceCredential(requestWithTLS(trustedTLSState(generateCert(t))))
		if err == nil || cred != nil {
			t.Fatalf("cred, err = (%v, %v), want (nil, error)", cred, err)
		}
	})

	t.Run("metadata rejected yields nil credential and no error", func(t *testing.T) {
		s := newSrc(
			verifierFunc(func(*http.Request) Verdict { return VerdictTrusted }),
			metadataFunc(func(*http.Request) (DeviceCertificateMetadata, Verdict) {
				return DeviceCertificateMetadata{}, VerdictRejected
			}),
			registryFunc(func(context.Context, DeviceCertificateMetadata) (ResolvedDeviceCertificate, Verdict) {
				return resolved, VerdictTrusted
			}),
		)
		cred, err := s.DeviceCredential(requestWithTLS(trustedTLSState(generateCert(t))))
		if err != nil || cred != nil {
			t.Fatalf("cred, err = (%v, %v), want (nil, nil)", cred, err)
		}
	})

	t.Run("metadata indeterminate yields error", func(t *testing.T) {
		s := newSrc(
			verifierFunc(func(*http.Request) Verdict { return VerdictTrusted }),
			metadataFunc(func(*http.Request) (DeviceCertificateMetadata, Verdict) {
				return DeviceCertificateMetadata{}, VerdictIndeterminate
			}),
			registryFunc(func(context.Context, DeviceCertificateMetadata) (ResolvedDeviceCertificate, Verdict) {
				return resolved, VerdictTrusted
			}),
		)
		cred, err := s.DeviceCredential(requestWithTLS(trustedTLSState(generateCert(t))))
		if err == nil || cred != nil {
			t.Fatalf("cred, err = (%v, %v), want (nil, error)", cred, err)
		}
	})

	t.Run("registry rejected yields nil credential and no error", func(t *testing.T) {
		s := newSrc(
			verifierFunc(func(*http.Request) Verdict { return VerdictTrusted }),
			metadataFunc(func(*http.Request) (DeviceCertificateMetadata, Verdict) { return trustedMD, VerdictTrusted }),
			registryFunc(func(context.Context, DeviceCertificateMetadata) (ResolvedDeviceCertificate, Verdict) {
				return ResolvedDeviceCertificate{}, VerdictRejected
			}),
		)
		cred, err := s.DeviceCredential(requestWithTLS(trustedTLSState(generateCert(t))))
		if err != nil || cred != nil {
			t.Fatalf("cred, err = (%v, %v), want (nil, nil)", cred, err)
		}
	})

	t.Run("registry indeterminate yields error", func(t *testing.T) {
		s := newSrc(
			verifierFunc(func(*http.Request) Verdict { return VerdictTrusted }),
			metadataFunc(func(*http.Request) (DeviceCertificateMetadata, Verdict) { return trustedMD, VerdictTrusted }),
			registryFunc(func(context.Context, DeviceCertificateMetadata) (ResolvedDeviceCertificate, Verdict) {
				return ResolvedDeviceCertificate{}, VerdictIndeterminate
			}),
		)
		cred, err := s.DeviceCredential(requestWithTLS(trustedTLSState(generateCert(t))))
		if err == nil || cred != nil {
			t.Fatalf("cred, err = (%v, %v), want (nil, error)", cred, err)
		}
	})
}

// TestSourceDoesNotReadMetadataBeforeProxyTrust proves the mandatory ordering:
// an untrusted request never triggers device-certificate metadata extraction or
// certificate/device identity resolution.
func TestSourceDoesNotReadMetadataBeforeProxyTrust(t *testing.T) {
	metadataRead := false
	registryRead := false

	s, err := NewSource(
		verifierFunc(func(*http.Request) Verdict { return VerdictRejected }),
		metadataFunc(func(*http.Request) (DeviceCertificateMetadata, Verdict) {
			metadataRead = true
			return DeviceCertificateMetadata{}, VerdictRejected
		}),
		registryFunc(func(context.Context, DeviceCertificateMetadata) (ResolvedDeviceCertificate, Verdict) {
			registryRead = true
			return ResolvedDeviceCertificate{}, VerdictRejected
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	cred, err := s.DeviceCredential(requestWithTLS(trustedTLSState(generateCert(t))))
	if err != nil || cred != nil {
		t.Fatalf("cred, err = (%v, %v), want (nil, nil)", cred, err)
	}
	if metadataRead {
		t.Fatal("device-certificate metadata was read despite untrusted proxy")
	}
	if registryRead {
		t.Fatal("certificate registry was consulted despite untrusted proxy")
	}
}
