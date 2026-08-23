package devicemtls

import (
	"context"
	"testing"
)

func validRecord() CertificateRecord {
	return CertificateRecord{
		CertificateID:         "cert-A",
		DeviceID:              "dev-D",
		IssuedForEnrollmentID: "enr-A",
		FingerprintSHA256:     "fp-A",
		Serial:                "sn-A",
		State:                 CertificateStateActive,
	}
}

func TestMemoryRegistrySeedValidation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*CertificateRecord)
	}{
		{"empty certificate id", func(r *CertificateRecord) { r.CertificateID = "" }},
		{"empty device id", func(r *CertificateRecord) { r.DeviceID = "" }},
		{"empty issued-for-enrollment id", func(r *CertificateRecord) { r.IssuedForEnrollmentID = "" }},
		{"empty fingerprint", func(r *CertificateRecord) { r.FingerprintSHA256 = "" }},
		{"empty serial", func(r *CertificateRecord) { r.Serial = "" }},
		{"zero/unknown state", func(r *CertificateRecord) { r.State = CertificateStateUnknown }},
		{"invalid state", func(r *CertificateRecord) { r.State = CertificateState(99) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := validRecord()
			tc.mutate(&rec)
			if err := NewMemoryCertificateRegistry().Seed(rec); err == nil {
				t.Fatal("invalid record was accepted")
			}
		})
	}
}

func TestMemoryRegistryRejectsDuplicateSelectors(t *testing.T) {
	r := NewMemoryCertificateRegistry()
	if err := r.Seed(validRecord()); err != nil {
		t.Fatal(err)
	}

	dupCert := validRecord()
	dupCert.FingerprintSHA256 = "fp-other"
	dupCert.Serial = "sn-other"
	if err := r.Seed(dupCert); err == nil {
		t.Fatal("duplicate certificate id was accepted")
	}

	dupFP := validRecord()
	dupFP.CertificateID = "cert-other"
	dupFP.Serial = "sn-other"
	if err := r.Seed(dupFP); err == nil {
		t.Fatal("duplicate fingerprint was accepted")
	}

	dupSN := validRecord()
	dupSN.CertificateID = "cert-other"
	dupSN.FingerprintSHA256 = "fp-other"
	if err := r.Seed(dupSN); err == nil {
		t.Fatal("duplicate serial was accepted")
	}
}

func TestMemoryRegistryResolve(t *testing.T) {
	ctx := context.Background()

	t.Run("matching fingerprint and serial resolves", func(t *testing.T) {
		r := NewMemoryCertificateRegistry()
		r.Seed(validRecord())
		md := DeviceCertificateMetadata{Verified: true, FingerprintSHA256: "fp-A", Serial: "sn-A"}
		got, verdict := r.ResolveDeviceCertificate(ctx, md)
		if verdict != VerdictTrusted {
			t.Fatalf("verdict = %v, want trusted", verdict)
		}
		if got.CertificateID != "cert-A" || got.DeviceID != "dev-D" || got.IssuedForEnrollmentID != "enr-A" {
			t.Fatalf("resolved = %+v", got)
		}
	})

	t.Run("fingerprint mismatch rejected", func(t *testing.T) {
		r := NewMemoryCertificateRegistry()
		r.Seed(validRecord())
		md := DeviceCertificateMetadata{Verified: true, FingerprintSHA256: "fp-wrong", Serial: "sn-A"}
		if _, verdict := r.ResolveDeviceCertificate(ctx, md); verdict != VerdictRejected {
			t.Fatalf("verdict = %v, want rejected", verdict)
		}
	})

	t.Run("serial mismatch rejected", func(t *testing.T) {
		r := NewMemoryCertificateRegistry()
		r.Seed(validRecord())
		md := DeviceCertificateMetadata{Verified: true, FingerprintSHA256: "fp-A", Serial: "sn-wrong"}
		if _, verdict := r.ResolveDeviceCertificate(ctx, md); verdict != VerdictRejected {
			t.Fatalf("verdict = %v, want rejected", verdict)
		}
	})

	t.Run("fingerprint from A and serial from B rejected", func(t *testing.T) {
		r := NewMemoryCertificateRegistry()
		r.Seed(validRecord())
		r.Seed(CertificateRecord{
			CertificateID:         "cert-B",
			DeviceID:              "dev-D",
			IssuedForEnrollmentID: "enr-B",
			FingerprintSHA256:     "fp-B",
			Serial:                "sn-B",
			State:                 CertificateStateActive,
		})
		md := DeviceCertificateMetadata{Verified: true, FingerprintSHA256: "fp-A", Serial: "sn-B"}
		if _, verdict := r.ResolveDeviceCertificate(ctx, md); verdict != VerdictRejected {
			t.Fatalf("verdict = %v, want rejected", verdict)
		}
	})

	t.Run("unknown rejected", func(t *testing.T) {
		r := NewMemoryCertificateRegistry()
		r.Seed(validRecord())
		md := DeviceCertificateMetadata{Verified: true, FingerprintSHA256: "fp-unknown", Serial: "sn-unknown"}
		if _, verdict := r.ResolveDeviceCertificate(ctx, md); verdict != VerdictRejected {
			t.Fatalf("verdict = %v, want rejected", verdict)
		}
	})

	t.Run("inactive certificate rejected", func(t *testing.T) {
		r := NewMemoryCertificateRegistry()
		rec := validRecord()
		rec.State = CertificateStateInactive
		r.Seed(rec)
		md := DeviceCertificateMetadata{Verified: true, FingerprintSHA256: "fp-A", Serial: "sn-A"}
		if _, verdict := r.ResolveDeviceCertificate(ctx, md); verdict != VerdictRejected {
			t.Fatalf("verdict = %v, want rejected", verdict)
		}
	})

	t.Run("unverified metadata rejected", func(t *testing.T) {
		r := NewMemoryCertificateRegistry()
		r.Seed(validRecord())
		md := DeviceCertificateMetadata{Verified: false, FingerprintSHA256: "fp-A", Serial: "sn-A"}
		if _, verdict := r.ResolveDeviceCertificate(ctx, md); verdict != VerdictRejected {
			t.Fatalf("verdict = %v, want rejected", verdict)
		}
	})

	t.Run("malformed resolved record indeterminate", func(t *testing.T) {
		// Seed rejects empty identity, so inject a malformed record directly
		// through the internal maps to exercise the fail-closed resolution
		// path for a structurally corrupt trusted record.
		r := NewMemoryCertificateRegistry()
		r.mu.Lock()
		r.records["cert-X"] = CertificateRecord{State: CertificateStateActive}
		r.byFingerprint["fp-X"] = "cert-X"
		r.bySerial["sn-X"] = "cert-X"
		r.mu.Unlock()
		md := DeviceCertificateMetadata{Verified: true, FingerprintSHA256: "fp-X", Serial: "sn-X"}
		if _, verdict := r.ResolveDeviceCertificate(ctx, md); verdict != VerdictIndeterminate {
			t.Fatalf("verdict = %v, want indeterminate", verdict)
		}
	})

	t.Run("nil registry indeterminate", func(t *testing.T) {
		var r *MemoryCertificateRegistry = nil
		md := DeviceCertificateMetadata{Verified: true, FingerprintSHA256: "fp-A", Serial: "sn-A"}
		if _, verdict := r.ResolveDeviceCertificate(ctx, md); verdict != VerdictIndeterminate {
			t.Fatalf("verdict = %v, want indeterminate", verdict)
		}
	})
}

func TestMemoryRegistryDistinctCertificatesPerDevice(t *testing.T) {
	r := NewMemoryCertificateRegistry()
	r.Seed(CertificateRecord{
		CertificateID:         "cert-A",
		DeviceID:              "dev-D",
		IssuedForEnrollmentID: "enr-A",
		FingerprintSHA256:     "fp-A",
		Serial:                "sn-A",
		State:                 CertificateStateActive,
	})
	r.Seed(CertificateRecord{
		CertificateID:         "cert-B",
		DeviceID:              "dev-D",
		IssuedForEnrollmentID: "enr-B",
		FingerprintSHA256:     "fp-B",
		Serial:                "sn-B",
		State:                 CertificateStateActive,
	})

	ctx := context.Background()
	a, va := r.ResolveDeviceCertificate(ctx, DeviceCertificateMetadata{Verified: true, FingerprintSHA256: "fp-A", Serial: "sn-A"})
	b, vb := r.ResolveDeviceCertificate(ctx, DeviceCertificateMetadata{Verified: true, FingerprintSHA256: "fp-B", Serial: "sn-B"})
	if va != VerdictTrusted || vb != VerdictTrusted {
		t.Fatalf("verdicts = (%v, %v), want trusted/trusted", va, vb)
	}
	if a.CertificateID == b.CertificateID {
		t.Fatal("distinct certificates collapsed into one identity")
	}
	if a.DeviceID != b.DeviceID {
		t.Fatal("same device resolved to different device IDs")
	}
	if a.IssuedForEnrollmentID != "enr-A" || b.IssuedForEnrollmentID != "enr-B" {
		t.Fatalf("issued-for-enrollment = (%q, %q)", a.IssuedForEnrollmentID, b.IssuedForEnrollmentID)
	}
}
