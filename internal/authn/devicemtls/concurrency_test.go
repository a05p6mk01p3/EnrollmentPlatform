package devicemtls

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// TestMemoryRegistryConcurrentResolution seeds distinct records and resolves
// them concurrently; it must be race-clean (run under -race).
func TestMemoryRegistryConcurrentResolution(t *testing.T) {
	r := NewMemoryCertificateRegistry()
	const n = 8
	for i := 0; i < n; i++ {
		if err := r.Seed(CertificateRecord{
			CertificateID:         fmt.Sprintf("cert-%d", i),
			DeviceID:              fmt.Sprintf("dev-%d", i),
			IssuedForEnrollmentID: fmt.Sprintf("enr-%d", i),
			FingerprintSHA256:     fmt.Sprintf("fp-%d", i),
			Serial:                fmt.Sprintf("sn-%d", i),
			State:                 CertificateStateActive,
		}); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			i := g % n
			md := DeviceCertificateMetadata{Verified: true, FingerprintSHA256: fmt.Sprintf("fp-%d", i), Serial: fmt.Sprintf("sn-%d", i)}
			got, verdict := r.ResolveDeviceCertificate(context.Background(), md)
			if verdict != VerdictTrusted {
				t.Errorf("verdict = %v, want trusted", verdict)
				return
			}
			if got.CertificateID != fmt.Sprintf("cert-%d", i) {
				t.Errorf("resolved certificate id = %q, want cert-%d", got.CertificateID, i)
			}
		}(g)
	}
	wg.Wait()
}
