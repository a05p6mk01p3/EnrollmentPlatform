package devicemtls

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func testHeaderConfig() HeaderMetadataConfig {
	return HeaderMetadataConfig{
		VerifiedHeader:    "X-Enrollment-Client-Cert-Verified",
		FingerprintHeader: "X-Enrollment-Client-Cert-Fingerprint-SHA256",
		SerialHeader:      "X-Enrollment-Client-Cert-Serial",
		VerifiedValue:     "SUCCESS",
	}
}

func TestNewHeaderMetadataSourceValidation(t *testing.T) {
	base := testHeaderConfig()
	cases := []struct {
		name   string
		mutate func(*HeaderMetadataConfig)
	}{
		{"empty verified header", func(c *HeaderMetadataConfig) { c.VerifiedHeader = " " }},
		{"empty fingerprint header", func(c *HeaderMetadataConfig) { c.FingerprintHeader = "" }},
		{"empty serial header", func(c *HeaderMetadataConfig) { c.SerialHeader = "" }},
		{"duplicate verified/fingerprint", func(c *HeaderMetadataConfig) { c.FingerprintHeader = c.VerifiedHeader }},
		{"duplicate verified/serial", func(c *HeaderMetadataConfig) { c.SerialHeader = c.VerifiedHeader }},
		{"empty verified value", func(c *HeaderMetadataConfig) { c.VerifiedValue = "" }},
		{"invalid field name", func(c *HeaderMetadataConfig) { c.VerifiedHeader = "Not A Header" }},
		{"colon in name", func(c *HeaderMetadataConfig) { c.VerifiedHeader = "X-Colon:Yes" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			if _, err := NewHeaderMetadataSource(cfg); err == nil {
				t.Fatal("malformed header configuration was accepted")
			}
		})
	}
}

// TestNewHeaderMetadataSourceCaseInsensitiveCollisions proves protected
// metadata header names are HTTP field names: pairwise collisions after
// canonical HTTP header normalization must fail construction.
func TestNewHeaderMetadataSourceCaseInsensitiveCollisions(t *testing.T) {
	base := testHeaderConfig()
	cases := []struct {
		name   string
		mutate func(*HeaderMetadataConfig)
	}{
		{"verified vs fingerprint exact", func(c *HeaderMetadataConfig) { c.FingerprintHeader = c.VerifiedHeader }},
		{"verified vs fingerprint case-only", func(c *HeaderMetadataConfig) {
			c.FingerprintHeader = "x-enrollment-client-cert-verified"
		}},
		{"verified vs serial exact", func(c *HeaderMetadataConfig) { c.SerialHeader = c.VerifiedHeader }},
		{"verified vs serial case-only", func(c *HeaderMetadataConfig) {
			c.SerialHeader = "X-ENROLLMENT-CLIENT-CERT-VERIFIED"
		}},
		{"fingerprint vs serial exact", func(c *HeaderMetadataConfig) { c.SerialHeader = c.FingerprintHeader }},
		{"fingerprint vs serial case-only", func(c *HeaderMetadataConfig) {
			c.SerialHeader = "x-enrollment-client-cert-fingerprint-sha256"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			if _, err := NewHeaderMetadataSource(cfg); err == nil {
				t.Fatal("colliding header names were accepted")
			}
		})
	}
}

// TestHeaderMetadataSourceDistinctNamesPass proves distinct names (differing
// only by case) pass construction.
func TestHeaderMetadataSourceDistinctNamesPass(t *testing.T) {
	cfg := HeaderMetadataConfig{
		VerifiedHeader:    "X-Device-Verified",
		FingerprintHeader: "x-device-fingerprint",
		SerialHeader:      "X-DEVICE-SERIAL",
		VerifiedValue:     "SUCCESS",
	}
	if _, err := NewHeaderMetadataSource(cfg); err != nil {
		t.Fatalf("distinct header names rejected: %v", err)
	}
}

// TestHeaderMetadataSourceHeaderCasingInsensitiveExtraction proves extraction
// works regardless of the request header casing used by the HTTP layer (Go's
// header storage canonicalizes incoming field names).
func TestHeaderMetadataSourceHeaderCasingInsensitiveExtraction(t *testing.T) {
	src, err := NewHeaderMetadataSource(testHeaderConfig())
	if err != nil {
		t.Fatal(err)
	}

	// Mixed-case Set calls; net/http canonicalizes the stored keys.
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("X-ENROLLMENT-CLIENT-CERT-VERIFIED", "SUCCESS")
	req.Header.Set("x-enrollment-client-cert-fingerprint-sha256", "fp-aa")
	req.Header.Set("X-Enrollment-Client-Cert-Serial", "sn-01")

	md, verdict := src.Metadata(req)
	if verdict != VerdictTrusted || !md.Verified || md.FingerprintSHA256 != "fp-aa" || md.Serial != "sn-01" {
		t.Fatalf("metadata = %+v, verdict = %v; want trusted with all fields", md, verdict)
	}
}

func TestHeaderMetadataSourceMetadata(t *testing.T) {
	src, err := NewHeaderMetadataSource(testHeaderConfig())
	if err != nil {
		t.Fatal(err)
	}
	cfg := testHeaderConfig()

	newReq := func() *http.Request { return httptest.NewRequest(http.MethodPost, "/x", nil) }

	t.Run("complete positive metadata trusted", func(t *testing.T) {
		req := newReq()
		req.Header.Set(cfg.VerifiedHeader, "SUCCESS")
		req.Header.Set(cfg.FingerprintHeader, "fp-aa")
		req.Header.Set(cfg.SerialHeader, "sn-01")
		md, verdict := src.Metadata(req)
		if verdict != VerdictTrusted || !md.Verified || md.FingerprintSHA256 != "fp-aa" || md.Serial != "sn-01" {
			t.Fatalf("metadata = %+v, verdict = %v; want trusted", md, verdict)
		}
	})

	t.Run("absent metadata rejected", func(t *testing.T) {
		md, verdict := src.Metadata(newReq())
		if verdict != VerdictRejected {
			t.Fatalf("verdict = %v, want rejected", verdict)
		}
		_ = md
	})

	t.Run("false/unverified marker rejected", func(t *testing.T) {
		req := newReq()
		req.Header.Set(cfg.VerifiedHeader, "UNVERIFIED")
		req.Header.Set(cfg.FingerprintHeader, "fp-aa")
		req.Header.Set(cfg.SerialHeader, "sn-01")
		if _, verdict := src.Metadata(req); verdict != VerdictRejected {
			t.Fatalf("verdict = %v, want rejected", verdict)
		}
	})

	t.Run("missing fingerprint rejected", func(t *testing.T) {
		req := newReq()
		req.Header.Set(cfg.VerifiedHeader, "SUCCESS")
		req.Header.Set(cfg.SerialHeader, "sn-01")
		if _, verdict := src.Metadata(req); verdict != VerdictRejected {
			t.Fatalf("verdict = %v, want rejected", verdict)
		}
	})

	t.Run("missing serial rejected", func(t *testing.T) {
		req := newReq()
		req.Header.Set(cfg.VerifiedHeader, "SUCCESS")
		req.Header.Set(cfg.FingerprintHeader, "fp-aa")
		if _, verdict := src.Metadata(req); verdict != VerdictRejected {
			t.Fatalf("verdict = %v, want rejected", verdict)
		}
	})

	t.Run("duplicate fingerprint rejected", func(t *testing.T) {
		req := newReq()
		req.Header.Set(cfg.VerifiedHeader, "SUCCESS")
		req.Header.Add(cfg.FingerprintHeader, "fp-aa")
		req.Header.Add(cfg.FingerprintHeader, "fp-bb")
		req.Header.Set(cfg.SerialHeader, "sn-01")
		if _, verdict := src.Metadata(req); verdict != VerdictRejected {
			t.Fatalf("verdict = %v, want rejected", verdict)
		}
	})

	t.Run("duplicate serial rejected", func(t *testing.T) {
		req := newReq()
		req.Header.Set(cfg.VerifiedHeader, "SUCCESS")
		req.Header.Set(cfg.FingerprintHeader, "fp-aa")
		req.Header.Add(cfg.SerialHeader, "sn-01")
		req.Header.Add(cfg.SerialHeader, "sn-02")
		if _, verdict := src.Metadata(req); verdict != VerdictRejected {
			t.Fatalf("verdict = %v, want rejected", verdict)
		}
	})

	t.Run("duplicate verified rejected", func(t *testing.T) {
		req := newReq()
		req.Header.Add(cfg.VerifiedHeader, "SUCCESS")
		req.Header.Add(cfg.VerifiedHeader, "SUCCESS")
		req.Header.Set(cfg.FingerprintHeader, "fp-aa")
		req.Header.Set(cfg.SerialHeader, "sn-01")
		if _, verdict := src.Metadata(req); verdict != VerdictRejected {
			t.Fatalf("verdict = %v, want rejected", verdict)
		}
	})

	t.Run("comma-combined metadata rejected", func(t *testing.T) {
		req := newReq()
		req.Header.Set(cfg.VerifiedHeader, "SUCCESS")
		req.Header.Set(cfg.FingerprintHeader, "fp-aa,fp-bb")
		req.Header.Set(cfg.SerialHeader, "sn-01")
		if _, verdict := src.Metadata(req); verdict != VerdictRejected {
			t.Fatalf("verdict = %v, want rejected", verdict)
		}
	})

	t.Run("empty fingerprint rejected", func(t *testing.T) {
		req := newReq()
		req.Header.Set(cfg.VerifiedHeader, "SUCCESS")
		req.Header.Set(cfg.FingerprintHeader, "")
		req.Header.Set(cfg.SerialHeader, "sn-01")
		if _, verdict := src.Metadata(req); verdict != VerdictRejected {
			t.Fatalf("verdict = %v, want rejected", verdict)
		}
	})

	t.Run("control character rejected", func(t *testing.T) {
		req := newReq()
		req.Header.Set(cfg.VerifiedHeader, "SUCCESS")
		req.Header.Set(cfg.FingerprintHeader, "fp-\x00aa")
		req.Header.Set(cfg.SerialHeader, "sn-01")
		if _, verdict := src.Metadata(req); verdict != VerdictRejected {
			t.Fatalf("verdict = %v, want rejected", verdict)
		}
	})

	t.Run("embedded whitespace rejected", func(t *testing.T) {
		req := newReq()
		req.Header.Set(cfg.VerifiedHeader, "SUCCESS")
		req.Header.Set(cfg.FingerprintHeader, "fp aa")
		req.Header.Set(cfg.SerialHeader, "sn-01")
		if _, verdict := src.Metadata(req); verdict != VerdictRejected {
			t.Fatalf("verdict = %v, want rejected", verdict)
		}
	})
}
