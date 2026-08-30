package application_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	domain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/domain/enrollment"
	application "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/application"
	enrollmentruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/runtime"
	preonboardingdomain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	preonboardingruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/replaycapsule"
)

type testEvidenceHelper struct {
	priv               *ecdsa.PrivateKey
	csrDer             []byte
	csrB64             string
	csrSha256Hex       string
	publicKeySha256Hex string
}

func newTestEvidenceHelper(t *testing.T) *testEvidenceHelper {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "test-device"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		t.Fatal(err)
	}
	csrB64 := base64.StdEncoding.EncodeToString(csrDer)

	csrHash := sha256.Sum256(csrDer)
	csrSha256Hex := hex.EncodeToString(csrHash[:])

	spkiDer, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	spkiHash := sha256.Sum256(spkiDer)
	publicKeySha256Hex := hex.EncodeToString(spkiHash[:])

	return &testEvidenceHelper{
		priv:               priv,
		csrDer:             csrDer,
		csrB64:             csrB64,
		csrSha256Hex:       csrSha256Hex,
		publicKeySha256Hex: publicKeySha256Hex,
	}
}

func (h *testEvidenceHelper) buildJWS(t *testing.T, enrollmentID, nonce string, challengeVersion int, headerMutator func(map[string]interface{}), payloadMutator func(map[string]interface{})) string {
	t.Helper()
	header := map[string]interface{}{
		"alg": "ES256",
		"typ": "enrollment-pop+jws",
	}
	if headerMutator != nil {
		headerMutator(header)
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	payload := map[string]interface{}{
		"version":           1,
		"purpose":           "enrollment-pop",
		"enrollment_id":     enrollmentID,
		"challenge_version": challengeVersion,
		"nonce":             nonce,
		"csr_sha256":        h.csrSha256Hex,
		"public_key_sha256": h.publicKeySha256Hex,
	}
	if payloadMutator != nil {
		payloadMutator(payload)
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := []byte(headerB64 + "." + payloadB64)
	digest := sha256.Sum256(signingInput)
	r, s, err := ecdsa.Sign(rand.Reader, h.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	rBytes := make([]byte, 32)
	sBytes := make([]byte, 32)
	r.FillBytes(rBytes)
	s.FillBytes(sBytes)
	sigBytes := append(rBytes, sBytes...)
	sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)

	return headerB64 + "." + payloadB64 + "." + sigB64
}

type appTestHarness struct {
	ctx     context.Context
	store   *enrollmentruntime.MemoryStore
	service *application.Service
	enrID   string
	nonce   string
	tpmJSON json.RawMessage
}

func newAppTestHarness(t *testing.T) *appTestHarness {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	clock := testClock{now: now}
	verifier, err := capability.NewHMACVerifier([]byte("test-app-verifier-key"))
	if err != nil {
		t.Fatal(err)
	}
	authority := preonboardingruntime.NewMemoryStore(nil)
	store, err := enrollmentruntime.NewMemoryStore(authority)
	if err != nil {
		t.Fatal(err)
	}

	requestID := "por-app-test"
	deviceID := "device-app-test"
	req, err := preonboardingdomain.RestoreRequest(
		preonboardingdomain.ID(requestID), preonboardingdomain.PartnerID("partner-app-test"),
		preonboardingdomain.ClaimedDevice{}, preonboardingdomain.Agent{},
		preonboardingdomain.StateEnrollmentReady, &deviceID,
		now.Add(-time.Hour), now.Add(2*time.Hour), 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	authority.SeedRequest(req)
	reqKey, err := verifier.Derive(authpolicy.CredentialKindRequestAccessToken, "secret-app-req-token")
	if err != nil {
		t.Fatal(err)
	}
	uow, err := authority.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := uow.RequestAccessWriter().CreateRequestAccess(ctx, reqKey, capability.RequestAccessRecord{
		PreOnboardingRequestID: requestID,
		ExpiresAt:              now.Add(time.Hour),
		State:                  capability.StateActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := uow.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	requirements := application.EvidenceRequirements{
		TPMEvidenceProtocolVersions: []string{"test-v1"},
		MinimumAssurance:            "A1",
		AllowedKeyProfiles:          []string{"ECDSA_P256"},
	}
	if err := store.SetInitialPolicy("partner-app-test", deviceID, "PARTNER_AUTH", true, requirements); err != nil {
		t.Fatal(err)
	}
	protector, err := replaycapsule.NewAEADProtector(bytes.Repeat([]byte{0x77}, 32), "test-capsule-key", func() time.Time {
		return clock.Now().Add(time.Hour)
	})
	if err != nil {
		t.Fatal(err)
	}

	svc, err := application.NewService(application.ServiceConfig{
		UOWManager:                    store,
		Clock:                         clock,
		RetentionPolicy:               application.StaticIdempotencyRetentionPolicy{Duration: time.Hour},
		ReplayCapsulePolicy:           application.StaticReplayCapsuleRetentionPolicy{Duration: 45 * time.Minute},
		ChallengeLifetime:             application.StaticChallengeLifetimePolicy{Duration: 20 * time.Minute},
		EnrollmentAccessTokenLifetime: application.StaticEnrollmentAccessTokenLifetimePolicy{Duration: time.Hour},
		Create: &application.CreateDependencies{
			IDGenerator:        appFixedID("enr-app-001"),
			ChallengeGenerator: appFixedChallenge(0x42),
			TokenGenerator:     appFixedToken("eat-app-001"),
			Verifier:           verifier,
			Protector:          protector,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	createRes, err := svc.CreateInitial(ctx, application.CreateInitialCommand{
		PreOnboardingRequestID: requestID,
		CertificateUsage:       "PARTNER_AUTH",
		IdempotencyKey:         "idem-app-create-001",
		CorrelationID:          "corr-create-001",
	})
	if err != nil {
		t.Fatal(err)
	}

	return &appTestHarness{
		ctx:     ctx,
		store:   store,
		service: svc,
		enrID:   createRes.Snapshot.EnrollmentID,
		nonce:   createRes.Snapshot.Challenge.Nonce,
		tpmJSON: json.RawMessage(`{"tpm":"mock-payload"}`),
	}
}

type testClock struct{ now time.Time }

func (c testClock) Now() time.Time  { return c.now }
func (c testClock) Validate() error { return nil }

type appFixedID string

func (g appFixedID) NewEnrollmentID(context.Context) (string, error) { return string(g), nil }

type appFixedChallenge byte

func (g appFixedChallenge) NewChallengeNonce(context.Context) ([]byte, error) {
	return bytes.Repeat([]byte{byte(g)}, 16), nil
}

type appFixedToken string

func (g appFixedToken) NewEnrollmentAccessToken(context.Context) (string, error) {
	return string(g), nil
}

func TestSubmitEvidenceHappyPathAndResourceIdempotency(t *testing.T) {
	h := newAppTestHarness(t)
	ev := newTestEvidenceHelper(t)
	jws := ev.buildJWS(t, h.enrID, h.nonce, 1, nil, nil)

	cmd := application.EvidenceSubmissionCommand{
		EnrollmentID:     h.enrID,
		ChallengeVersion: 1,
		CsrDerBase64:     ev.csrB64,
		PopFormat:        "enrollment-pop+jws",
		PopJWS:           jws,
		TpmFormat:        "enrollment-tpm-evidence",
		TpmVersion:       "1",
		TpmPayload:       h.tpmJSON,
	}

	res, err := h.service.SubmitEvidence(h.ctx, cmd)
	if err != nil {
		t.Fatalf("SubmitEvidence failed: %v", err)
	}
	if res.EnrollmentID != h.enrID || res.State != domain.StateEvidenceReceived || res.StatusURL != "/v1/enrollments/"+h.enrID || res.Replay {
		t.Fatalf("unexpected res: %#v", res)
	}

	// Retry exact same evidence -> idempotent replay
	retryRes, err := h.service.SubmitEvidence(h.ctx, cmd)
	if err != nil {
		t.Fatalf("SubmitEvidence retry failed: %v", err)
	}
	if retryRes.EnrollmentID != h.enrID || retryRes.State != domain.StateEvidenceReceived || !retryRes.Replay {
		t.Fatalf("unexpected retry res: %#v", retryRes)
	}

	// Conflicting evidence with different CSR on second submission -> ErrEvidenceConflict
	ev2 := newTestEvidenceHelper(t)
	jws2 := ev2.buildJWS(t, h.enrID, h.nonce, 1, nil, nil)
	cmd2 := cmd
	cmd2.CsrDerBase64 = ev2.csrB64
	cmd2.PopJWS = jws2
	if _, err := h.service.SubmitEvidence(h.ctx, cmd2); !errors.Is(err, application.ErrEvidenceConflict) {
		t.Fatalf("expected ErrEvidenceConflict, got: %v", err)
	}
}

func TestSubmitEvidenceCSRValidationFailures(t *testing.T) {
	h := newAppTestHarness(t)
	ev := newTestEvidenceHelper(t)
	jws := ev.buildJWS(t, h.enrID, h.nonce, 1, nil, nil)

	baseCmd := application.EvidenceSubmissionCommand{
		EnrollmentID:     h.enrID,
		ChallengeVersion: 1,
		CsrDerBase64:     ev.csrB64,
		PopFormat:        "enrollment-pop+jws",
		PopJWS:           jws,
		TpmFormat:        "enrollment-tpm-evidence",
		TpmVersion:       "1",
		TpmPayload:       h.tpmJSON,
	}

	t.Run("invalid base64", func(t *testing.T) {
		c := baseCmd
		c.CsrDerBase64 = "%%%not-base64%%%"
		if _, err := h.service.SubmitEvidence(h.ctx, c); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid, got %v", err)
		}
	})

	t.Run("malformed DER", func(t *testing.T) {
		c := baseCmd
		c.CsrDerBase64 = base64.StdEncoding.EncodeToString([]byte("garbage not a DER CSR"))
		if _, err := h.service.SubmitEvidence(h.ctx, c); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid, got %v", err)
		}
	})

	t.Run("disallowed key type RSA", func(t *testing.T) {
		rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		rsaCsr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject:            pkix.Name{CommonName: "rsa-device"},
			SignatureAlgorithm: x509.SHA256WithRSA,
		}, rsaPriv)
		if err != nil {
			t.Fatal(err)
		}
		c := baseCmd
		c.CsrDerBase64 = base64.StdEncoding.EncodeToString(rsaCsr)
		if _, err := h.service.SubmitEvidence(h.ctx, c); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for RSA key, got %v", err)
		}
	})

	t.Run("disallowed curve P-384", func(t *testing.T) {
		p384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p384Csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject:            pkix.Name{CommonName: "p384-device"},
			SignatureAlgorithm: x509.ECDSAWithSHA384,
		}, p384Priv)
		if err != nil {
			t.Fatal(err)
		}
		c := baseCmd
		c.CsrDerBase64 = base64.StdEncoding.EncodeToString(p384Csr)
		if _, err := h.service.SubmitEvidence(h.ctx, c); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for P-384, got %v", err)
		}
	})
}

func TestSubmitEvidenceJWSValidationFailures(t *testing.T) {
	h := newAppTestHarness(t)
	ev := newTestEvidenceHelper(t)

	baseCmd := func(jws string) application.EvidenceSubmissionCommand {
		return application.EvidenceSubmissionCommand{
			EnrollmentID:     h.enrID,
			ChallengeVersion: 1,
			CsrDerBase64:     ev.csrB64,
			PopFormat:        "enrollment-pop+jws",
			PopJWS:           jws,
			TpmFormat:        "enrollment-tpm-evidence",
			TpmVersion:       "1",
			TpmPayload:       h.tpmJSON,
		}
	}

	t.Run("malformed serialization - missing parts", func(t *testing.T) {
		cmd := baseCmd("only.two")
		if _, err := h.service.SubmitEvidence(h.ctx, cmd); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid, got %v", err)
		}
	})

	t.Run("alg=none", func(t *testing.T) {
		jws := ev.buildJWS(t, h.enrID, h.nonce, 1, func(hdr map[string]interface{}) {
			hdr["alg"] = "none"
		}, nil)
		if _, err := h.service.SubmitEvidence(h.ctx, baseCmd(jws)); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for alg=none, got %v", err)
		}
	})

	t.Run("non-ES256 alg", func(t *testing.T) {
		jws := ev.buildJWS(t, h.enrID, h.nonce, 1, func(hdr map[string]interface{}) {
			hdr["alg"] = "RS256"
		}, nil)
		if _, err := h.service.SubmitEvidence(h.ctx, baseCmd(jws)); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for alg=RS256, got %v", err)
		}
	})

	t.Run("missing or wrong typ", func(t *testing.T) {
		jws := ev.buildJWS(t, h.enrID, h.nonce, 1, func(hdr map[string]interface{}) {
			hdr["typ"] = "JWT"
		}, nil)
		if _, err := h.service.SubmitEvidence(h.ctx, baseCmd(jws)); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for typ=JWT, got %v", err)
		}
	})

	t.Run("forbidden jwk header", func(t *testing.T) {
		jws := ev.buildJWS(t, h.enrID, h.nonce, 1, func(hdr map[string]interface{}) {
			hdr["jwk"] = map[string]string{"kty": "EC"}
		}, nil)
		if _, err := h.service.SubmitEvidence(h.ctx, baseCmd(jws)); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for jwk header, got %v", err)
		}
	})

	t.Run("forbidden jku header", func(t *testing.T) {
		jws := ev.buildJWS(t, h.enrID, h.nonce, 1, func(hdr map[string]interface{}) {
			hdr["jku"] = "https://attacker.example/jwks.json"
		}, nil)
		if _, err := h.service.SubmitEvidence(h.ctx, baseCmd(jws)); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for jku header, got %v", err)
		}
	})

	t.Run("forbidden x5u header", func(t *testing.T) {
		jws := ev.buildJWS(t, h.enrID, h.nonce, 1, func(hdr map[string]interface{}) {
			hdr["x5u"] = "https://attacker.example/cert.pem"
		}, nil)
		if _, err := h.service.SubmitEvidence(h.ctx, baseCmd(jws)); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for x5u header, got %v", err)
		}
	})

	t.Run("wrong nonce in payload", func(t *testing.T) {
		jws := ev.buildJWS(t, h.enrID, "wrong-nonce-value", 1, nil, func(payload map[string]interface{}) {
			payload["nonce"] = "wrong-nonce-value"
		})
		if _, err := h.service.SubmitEvidence(h.ctx, baseCmd(jws)); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for wrong nonce, got %v", err)
		}
	})

	t.Run("wrong challenge_version in payload", func(t *testing.T) {
		jws := ev.buildJWS(t, h.enrID, h.nonce, 1, nil, func(payload map[string]interface{}) {
			payload["challenge_version"] = 2
		})
		if _, err := h.service.SubmitEvidence(h.ctx, baseCmd(jws)); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for wrong challenge_version, got %v", err)
		}
	})

	t.Run("wrong enrollment_id in payload", func(t *testing.T) {
		jws := ev.buildJWS(t, h.enrID, h.nonce, 1, nil, func(payload map[string]interface{}) {
			payload["enrollment_id"] = "enr-different"
		})
		if _, err := h.service.SubmitEvidence(h.ctx, baseCmd(jws)); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for wrong enrollment_id, got %v", err)
		}
	})

	t.Run("wrong purpose in payload", func(t *testing.T) {
		jws := ev.buildJWS(t, h.enrID, h.nonce, 1, nil, func(payload map[string]interface{}) {
			payload["purpose"] = "not-enrollment-pop"
		})
		if _, err := h.service.SubmitEvidence(h.ctx, baseCmd(jws)); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for wrong purpose, got %v", err)
		}
	})

	t.Run("wrong version in payload", func(t *testing.T) {
		jws := ev.buildJWS(t, h.enrID, h.nonce, 1, nil, func(payload map[string]interface{}) {
			payload["version"] = 2
		})
		if _, err := h.service.SubmitEvidence(h.ctx, baseCmd(jws)); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for version=2, got %v", err)
		}
	})

	t.Run("wrong CSR hash in payload", func(t *testing.T) {
		jws := ev.buildJWS(t, h.enrID, h.nonce, 1, nil, func(payload map[string]interface{}) {
			payload["csr_sha256"] = strings.Repeat("a", 64)
		})
		if _, err := h.service.SubmitEvidence(h.ctx, baseCmd(jws)); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for wrong csr_sha256, got %v", err)
		}
	})

	t.Run("wrong SPKI hash in payload", func(t *testing.T) {
		jws := ev.buildJWS(t, h.enrID, h.nonce, 1, nil, func(payload map[string]interface{}) {
			payload["public_key_sha256"] = strings.Repeat("b", 64)
		})
		if _, err := h.service.SubmitEvidence(h.ctx, baseCmd(jws)); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for wrong public_key_sha256, got %v", err)
		}
	})

	t.Run("tampered signature", func(t *testing.T) {
		validJWS := ev.buildJWS(t, h.enrID, h.nonce, 1, nil, nil)
		parts := strings.Split(validJWS, ".")
		sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		sigBytes[0] ^= 0xFF // flip bits
		badJWS := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sigBytes)
		if _, err := h.service.SubmitEvidence(h.ctx, baseCmd(badJWS)); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for tampered signature, got %v", err)
		}
	})

	t.Run("duplicate member in JWS protected header", func(t *testing.T) {
		hdrJSON := []byte(`{"alg":"ES256","typ":"enrollment-pop+jws","alg":"ES256"}`)
		hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
		plJSON, _ := json.Marshal(map[string]interface{}{
			"version":           1,
			"purpose":           "enrollment-pop",
			"enrollment_id":     h.enrID,
			"challenge_version": 1,
			"nonce":             h.nonce,
			"csr_sha256":        ev.csrSha256Hex,
			"public_key_sha256": ev.publicKeySha256Hex,
		})
		plB64 := base64.RawURLEncoding.EncodeToString(plJSON)
		digest := sha256.Sum256([]byte(hdrB64 + "." + plB64))
		r, s, _ := ecdsa.Sign(rand.Reader, ev.priv, digest[:])
		rB := make([]byte, 32)
		sB := make([]byte, 32)
		r.FillBytes(rB)
		s.FillBytes(sB)
		sigB64 := base64.RawURLEncoding.EncodeToString(append(rB, sB...))
		dupJWS := hdrB64 + "." + plB64 + "." + sigB64
		if _, err := h.service.SubmitEvidence(h.ctx, baseCmd(dupJWS)); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for duplicate header member, got %v", err)
		}
	})

	t.Run("duplicate member in JWS payload", func(t *testing.T) {
		hdrJSON, _ := json.Marshal(map[string]interface{}{
			"alg": "ES256",
			"typ": "enrollment-pop+jws",
		})
		hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
		plJSON := []byte(fmt.Sprintf(`{"version":1,"purpose":"enrollment-pop","enrollment_id":%q,"challenge_version":1,"nonce":%q,"csr_sha256":%q,"public_key_sha256":%q,"version":1}`,
			h.enrID, h.nonce, ev.csrSha256Hex, ev.publicKeySha256Hex))
		plB64 := base64.RawURLEncoding.EncodeToString(plJSON)
		digest := sha256.Sum256([]byte(hdrB64 + "." + plB64))
		r, s, _ := ecdsa.Sign(rand.Reader, ev.priv, digest[:])
		rB := make([]byte, 32)
		sB := make([]byte, 32)
		r.FillBytes(rB)
		s.FillBytes(sB)
		sigB64 := base64.RawURLEncoding.EncodeToString(append(rB, sB...))
		dupJWS := hdrB64 + "." + plB64 + "." + sigB64
		if _, err := h.service.SubmitEvidence(h.ctx, baseCmd(dupJWS)); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for duplicate payload member, got %v", err)
		}
	})

	t.Run("duplicate member in TPM payload", func(t *testing.T) {
		cmd := baseCmd(ev.buildJWS(t, h.enrID, h.nonce, 1, nil, nil))
		cmd.TpmPayload = json.RawMessage(`{"field":"a","field":"b"}`)
		if _, err := h.service.SubmitEvidence(h.ctx, cmd); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for duplicate TPM payload member, got %v", err)
		}
	})

	t.Run("nested duplicate member in TPM payload", func(t *testing.T) {
		cmd := baseCmd(ev.buildJWS(t, h.enrID, h.nonce, 1, nil, nil))
		cmd.TpmPayload = json.RawMessage(`{"nested":{"a":1,"a":2}}`)
		if _, err := h.service.SubmitEvidence(h.ctx, cmd); !errors.Is(err, application.ErrEvidenceInvalid) {
			t.Fatalf("expected ErrEvidenceInvalid for nested duplicate TPM payload member, got %v", err)
		}
	})
}

func TestSubmitEvidenceCSRSignatureAlgorithmIndependent(t *testing.T) {
	// SOL-M5.8-POST-002: P-256 CSR with valid non-SHA256 self-signature (e.g. ECDSAWithSHA384 / ECDSAWithSHA512)
	// must be accepted according to Protocol v0.2.5.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, sigAlg := range []x509.SignatureAlgorithm{x509.ECDSAWithSHA384, x509.ECDSAWithSHA512} {
		t.Run(sigAlg.String(), func(t *testing.T) {
			h := newAppTestHarness(t)
			csrDer, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
				Subject:            pkix.Name{CommonName: "device-sigalg-test"},
				SignatureAlgorithm: sigAlg,
			}, priv)
			if err != nil {
				t.Fatal(err)
			}
			csrB64 := base64.StdEncoding.EncodeToString(csrDer)
			csrHash := sha256.Sum256(csrDer)
			csrSha256Hex := hex.EncodeToString(csrHash[:])

			spkiDer, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			spkiHash := sha256.Sum256(spkiDer)
			publicKeySha256Hex := hex.EncodeToString(spkiHash[:])

			// Build valid JWS PoP (alg=ES256 is for JWS)
			headerJSON, _ := json.Marshal(map[string]interface{}{"alg": "ES256", "typ": "enrollment-pop+jws"})
			headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
			payloadJSON, _ := json.Marshal(map[string]interface{}{
				"version":           1,
				"purpose":           "enrollment-pop",
				"enrollment_id":     h.enrID,
				"challenge_version": 1,
				"nonce":             h.nonce,
				"csr_sha256":        csrSha256Hex,
				"public_key_sha256": publicKeySha256Hex,
			})
			payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
			digest := sha256.Sum256([]byte(headerB64 + "." + payloadB64))
			r, sVal, err := ecdsa.Sign(rand.Reader, priv, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			rB := make([]byte, 32)
			sB := make([]byte, 32)
			r.FillBytes(rB)
			sVal.FillBytes(sB)
			sigB64 := base64.RawURLEncoding.EncodeToString(append(rB, sB...))
			jws := headerB64 + "." + payloadB64 + "." + sigB64

			cmd := application.EvidenceSubmissionCommand{
				EnrollmentID:     h.enrID,
				ChallengeVersion: 1,
				CsrDerBase64:     csrB64,
				PopFormat:        "enrollment-pop+jws",
				PopJWS:           jws,
				TpmFormat:        "enrollment-tpm-evidence",
				TpmVersion:       "1",
				TpmPayload:       h.tpmJSON,
			}

			res, err := h.service.SubmitEvidence(h.ctx, cmd)
			if err != nil {
				t.Fatalf("SubmitEvidence failed for %s: %v", sigAlg, err)
			}
			if res.State != domain.StateEvidenceReceived {
				t.Fatalf("unexpected state: %s", res.State)
			}
		})
	}
}

func TestEvidenceIdentityV1_VectorsAndEncodings(t *testing.T) {
	csrDer := []byte("mock-pkcs10-csr-der-bytes-for-vector-testing")
	jwsCompact := "eyJhbGciOiJFUzI1NiIsInR5cCI6ImVucm9sbG1lbnQtcG9wK2p3cyJ9.payload.sig"
	tpmFormat := "enrollment-tpm-evidence"
	tpmVersion := "1"
	tpmPayload := []byte(`{"version":1,"pcr_values":{"0":"abc","1":"def"}}`)

	// 1. Reordered TPM JSON produces the EXACT same EvidenceIdentityV1
	tpmPayloadReordered := []byte(`{"pcr_values":{"1":"def","0":"abc"},"version":1}`)
	fp1, rep1, err := application.ComputeEvidenceIdentityV1("enr-001", 1, csrDer, jwsCompact, tpmFormat, tpmVersion, tpmPayload, nil)
	if err != nil {
		t.Fatal(err)
	}
	fp2, rep2, err := application.ComputeEvidenceIdentityV1("enr-001", 1, csrDer, jwsCompact, tpmFormat, tpmVersion, tpmPayloadReordered, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !fp1.Equal(fp2) {
		t.Fatalf("reordered TPM JSON must produce identical fingerprint: %v != %v", fp1, fp2)
	}
	if !bytes.Equal(rep1, rep2) {
		t.Fatalf("reordered TPM JSON must produce identical representation: %x != %x", rep1, rep2)
	}

	// 2. Whitespace in TPM JSON produces the EXACT same EvidenceIdentityV1
	tpmPayloadWhitespace := []byte("{\n  \"version\": 1,\n  \"pcr_values\": {\n    \"0\": \"abc\",\n    \"1\": \"def\"\n  }\n}")
	fp3, rep3, err := application.ComputeEvidenceIdentityV1("enr-001", 1, csrDer, jwsCompact, tpmFormat, tpmVersion, tpmPayloadWhitespace, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !fp1.Equal(fp3) || !bytes.Equal(rep1, rep3) {
		t.Fatalf("whitespace in TPM JSON must produce identical fingerprint: %v != %v", fp1, fp3)
	}

	// 3. Changed TPM value produces DIFFERENT EvidenceIdentityV1
	tpmPayloadDiff := []byte(`{"version":1,"pcr_values":{"0":"abc","1":"different"}}`)
	fpDiff, _, err := application.ComputeEvidenceIdentityV1("enr-001", 1, csrDer, jwsCompact, tpmFormat, tpmVersion, tpmPayloadDiff, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fp1.Equal(fpDiff) {
		t.Fatal("different TPM payload must produce different fingerprint")
	}

	// 4. agent_assertions absent (nil) vs present empty ({}) produce DIFFERENT EvidenceIdentityV1
	fpAbsent, _, err := application.ComputeEvidenceIdentityV1("enr-001", 1, csrDer, jwsCompact, tpmFormat, tpmVersion, tpmPayload, nil)
	if err != nil {
		t.Fatal(err)
	}
	fpPresentEmpty, _, err := application.ComputeEvidenceIdentityV1("enr-001", 1, csrDer, jwsCompact, tpmFormat, tpmVersion, tpmPayload, json.RawMessage("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if fpAbsent.Equal(fpPresentEmpty) {
		t.Fatal("agent_assertions absent must produce different fingerprint from agent_assertions present empty ({})")
	}

	// 5. Changed agent_assertions produces DIFFERENT EvidenceIdentityV1
	fpAA1, _, err := application.ComputeEvidenceIdentityV1("enr-001", 1, csrDer, jwsCompact, tpmFormat, tpmVersion, tpmPayload, json.RawMessage(`{"tpm_ready":true}`))
	if err != nil {
		t.Fatal(err)
	}
	fpAA2, _, err := application.ComputeEvidenceIdentityV1("enr-001", 1, csrDer, jwsCompact, tpmFormat, tpmVersion, tpmPayload, json.RawMessage(`{"tpm_ready":false}`))
	if err != nil {
		t.Fatal(err)
	}
	if fpAA1.Equal(fpAA2) {
		t.Fatal("different agent_assertions must produce different fingerprint")
	}

	// 6. Changed enrollment_id produces DIFFERENT EvidenceIdentityV1
	fpEnrDiff, _, err := application.ComputeEvidenceIdentityV1("enr-002", 1, csrDer, jwsCompact, tpmFormat, tpmVersion, tpmPayload, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fp1.Equal(fpEnrDiff) {
		t.Fatal("different enrollment_id must produce different fingerprint")
	}

	// 7. Changed challenge_version produces DIFFERENT EvidenceIdentityV1
	fpVerDiff, _, err := application.ComputeEvidenceIdentityV1("enr-001", 2, csrDer, jwsCompact, tpmFormat, tpmVersion, tpmPayload, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fp1.Equal(fpVerDiff) {
		t.Fatal("different challenge_version must produce different fingerprint")
	}

	// 8. Different JWS compact string produces DIFFERENT EvidenceIdentityV1
	fpJWSDiff, _, err := application.ComputeEvidenceIdentityV1("enr-001", 1, csrDer, jwsCompact+".different", tpmFormat, tpmVersion, tpmPayload, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fp1.Equal(fpJWSDiff) {
		t.Fatal("different JWS compact string must produce different fingerprint")
	}

	// 9. Framing structure verification: check domain, length prefix and component 1
	if !bytes.Contains(rep1, []byte(application.EvidenceIdentityDomain)) {
		t.Fatal("representation must contain EvidenceIdentityDomain literal")
	}
}

func TestComputeEvidenceIdentityV1FixedVector(t *testing.T) {
	// Fixed end-to-end known vector (SOL-M5.8-FIXREV-001 section L). The
	// expected digest was computed independently of ComputeEvidenceIdentityV1
	// by assembling the ten ordered, domain-separated, uint32-big-endian
	// length-framed components and hashing with SHA-256. It must fail if
	// component order, framing, integer encoding, or JCS source bytes change.
	enrollmentID := "enr-fixed-vector-001"
	challengeVersion := 7
	csrDer := []byte("test-csr-der-bytes-for-vector")
	jwsCompact := "e30.e30.abc"
	tpmFormat := "enrollment-tpm-evidence"
	tpmVersion := "1"
	tpmPayload := []byte(`{"a":1,"b":"x"}`)

	fp, _, err := application.ComputeEvidenceIdentityV1(
		enrollmentID, challengeVersion, csrDer, jwsCompact,
		tpmFormat, tpmVersion, tpmPayload, nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	const wantHex = "dd4d6da55f3a27961aae78c9f39a3f4eafcc4709a35ebb1505a1cee575b53785"
	digest := fp.Digest()
	if got := hex.EncodeToString(digest[:]); got != wantHex {
		t.Fatalf("EvidenceIdentityV1 digest = %s, want %s", got, wantHex)
	}
}

// SOL-M5.8-AUDIT-001: RFC 8785/I-JSON Unicode admission operates on the
// original raw JSON bytes and rejects malformed surrogate data before JCS
// could silently convert it to U+FFFD.
func TestComputeEvidenceIdentityV1UnicodeAdmission(t *testing.T) {
	base := func(tpmPayload []byte) error {
		_, _, err := application.ComputeEvidenceIdentityV1(
			"enr-001", 1, []byte("test-csr-der-bytes-for-vector"), "e30.e30.abc",
			"enrollment-tpm-evidence", "1", tpmPayload, nil,
		)
		return err
	}

	cases := []struct {
		name string
		in   string
		want bool // true = admitted (no error)
	}{
		{"lone high surrogate", `{"x":"\ud800"}`, false},
		{"lone low surrogate", `{"x":"\udc00"}`, false},
		{"high followed by non-low", `{"x":"\ud800\u0041"}`, false},
		{"high followed by high", `{"x":"\ud800\ud800"}`, false},
		{"low followed by low", `{"x":"\udc00\udc00"}`, false},
		{"valid pair", `{"x":"\ud83d\ude00"}`, true},
		{"literal replacement char escape", `{"x":"\ufffd"}`, true},
		{"plain ascii", `{"x":"ok"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := base([]byte(tc.in))
			if tc.want && err != nil {
				t.Fatalf("admissible input rejected: %v", err)
			}
			if !tc.want && err == nil {
				t.Fatal("malformed surrogate admitted")
			}
		})
	}

	t.Run("invalid raw UTF-8 inside JSON string", func(t *testing.T) {
		payload := append([]byte(`{"x":"a`), append([]byte{0xFF}, []byte(`"}`)...)...)
		if err := base(payload); err == nil {
			t.Fatal("invalid raw UTF-8 must be rejected")
		}
	})

	t.Run("valid surrogate pair and literal U+FFFD are distinct accepted identities", func(t *testing.T) {
		fpPair, _, err := application.ComputeEvidenceIdentityV1(
			"enr-001", 1, []byte("test-csr-der-bytes-for-vector"), "e30.e30.abc",
			"enrollment-tpm-evidence", "1", []byte(`{"x":"\ud83d\ude00"}`), nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		fpReplacement, _, err := application.ComputeEvidenceIdentityV1(
			"enr-001", 1, []byte("test-csr-der-bytes-for-vector"), "e30.e30.abc",
			"enrollment-tpm-evidence", "1", []byte(`{"x":"\ufffd"}`), nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		if fpPair.Equal(fpReplacement) {
			t.Fatal("surrogate pair and literal U+FFFD must have different identities")
		}
	})
}
