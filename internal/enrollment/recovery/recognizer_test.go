package recovery_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/recovery"
)

type requestStore struct {
	records map[capability.VerifierKey]capability.RequestAccessRecord
	err     error
}

func (s *requestStore) LookupRequestAccess(_ context.Context, key capability.VerifierKey) (*capability.RequestAccessRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	rec, ok := s.records[key]
	if !ok {
		return nil, capability.ErrNotFound
	}
	cp := rec
	return &cp, nil
}

func (s *requestStore) LookupEnrollmentAccess(context.Context, capability.VerifierKey) (*capability.EnrollmentAccessRecord, error) {
	return nil, capability.ErrNotFound
}

func TestRecognizer_ConsumedCapabilityOnly(t *testing.T) {
	verifier, err := capability.NewHMACVerifier([]byte("m57-recovery-verifier-key"))
	if err != nil {
		t.Fatal(err)
	}
	consumedKey, err := verifier.Derive(authpolicy.CredentialKindRequestAccessToken, "consumed-secret")
	if err != nil {
		t.Fatal(err)
	}
	activeKey, err := verifier.Derive(authpolicy.CredentialKindRequestAccessToken, "active-secret")
	if err != nil {
		t.Fatal(err)
	}
	store := &requestStore{records: map[capability.VerifierKey]capability.RequestAccessRecord{
		consumedKey: {PreOnboardingRequestID: "por-consumed", ExpiresAt: time.Now().Add(-time.Hour), State: capability.StateConsumed},
		activeKey:   {PreOnboardingRequestID: "por-active", ExpiresAt: time.Now().Add(time.Hour), State: capability.StateActive},
	}}
	r, err := recovery.NewRecognizer(verifier, store)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := r.Recognize(context.Background(), "consumed-secret")
	if err != nil {
		t.Fatal(err)
	}
	if proof.IsZero() || proof.RequestID() != "por-consumed" {
		t.Fatalf("proof = %#v", proof)
	}
	if !proof.Matches("por-consumed", consumedKey) {
		t.Fatal("proof did not match the exact retained consumed verifier")
	}
	if proof.Matches("por-consumed", activeKey) || proof.Matches("por-other", consumedKey) {
		t.Fatal("proof matched a different request or verifier")
	}

	if _, err := r.Recognize(context.Background(), "active-secret"); !errors.Is(err, recovery.ErrNotRecognized) {
		t.Fatalf("active token recognition error = %v, want ErrNotRecognized", err)
	}
	if _, err := r.Recognize(context.Background(), "unknown-secret"); !errors.Is(err, recovery.ErrNotRecognized) {
		t.Fatalf("unknown token recognition error = %v, want ErrNotRecognized", err)
	}
}

func TestRecognizer_StoreFailureIsIndeterminate(t *testing.T) {
	verifier, err := capability.NewHMACVerifier([]byte("m57-recovery-verifier-key"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := recovery.NewRecognizer(verifier, &requestStore{err: errors.New("backend down")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Recognize(context.Background(), "some-secret"); !errors.Is(err, recovery.ErrDependencyUnavailable) {
		t.Fatalf("error = %v, want ErrDependencyUnavailable", err)
	}
}
