package application

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/capability"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	domain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/domain/enrollment"
	enrollmentrecovery "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/recovery"
	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
	preonboardingdomain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/replaycapsule"
)

// Service coordinates the M5.7 INITIAL RequestAccessToken exchange. It owns
// no HTTP, generated OpenAPI, TPM/PoP, CA, or physical persistence behavior.
type Service struct {
	uowManager              UnitOfWorkManager
	clock                   Clock
	retentionPolicy         IdempotencyRetentionPolicy
	replayCapsulePolicy     ReplayCapsuleRetentionPolicy
	challengeLifetime       ChallengeLifetimePolicy
	enrollmentTokenLifetime EnrollmentAccessTokenLifetimePolicy
	create                  *CreateDependencies
}

// ServiceConfig contains only mandatory dependencies for the M5.7 INITIAL
// secret-originator operation. Quantitative lifetimes are injected rather than
// frozen by this package.
type ServiceConfig struct {
	UOWManager                    UnitOfWorkManager
	Clock                         Clock
	RetentionPolicy               IdempotencyRetentionPolicy
	ReplayCapsulePolicy           ReplayCapsuleRetentionPolicy
	ChallengeLifetime             ChallengeLifetimePolicy
	EnrollmentAccessTokenLifetime EnrollmentAccessTokenLifetimePolicy
	Create                        *CreateDependencies
}

type validator interface{ Validate() error }

func isNilLike(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

func validateDependency(name string, dep any) error {
	if isNilLike(dep) {
		return fmt.Errorf("enrollment application: %s missing or typed-nil", name)
	}
	if v, ok := dep.(validator); ok {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("enrollment application: %s invalid: %w", name, err)
		}
	}
	return nil
}

func NewService(cfg ServiceConfig) (*Service, error) {
	s := &Service{
		uowManager:              cfg.UOWManager,
		clock:                   cfg.Clock,
		retentionPolicy:         cfg.RetentionPolicy,
		replayCapsulePolicy:     cfg.ReplayCapsulePolicy,
		challengeLifetime:       cfg.ChallengeLifetime,
		enrollmentTokenLifetime: cfg.EnrollmentAccessTokenLifetime,
		create:                  cfg.Create,
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) Validate() error {
	if s == nil {
		return errors.New("enrollment application: nil service")
	}
	if err := validateDependency("uow manager", s.uowManager); err != nil {
		return err
	}
	if err := validateDependency("clock", s.clock); err != nil {
		return err
	}
	if err := validateDependency("idempotency retention policy", s.retentionPolicy); err != nil {
		return err
	}
	if err := validateDependency("replay capsule policy", s.replayCapsulePolicy); err != nil {
		return err
	}
	if err := validateDependency("challenge lifetime", s.challengeLifetime); err != nil {
		return err
	}
	if err := validateDependency("enrollment access token lifetime", s.enrollmentTokenLifetime); err != nil {
		return err
	}
	if s.retentionPolicy.ReservationDuration() <= 0 ||
		s.replayCapsulePolicy.ReplayCapsuleLifetime() <= 0 ||
		s.challengeLifetime.ChallengeLifetime() <= 0 ||
		s.enrollmentTokenLifetime.EnrollmentAccessTokenLifetime() <= 0 {
		return errors.New("enrollment application: all lifetimes must be positive")
	}
	if isNilLike(s.create) {
		return errors.New("enrollment application: create dependencies missing")
	}
	if err := validateDependency("create id generator", s.create.IDGenerator); err != nil {
		return err
	}
	if err := validateDependency("create challenge generator", s.create.ChallengeGenerator); err != nil {
		return err
	}
	if err := validateDependency("create token generator", s.create.TokenGenerator); err != nil {
		return err
	}
	if err := validateDependency("create verifier", s.create.Verifier); err != nil {
		return err
	}
	if err := validateDependency("create protector", s.create.Protector); err != nil {
		return err
	}
	return nil
}

// RecoverInitialCommand carries only request material that is part of the
// createEnrollment operation. The pre-onboarding binding is intentionally
// absent: recovery obtains that authoritative binding exclusively from the
// opaque consumed-capability Proof returned by enrollment/recovery.
type RecoverInitialCommand struct {
	CertificateUsage string
	IdempotencyKey   string
	CorrelationID    string
}

type executionMode uint8

const (
	executionModeNew executionMode = iota + 1
	executionModeRecovery
)

// CreateInitial performs the M5.7 NEW INITIAL exchange through
// CHALLENGE_ISSUED. It is the ordinary-authentication path and therefore
// accepts only an ACTIVE RequestAccess capability. A CONSUMED capability is
// rejected here even when an exact committed idempotency record exists; exact
// response-loss recovery is available only through RecoverInitial with an
// opaque consumed-capability proof.
func (s *Service) CreateInitial(ctx context.Context, cmd CreateInitialCommand) (CreateInitialResult, error) {
	return s.executeInitial(ctx, cmd, executionModeNew, enrollmentrecovery.Proof{})
}

// RecoverInitial performs exact response-loss recovery for a previously
// committed INITIAL exchange. Proof establishes possession of the retained
// CONSUMED RequestAccess capability; this method then independently requires
// an exact committed idempotency scope/fingerprint/result and a valid Replay
// Capsule. It never grants NEW mutation authority and never reactivates or
// remints a capability.
func (s *Service) RecoverInitial(ctx context.Context, proof enrollmentrecovery.Proof, cmd RecoverInitialCommand) (CreateInitialResult, error) {
	if proof.IsZero() || strings.TrimSpace(proof.RequestID()) == "" {
		return CreateInitialResult{}, ErrAuthenticationRequired
	}
	return s.executeInitial(ctx, CreateInitialCommand{
		PreOnboardingRequestID: proof.RequestID(),
		CertificateUsage:       cmd.CertificateUsage,
		IdempotencyKey:         cmd.IdempotencyKey,
		CorrelationID:          cmd.CorrelationID,
	}, executionModeRecovery, proof)
}

func (s *Service) executeInitial(ctx context.Context, cmd CreateInitialCommand, mode executionMode, proof enrollmentrecovery.Proof) (CreateInitialResult, error) {
	if err := s.Validate(); err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	if mode != executionModeNew && mode != executionModeRecovery {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	if strings.TrimSpace(cmd.PreOnboardingRequestID) == "" || cmd.PreOnboardingRequestID != strings.TrimSpace(cmd.PreOnboardingRequestID) ||
		strings.TrimSpace(cmd.CertificateUsage) == "" || cmd.CertificateUsage != strings.TrimSpace(cmd.CertificateUsage) ||
		strings.TrimSpace(cmd.IdempotencyKey) == "" {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}

	credScope, err := idempotencyruntime.NewCredentialScope(authpolicy.CredentialKindRequestAccessToken, cmd.PreOnboardingRequestID)
	if err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	key, err := idempotencyruntime.NewIdempotencyKey(cmd.IdempotencyKey)
	if err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	scope, err := idempotencyruntime.NewEffectiveScope(credScope, "POST", createEnrollmentRoute, key)
	if err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	fp, err := ComputeCreateInitialFingerprint(cmd)
	if err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}

	now := s.clock.Now()
	uow, err := s.uowManager.Begin(ctx)
	if err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	defer uow.Rollback(ctx)

	request, requestAccess, deviceID, err := s.loadAuthoritativeExchangeState(ctx, uow, cmd.PreOnboardingRequestID, now, mode)
	if err != nil {
		return CreateInitialResult{}, err
	}
	if mode == executionModeRecovery && !proof.Matches(cmd.PreOnboardingRequestID, requestAccess.Key) {
		return CreateInitialResult{}, ErrAuthenticationRequired
	}

	eligible, err := uow.Eligibility().IsInitialEligible(ctx, string(request.PartnerID()), deviceID, cmd.CertificateUsage)
	if err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	if !eligible {
		return CreateInitialResult{}, ErrNotAuthorized
	}

	idem, err := idempotencyruntime.NewService(uow.IdempotencyStore(), s.create.Protector, idempotencyruntime.WithClock(s.clock))
	if err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	reservation, err := idem.Reserve(ctx, idempotencyruntime.ReserveRequest{
		Scope:       scope,
		Fingerprint: fp,
		Now:         now,
		ExpiresAt:   now.Add(s.retentionPolicy.ReservationDuration()),
	})
	if err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}

	switch reservation.Status {
	case idempotencyruntime.ReservationConflict:
		return CreateInitialResult{}, ErrIdempotencyConflict
	case idempotencyruntime.ReservationInProgress:
		return CreateInitialResult{}, &InProgressError{Message: "createEnrollment reservation active"}
	case idempotencyruntime.ReservationReplay:
		if mode != executionModeRecovery || requestAccess.Record.State != capability.StateConsumed {
			// Ordinary ACTIVE authentication is not a replay credential, and a
			// committed result without committed consumption is an integrity
			// defect. Neither condition is allowed to become recovery authority.
			return CreateInitialResult{}, ErrAuthenticationRequired
		}
		return s.replayInitial(ctx, uow, idem, scope, fp, reservation, request, deviceID, cmd)
	case idempotencyruntime.ReservationNew:
		if mode != executionModeNew || requestAccess.Record.State != capability.StateActive {
			// A consumed recovery proof never owns NEW mutation authority. This
			// closes the different-key path even if idempotency has no record.
			return CreateInitialResult{}, ErrAuthenticationRequired
		}
	default:
		return CreateInitialResult{}, ErrDependencyUnavailable
	}

	// From this point execution is NEW-only. Re-check active lifetime
	// immediately before staging; the UoW performs the final authoritative
	// freshness check again at commit.
	if !now.Before(requestAccess.Record.ExpiresAt) {
		return CreateInitialResult{}, ErrResourceExpired
	}
	if request.EffectiveStatus(now) == preonboardingdomain.StateExpired {
		return CreateInitialResult{}, ErrResourceExpired
	}
	if request.Status() != preonboardingdomain.StateEnrollmentReady {
		return CreateInitialResult{}, ErrNotAuthorized
	}

	requirements, err := uow.EvidenceRequirements().InitialEvidenceRequirements(ctx, string(request.PartnerID()), deviceID, cmd.CertificateUsage)
	if err != nil || requirements.Validate() != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}

	enrollmentID, err := s.create.IDGenerator.NewEnrollmentID(ctx)
	if err != nil || strings.TrimSpace(enrollmentID) == "" || enrollmentID != strings.TrimSpace(enrollmentID) {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	nonceBytes, err := s.create.ChallengeGenerator.NewChallengeNonce(ctx)
	if err != nil || len(nonceBytes) < 16 {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	challenge := Challenge{
		Nonce:            base64.RawURLEncoding.EncodeToString(nonceBytes),
		ChallengeVersion: 1,
		ExpiresAt:        now.Add(s.challengeLifetime.ChallengeLifetime()),
		PopFormat:        PopFormatEnrollmentJWS,
	}
	if err := challenge.Validate(now); err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}

	token, err := s.create.TokenGenerator.NewEnrollmentAccessToken(ctx)
	if err != nil || strings.TrimSpace(token) == "" || token != strings.TrimSpace(token) {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	tokenVerifier, err := s.create.Verifier.Derive(authpolicy.CredentialKindEnrollmentAccessToken, token)
	if err != nil || string(tokenVerifier) == "" {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}

	aggregate := domain.NewEnrollment(domain.EnrollmentID(enrollmentID))
	record := EnrollmentRecord{
		Aggregate:            aggregate,
		DeviceID:             deviceID,
		PartnerID:            string(request.PartnerID()),
		Operation:            OperationInitial,
		CertificateUsage:     cmd.CertificateUsage,
		Challenge:            challenge,
		EvidenceRequirements: requirements.Clone(),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := record.Validate(); err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}

	requestAccess.Record.State = capability.StateConsumed
	if err := uow.RequestAccess().Save(ctx, requestAccess); err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	if err := uow.Enrollments().Create(ctx, record); err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	if err := uow.EnrollmentAccess().CreateEnrollmentAccess(ctx, tokenVerifier, capability.EnrollmentAccessRecord{
		EnrollmentID: enrollmentID,
		ExpiresAt:    now.Add(s.enrollmentTokenLifetime.EnrollmentAccessTokenLifetime()),
	}); err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}

	loc, err := idempotencyruntime.NewResultLocator("enrollment-create:" + enrollmentID)
	if err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	snapshot := CreateResultSnapshot{
		EnrollmentID:         enrollmentID,
		Operation:            OperationInitial,
		CertificateUsage:     cmd.CertificateUsage,
		DeviceID:             deviceID,
		State:                domain.StateChallengeIssued,
		Challenge:            challenge,
		EvidenceRequirements: requirements.Clone(),
		Location:             "/v1/enrollments/" + enrollmentID,
		CommittedAt:          now,
	}
	if err := snapshot.Validate(); err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	if err := uow.Results().SaveCreateResult(ctx, loc, snapshot); err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}

	aad, err := (replaycapsule.EnrollmentAAD{ResourceID: enrollmentID, Scope: scope, Fingerprint: fp}).Bytes()
	if err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	envelope, err := s.create.Protector.Seal(ctx, []byte(token), aad)
	if err != nil || envelope == nil || envelope.Validate() != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	capsule, err := idempotencyruntime.NewProtectedEnvelope(
		envelope.Ciphertext(),
		envelope.Nonce(),
		envelope.KeyID(),
		envelope.KeyVersion(),
		capsuleExpiry(now, s.replayCapsulePolicy.ReplayCapsuleLifetime(), s.retentionPolicy.ReservationDuration()),
	)
	if err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}

	if err := uow.Audit().StageEvent(ctx, AuditEvent{
		Type:             AuditEventEnrollmentCreated,
		EnrollmentID:     enrollmentID,
		DeviceID:         deviceID,
		Operation:        OperationInitial,
		CertificateUsage: cmd.CertificateUsage,
		IdempotencyRef:   loc.String(),
		CorrelationID:    cmd.CorrelationID,
		Timestamp:        now,
	}); err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	if _, err := idem.Commit(ctx, idempotencyruntime.CommitRequest{
		Token:   reservation.Token,
		Scope:   scope,
		Result:  loc,
		Capsule: capsule,
	}); err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}

	if err := uow.Commit(ContextWithCommitClock(ctx, s.clock)); err != nil {
		switch {
		case errors.Is(err, ErrAuthenticationRequired):
			return CreateInitialResult{}, ErrAuthenticationRequired
		case errors.Is(err, ErrResourceExpired):
			return CreateInitialResult{}, ErrResourceExpired
		case errors.Is(err, ErrNotAuthorized):
			return CreateInitialResult{}, ErrNotAuthorized
		default:
			return CreateInitialResult{}, ErrDependencyUnavailable
		}
	}
	return CreateInitialResult{Snapshot: snapshot.Clone(), EnrollmentAccessToken: token, Replay: false}, nil
}

func (s *Service) loadAuthoritativeExchangeState(ctx context.Context, uow UnitOfWork, requestID string, now time.Time, mode executionMode) (*preonboardingdomain.PreOnboardingRequest, RequestAccessCredential, string, error) {
	request, found, err := uow.PreOnboarding().Get(ctx, preonboardingdomain.ID(requestID))
	if err != nil || !found || request == nil {
		return nil, RequestAccessCredential{}, "", ErrDependencyUnavailable
	}
	requestAccess, found, err := uow.RequestAccess().GetByPreOnboardingRequestID(ctx, requestID)
	if err != nil || !found {
		return nil, RequestAccessCredential{}, "", ErrDependencyUnavailable
	}
	if requestAccess.Record.PreOnboardingRequestID != requestID || string(requestAccess.Key) == "" {
		return nil, RequestAccessCredential{}, "", ErrDependencyUnavailable
	}

	switch mode {
	case executionModeNew:
		if requestAccess.Record.State != capability.StateActive {
			return nil, RequestAccessCredential{}, "", ErrAuthenticationRequired
		}
		if !now.Before(requestAccess.Record.ExpiresAt) || request.EffectiveStatus(now) == preonboardingdomain.StateExpired {
			return nil, RequestAccessCredential{}, "", ErrResourceExpired
		}
		if request.Status() != preonboardingdomain.StateEnrollmentReady {
			return nil, RequestAccessCredential{}, "", ErrNotAuthorized
		}
	case executionModeRecovery:
		if requestAccess.Record.State != capability.StateConsumed {
			return nil, RequestAccessCredential{}, "", ErrAuthenticationRequired
		}
		// Time advancement after a committed exchange does not erase exact
		// response-loss recovery authority. The persisted request must remain
		// the approved ENROLLMENT_READY record; current eligibility is checked
		// separately before any replay material is opened.
		if request.Status() != preonboardingdomain.StateEnrollmentReady {
			return nil, RequestAccessCredential{}, "", ErrDependencyUnavailable
		}
	default:
		return nil, RequestAccessCredential{}, "", ErrDependencyUnavailable
	}

	device := request.DeviceID()
	if device == nil || strings.TrimSpace(*device) == "" {
		return nil, RequestAccessCredential{}, "", ErrDependencyUnavailable
	}
	return request, requestAccess, *device, nil
}

func (s *Service) replayInitial(
	ctx context.Context,
	uow UnitOfWork,
	idem *idempotencyruntime.Service,
	scope idempotencyruntime.EffectiveScope,
	fp idempotencyruntime.Fingerprint,
	reservation idempotencyruntime.Reservation,
	request *preonboardingdomain.PreOnboardingRequest,
	deviceID string,
	cmd CreateInitialCommand,
) (CreateInitialResult, error) {
	snapshot, ok, err := uow.Results().GetCreateResult(ctx, reservation.Result)
	if err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	if !ok || snapshot.Validate() != nil {
		return CreateInitialResult{}, ErrIdempotencyReplayUnavailable
	}
	if snapshot.DeviceID != deviceID || snapshot.CertificateUsage != cmd.CertificateUsage || snapshot.Operation != OperationInitial {
		return CreateInitialResult{}, ErrIdempotencyReplayUnavailable
	}
	if string(request.PartnerID()) == "" {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	enrollment, found, err := uow.Enrollments().GetEnrollment(ctx, snapshot.EnrollmentID)
	if err != nil {
		return CreateInitialResult{}, ErrDependencyUnavailable
	}
	if !found || !matchesRecoveredEnrollment(enrollment, snapshot, string(request.PartnerID())) {
		// A committed originator result may recover only the existing enrollment it
		// created. Idempotency metadata/capsule material by itself is never enough
		// authority to disclose the original EnrollmentAccessToken.
		return CreateInitialResult{}, ErrIdempotencyReplayUnavailable
	}
	aad, err := (replaycapsule.EnrollmentAAD{ResourceID: snapshot.EnrollmentID, Scope: scope, Fingerprint: fp}).Bytes()
	if err != nil {
		return CreateInitialResult{}, ErrIdempotencyReplayUnavailable
	}
	secret, err := idem.RecoverSecret(ctx, idempotencyruntime.RecoverSecretRequest{
		Scope:          scope,
		Fingerprint:    fp,
		AssociatedData: aad,
	})
	if err != nil {
		return CreateInitialResult{}, mapRecovery(err)
	}
	if len(secret) == 0 {
		return CreateInitialResult{}, ErrIdempotencyReplayUnavailable
	}
	return CreateInitialResult{Snapshot: snapshot.Clone(), EnrollmentAccessToken: string(secret), Replay: true}, nil
}

func matchesRecoveredEnrollment(record EnrollmentRecord, snapshot CreateResultSnapshot, partnerID string) bool {
	return record.Aggregate != nil &&
		string(record.Aggregate.ID()) == snapshot.EnrollmentID &&
		record.DeviceID == snapshot.DeviceID &&
		record.PartnerID == partnerID &&
		record.Operation == OperationInitial &&
		record.CertificateUsage == snapshot.CertificateUsage
}

func mapRecovery(err error) error {
	if err == nil {
		return nil
	}
	var recErr *idempotencyruntime.RecoveryError
	if errors.As(err, &recErr) {
		switch recErr.Reason {
		case idempotencyruntime.RecoveryReasonNoCapsule,
			idempotencyruntime.RecoveryReasonRecordExpired,
			idempotencyruntime.RecoveryReasonCapsuleExpired,
			idempotencyruntime.RecoveryReasonUnavailable:
			return ErrIdempotencyReplayUnavailable
		case idempotencyruntime.RecoveryReasonOpenFailed:
			return classifyProtectorFailure(recErr.Cause)
		default:
			return ErrDependencyUnavailable
		}
	}
	return classifyProtectorFailure(err)
}

func classifyProtectorFailure(err error) error {
	if errors.Is(err, replaycapsule.ErrTransient) {
		return ErrDependencyUnavailable
	}
	if errors.Is(err, replaycapsule.ErrPermanent) {
		return ErrIdempotencyReplayUnavailable
	}
	return ErrDependencyUnavailable
}
