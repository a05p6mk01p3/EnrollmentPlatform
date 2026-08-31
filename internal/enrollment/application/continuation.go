package application

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	domain "github.com/a05p6mk01p3/EnrollmentPlatform/internal/domain/enrollment"
	idempotencyruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/idempotency/runtime"
)

// GetEnrollmentCommand is the application input after the HTTP/authentication
// boundary has established resource access.
type GetEnrollmentCommand struct{ EnrollmentID string }

type GetEnrollmentResult struct{ Snapshot EnrollmentSnapshot }

// EvidenceAcceptanceCommand carries an opaque representation produced by the
// later evidence-admission boundary. This service owns state/challenge/time
// acceptance only; it does not parse CSR, JWS, or OPEN-004A TPM evidence.
type EvidenceAcceptanceCommand struct {
	EnrollmentID             string
	ExpectedChallengeVersion int
	Fingerprint              idempotencyruntime.Fingerprint
	Representation           []byte
	PopNonce                 string
	Material                 *EvaluationMaterial
}

// RefreshChallengeCommand uses CredentialBinding from the already-authenticated
// EnrollmentAccess capability. The raw bearer token is intentionally absent.
type RefreshChallengeCommand struct {
	EnrollmentID             string
	CredentialBinding        string
	IdempotencyKey           string
	ExpectedChallengeVersion int
}

func (s *Service) GetEnrollment(ctx context.Context, cmd GetEnrollmentCommand) (GetEnrollmentResult, error) {
	if err := s.Validate(); err != nil || strings.TrimSpace(cmd.EnrollmentID) == "" || cmd.EnrollmentID != strings.TrimSpace(cmd.EnrollmentID) {
		return GetEnrollmentResult{}, ErrDependencyUnavailable
	}
	uow, err := s.uowManager.Begin(ctx)
	if err != nil {
		return GetEnrollmentResult{}, ErrDependencyUnavailable
	}
	defer uow.Rollback(ctx)
	record, found, err := uow.Enrollments().GetEnrollment(ctx, cmd.EnrollmentID)
	if err != nil {
		return GetEnrollmentResult{}, ErrDependencyUnavailable
	}
	if !found {
		return GetEnrollmentResult{}, ErrEnrollmentNotFound
	}
	if record.Aggregate == nil {
		return GetEnrollmentResult{}, ErrDependencyUnavailable
	}
	if record.Aggregate.ID() != domain.EnrollmentID(cmd.EnrollmentID) || !record.Aggregate.State().Valid() {
		return GetEnrollmentResult{}, ErrDependencyUnavailable
	}
	snapshot := record.Snapshot()
	if snapshot.EnrollmentID == "" {
		return GetEnrollmentResult{}, ErrDependencyUnavailable
	}
	return GetEnrollmentResult{Snapshot: snapshot.Clone()}, nil
}

func (s *Service) AcceptEvidence(ctx context.Context, cmd EvidenceAcceptanceCommand) (EvidenceAcceptedResult, error) {
	if err := s.Validate(); err != nil || strings.TrimSpace(cmd.EnrollmentID) == "" || cmd.EnrollmentID != strings.TrimSpace(cmd.EnrollmentID) ||
		cmd.ExpectedChallengeVersion < 1 || cmd.Fingerprint.IsZero() || len(cmd.Representation) == 0 {
		return EvidenceAcceptedResult{}, ErrDependencyUnavailable
	}
	raw, err := s.uowManager.Begin(ctx)
	if err != nil {
		return EvidenceAcceptedResult{}, ErrDependencyUnavailable
	}
	uow, ok := raw.(ContinuationUnitOfWork)
	if !ok {
		_ = raw.Rollback(ctx)
		return EvidenceAcceptedResult{}, ErrDependencyUnavailable
	}
	defer uow.Rollback(ctx)

	now := s.clock.Now()
	if now.IsZero() {
		return EvidenceAcceptedResult{}, ErrDependencyUnavailable
	}
	record, found, err := uow.EnrollmentContinuation().GetEnrollment(ctx, cmd.EnrollmentID)
	if err != nil {
		return EvidenceAcceptedResult{}, ErrDependencyUnavailable
	}
	if !found {
		return EvidenceAcceptedResult{}, ErrEnrollmentNotFound
	}
	if record.Aggregate == nil {
		return EvidenceAcceptedResult{}, ErrDependencyUnavailable
	}
	if record.Aggregate.ID() != domain.EnrollmentID(cmd.EnrollmentID) {
		return EvidenceAcceptedResult{}, ErrDependencyUnavailable
	}

	// Once accepted, retry recognition is independent of current clock. It is
	// also independent of the now-expired active challenge, as required by §6.3.
	if record.Aggregate.State() == domain.StateEvidenceReceived {
		if record.AcceptedEvidence == nil || record.AcceptedEvidence.Validate() != nil {
			return EvidenceAcceptedResult{}, ErrDependencyUnavailable
		}
		if record.AcceptedEvidence.Fingerprint.Equal(cmd.Fingerprint) &&
			record.AcceptedEvidence.ChallengeVersion == cmd.ExpectedChallengeVersion {
			return evidenceAcceptedResult(record), nil
		}
		return EvidenceAcceptedResult{}, ErrEvidenceConflict
	}
	if record.AcceptedEvidence != nil {
		if record.AcceptedEvidence.Fingerprint.Equal(cmd.Fingerprint) &&
			record.AcceptedEvidence.ChallengeVersion == cmd.ExpectedChallengeVersion {
			return evidenceAcceptedResult(record), nil
		}
		return EvidenceAcceptedResult{}, ErrEvidenceConflict
	}
	if record.Aggregate.State() != domain.StateChallengeIssued || record.Challenge.ChallengeVersion != cmd.ExpectedChallengeVersion {
		return EvidenceAcceptedResult{}, ErrStateConflict
	}
	if cmd.PopNonce != "" && record.Challenge.Nonce != cmd.PopNonce {
		return EvidenceAcceptedResult{}, ErrEvidenceInvalid
	}
	if !now.Before(record.Challenge.ExpiresAt) {
		return EvidenceAcceptedResult{}, ErrResourceExpired
	}

	accepted := AcceptedEvidence{
		Fingerprint:      cmd.Fingerprint,
		ChallengeVersion: cmd.ExpectedChallengeVersion,
		Representation:   append([]byte(nil), cmd.Representation...),
		AcceptedAt:       now,
	}
	if err := accepted.Validate(); err != nil {
		return EvidenceAcceptedResult{}, ErrDependencyUnavailable
	}
	if err := uow.EnrollmentContinuation().StageEvidenceAcceptance(ctx, EvidenceAcceptanceWrite{
		EnrollmentID: cmd.EnrollmentID, ExpectedChallengeVersion: cmd.ExpectedChallengeVersion,
		Evidence: accepted, Material: cmd.Material, AcceptedAt: now,
	}); err != nil {
		return EvidenceAcceptedResult{}, mapContinuationError(err)
	}
	if err := uow.Commit(ContextWithCommitClock(ctx, s.clock)); err != nil {
		return EvidenceAcceptedResult{}, mapContinuationError(err)
	}
	return evidenceAcceptedResultFromID(cmd.EnrollmentID), nil
}

func (s *Service) RefreshChallenge(ctx context.Context, cmd RefreshChallengeCommand) (ChallengeRefreshResult, error) {
	if err := s.Validate(); err != nil || strings.TrimSpace(cmd.EnrollmentID) == "" || cmd.EnrollmentID != strings.TrimSpace(cmd.EnrollmentID) ||
		cmd.CredentialBinding == "" || cmd.IdempotencyKey == "" || cmd.ExpectedChallengeVersion < 1 {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	if s.create == nil || s.create.ChallengeGenerator == nil {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	raw, err := s.uowManager.Begin(ctx)
	if err != nil {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	uow, ok := raw.(ContinuationUnitOfWork)
	if !ok {
		_ = raw.Rollback(ctx)
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	defer uow.Rollback(ctx)

	now := s.clock.Now()
	if now.IsZero() {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	cred, recognized := authpolicy.ParseCredentialKind(string(authpolicy.CredentialKindEnrollmentAccessToken))
	if !recognized {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	credentialScope, err := idempotencyruntime.NewCredentialScope(cred, cmd.CredentialBinding)
	if err != nil {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	key, err := idempotencyruntime.NewIdempotencyKey(cmd.IdempotencyKey)
	if err != nil {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	scope, err := idempotencyruntime.NewEffectiveScope(credentialScope, "POST", ChallengeRefreshRoute, key)
	if err != nil {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	fp, err := ComputeChallengeRefreshFingerprint(cmd.ExpectedChallengeVersion)
	if err != nil {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	idem, err := idempotencyruntime.NewService(uow.IdempotencyStore(), s.create.Protector, idempotencyruntime.WithClock(s.clock))
	if err != nil {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	reservation, err := idem.Reserve(ctx, idempotencyruntime.ReserveRequest{
		Scope: scope, Fingerprint: fp, Now: now, ExpiresAt: now.Add(s.retentionPolicy.ReservationDuration()),
	})
	if err != nil {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	switch reservation.Status {
	case idempotencyruntime.ReservationConflict:
		return ChallengeRefreshResult{}, ErrIdempotencyConflict
	case idempotencyruntime.ReservationInProgress:
		return ChallengeRefreshResult{}, &InProgressError{Message: "challenge refresh reservation active"}
	case idempotencyruntime.ReservationReplay:
		result, found, getErr := uow.RefreshResults().GetChallengeRefreshResult(ctx, reservation.Result)
		if getErr != nil {
			return ChallengeRefreshResult{}, ErrDependencyUnavailable
		}
		if !found || result.EnrollmentID != cmd.EnrollmentID || result.Validate(now) != nil {
			return ChallengeRefreshResult{}, ErrDependencyUnavailable
		}
		return result.Clone(), nil
	case idempotencyruntime.ReservationNew:
		// Continue with the single owner of this refresh reservation.
	default:
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}

	record, found, err := uow.EnrollmentContinuation().GetEnrollment(ctx, cmd.EnrollmentID)
	if err != nil {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	if !found {
		return ChallengeRefreshResult{}, ErrEnrollmentNotFound
	}
	if record.Aggregate == nil {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	if record.Aggregate.State() != domain.StateChallengeIssued || record.Challenge.ChallengeVersion != cmd.ExpectedChallengeVersion {
		return ChallengeRefreshResult{}, ErrStateConflict
	}
	if record.AcceptedEvidence != nil {
		return ChallengeRefreshResult{}, ErrStateConflict
	}
	if record.Challenge.ChallengeVersion == int(^uint(0)>>1) {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	nonce, err := s.create.ChallengeGenerator.NewChallengeNonce(ctx)
	if err != nil || len(nonce) < 16 {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	newChallenge := Challenge{
		Nonce:            encodeNonce(nonce),
		ChallengeVersion: cmd.ExpectedChallengeVersion + 1,
		ExpiresAt:        now.Add(s.challengeLifetime.ChallengeLifetime()),
		PopFormat:        PopFormatEnrollmentJWS,
	}
	if newChallenge.Nonce == record.Challenge.Nonce || newChallenge.Validate(now) != nil {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	result := ChallengeRefreshResult{EnrollmentID: cmd.EnrollmentID, State: domain.StateChallengeIssued, Challenge: newChallenge, RefreshedAt: now}
	if result.Validate(now) != nil {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	loc, err := idempotencyruntime.NewResultLocator("enrollment-refresh:" + cmd.EnrollmentID + ":" + newChallenge.Nonce)
	if err != nil {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	if err := uow.RefreshResults().SaveChallengeRefreshResult(ctx, loc, result); err != nil {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	if _, err := idem.Commit(ctx, idempotencyruntime.CommitRequest{Token: reservation.Token, Scope: scope, Result: loc}); err != nil {
		return ChallengeRefreshResult{}, ErrDependencyUnavailable
	}
	if err := uow.EnrollmentContinuation().StageChallengeRefresh(ctx, ChallengeRefreshWrite{
		EnrollmentID: cmd.EnrollmentID, ExpectedChallengeVersion: cmd.ExpectedChallengeVersion,
		Challenge: newChallenge, RefreshedAt: now,
	}); err != nil {
		return ChallengeRefreshResult{}, mapContinuationError(err)
	}
	if err := uow.Commit(ContextWithCommitClock(ctx, s.clock)); err != nil {
		return ChallengeRefreshResult{}, mapContinuationError(err)
	}
	return result.Clone(), nil
}

func evidenceAcceptedResult(record EnrollmentRecord) EvidenceAcceptedResult {
	result := evidenceAcceptedResultFromID(string(record.Aggregate.ID()))
	result.Replay = true
	return result
}

func evidenceAcceptedResultFromID(id string) EvidenceAcceptedResult {
	return EvidenceAcceptedResult{EnrollmentID: id, State: domain.StateEvidenceReceived, StatusURL: "/v1/enrollments/" + id, RetryAfterSeconds: 2, Replay: false}
}

func encodeNonce(nonce []byte) string { return base64.RawURLEncoding.EncodeToString(nonce) }

func mapContinuationError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrStateConflict), errors.Is(err, ErrEvidenceConflict):
		return err
	case errors.Is(err, ErrEvidenceInvalid):
		return ErrEvidenceInvalid
	case errors.Is(err, ErrResourceExpired):
		return ErrResourceExpired
	case errors.Is(err, ErrEnrollmentNotFound):
		return ErrEnrollmentNotFound
	case errors.Is(err, ErrIdempotencyConflict):
		return ErrIdempotencyConflict
	default:
		return ErrDependencyUnavailable
	}
}
