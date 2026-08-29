package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	enrollmentapp "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/application"
	enrollmentrecovery "github.com/a05p6mk01p3/EnrollmentPlatform/internal/enrollment/recovery"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi/problem"
)

const createEnrollmentRoutePattern = "/v1/enrollments"

// enrollmentDecorator owns M5.7 createEnrollment business execution. Other
// enrollment operations remain delegated to later milestones.
type enrollmentDecorator struct {
	openapi.StrictServerInterface
	service *enrollmentapp.Service
}

func (s *Server) wrapEnrollment(inner openapi.StrictServerInterface) openapi.StrictServerInterface {
	return &enrollmentDecorator{StrictServerInterface: inner, service: s.enrollment}
}

// CreateEnrollment executes only the M5.7 INITIAL branch. Conditional
// authentication has already run before this method: INITIAL therefore reaches
// this boundary only with an ordinary ACTIVE RequestAccessToken binding, while
// correctly authenticated RENEWAL/REKEY requests fail closed as deferred work.
func (d *enrollmentDecorator) CreateEnrollment(ctx context.Context, request openapi.CreateEnrollmentRequestObject) (openapi.CreateEnrollmentResponseObject, error) {
	if request.Body == nil {
		return createEnrollment400(ctx), nil
	}
	discriminator, err := request.Body.Discriminator()
	if err != nil {
		return createEnrollment503(ctx), nil
	}

	switch discriminator {
	case enrollmentapp.OperationInitial:
		body, err := request.Body.AsInitialEnrollmentCreateRequest()
		if err != nil || body.Operation != openapi.INITIAL {
			return createEnrollment503(ctx), nil
		}
		ac, ok := authruntime.AuthenticationContextFrom(ctx)
		if !ok || ac == nil || !ac.Has(authpolicy.CredentialKindRequestAccessToken) {
			// Phase B guarantees this pairing. Reaching the business boundary
			// without it is an integrity failure, not a new authentication path.
			return createEnrollment503(ctx), nil
		}
		binding, ok := ac.Binding(authpolicy.CredentialKindRequestAccessToken)
		if !ok {
			return createEnrollment503(ctx), nil
		}
		requestAccess, ok := binding.RequestAccess()
		if !ok || requestAccess.PreOnboardingRequestID == "" {
			return createEnrollment503(ctx), nil
		}
		result, err := d.service.CreateInitial(ctx, enrollmentapp.CreateInitialCommand{
			PreOnboardingRequestID: requestAccess.PreOnboardingRequestID,
			CertificateUsage:       string(body.CertificateUsage),
			IdempotencyKey:         string(request.Params.IdempotencyKey),
			CorrelationID:          problem.CorrelationID(ctx),
		})
		return mapCreateEnrollmentApplicationResult(ctx, result, err), nil

	case "RENEWAL", "REKEY":
		// M5.7 deliberately preserves the contract's DeviceMTLS conditional
		// authentication but does not execute these business branches yet.
		return createEnrollment503(ctx), nil
	default:
		// M3 schema validation should make this unreachable.
		return createEnrollment503(ctx), nil
	}
}

// enrollmentRecoveryMiddleware is an outer fallback around the normal M4 ->
// M3 -> Phase-B pipeline. It never authenticates a CONSUMED RequestAccessToken.
// The normal pipeline runs first; only a 401 response can trigger the separate
// consumed-capability recognizer and exact response-loss recovery path.
func (s *Server) enrollmentRecoveryMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rctx := chi.RouteContext(r.Context())
			if rctx == nil || r.Method != http.MethodPost || rctx.RoutePattern() != createEnrollmentRoutePattern {
				next.ServeHTTP(w, r)
				return
			}

			// Record body bytes lazily as downstream reads them. This preserves
			// the required BaseAuthentication-before-M3 ordering: an immediate M4
			// rejection does not cause this middleware to pre-read the request.
			bodyRecorder := newReadRecorder(r.Body)
			if r.Body != nil && r.Body != http.NoBody {
				r.Body = bodyRecorder
			}

			buffered := newBufferedResponseWriter()
			next.ServeHTTP(buffered, r)
			if buffered.statusCode() != http.StatusUnauthorized {
				buffered.flushTo(w)
				return
			}

			bearer, present, err := authruntime.BearerTokenFromRequest(r)
			if err != nil || !present {
				buffered.flushTo(w)
				return
			}
			proof, err := s.enrollmentRecovery.Recognize(r.Context(), bearer)
			switch {
			case errors.Is(err, enrollmentrecovery.ErrNotRecognized):
				buffered.flushTo(w)
				return
			case err != nil:
				problem.WriteServiceUnavailable(w, r)
				return
			}

			// If M3/Phase-B/strict decoding already read the body before the 401,
			// restore the exact bytes captured during that first pass. If no read
			// occurred (ordinary M4 rejected immediately), the original stream is
			// still untouched and remains installed on r.Body.
			if bodyRecorder.wasRead() {
				data := bodyRecorder.bytes()
				r.Body = io.NopCloser(bytes.NewReader(data))
				r.ContentLength = int64(len(data))
				r.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(data)), nil
				}
			}

			// The normal pipeline did not reach a business mutation when the
			// credential was already consumed. Re-run contract enforcement and the
			// compiled M5.1 authorization boundary before the narrow recovery branch.
			// createEnrollment is PolicyKindNone in the current controlled contract;
			// re-running authz here makes a future policy change fail closed instead
			// of silently bypassing it. No AuthenticationContext is fabricated and no
			// NEW mutation path is exposed.
			recoveryHandler := s.enforcer.OperationMiddleware()(
				s.authz.OperationMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					s.serveConsumedCreateEnrollmentRecovery(w, r, proof)
				})),
			)
			recoveryHandler.ServeHTTP(w, r)
		})
	}
}

func (s *Server) serveConsumedCreateEnrollmentRecovery(w http.ResponseWriter, r *http.Request, proof enrollmentrecovery.Proof) {
	var body openapi.CreateEnrollmentJSONRequestBody
	if r.Body == nil || json.NewDecoder(r.Body).Decode(&body) != nil {
		problem.WriteInternal(w, r)
		return
	}
	discriminator, err := body.Discriminator()
	if err != nil {
		problem.WriteInternal(w, r)
		return
	}
	if discriminator != enrollmentapp.OperationInitial {
		// A consumed RequestAccess capability can recover only INITIAL. It never
		// satisfies the DeviceMTLS requirement for RENEWAL/REKEY.
		problem.WriteUnauthorized(w, r)
		return
	}
	initial, err := body.AsInitialEnrollmentCreateRequest()
	if err != nil || initial.Operation != openapi.INITIAL {
		problem.WriteInternal(w, r)
		return
	}
	idemValues := r.Header.Values("Idempotency-Key")
	if len(idemValues) != 1 {
		// M3 should already have rejected this. Keep the fallback fail closed if
		// transport/header behavior ever diverges.
		problem.WriteInvalidRequest(w, r, "request does not satisfy the API contract")
		return
	}

	result, appErr := s.enrollment.RecoverInitial(r.Context(), proof, enrollmentapp.RecoverInitialCommand{
		CertificateUsage: string(initial.CertificateUsage),
		IdempotencyKey:   idemValues[0],
		CorrelationID:    problem.CorrelationID(r.Context()),
	})
	response := mapCreateEnrollmentApplicationResult(r.Context(), result, appErr)
	if err := response.VisitCreateEnrollmentResponse(w); err != nil {
		problem.WriteInternal(w, r)
	}
}

func mapCreateEnrollmentApplicationResult(ctx context.Context, result enrollmentapp.CreateInitialResult, err error) openapi.CreateEnrollmentResponseObject {
	if err == nil {
		return createEnrollment201(ctx, result)
	}
	switch {
	case errors.Is(err, enrollmentapp.ErrAuthenticationRequired):
		return createEnrollment401(ctx)
	case errors.Is(err, enrollmentapp.ErrNotAuthorized):
		return createEnrollment403(ctx)
	case errors.Is(err, enrollmentapp.ErrResourceExpired):
		return createEnrollment410(ctx)
	case errors.Is(err, enrollmentapp.ErrIdempotencyConflict):
		return createEnrollment409(ctx, "IDEMPOTENCY_CONFLICT")
	case errors.Is(err, enrollmentapp.ErrIdempotencyReplayUnavailable):
		return createEnrollment409(ctx, "IDEMPOTENCY_REPLAY_UNAVAILABLE")
	default:
		var inProgress *enrollmentapp.InProgressError
		if errors.As(err, &inProgress) {
			return createEnrollment503(ctx)
		}
		return createEnrollment503(ctx)
	}
}

func createEnrollment201(ctx context.Context, result enrollmentapp.CreateInitialResult) openapi.CreateEnrollmentResponseObject {
	s := result.Snapshot
	return openapi.CreateEnrollment201JSONResponse{
		Body: openapi.EnrollmentCreateResponse{
			EnrollmentId:          openapi.ResourceId(s.EnrollmentID),
			Operation:             s.Operation,
			DeviceId:              openapi.ResourceId(s.DeviceID),
			State:                 openapi.EnrollmentCreateResponseStateCHALLENGEISSUED,
			EnrollmentAccessToken: result.EnrollmentAccessToken,
			Challenge: openapi.Challenge{
				Nonce:            openapi.Base64Url(s.Challenge.Nonce),
				ChallengeVersion: s.Challenge.ChallengeVersion,
				ExpiresAt:        s.Challenge.ExpiresAt,
				PopFormat:        openapi.ChallengePopFormatEnrollmentPopJws,
			},
			EvidenceRequirements: openapi.EvidenceRequirements{
				TpmEvidenceProtocolVersions: append([]string(nil), s.EvidenceRequirements.TPMEvidenceProtocolVersions...),
				MinimumAssurance:            openapi.EvidenceRequirementsMinimumAssurance(s.EvidenceRequirements.MinimumAssurance),
				AllowedKeyProfiles:          append([]string(nil), s.EvidenceRequirements.AllowedKeyProfiles...),
			},
		},
		Headers: openapi.CreateEnrollment201ResponseHeaders{
			Location:       strPtr(s.Location),
			XCorrelationID: correlationPtr(ctx),
		},
	}
}

func createEnrollment400(ctx context.Context) openapi.CreateEnrollmentResponseObject {
	return openapi.CreateEnrollment400ApplicationProblemPlusJSONResponse{
		BadRequestApplicationProblemPlusJSONResponse: openapi.BadRequestApplicationProblemPlusJSONResponse{
			Body:    problemDetail(ctx, http.StatusBadRequest, "INVALID_REQUEST", problem.TypeInvalidRequest, "Invalid request", false),
			Headers: openapi.BadRequestResponseHeaders{XCorrelationID: correlationPtr(ctx)},
		},
	}
}

func createEnrollment401(ctx context.Context) openapi.CreateEnrollmentResponseObject {
	challenge := "Bearer"
	return openapi.CreateEnrollment401ApplicationProblemPlusJSONResponse{
		UnauthorizedApplicationProblemPlusJSONResponse: openapi.UnauthorizedApplicationProblemPlusJSONResponse{
			Body: problemDetail(ctx, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", problem.TypeAuthenticationRequired, "Authentication required", false),
			Headers: openapi.UnauthorizedResponseHeaders{
				WWWAuthenticate: &challenge,
				XCorrelationID:  correlationPtr(ctx),
			},
		},
	}
}

func createEnrollment403(ctx context.Context) openapi.CreateEnrollmentResponseObject {
	return openapi.CreateEnrollment403ApplicationProblemPlusJSONResponse{
		ForbiddenApplicationProblemPlusJSONResponse: openapi.ForbiddenApplicationProblemPlusJSONResponse{
			Body:    problemDetail(ctx, http.StatusForbidden, "SCOPE_DENIED", problem.TypeScopeDenied, "Access denied", false),
			Headers: openapi.ForbiddenResponseHeaders{XCorrelationID: correlationPtr(ctx)},
		},
	}
}

func createEnrollment409(ctx context.Context, code string) openapi.CreateEnrollmentResponseObject {
	typeURI := problem.TypeIdempotencyConflict
	title := "Idempotency conflict"
	if code == "IDEMPOTENCY_REPLAY_UNAVAILABLE" {
		typeURI = problem.TypeIdempotencyReplayUnavailable
		title = "Idempotency replay unavailable"
	}
	return openapi.CreateEnrollment409ApplicationProblemPlusJSONResponse{
		IdempotencyReplayConflictOrUnavailableApplicationProblemPlusJSONResponse: openapi.IdempotencyReplayConflictOrUnavailableApplicationProblemPlusJSONResponse{
			Body:    problemDetail(ctx, http.StatusConflict, code, typeURI, title, false),
			Headers: openapi.IdempotencyReplayConflictOrUnavailableResponseHeaders{XCorrelationID: correlationPtr(ctx)},
		},
	}
}

func createEnrollment410(ctx context.Context) openapi.CreateEnrollmentResponseObject {
	return openapi.CreateEnrollment410ApplicationProblemPlusJSONResponse{
		GoneApplicationProblemPlusJSONResponse: openapi.GoneApplicationProblemPlusJSONResponse{
			Body:    problemDetail(ctx, http.StatusGone, "RESOURCE_EXPIRED", problem.TypeResourceExpired, "Resource expired", false),
			Headers: openapi.GoneResponseHeaders{XCorrelationID: correlationPtr(ctx)},
		},
	}
}

func createEnrollment503(ctx context.Context) openapi.CreateEnrollmentResponseObject {
	return openapi.CreateEnrollment503ApplicationProblemPlusJSONResponse{
		ServiceUnavailableApplicationProblemPlusJSONResponse: openapi.ServiceUnavailableApplicationProblemPlusJSONResponse{
			Body:    problemDetail(ctx, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", problem.TypeDependencyUnavailable, "Dependency unavailable", true),
			Headers: openapi.ServiceUnavailableResponseHeaders{XCorrelationID: correlationPtr(ctx)},
		},
	}
}

type readRecorder struct {
	inner io.ReadCloser
	buf   bytes.Buffer
	read  bool
}

func newReadRecorder(body io.ReadCloser) *readRecorder { return &readRecorder{inner: body} }

func (r *readRecorder) Read(p []byte) (int, error) {
	r.read = true
	if r.inner == nil {
		return 0, io.EOF
	}
	n, err := r.inner.Read(p)
	if n > 0 {
		_, _ = r.buf.Write(p[:n])
	}
	return n, err
}
func (r *readRecorder) Close() error {
	if r.inner == nil {
		return nil
	}
	return r.inner.Close()
}
func (r *readRecorder) wasRead() bool { return r != nil && r.read }
func (r *readRecorder) bytes() []byte {
	if r == nil {
		return nil
	}
	return append([]byte(nil), r.buf.Bytes()...)
}

type bufferedResponseWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newBufferedResponseWriter() *bufferedResponseWriter {
	return &bufferedResponseWriter{header: make(http.Header)}
}
func (w *bufferedResponseWriter) Header() http.Header { return w.header }
func (w *bufferedResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *bufferedResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}
func (w *bufferedResponseWriter) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}
func (w *bufferedResponseWriter) flushTo(dst http.ResponseWriter) {
	// Correlation is installed by the outer middleware on the real writer,
	// while the normal routed pipeline runs against this private buffer. Keep
	// that outer value if the buffered response does not explicitly carry one.
	// Do not compare header-map keys directly: net/http canonicalizes "ID" as
	// "Id" internally.
	correlation := dst.Header().Get("X-Correlation-ID")
	for k := range dst.Header() {
		dst.Header().Del(k)
	}
	for k, values := range w.header {
		for _, value := range values {
			dst.Header().Add(k, value)
		}
	}
	if dst.Header().Get("X-Correlation-ID") == "" && correlation != "" {
		dst.Header().Set("X-Correlation-ID", correlation)
	}
	dst.WriteHeader(w.statusCode())
	_, _ = dst.Write(w.body.Bytes())
}
