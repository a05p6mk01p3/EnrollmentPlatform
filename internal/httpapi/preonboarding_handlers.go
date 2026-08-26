package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi/problem"
	preonboardingapp "github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/application"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/preonboarding/domain"
)

type preOnboardResponseOverride interface {
	OverrideGetPreOnboardingRequest(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, bool, error)
}

// preOnboardingDecorator applies M5.5 Pre-Onboarding lifecycle business operations
// over StrictServerInterface.
type preOnboardingDecorator struct {
	openapi.StrictServerInterface
	service *preonboardingapp.Service
}

func (s *Server) wrapPreOnboarding(inner openapi.StrictServerInterface) openapi.StrictServerInterface {
	return &preOnboardingDecorator{StrictServerInterface: inner, service: s.preonboarding}
}

// CreatePreOnboardingRequest executes pre-onboarding proposal creation.
// In M5.5, mandatory secret-originator capabilities are absent, so production execution
// MUST fail closed with 503 before any durable domain side effect.
func (d *preOnboardingDecorator) CreatePreOnboardingRequest(ctx context.Context, request openapi.CreatePreOnboardingRequestRequestObject) (openapi.CreatePreOnboardingRequestResponseObject, error) {
	if request.Body == nil {
		return createPreOnboarding400(ctx), nil
	}
	ac, ok := authruntime.AuthenticationContextFrom(ctx)
	if !ok || ac == nil {
		return createPreOnboarding503(ctx), nil
	}
	var kind authpolicy.CredentialKind
	var binding string
	if ac.Has(authpolicy.CredentialKindHumanOIDC) {
		b, ok := ac.Binding(authpolicy.CredentialKindHumanOIDC)
		if !ok {
			return createPreOnboarding503(ctx), nil
		}
		o, ok := b.OIDCIdentity()
		if !ok {
			return createPreOnboarding503(ctx), nil
		}
		kind = authpolicy.CredentialKindHumanOIDC
		binding = o.Issuer + "|" + o.Subject
	} else if ac.Has(authpolicy.CredentialKindTemporaryPrincipalToken) {
		b, ok := ac.Binding(authpolicy.CredentialKindTemporaryPrincipalToken)
		if !ok {
			return createPreOnboarding503(ctx), nil
		}
		tp, ok := b.TemporaryPrincipal()
		if !ok {
			return createPreOnboarding503(ctx), nil
		}
		kind = authpolicy.CredentialKindTemporaryPrincipalToken
		binding = tp.TemporaryPrincipalID
	} else {
		return createPreOnboarding503(ctx), nil
	}
	b := request.Body
	claimed := domain.ClaimedDevice{Hostname: b.ClaimedDevice.Hostname}
	if b.ClaimedDevice.SerialNumber != nil {
		claimed.SerialNumber = *b.ClaimedDevice.SerialNumber
	}
	if b.ClaimedDevice.SmbiosUuid != nil {
		claimed.SMBIOSUUID = *b.ClaimedDevice.SmbiosUuid
	}
	if b.ClaimedDevice.Manufacturer != nil {
		claimed.Manufacturer = *b.ClaimedDevice.Manufacturer
	}
	if b.ClaimedDevice.Model != nil {
		claimed.Model = *b.ClaimedDevice.Model
	}
	if b.ClaimedDevice.TpmPresent != nil {
		claimed.TPMPresent = *b.ClaimedDevice.TpmPresent
	}
	if b.ClaimedDevice.TpmVendor != nil {
		claimed.TPMVendor = *b.ClaimedDevice.TpmVendor
	}
	if b.ClaimedDevice.EkPublicHash != nil {
		claimed.EKPublicHash = *b.ClaimedDevice.EkPublicHash
	}
	res, err := d.service.CreateOriginator(ctx, preonboardingapp.CreateOriginatorCommand{CreateCommand: preonboardingapp.CreateCommand{PartnerID: string(b.PartnerId), ClaimedDevice: claimed, Agent: domain.Agent{Platform: string(b.Agent.Platform), Version: b.Agent.Version}}, CredentialKind: kind, CredentialBinding: binding, IdempotencyKey: request.Params.IdempotencyKey, CorrelationID: problem.CorrelationID(ctx)})
	if err != nil {
		if errors.Is(err, preonboardingapp.ErrPartnerNotAuthorized) {
			return createPreOnboarding403(ctx, "PARTNER_NOT_AUTHORIZED"), nil
		}
		if errors.Is(err, preonboardingapp.ErrIdempotencyReplayUnavailable) {
			return openapi.CreatePreOnboardingRequest409ApplicationProblemPlusJSONResponse{IdempotencyReplayConflictOrUnavailableApplicationProblemPlusJSONResponse: openapi.IdempotencyReplayConflictOrUnavailableApplicationProblemPlusJSONResponse{Body: problemDetail(ctx, http.StatusConflict, "IDEMPOTENCY_REPLAY_UNAVAILABLE", problem.TypeIdempotencyReplayUnavailable, "Idempotency replay unavailable", false), Headers: openapi.IdempotencyReplayConflictOrUnavailableResponseHeaders{XCorrelationID: correlationPtr(ctx)}}}, nil
		}
		if errors.Is(err, preonboardingapp.ErrIdempotencyConflict) {
			return openapi.CreatePreOnboardingRequest409ApplicationProblemPlusJSONResponse{IdempotencyReplayConflictOrUnavailableApplicationProblemPlusJSONResponse: openapi.IdempotencyReplayConflictOrUnavailableApplicationProblemPlusJSONResponse{Body: problemDetail(ctx, http.StatusConflict, "IDEMPOTENCY_CONFLICT", problem.TypeIdempotencyConflict, "Idempotency conflict", false), Headers: openapi.IdempotencyReplayConflictOrUnavailableResponseHeaders{XCorrelationID: correlationPtr(ctx)}}}, nil
		}
		return createPreOnboarding503(ctx), nil
	}
	return openapi.CreatePreOnboardingRequest201JSONResponse{Body: openapi.PreOnboardingCreateResponse{PreOnboardingRequestId: openapi.ResourceId(res.Snapshot.PreOnboardingRequestID), PartnerId: openapi.ResourceId(res.Snapshot.PartnerID), ExpiresAt: res.Snapshot.ExpiresAt, Status: openapi.PreOnboardingCreateResponseStatusPENDINGAPPROVAL, RequestAccessToken: res.RequestAccessToken}, Headers: openapi.CreatePreOnboardingRequest201ResponseHeaders{ETag: strPtr(res.Snapshot.ETag), Location: strPtr(res.Snapshot.Location), XCorrelationID: correlationPtr(ctx)}}, nil
}

// GetPreOnboardingRequest executes public read of a pre-onboarding request.
// Effective EXPIRED status maps to HTTP 410 (RESOURCE_EXPIRED).
func (d *preOnboardingDecorator) GetPreOnboardingRequest(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error) {
	if overrider, ok := d.StrictServerInterface.(preOnboardResponseOverride); ok {
		if resp, overridden, err := overrider.OverrideGetPreOnboardingRequest(ctx, request); overridden {
			return resp, err
		}
	}
	res, err := d.service.GetPublic(ctx, string(request.Id))
	if err != nil {
		if errors.Is(err, preonboardingapp.ErrResourceExpired) {
			return openapi.GetPreOnboardingRequest410ApplicationProblemPlusJSONResponse{
				GoneApplicationProblemPlusJSONResponse: openapi.GoneApplicationProblemPlusJSONResponse{
					Body:    problemDetail(ctx, http.StatusGone, "RESOURCE_EXPIRED", problem.TypeResourceExpired, "Resource expired", false),
					Headers: openapi.GoneResponseHeaders{XCorrelationID: correlationPtr(ctx)},
				},
			}, nil
		}
		if errors.Is(err, preonboardingapp.ErrNotFound) {
			return openapi.GetPreOnboardingRequest404ApplicationProblemPlusJSONResponse{
				NotFoundApplicationProblemPlusJSONResponse: openapi.NotFoundApplicationProblemPlusJSONResponse{
					Body:    problemDetail(ctx, http.StatusNotFound, "RESOURCE_NOT_FOUND", problem.TypeResourceNotFound, "Resource not found", false),
					Headers: openapi.NotFoundResponseHeaders{XCorrelationID: correlationPtr(ctx)},
				},
			}, nil
		}
		return openapi.GetPreOnboardingRequest503ApplicationProblemPlusJSONResponse{
			ServiceUnavailableApplicationProblemPlusJSONResponse: openapi.ServiceUnavailableApplicationProblemPlusJSONResponse{
				Body:    problemDetail(ctx, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", problem.TypeDependencyUnavailable, "Dependency unavailable", true),
				Headers: openapi.ServiceUnavailableResponseHeaders{XCorrelationID: correlationPtr(ctx)},
			},
		}, nil
	}

	view := toOpenAPIPreOnboardingRequest(res.Request, res.EffectiveStatus)
	return openapi.GetPreOnboardingRequest200JSONResponse{
		Body: view,
		Headers: openapi.GetPreOnboardingRequest200ResponseHeaders{
			ETag:           strPtr(res.ETag),
			XCorrelationID: correlationPtr(ctx),
		},
	}, nil
}

// AdminListPreOnboardingRequests executes an administrative listing query.
func (d *preOnboardingDecorator) AdminListPreOnboardingRequests(ctx context.Context, request openapi.AdminListPreOnboardingRequestsRequestObject) (openapi.AdminListPreOnboardingRequestsResponseObject, error) {
	admin, ok := adminPrincipalFrom(ctx)
	if !ok {
		return openapi.AdminListPreOnboardingRequests503ApplicationProblemPlusJSONResponse{
			ServiceUnavailableApplicationProblemPlusJSONResponse: openapi.ServiceUnavailableApplicationProblemPlusJSONResponse{
				Body:    problemDetail(ctx, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", problem.TypeDependencyUnavailable, "Dependency unavailable", true),
				Headers: openapi.ServiceUnavailableResponseHeaders{XCorrelationID: correlationPtr(ctx)},
			},
		}, nil
	}

	filter := preonboardingapp.AdminListFilter{}
	if request.Params.PageSize != nil {
		filter.PageSize = *request.Params.PageSize
	}
	if request.Params.PageToken != nil {
		filter.PageToken = *request.Params.PageToken
	}
	if request.Params.PartnerId != nil {
		p := string(*request.Params.PartnerId)
		filter.PartnerID = &p
	}
	if request.Params.Status != nil {
		st := domain.State(*request.Params.Status)
		filter.Status = &st
	}
	if request.Params.CreatedFrom != nil {
		t := time.Time(*request.Params.CreatedFrom)
		filter.From = &t
	}
	if request.Params.CreatedTo != nil {
		t := time.Time(*request.Params.CreatedTo)
		filter.To = &t
	}

	listRes, err := d.service.ListAdmin(ctx, admin, filter)
	if err != nil {
		return openapi.AdminListPreOnboardingRequests503ApplicationProblemPlusJSONResponse{
			ServiceUnavailableApplicationProblemPlusJSONResponse: openapi.ServiceUnavailableApplicationProblemPlusJSONResponse{
				Body:    problemDetail(ctx, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", problem.TypeDependencyUnavailable, "Dependency unavailable", true),
				Headers: openapi.ServiceUnavailableResponseHeaders{XCorrelationID: correlationPtr(ctx)},
			},
		}, nil
	}

	items := make([]openapi.PreOnboardingRequest, 0, len(listRes.Items))
	for _, item := range listRes.Items {
		items = append(items, toOpenAPIPreOnboardingRequest(item.Request, item.EffectiveStatus))
	}

	var nextPageToken *string
	if listRes.NextPageToken != "" {
		nextPageToken = &listRes.NextPageToken
	}

	return openapi.AdminListPreOnboardingRequests200JSONResponse{
		Body: openapi.PaginatedPreOnboardingRequests{
			Items:         items,
			NextPageToken: nextPageToken,
		},
		Headers: openapi.AdminListPreOnboardingRequests200ResponseHeaders{
			XCorrelationID: correlationPtr(ctx),
		},
	}, nil
}

// AdminGetPreOnboardingRequest executes administrative read-by-id.
// Lack of authority over resource's partner is concealed as 404 RESOURCE_NOT_FOUND (M5.5-DEC-002).
func (d *preOnboardingDecorator) AdminGetPreOnboardingRequest(ctx context.Context, request openapi.AdminGetPreOnboardingRequestRequestObject) (openapi.AdminGetPreOnboardingRequestResponseObject, error) {
	admin, ok := adminPrincipalFrom(ctx)
	if !ok {
		return openapi.AdminGetPreOnboardingRequest503ApplicationProblemPlusJSONResponse{
			ServiceUnavailableApplicationProblemPlusJSONResponse: openapi.ServiceUnavailableApplicationProblemPlusJSONResponse{
				Body:    problemDetail(ctx, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", problem.TypeDependencyUnavailable, "Dependency unavailable", true),
				Headers: openapi.ServiceUnavailableResponseHeaders{XCorrelationID: correlationPtr(ctx)},
			},
		}, nil
	}

	res, err := d.service.GetAdmin(ctx, admin, string(request.Id))
	if err != nil {
		if errors.Is(err, preonboardingapp.ErrNotFound) {
			return openapi.AdminGetPreOnboardingRequest404ApplicationProblemPlusJSONResponse{
				NotFoundApplicationProblemPlusJSONResponse: openapi.NotFoundApplicationProblemPlusJSONResponse{
					Body:    problemDetail(ctx, http.StatusNotFound, "RESOURCE_NOT_FOUND", problem.TypeResourceNotFound, "Resource not found", false),
					Headers: openapi.NotFoundResponseHeaders{XCorrelationID: correlationPtr(ctx)},
				},
			}, nil
		}
		return openapi.AdminGetPreOnboardingRequest503ApplicationProblemPlusJSONResponse{
			ServiceUnavailableApplicationProblemPlusJSONResponse: openapi.ServiceUnavailableApplicationProblemPlusJSONResponse{
				Body:    problemDetail(ctx, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", problem.TypeDependencyUnavailable, "Dependency unavailable", true),
				Headers: openapi.ServiceUnavailableResponseHeaders{XCorrelationID: correlationPtr(ctx)},
			},
		}, nil
	}

	view := toOpenAPIPreOnboardingRequest(res.Request, res.EffectiveStatus)
	return openapi.AdminGetPreOnboardingRequest200JSONResponse{
		Body: view,
		Headers: openapi.AdminGetPreOnboardingRequest200ResponseHeaders{
			ETag:           strPtr(res.ETag),
			XCorrelationID: correlationPtr(ctx),
		},
	}, nil
}

// AdminApprovePreOnboardingRequest executes administrative approval.
func (d *preOnboardingDecorator) AdminApprovePreOnboardingRequest(ctx context.Context, request openapi.AdminApprovePreOnboardingRequestRequestObject) (openapi.AdminApprovePreOnboardingRequestResponseObject, error) {
	admin, ok := adminPrincipalFrom(ctx)
	if !ok {
		return openapi.AdminApprovePreOnboardingRequest503ApplicationProblemPlusJSONResponse{
			ServiceUnavailableApplicationProblemPlusJSONResponse: openapi.ServiceUnavailableApplicationProblemPlusJSONResponse{
				Body:    problemDetail(ctx, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", problem.TypeDependencyUnavailable, "Dependency unavailable", true),
				Headers: openapi.ServiceUnavailableResponseHeaders{XCorrelationID: correlationPtr(ctx)},
			},
		}, nil
	}

	expectedStatus := ""
	reason := ""
	if request.Body != nil {
		expectedStatus = string(request.Body.ExpectedStatus)
		reason = request.Body.Reason
	}

	corr := problem.CorrelationID(ctx)
	cmd := preonboardingapp.ApproveCommand{
		ID:             string(request.Id),
		IfMatch:        request.Params.IfMatch,
		IdempotencyKey: request.Params.IdempotencyKey,
		ExpectedStatus: expectedStatus,
		Reason:         reason,
		CorrelationID:  corr,
	}

	res, err := d.service.Approve(ctx, admin, cmd)
	if err != nil {
		if errors.Is(err, preonboardingapp.ErrPartnerNotAuthorized) || errors.Is(err, preonboardingapp.ErrPartnerIneligible) {
			return openapi.AdminApprovePreOnboardingRequest403ApplicationProblemPlusJSONResponse{
				ForbiddenApplicationProblemPlusJSONResponse: openapi.ForbiddenApplicationProblemPlusJSONResponse{
					Body:    problemDetail(ctx, http.StatusForbidden, "PARTNER_NOT_AUTHORIZED", problem.TypePartnerNotAuthorized, "Access denied", false),
					Headers: openapi.ForbiddenResponseHeaders{XCorrelationID: correlationPtr(ctx)},
				},
			}, nil
		}
		if errors.Is(err, preonboardingapp.ErrNotFound) {
			return openapi.AdminApprovePreOnboardingRequest404ApplicationProblemPlusJSONResponse{
				NotFoundApplicationProblemPlusJSONResponse: openapi.NotFoundApplicationProblemPlusJSONResponse{
					Body:    problemDetail(ctx, http.StatusNotFound, "RESOURCE_NOT_FOUND", problem.TypeResourceNotFound, "Resource not found", false),
					Headers: openapi.NotFoundResponseHeaders{XCorrelationID: correlationPtr(ctx)},
				},
			}, nil
		}
		if errors.Is(err, preonboardingapp.ErrPreconditionFailed) {
			return openapi.AdminApprovePreOnboardingRequest412ApplicationProblemPlusJSONResponse{
				PreconditionFailedApplicationProblemPlusJSONResponse: openapi.PreconditionFailedApplicationProblemPlusJSONResponse{
					Body:    problemDetail(ctx, http.StatusPreconditionFailed, "PRECONDITION_FAILED", problem.TypePreconditionFailed, "Precondition failed", false),
					Headers: openapi.PreconditionFailedResponseHeaders{XCorrelationID: correlationPtr(ctx)},
				},
			}, nil
		}
		if errors.Is(err, preonboardingapp.ErrStateConflict) {
			return openapi.AdminApprovePreOnboardingRequest409ApplicationProblemPlusJSONResponse{
				ConflictApplicationProblemPlusJSONResponse: openapi.ConflictApplicationProblemPlusJSONResponse{
					Body:    problemDetail(ctx, http.StatusConflict, "STATE_CONFLICT", problem.TypeStateConflict, "State conflict", false),
					Headers: openapi.ConflictResponseHeaders{XCorrelationID: correlationPtr(ctx)},
				},
			}, nil
		}
		if errors.Is(err, preonboardingapp.ErrIdempotencyConflict) {
			return openapi.AdminApprovePreOnboardingRequest409ApplicationProblemPlusJSONResponse{
				ConflictApplicationProblemPlusJSONResponse: openapi.ConflictApplicationProblemPlusJSONResponse{
					Body:    problemDetail(ctx, http.StatusConflict, "IDEMPOTENCY_CONFLICT", problem.TypeIdempotencyConflict, "Idempotency conflict", false),
					Headers: openapi.ConflictResponseHeaders{XCorrelationID: correlationPtr(ctx)},
				},
			}, nil
		}
		return openapi.AdminApprovePreOnboardingRequest503ApplicationProblemPlusJSONResponse{
			ServiceUnavailableApplicationProblemPlusJSONResponse: openapi.ServiceUnavailableApplicationProblemPlusJSONResponse{
				Body:    problemDetail(ctx, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", problem.TypeDependencyUnavailable, "Dependency unavailable", true),
				Headers: openapi.ServiceUnavailableResponseHeaders{XCorrelationID: correlationPtr(ctx)},
			},
		}, nil
	}

	return openapi.AdminApprovePreOnboardingRequest200JSONResponse{
		Body: openapi.PreOnboardingApprovalResponse{
			PreOnboardingRequestId: openapi.ResourceId(res.PreOnboardingRequestID),
			DeviceId:               openapi.ResourceId(res.DeviceID),
			Status:                 openapi.PreOnboardingApprovalResponseStatus(res.Status),
			ResourceVersion:        res.ResourceVersion,
		},
		Headers: openapi.AdminApprovePreOnboardingRequest200ResponseHeaders{
			ETag:           strPtr(res.ETag),
			XCorrelationID: correlationPtr(ctx),
		},
	}, nil
}

// AdminRejectPreOnboardingRequest executes administrative rejection.
func (d *preOnboardingDecorator) AdminRejectPreOnboardingRequest(ctx context.Context, request openapi.AdminRejectPreOnboardingRequestRequestObject) (openapi.AdminRejectPreOnboardingRequestResponseObject, error) {
	admin, ok := adminPrincipalFrom(ctx)
	if !ok {
		return openapi.AdminRejectPreOnboardingRequest503ApplicationProblemPlusJSONResponse{
			ServiceUnavailableApplicationProblemPlusJSONResponse: openapi.ServiceUnavailableApplicationProblemPlusJSONResponse{
				Body:    problemDetail(ctx, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", problem.TypeDependencyUnavailable, "Dependency unavailable", true),
				Headers: openapi.ServiceUnavailableResponseHeaders{XCorrelationID: correlationPtr(ctx)},
			},
		}, nil
	}

	expectedStatus := ""
	reason := ""
	if request.Body != nil {
		expectedStatus = string(request.Body.ExpectedStatus)
		reason = request.Body.Reason
	}

	corr := problem.CorrelationID(ctx)
	cmd := preonboardingapp.RejectCommand{
		ID:             string(request.Id),
		IfMatch:        request.Params.IfMatch,
		IdempotencyKey: request.Params.IdempotencyKey,
		ExpectedStatus: expectedStatus,
		Reason:         reason,
		CorrelationID:  corr,
	}

	res, err := d.service.Reject(ctx, admin, cmd)
	if err != nil {
		if errors.Is(err, preonboardingapp.ErrPartnerNotAuthorized) {
			return openapi.AdminRejectPreOnboardingRequest403ApplicationProblemPlusJSONResponse{
				ForbiddenApplicationProblemPlusJSONResponse: openapi.ForbiddenApplicationProblemPlusJSONResponse{
					Body:    problemDetail(ctx, http.StatusForbidden, "PARTNER_NOT_AUTHORIZED", problem.TypePartnerNotAuthorized, "Access denied", false),
					Headers: openapi.ForbiddenResponseHeaders{XCorrelationID: correlationPtr(ctx)},
				},
			}, nil
		}
		if errors.Is(err, preonboardingapp.ErrNotFound) {
			return openapi.AdminRejectPreOnboardingRequest404ApplicationProblemPlusJSONResponse{
				NotFoundApplicationProblemPlusJSONResponse: openapi.NotFoundApplicationProblemPlusJSONResponse{
					Body:    problemDetail(ctx, http.StatusNotFound, "RESOURCE_NOT_FOUND", problem.TypeResourceNotFound, "Resource not found", false),
					Headers: openapi.NotFoundResponseHeaders{XCorrelationID: correlationPtr(ctx)},
				},
			}, nil
		}
		if errors.Is(err, preonboardingapp.ErrPreconditionFailed) {
			return openapi.AdminRejectPreOnboardingRequest412ApplicationProblemPlusJSONResponse{
				PreconditionFailedApplicationProblemPlusJSONResponse: openapi.PreconditionFailedApplicationProblemPlusJSONResponse{
					Body:    problemDetail(ctx, http.StatusPreconditionFailed, "PRECONDITION_FAILED", problem.TypePreconditionFailed, "Precondition failed", false),
					Headers: openapi.PreconditionFailedResponseHeaders{XCorrelationID: correlationPtr(ctx)},
				},
			}, nil
		}
		if errors.Is(err, preonboardingapp.ErrStateConflict) {
			return openapi.AdminRejectPreOnboardingRequest409ApplicationProblemPlusJSONResponse{
				ConflictApplicationProblemPlusJSONResponse: openapi.ConflictApplicationProblemPlusJSONResponse{
					Body:    problemDetail(ctx, http.StatusConflict, "STATE_CONFLICT", problem.TypeStateConflict, "State conflict", false),
					Headers: openapi.ConflictResponseHeaders{XCorrelationID: correlationPtr(ctx)},
				},
			}, nil
		}
		if errors.Is(err, preonboardingapp.ErrIdempotencyConflict) {
			return openapi.AdminRejectPreOnboardingRequest409ApplicationProblemPlusJSONResponse{
				ConflictApplicationProblemPlusJSONResponse: openapi.ConflictApplicationProblemPlusJSONResponse{
					Body:    problemDetail(ctx, http.StatusConflict, "IDEMPOTENCY_CONFLICT", problem.TypeIdempotencyConflict, "Idempotency conflict", false),
					Headers: openapi.ConflictResponseHeaders{XCorrelationID: correlationPtr(ctx)},
				},
			}, nil
		}
		return openapi.AdminRejectPreOnboardingRequest503ApplicationProblemPlusJSONResponse{
			ServiceUnavailableApplicationProblemPlusJSONResponse: openapi.ServiceUnavailableApplicationProblemPlusJSONResponse{
				Body:    problemDetail(ctx, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", problem.TypeDependencyUnavailable, "Dependency unavailable", true),
				Headers: openapi.ServiceUnavailableResponseHeaders{XCorrelationID: correlationPtr(ctx)},
			},
		}, nil
	}

	view := toOpenAPIPreOnboardingRequest(res.Request, res.EffectiveStatus)
	return openapi.AdminRejectPreOnboardingRequest200JSONResponse{
		Body: view,
		Headers: openapi.AdminRejectPreOnboardingRequest200ResponseHeaders{
			ETag:           strPtr(res.ETag),
			XCorrelationID: correlationPtr(ctx),
		},
	}, nil
}

func adminPrincipalFrom(ctx context.Context) (preonboardingapp.AdminPrincipal, bool) {
	ac, ok := authruntime.AuthenticationContextFrom(ctx)
	if !ok || ac == nil {
		return preonboardingapp.AdminPrincipal{}, false
	}
	b, ok := ac.Binding(authpolicy.CredentialKindAdminOIDC)
	if !ok {
		return preonboardingapp.AdminPrincipal{}, false
	}
	oidc, ok := b.OIDCIdentity()
	if !ok || oidc.Issuer == "" || oidc.Subject == "" {
		return preonboardingapp.AdminPrincipal{}, false
	}
	return preonboardingapp.AdminPrincipal{Issuer: oidc.Issuer, Subject: oidc.Subject}, true
}

func toOpenAPIPreOnboardingRequest(req *domain.PreOnboardingRequest, effStatus domain.State) openapi.PreOnboardingRequest {
	if req == nil {
		return openapi.PreOnboardingRequest{}
	}

	var devID *openapi.ResourceId
	if req.DeviceID() != nil && *req.DeviceID() != "" {
		d := openapi.ResourceId(*req.DeviceID())
		devID = &d
	}

	claimed := req.ClaimedDevice()
	view := openapi.ClaimedDeviceView{
		Hostname: claimed.Hostname,
	}
	if claimed.SerialNumber != "" {
		view.SerialNumber = &claimed.SerialNumber
	}
	if claimed.SMBIOSUUID != "" {
		view.SmbiosUuid = &claimed.SMBIOSUUID
	}
	if claimed.Manufacturer != "" {
		view.Manufacturer = &claimed.Manufacturer
	}
	if claimed.Model != "" {
		view.Model = &claimed.Model
	}
	if claimed.TPMPresent {
		t := true
		view.TpmPresent = &t
	}
	if claimed.TPMVendor != "" {
		view.TpmVendor = &claimed.TPMVendor
	}
	if claimed.EKPublicHash != "" {
		view.EkPublicHash = &claimed.EKPublicHash
	}

	return openapi.PreOnboardingRequest{
		PreOnboardingRequestId: openapi.ResourceId(req.ID()),
		PartnerId:              openapi.ResourceId(req.PartnerID()),
		Status:                 string(effStatus),
		ResourceVersion:        req.ResourceVersion(),
		DeviceId:               devID,
		CreatedAt:              req.CreatedAt(),
		ExpiresAt:              req.ExpiresAt(),
		ClaimedDevice:          view,
	}
}
