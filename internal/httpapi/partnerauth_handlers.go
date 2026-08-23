package httpapi

import (
	"context"
	"net/http"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi/problem"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
)

// partnerAuthDecorator applies the M5.2 partner authorization boundary over a
// StrictServerInterface. It resolves and selects partner authorization for the
// two M5.2-owned operations before delegating to the protected inner handler;
// every other operation delegates through unchanged (embedded promotion).
//
// The decorator is part of the mandatory Server.Handler composition: there is
// no public construction path that skips it.
//
// The protected handler (inner) is the application mutation seam for
// POST /v1/pre-onboarding-requests: it is invoked exactly once and only after
// M5.2 partner/scope selection ALLOWS. GET /v1/me/authorizations is answered
// directly from the resolver and never reaches inner.
type partnerAuthDecorator struct {
	openapi.StrictServerInterface
	service *partnerauth.Service
}

// wrapPartnerAuth wraps inner with the M5.2 partner authorization boundary.
// It is private: Server.Handler composes it unconditionally, so no public
// handler-construction path can register protected handlers while skipping
// M5.2 partner/scope selection.
func (s *Server) wrapPartnerAuth(inner openapi.StrictServerInterface) openapi.StrictServerInterface {
	return &partnerAuthDecorator{StrictServerInterface: inner, service: s.partnerAuth}
}

// GetMyAuthorizations resolves and returns the current effective authorizations
// for the authenticated HumanOIDC principal. A dependency failure or malformed
// authorization state fails closed (503) and is never mapped to 200 + empty.
func (d *partnerAuthDecorator) GetMyAuthorizations(ctx context.Context, request openapi.GetMyAuthorizationsRequestObject) (openapi.GetMyAuthorizationsResponseObject, error) {
	principal, ok := d.humanPrincipal(ctx)
	if !ok {
		return getMyAuthorizations503(ctx), nil
	}
	set, err := d.service.ResolveMyAuthorizations(ctx, principal)
	if err != nil {
		return getMyAuthorizations503(ctx), nil
	}
	return openapi.GetMyAuthorizations200JSONResponse{
		Body: toMyAuthorizationsResponse(set),
		Headers: openapi.GetMyAuthorizations200ResponseHeaders{
			XCorrelationID: correlationPtr(ctx),
		},
	}, nil
}

// CreatePreOnboardingRequest authorizes the requested partner/scope before
// delegating to the protected mutation handler. Denied or indeterminate
// authorization never reaches inner.
func (d *partnerAuthDecorator) CreatePreOnboardingRequest(ctx context.Context, request openapi.CreatePreOnboardingRequestRequestObject) (openapi.CreatePreOnboardingRequestResponseObject, error) {
	ac, ok := authruntime.AuthenticationContextFrom(ctx)
	if !ok || ac == nil {
		return createPreOnboarding503(ctx), nil
	}

	switch {
	case ac.Has(authpolicy.CredentialKindHumanOIDC):
		b, ok := ac.Binding(authpolicy.CredentialKindHumanOIDC)
		if !ok {
			return createPreOnboarding503(ctx), nil
		}
		oidc, ok := b.OIDCIdentity()
		if !ok {
			return createPreOnboarding503(ctx), nil
		}
		if request.Body == nil {
			return createPreOnboarding400(ctx), nil
		}
		decision, err := d.service.AuthorizeHumanPreOnboarding(ctx, partnerauth.HumanPrincipal{Issuer: oidc.Issuer, Subject: oidc.Subject}, request.Body.PartnerId)
		if err != nil || decision == partnerauth.SelectionIndeterminate {
			return createPreOnboarding503(ctx), nil
		}
		switch decision {
		case partnerauth.SelectionAllowed:
			return d.StrictServerInterface.CreatePreOnboardingRequest(ctx, request)
		case partnerauth.SelectionDeniedPartner:
			return createPreOnboarding403(ctx, "PARTNER_NOT_AUTHORIZED"), nil
		case partnerauth.SelectionDeniedScope:
			return createPreOnboarding403(ctx, "SCOPE_DENIED"), nil
		default:
			return createPreOnboarding503(ctx), nil
		}

	case ac.Has(authpolicy.CredentialKindTemporaryPrincipalToken):
		// Production TemporaryPrincipalToken pre-onboarding remains fail-closed:
		// the concrete token verifier/bootstrap and the transactional
		// max_submissions/quota consumption gates are not implemented in M5.2.
		// The M5.2 selection sub-gate alone never yields a production 201.
		return createPreOnboarding503(ctx), nil

	default:
		// The authn policy restricts this route to HumanOIDC or
		// TemporaryPrincipalToken; any other authenticated kind is a defect.
		return createPreOnboarding503(ctx), nil
	}
}

// humanPrincipal extracts the server-authenticated HumanOIDC identity binding.
// It never trusts client-supplied partner hints or JWT claims.
func (d *partnerAuthDecorator) humanPrincipal(ctx context.Context) (partnerauth.HumanPrincipal, bool) {
	ac, ok := authruntime.AuthenticationContextFrom(ctx)
	if !ok || ac == nil {
		return partnerauth.HumanPrincipal{}, false
	}
	b, ok := ac.Binding(authpolicy.CredentialKindHumanOIDC)
	if !ok {
		return partnerauth.HumanPrincipal{}, false
	}
	oidc, ok := b.OIDCIdentity()
	if !ok || oidc.Issuer == "" || oidc.Subject == "" {
		return partnerauth.HumanPrincipal{}, false
	}
	return partnerauth.HumanPrincipal{Issuer: oidc.Issuer, Subject: oidc.Subject}, true
}

// toMyAuthorizationsResponse maps the handwritten authorization set to the
// generated transport response type.
func toMyAuthorizationsResponse(set partnerauth.HumanAuthorizations) openapi.MyAuthorizationsResponse {
	partners := make([]openapi.PartnerAuthorization, 0, len(set.Partners))
	for _, p := range set.Partners {
		scopes := p.Scopes
		if scopes == nil {
			scopes = []string{}
		}
		partners = append(partners, openapi.PartnerAuthorization{
			PartnerId:   p.PartnerID,
			DisplayName: p.DisplayName,
			Scopes:      scopes,
		})
	}
	return openapi.MyAuthorizationsResponse{
		PrincipalId: set.PrincipalID,
		Partners:    partners,
	}
}

// --- transport problem-response construction ---

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func correlationPtr(ctx context.Context) *string {
	return strPtr(problem.CorrelationID(ctx))
}

func problemDetail(ctx context.Context, status int, errorCode, typeURI, title string, retryable bool) openapi.ProblemDetail {
	return openapi.ProblemDetail{
		Type:          typeURI,
		Title:         title,
		Status:        status,
		ErrorCode:     errorCode,
		CorrelationId: problem.CorrelationID(ctx),
		Retryable:     retryable,
	}
}

func getMyAuthorizations503(ctx context.Context) openapi.GetMyAuthorizationsResponseObject {
	return openapi.GetMyAuthorizations503ApplicationProblemPlusJSONResponse{
		ServiceUnavailableApplicationProblemPlusJSONResponse: openapi.ServiceUnavailableApplicationProblemPlusJSONResponse{
			Body:    problemDetail(ctx, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", problem.TypeDependencyUnavailable, "Dependency unavailable", true),
			Headers: openapi.ServiceUnavailableResponseHeaders{XCorrelationID: correlationPtr(ctx)},
		},
	}
}

func createPreOnboarding400(ctx context.Context) openapi.CreatePreOnboardingRequestResponseObject {
	return openapi.CreatePreOnboardingRequest400ApplicationProblemPlusJSONResponse{
		BadRequestApplicationProblemPlusJSONResponse: openapi.BadRequestApplicationProblemPlusJSONResponse{
			Body:    problemDetail(ctx, http.StatusBadRequest, "INVALID_REQUEST", problem.TypeInvalidRequest, "Invalid request", false),
			Headers: openapi.BadRequestResponseHeaders{XCorrelationID: correlationPtr(ctx)},
		},
	}
}

func createPreOnboarding403(ctx context.Context, errorCode string) openapi.CreatePreOnboardingRequestResponseObject {
	typeURI := problem.TypeScopeDenied
	if errorCode == "PARTNER_NOT_AUTHORIZED" {
		typeURI = problem.TypePartnerNotAuthorized
	}
	return openapi.CreatePreOnboardingRequest403ApplicationProblemPlusJSONResponse{
		ForbiddenApplicationProblemPlusJSONResponse: openapi.ForbiddenApplicationProblemPlusJSONResponse{
			Body:    problemDetail(ctx, http.StatusForbidden, errorCode, typeURI, "Access denied", false),
			Headers: openapi.ForbiddenResponseHeaders{XCorrelationID: correlationPtr(ctx)},
		},
	}
}

func createPreOnboarding503(ctx context.Context) openapi.CreatePreOnboardingRequestResponseObject {
	return openapi.CreatePreOnboardingRequest503ApplicationProblemPlusJSONResponse{
		ServiceUnavailableApplicationProblemPlusJSONResponse: openapi.ServiceUnavailableApplicationProblemPlusJSONResponse{
			Body:    problemDetail(ctx, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", problem.TypeDependencyUnavailable, "Dependency unavailable", true),
			Headers: openapi.ServiceUnavailableResponseHeaders{XCorrelationID: correlationPtr(ctx)},
		},
	}
}
