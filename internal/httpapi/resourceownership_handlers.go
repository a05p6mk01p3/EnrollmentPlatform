package httpapi

import (
	"context"
	"net/http"

	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/generated/openapi"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi/problem"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/partnerauth"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/resourceownership"
)

// resourceOwnershipDecorator applies the M5.3 resource ownership and
// visibility boundary over a StrictServerInterface. It enforces Human
// visibility rules and post-read response consistency for
// GET /v1/pre-onboarding-requests/{id} before delegating or disclosing;
// every other operation delegates through unchanged (embedded promotion).
//
// The decorator is part of the mandatory Server.Handler composition: there is
// no public construction path that skips it.
type resourceOwnershipDecorator struct {
	openapi.StrictServerInterface
	service *resourceownership.Service
}

// wrapResourceOwnership wraps inner with the M5.3 resource ownership and
// visibility boundary. It is private: Server.Handler composes it unconditionally.
func (s *Server) wrapResourceOwnership(inner openapi.StrictServerInterface) openapi.StrictServerInterface {
	return &resourceOwnershipDecorator{StrictServerInterface: inner, service: s.resourceOwnership}
}

// GetPreOnboardingRequest evaluates resource visibility for HumanOIDC and
// RequestAccessToken callers before delegating to the protected inner handler,
// and enforces response consistency before disclosing a successful 200 body.
func (d *resourceOwnershipDecorator) GetPreOnboardingRequest(ctx context.Context, request openapi.GetPreOnboardingRequestRequestObject) (openapi.GetPreOnboardingRequestResponseObject, error) {
	ac, ok := authruntime.AuthenticationContextFrom(ctx)
	if !ok || ac == nil {
		return getPreOnboarding503(ctx), nil
	}

	requestedID := string(request.Id)

	switch {
	case ac.Has(authpolicy.CredentialKindHumanOIDC):
		principal, ok := d.humanPrincipal(ctx)
		if !ok {
			return getPreOnboarding503(ctx), nil
		}

		decision, authoritativePartnerID, err := d.service.EvaluateHumanVisibility(ctx, principal, requestedID)
		if err != nil || decision == resourceownership.VisibilityIndeterminate {
			return getPreOnboarding503(ctx), nil
		}

		switch decision {
		case resourceownership.VisibilityAllowed:
			// Visibility allows protected read.
			resp, err := d.StrictServerInterface.GetPreOnboardingRequest(ctx, request)
			if err != nil {
				return resp, err
			}
			return validateResponseConsistency(ctx, resp, requestedID, authoritativePartnerID, true), nil

		case resourceownership.VisibilityHiddenNotFound:
			return getPreOnboarding404(ctx), nil

		default:
			return getPreOnboarding503(ctx), nil
		}

	case ac.Has(authpolicy.CredentialKindRequestAccessToken):
		b, ok := ac.Binding(authpolicy.CredentialKindRequestAccessToken)
		if !ok {
			return getPreOnboarding503(ctx), nil
		}
		rab, ok := b.RequestAccess()
		if !ok || rab.PreOnboardingRequestID != requestedID {
			// Upstream M4.3 resource binding already rejected mismatches; defensive fail-closed.
			return getPreOnboarding503(ctx), nil
		}

		// RequestAccessToken does not invoke Human partner authorization or ownership resolver.
		resp, err := d.StrictServerInterface.GetPreOnboardingRequest(ctx, request)
		if err != nil {
			return resp, err
		}
		return validateResponseConsistency(ctx, resp, requestedID, "", false), nil

	default:
		// Upstream authentication guarantees either HumanOIDC or RequestAccessToken.
		return getPreOnboarding503(ctx), nil
	}
}

// validateResponseConsistency validates that a protected response object is a
// recognized generated response type, that 200 responses (whether returned by
// value or by pointer) satisfy resource/partner consistency, and that
// unrecognized or nil/typed-nil response objects fail closed (503).
func validateResponseConsistency(ctx context.Context, resp openapi.GetPreOnboardingRequestResponseObject, requestedID string, authoritativePartnerID string, isHuman bool) openapi.GetPreOnboardingRequestResponseObject {
	if resp == nil {
		return getPreOnboarding503(ctx)
	}

	switch r := resp.(type) {
	case openapi.GetPreOnboardingRequest200JSONResponse:
		if string(r.Body.PreOnboardingRequestId) != requestedID {
			return getPreOnboarding503(ctx)
		}
		if isHuman && string(r.Body.PartnerId) != authoritativePartnerID {
			return getPreOnboarding503(ctx)
		}
		return resp

	case *openapi.GetPreOnboardingRequest200JSONResponse:
		if r == nil {
			return getPreOnboarding503(ctx)
		}
		if string(r.Body.PreOnboardingRequestId) != requestedID {
			return getPreOnboarding503(ctx)
		}
		if isHuman && string(r.Body.PartnerId) != authoritativePartnerID {
			return getPreOnboarding503(ctx)
		}
		return resp

	case openapi.GetPreOnboardingRequest401ApplicationProblemPlusJSONResponse:
		return resp
	case *openapi.GetPreOnboardingRequest401ApplicationProblemPlusJSONResponse:
		if r == nil {
			return getPreOnboarding503(ctx)
		}
		return resp

	case openapi.GetPreOnboardingRequest403ApplicationProblemPlusJSONResponse:
		return resp
	case *openapi.GetPreOnboardingRequest403ApplicationProblemPlusJSONResponse:
		if r == nil {
			return getPreOnboarding503(ctx)
		}
		return resp

	case openapi.GetPreOnboardingRequest404ApplicationProblemPlusJSONResponse:
		return resp
	case *openapi.GetPreOnboardingRequest404ApplicationProblemPlusJSONResponse:
		if r == nil {
			return getPreOnboarding503(ctx)
		}
		return resp

	case openapi.GetPreOnboardingRequest410ApplicationProblemPlusJSONResponse:
		return resp
	case *openapi.GetPreOnboardingRequest410ApplicationProblemPlusJSONResponse:
		if r == nil {
			return getPreOnboarding503(ctx)
		}
		return resp

	case openapi.GetPreOnboardingRequest429ApplicationProblemPlusJSONResponse:
		return resp
	case *openapi.GetPreOnboardingRequest429ApplicationProblemPlusJSONResponse:
		if r == nil {
			return getPreOnboarding503(ctx)
		}
		return resp

	case openapi.GetPreOnboardingRequest503ApplicationProblemPlusJSONResponse:
		return resp
	case *openapi.GetPreOnboardingRequest503ApplicationProblemPlusJSONResponse:
		if r == nil {
			return getPreOnboarding503(ctx)
		}
		return resp

	default:
		// Unknown/custom response object implementation: cannot prove that it does not
		// disclose inconsistent protected content -> fail closed.
		return getPreOnboarding503(ctx)
	}
}

// humanPrincipal extracts the server-authenticated HumanOIDC identity binding.
func (d *resourceOwnershipDecorator) humanPrincipal(ctx context.Context) (partnerauth.HumanPrincipal, bool) {
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

func getPreOnboarding404(ctx context.Context) openapi.GetPreOnboardingRequestResponseObject {
	return openapi.GetPreOnboardingRequest404ApplicationProblemPlusJSONResponse{
		NotFoundApplicationProblemPlusJSONResponse: openapi.NotFoundApplicationProblemPlusJSONResponse{
			Body:    problemDetail(ctx, http.StatusNotFound, "RESOURCE_NOT_FOUND", problem.TypeResourceNotFound, "Resource not found", false),
			Headers: openapi.NotFoundResponseHeaders{XCorrelationID: correlationPtr(ctx)},
		},
	}
}

func getPreOnboarding503(ctx context.Context) openapi.GetPreOnboardingRequestResponseObject {
	return openapi.GetPreOnboardingRequest503ApplicationProblemPlusJSONResponse{
		ServiceUnavailableApplicationProblemPlusJSONResponse: openapi.ServiceUnavailableApplicationProblemPlusJSONResponse{
			Body:    problemDetail(ctx, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", problem.TypeDependencyUnavailable, "Dependency unavailable", true),
			Headers: openapi.ServiceUnavailableResponseHeaders{XCorrelationID: correlationPtr(ctx)},
		},
	}
}
