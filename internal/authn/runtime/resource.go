package runtime

import (
	"fmt"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// ResourceKind classifies the domain resource type of a route's path
// resource. It is derived ONCE at startup from the canonical OpenAPI path
// parameter COMPONENT identity, never from the path parameter NAME alone:
// every canonical resource path parameter is named "id", so the name "id" by
// itself carries no domain semantics.
type ResourceKind uint8

const (
	// ResourceKindUnknown means the route carries no classified path
	// resource.
	ResourceKindUnknown ResourceKind = iota
	ResourceKindPreOnboardingRequest
	ResourceKindEnrollment
	ResourceKindDevice
	ResourceKindDeviceRebindRequest
	ResourceKindCertificate
	ResourceKindTemporaryPrincipal
	ResourceKindRevocationRequest
)

func (k ResourceKind) String() string {
	switch k {
	case ResourceKindPreOnboardingRequest:
		return "pre_onboarding_request"
	case ResourceKindEnrollment:
		return "enrollment"
	case ResourceKindDevice:
		return "device"
	case ResourceKindDeviceRebindRequest:
		return "device_rebind_request"
	case ResourceKindCertificate:
		return "certificate"
	case ResourceKindTemporaryPrincipal:
		return "temporary_principal"
	case ResourceKindRevocationRequest:
		return "revocation_request"
	default:
		return "unknown"
	}
}

// canonicalPathResourceKinds maps each canonical OpenAPI path-parameter
// COMPONENT identity of the current contract to its domain resource kind.
// This is the closed classification of the contract's {id}-style path
// parameters; any route whose path parameter resolves to a component outside
// this set fails construction rather than being inferred from the parameter
// name.
var canonicalPathResourceKinds = map[string]ResourceKind{
	"PreOnboardingRequestId": ResourceKindPreOnboardingRequest,
	"EnrollmentId":           ResourceKindEnrollment,
	"DeviceId":               ResourceKindDevice,
	"RebindRequestId":        ResourceKindDeviceRebindRequest,
	"CertificateId":          ResourceKindCertificate,
	"TemporaryPrincipalId":   ResourceKindTemporaryPrincipal,
	"RevocationRequestId":    ResourceKindRevocationRequest,
}

// MatchedResource is the typed route resource resolved for a matched route:
// the domain resource Kind (derived at startup from canonical route metadata)
// and the matched Value (from chi's parsed path parameters, never a raw URL
// string). Present=false means the route carries no path resource and no
// resource constraint applies.
type MatchedResource struct {
	Kind    ResourceKind
	Value   string
	Present bool
}

// classifyRouteResource derives the ResourceKind of a route from the
// canonical path-parameter component identity of its path item and operation
// parameters. A route with no path parameter yields ResourceKindUnknown with
// no error. A path parameter whose canonical component is unrecognized, or an
// inline path parameter without a canonical component identity, fails closed
// with an error: the path parameter name "id" is never used to infer domain
// semantics.
//
// Any UNRESOLVED parameter reference fails construction unconditionally
// (SOL-M4.5-004): without a resolved value the parameter's location
// (path/query/header/cookie), name, component identity and resource semantics
// cannot be evaluated, so silently skipping it could silently remove
// resource-binding constraints. The failure is never conditioned on whether
// the referenced component name is recognized, and the kind is never inferred
// from the Ref suffix, the wire parameter name, "{id}", operationId, or route
// literals.
func classifyRouteResource(pi *openapi3.PathItem, op *openapi3.Operation, path string) (ResourceKind, error) {
	kind := ResourceKindUnknown
	found := false

	params := make([]*openapi3.ParameterRef, 0, len(pi.Parameters)+len(op.Parameters))
	params = append(params, pi.Parameters...)
	params = append(params, op.Parameters...)

	for _, pr := range params {
		if pr == nil {
			return ResourceKindUnknown, fmt.Errorf("runtime: route %s contains a nil parameter reference", path)
		}
		if pr.Value == nil {
			// Unresolved parameter reference (or an empty parameter entry):
			// the parameter's location, name and component identity are
			// unevaluable. Fail closed unconditionally; never guess whether
			// it was a path/query/header/cookie parameter and never infer
			// resource semantics from the reference string.
			if pr.Ref != "" {
				return ResourceKindUnknown, fmt.Errorf("runtime: route %s parameter reference %q is unresolved", path, pr.Ref)
			}
			return ResourceKindUnknown, fmt.Errorf("runtime: route %s has a parameter entry with neither a reference nor a resolved value", path)
		}
		if pr.Value.In != "path" {
			continue
		}
		k, err := classifyPathParameter(pr, path)
		if err != nil {
			return ResourceKindUnknown, err
		}
		if found && k != kind {
			return ResourceKindUnknown, fmt.Errorf("runtime: route %s has multiple path parameters with different resource kinds", path)
		}
		kind = k
		found = true
	}
	return kind, nil
}

// canonicalParameterComponent extracts the component name from a
// "#/components/parameters/<name>" reference.
func canonicalParameterComponent(ref string) (string, bool) {
	const prefix = "#/components/parameters/"
	if !strings.HasPrefix(ref, prefix) {
		return "", false
	}
	name := strings.TrimPrefix(ref, prefix)
	if name == "" {
		return "", false
	}
	return name, true
}

// classifyPathParameter classifies one path parameter by its canonical
// component identity. An inline parameter (no ref) has only its name ("id")
// and therefore no canonical identity: classification refuses to infer
// semantics from it.
func classifyPathParameter(pr *openapi3.ParameterRef, path string) (ResourceKind, error) {
	if pr.Ref == "" {
		name := ""
		if pr.Value != nil {
			name = pr.Value.Name
		}
		return ResourceKindUnknown, fmt.Errorf("runtime: route %s has an inline path parameter %q without a canonical component identity; resource classification refuses to infer semantics from the parameter name", path, name)
	}
	name, ok := canonicalParameterComponent(pr.Ref)
	if !ok {
		return ResourceKindUnknown, fmt.Errorf("runtime: route %s path parameter reference %q is not a canonical components/parameters reference", path, pr.Ref)
	}
	kind, ok := canonicalPathResourceKinds[name]
	if !ok {
		return ResourceKindUnknown, fmt.Errorf("runtime: route %s path parameter component %q is not in the closed canonical resource classification", path, name)
	}
	return kind, nil
}
