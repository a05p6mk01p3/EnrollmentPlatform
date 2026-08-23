// Package devicemtls implements the Enrollment API side of the M4.5
// DeviceMTLS trusted-proxy boundary.
//
// The architecture is:
//
//	External Device
//	    | device mTLS / device client certificate
//	    v
//	Trusted Reverse Proxy
//	    | separate mTLS connection using PROXY SERVICE IDENTITY
//	    | + protected device-certificate metadata
//	    v
//	Enrollment API
//
// This package establishes the authenticated upstream Reverse Proxy service
// boundary, the strict protected certificate-metadata boundary, server-side
// certificate lookup, and the certificate -> device -> issuing-enrollment
// correlation. It plugs into the M4.2 runtime through the DeviceMTLSSource and
// Authenticator ports.
//
// The Enrollment API never interprets its r.TLS peer certificate as the device
// certificate. r.TLS is used only, where configured, to authenticate the
// Reverse Proxy service hop.
package devicemtls

import (
	"errors"
	"fmt"
	"reflect"
)

// Verdict classifies the outcome of a trust-boundary evaluation. The zero
// value is VerdictRejected so that a naive or buggy boundary can never
// authenticate by default (fail closed).
type Verdict int

const (
	// VerdictRejected means the boundary definitively rejected the request.
	VerdictRejected Verdict = iota
	// VerdictTrusted means the boundary positively established the expected
	// fact.
	VerdictTrusted
	// VerdictIndeterminate means the boundary could not decide because a
	// trusted dependency/infrastructure was unavailable or inconsistent.
	VerdictIndeterminate
)

func (v Verdict) String() string {
	switch v {
	case VerdictRejected:
		return "rejected"
	case VerdictTrusted:
		return "trusted"
	case VerdictIndeterminate:
		return "indeterminate"
	default:
		return "unknown"
	}
}

// ConfigError reports a deterministic unsafe M4.5 construction configuration.
// It is a typed Go error and carries no HTTP error type or credential detail.
type ConfigError struct {
	Component string
	Reason    string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("devicemtls: invalid %s configuration: %s", e.Component, e.Reason)
}

// ErrTrustedMaterialUnavailable is the internal sentinel returned by the
// DeviceMTLS source when a trusted dependency cannot be evaluated. It carries
// no detail and is mapped by the runtime to 503 DEPENDENCY_UNAVAILABLE.
var ErrTrustedMaterialUnavailable = errors.New("devicemtls: trusted verification dependency unavailable")

// isNilInterfaceValue reports whether an interface value is nil or holds a
// typed-nil dynamic value (pointer/interface/func/map/slice/channel). It is
// used at every construction boundary so a typed-nil verifier/matcher/source/
// registry is rejected deterministically at construction rather than panicking
// at authentication time. It never calls IsNil on a non-nilable kind.
func isNilInterfaceValue(v any) bool {
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
