package runtime

import (
	"errors"
	"strings"
)

// Errors returned by strict bearer extraction. None of them carries the raw
// credential; they are converted to the contracted 401 response by the
// middleware without exposing detail.
var (
	// errBearerDuplicate marks multiple Authorization header lines.
	errBearerDuplicate = errors.New("duplicate Authorization header")
	// errBearerMalformed marks a malformed scheme/value (unknown scheme,
	// combined credentials, comma inside the token, embedded whitespace).
	errBearerMalformed = errors.New("malformed Authorization header")
	// errBearerEmpty marks a Bearer scheme with no token.
	errBearerEmpty = errors.New("empty Bearer token")
)

// extractBearer strictly extracts a single opaque Bearer credential from the
// raw Authorization header values.
//
//   - zero values        -> absent (present=false, nil error);
//   - exactly one value  -> parsed strictly;
//   - two or more values -> fail closed (errBearerDuplicate).
//
// The scheme name comparison is case-insensitive (RFC 7235). The token must
// be non-empty and free of spaces, tabs and commas (which would indicate
// multiple/combined credentials). Credentials are never read from query
// parameters.
//
// The returned token is intentionally opaque: no classification by prefix,
// shape or JWT appearance happens here.
func extractBearer(values []string) (token string, present bool, err error) {
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) > 1 {
		return "", false, errBearerDuplicate
	}

	v := values[0]
	i := strings.IndexAny(v, " \t")
	if i < 0 {
		// No separator at all: either a bare "Bearer" (empty token) or an
		// unknown scheme. Both fail closed.
		if strings.EqualFold(v, "Bearer") {
			return "", false, errBearerEmpty
		}
		return "", false, errBearerMalformed
	}
	scheme := v[:i]
	if !strings.EqualFold(scheme, "Bearer") {
		return "", false, errBearerMalformed
	}

	token = strings.TrimLeft(v[i:], " \t")
	if token == "" {
		return "", false, errBearerEmpty
	}
	if strings.ContainsAny(token, " \t,") {
		return "", false, errBearerMalformed
	}
	return token, true, nil
}
