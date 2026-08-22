package httpapi_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/oidc"
	authpolicy "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/policy"
	authruntime "github.com/a05p6mk01p3/EnrollmentPlatform/internal/authn/runtime"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/config"
	"github.com/a05p6mk01p3/EnrollmentPlatform/internal/httpapi"
)

const (
	humanIss = "https://issuer.example/human"
	adminIss = "https://issuer.example/admin"
	humanAud = "enrollment-human"
	adminAud = "enrollment-admin"
)

// oidcKeyFixture holds a public JWK (verification) and the private key (signing).
type oidcKeyFixture struct {
	kid  string
	pub  jwk.Key
	priv *rsa.PrivateKey
}

func newOIDCKey(t *testing.T, kid string) oidcKeyFixture {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sign, err := jwk.Import(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := sign.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	pub, err := jwk.PublicKeyOf(sign)
	if err != nil {
		t.Fatal(err)
	}
	return oidcKeyFixture{kid: kid, pub: pub, priv: priv}
}

func (f oidcKeyFixture) publicSet() jwk.Set {
	set := jwk.NewSet()
	_ = set.AddKey(f.pub)
	return set
}

func (f oidcKeyFixture) sign(t *testing.T, iss, sub, aud string) string {
	t.Helper()
	tok, err := jwt.NewBuilder().Issuer(iss).Subject(sub).Audience([]string{aud}).Expiration(time.Now().Add(time.Hour)).Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), f.priv))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func oidcRegistry(t *testing.T, humanAuth, adminAuth authruntime.Authenticator) *authruntime.Registry {
	t.Helper()
	return registry(t,
		humanAuth,
		adminAuth,
		rejectAll(authpolicy.CredentialKindTemporaryPrincipalToken),
		rejectAll(authpolicy.CredentialKindRequestAccessToken),
		rejectAll(authpolicy.CredentialKindEnrollmentAccessToken),
		acceptDeviceMTLS(),
	)
}

func oidcHandler(t *testing.T, humanAuth, adminAuth authruntime.Authenticator) (http.Handler, *probeSSI) {
	t.Helper()
	cfg := config.Config{GeneralJSONDefaultBytes: 262144, AbsoluteRequestBodyBytes: 4 << 20}
	srv, err := httpapi.NewServer(cfg, httpapi.WithAuthnRegistry(oidcRegistry(t, humanAuth, adminAuth)))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	p := &probeSSI{calls: map[string]int{}}
	return srv.Handler(p), p
}

func humanAuthenticator(t *testing.T, source oidc.KeySetSource) authruntime.Authenticator {
	t.Helper()
	cfg, err := oidc.NewProviderConfig(authpolicy.CredentialKindHumanOIDC, humanIss, []string{humanAud}, []string{"RS256"}, source, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	a, err := oidc.NewHumanOIDCAuthenticator(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func adminAuthenticator(t *testing.T, source oidc.KeySetSource) authruntime.Authenticator {
	t.Helper()
	cfg, err := oidc.NewProviderConfig(authpolicy.CredentialKindAdminOIDC, adminIss, []string{adminAud}, []string{"RS256"}, source, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	a, err := oidc.NewAdminOIDCAuthenticator(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestOIDCHTTPCredentialDispatch(t *testing.T) {
	humanKey := newOIDCKey(t, "human-key")
	adminKey := newOIDCKey(t, "admin-key")

	humanAuth := humanAuthenticator(t, oidc.StaticKeySetSource{KeySets: map[string]jwk.Set{humanIss: humanKey.publicSet()}})
	adminAuth := adminAuthenticator(t, oidc.StaticKeySetSource{KeySets: map[string]jwk.Set{adminIss: adminKey.publicSet()}})
	h, p := oidcHandler(t, humanAuth, adminAuth)

	humanTok := humanKey.sign(t, humanIss, "human-subject", humanAud)
	adminTok := adminKey.sign(t, adminIss, "admin-subject", adminAud)

	t.Run("human on human route", func(t *testing.T) {
		rr := doAuth(t, h, "GET", "/v1/me/authorizations", "", map[string]string{"Authorization": "Bearer " + humanTok})
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
		}
		if p.count("GetMyAuthorizations") != 1 {
			t.Fatal("GetMyAuthorizations was not reached")
		}
	})

	t.Run("admin on admin route", func(t *testing.T) {
		rr := doAuth(t, h, "GET", "/v1/admin/pre-onboarding-requests", "", map[string]string{"Authorization": "Bearer " + adminTok})
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rr.Code, rr.Body.String())
		}
		if p.count("AdminListPreOnboardingRequests") != 1 {
			t.Fatal("AdminListPreOnboardingRequests was not reached")
		}
	})

	t.Run("human on admin route rejected", func(t *testing.T) {
		rr := doAuth(t, h, "GET", "/v1/admin/pre-onboarding-requests", "", map[string]string{"Authorization": "Bearer " + humanTok})
		assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	})

	t.Run("admin on human route rejected", func(t *testing.T) {
		rr := doAuth(t, h, "GET", "/v1/me/authorizations", "", map[string]string{"Authorization": "Bearer " + adminTok})
		assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
	})
}

func TestOIDCHTTPErrorMapping(t *testing.T) {
	key := newOIDCKey(t, "key-1")
	adminKey := newOIDCKey(t, "admin-key")
	source := oidc.StaticKeySetSource{KeySets: map[string]jwk.Set{humanIss: key.publicSet(), adminIss: adminKey.publicSet()}}
	humanAuth := humanAuthenticator(t, source)
	adminAuth := adminAuthenticator(t, source)
	h, _ := oidcHandler(t, humanAuth, adminAuth)

	t.Run("malformed JWT -> 401 Bearer", func(t *testing.T) {
		rr := doAuth(t, h, "GET", "/v1/me/authorizations", "", map[string]string{"Authorization": "Bearer not-a-jwt"})
		assertProblem(t, rr, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED")
		if got := rr.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Fatalf("WWW-Authenticate = %q, want Bearer", got)
		}
	})

	t.Run("key source unavailable -> 503", func(t *testing.T) {
		failing := oidc.KeySetSourceFunc(func(context.Context, *oidc.ProviderConfig) (jwk.Set, error) {
			return nil, context.DeadlineExceeded
		})
		fa := humanAuthenticator(t, failing)
		faAdmin := adminAuthenticator(t, failing)
		h2, _ := oidcHandler(t, fa, faAdmin)
		rr := doAuth(t, h2, "GET", "/v1/me/authorizations", "", map[string]string{"Authorization": "Bearer " + key.sign(t, humanIss, "s", humanAud)})
		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
	})

	t.Run("nil key set -> 503, generic, no panic", func(t *testing.T) {
		nilSet := oidc.KeySetSourceFunc(func(context.Context, *oidc.ProviderConfig) (jwk.Set, error) {
			return nil, nil
		})
		fa := humanAuthenticator(t, nilSet)
		faAdmin := adminAuthenticator(t, nilSet)
		h2, _ := oidcHandler(t, fa, faAdmin)
		rr := doAuth(t, h2, "GET", "/v1/me/authorizations", "", map[string]string{"Authorization": "Bearer " + key.sign(t, humanIss, "s", humanAud)})
		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
		if strings.Contains(rr.Body.String(), "nil") || strings.Contains(rr.Body.String(), "malformed") {
			t.Fatalf("internal detail leaked into response: %s", rr.Body.String())
		}
	})

	t.Run("typed-nil key set -> 503, generic, no panic", func(t *testing.T) {
		typedNil := oidc.KeySetSourceFunc(func(context.Context, *oidc.ProviderConfig) (jwk.Set, error) {
			var c *typedNilJWKSet
			return jwk.Set(c), nil
		})
		fa := humanAuthenticator(t, typedNil)
		faAdmin := adminAuthenticator(t, typedNil)
		h2, _ := oidcHandler(t, fa, faAdmin)
		rr := doAuth(t, h2, "GET", "/v1/me/authorizations", "", map[string]string{"Authorization": "Bearer " + key.sign(t, humanIss, "s", humanAud)})
		assertProblem(t, rr, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE")
		if strings.Contains(rr.Body.String(), "nil") {
			t.Fatalf("internal detail leaked into response: %s", rr.Body.String())
		}
	})
}

// setAlias avoids the embedded-field name shadowing the jwk.Set interface's
// own Set method (Go names an embedded interface field after its type).
type setAlias = jwk.Set

// typedNilJWKSet wraps the jwk.Set interface so a nil pointer satisfies the
// interface with a typed-nil dynamic value.
type typedNilJWKSet struct {
	setAlias
}
