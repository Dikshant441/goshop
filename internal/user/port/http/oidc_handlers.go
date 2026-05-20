package http

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	goOIDC "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/quangdangfit/gocommon/logger"
	"golang.org/x/oauth2"

	"goshop/internal/user/service"
	"goshop/pkg/apperror"
	"goshop/pkg/config"
	"goshop/pkg/jtoken"
	"goshop/pkg/oidc"
)

// oidcClient is the subset of oidc.Validator that this handler depends on.
// Carved out as an interface so tests can inject a fake without spinning up a
// real OIDC provider.
type oidcClient interface {
	AuthCodeURL(state string) string
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	Verify(ctx context.Context, rawIDToken string) (*goOIDC.IDToken, error)
}

// providerSlug resolves a public provider id ("google" / "facebook" / "apple")
// to the federated-source slug configured inside Authentik. Returns "" when
// the provider is unknown or its slug has not been configured.
func providerSlug(cfg *config.Schema, provider string) string {
	switch strings.ToLower(provider) {
	case "google":
		return cfg.AuthentikGoogleSourceSlug
	case "facebook":
		return cfg.AuthentikFacebookSourceSlug
	case "apple":
		return cfg.AuthentikAppleSourceSlug
	default:
		return ""
	}
}

// OIDCHandler handles the Authentik OIDC login flow.
type OIDCHandler struct {
	service service.UserService
	cfg     *config.Schema
	oidc    oidcClient
}

// onValidatorInitError is the failure hook for NewOIDCHandler. In production
// it terminates the process — running the API in OIDC mode without a
// reachable Authentik is a misconfig the operator must fix. Tests override
// the hook to capture the call instead.
var onValidatorInitError = func(err error) {
	logger.Fatalf("failed to create OIDC validator: %v", err)
}

// NewOIDCHandler builds the handler and eagerly initialises the OIDC
// validator. Init failure delegates to onValidatorInitError, which exits the
// process in production.
func NewOIDCHandler(svc service.UserService, cfg *config.Schema) *OIDCHandler {
	v, err := oidc.NewValidator(
		cfg.OIDCIssuer,
		cfg.OIDCClientID,
		cfg.OIDCClientSecret,
		cfg.OIDCRedirectURL,
	)
	if err != nil {
		onValidatorInitError(err)
		return nil
	}
	return &OIDCHandler{service: svc, cfg: cfg, oidc: v}
}

// newOIDCHandlerWith is the test-only constructor that accepts a pre-built
// oidcClient. Production code always goes through NewOIDCHandler.
func newOIDCHandlerWith(svc service.UserService, cfg *config.Schema, client oidcClient) *OIDCHandler {
	return &OIDCHandler{service: svc, cfg: cfg, oidc: client}
}

// SSORedirect 302s the browser to Authentik's authorize endpoint with a
// `source=<slug>` query parameter, which tells Authentik to skip its own
// login UI and bounce immediately to the federated provider (Google /
// Facebook / Apple).
// GET /api/v1/auth/sso/:provider
func (h *OIDCHandler) SSORedirect(c *gin.Context) {
	slug := providerSlug(h.cfg, c.Param("provider"))
	if slug == "" {
		apperror.WrapMessage(apperror.ErrBadRequest, nil, "unsupported provider").HTTPError(c)
		return
	}

	authURL := h.oidc.AuthCodeURL("goshop-state")
	u, err := url.Parse(authURL)
	if err != nil {
		apperror.Wrap(apperror.ErrInternal, err).HTTPError(c)
		return
	}
	q := u.Query()
	q.Set("source", slug)
	u.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, u.String())
}

// Callback consumes the authorization code from Authentik, exchanges it for
// an ID token, upserts the local user, mints a GoShop JWT pair, and finally
// redirects the browser back to the FE with the tokens in the query string.
//
// The FE must expose a /auth/callback route that reads access_token /
// refresh_token from the URL and persists them.
// GET /api/v1/auth/callback?code=xxx
func (h *OIDCHandler) Callback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		apperror.WrapMessage(apperror.ErrBadRequest, nil, "missing authorization code").HTTPError(c)
		return
	}

	ctx := c.Request.Context()
	oauth2Token, err := h.oidc.Exchange(ctx, code)
	if err != nil {
		logger.Errorf("OIDC exchange failed: %v", err)
		apperror.Wrap(apperror.ErrUnauthorized, err).HTTPError(c)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		apperror.WrapMessage(apperror.ErrUnauthorized, nil, "no id_token in token response").HTTPError(c)
		return
	}

	idToken, err := h.oidc.Verify(ctx, rawIDToken)
	if err != nil {
		logger.Errorf("OIDC verify failed: %v", err)
		apperror.Wrap(apperror.ErrUnauthorized, err).HTTPError(c)
		return
	}

	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		logger.Errorf("failed to parse OIDC claims: %v", err)
		apperror.Wrap(apperror.ErrUnauthorized, err).HTTPError(c)
		return
	}

	if claims.Email == "" {
		apperror.WrapMessage(apperror.ErrBadRequest, nil, "id_token email claim is empty").HTTPError(c)
		return
	}

	user, err := h.service.UpsertUserFromOIDC(ctx, claims.Sub, claims.Email, claims.Name)
	if err != nil {
		logger.Errorf("UpsertUserFromOIDC failed: %v", err)
		apperror.ToHTTPError(c, err, http.StatusInternalServerError, "Something went wrong")
		return
	}

	tokenData := map[string]interface{}{
		"id":    user.ID,
		"email": user.Email,
		"role":  user.Role,
	}
	accessToken := jtoken.GenerateAccessToken(tokenData)
	refreshToken := jtoken.GenerateRefreshToken(tokenData)

	// Build the FE redirect: <frontend_base_url>/auth/callback?access_token=…&refresh_token=…
	target, err := url.Parse(h.cfg.FrontendBaseURL)
	if err != nil || target.Host == "" {
		apperror.WrapMessage(apperror.ErrInternal, err, "invalid frontend_base_url").HTTPError(c)
		return
	}
	target.Path = strings.TrimRight(target.Path, "/") + "/auth/callback"
	q := target.Query()
	q.Set("access_token", accessToken)
	q.Set("refresh_token", refreshToken)
	target.RawQuery = q.Encode()

	c.Redirect(http.StatusFound, target.String())
}
