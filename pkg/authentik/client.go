// Package authentik is a thin HTTP client to Authentik used in headless mode:
// goshop renders all auth UI itself and talks to Authentik server-to-server
// for password login (ROPG), self-service registration, and to look up the
// federated source slug for "Login with Google / Facebook" deep links.
package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to a single Authentik instance.
type Client struct {
	BaseURL      string
	ClientID     string
	ClientSecret string
	AdminToken   string

	HTTPClient *http.Client
}

// Config bundles everything needed to construct a Client.
type Config struct {
	BaseURL      string // e.g. https://auth.example.com
	ClientID     string // OAuth2 application client_id
	ClientSecret string // OAuth2 application client_secret
	AdminToken   string // long-lived API token with user-write scope
}

func New(cfg Config) *Client {
	return &Client{
		BaseURL:      strings.TrimRight(cfg.BaseURL, "/"),
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		AdminToken:   cfg.AdminToken,
		HTTPClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

// UserClaims is the subset of OIDC userinfo we care about.
type UserClaims struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
}

// PasswordLogin runs the Resource Owner Password Grant flow against the
// configured OAuth2 provider, then fetches userinfo with the resulting access
// token. Returns the claims of the authenticated user.
func (c *Client) PasswordLogin(ctx context.Context, email, password string) (*UserClaims, error) {
	form := url.Values{
		"grant_type": {"password"},
		"username":   {email},
		"password":   {password},
		"scope":      {"openid email profile"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/application/o/token/", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.ClientID, c.ClientSecret)

	tok, err := c.doToken(req)
	if err != nil {
		return nil, err
	}
	return c.UserInfo(ctx, tok.AccessToken)
}

func (c *Client) doToken(req *http.Request) (*tokenResponse, error) {
	resp, err := c.HTTPClient.Do(req) //nolint:gosec // URL is built from server config, not user input
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authentik token endpoint %d: %s", resp.StatusCode, string(body))
	}
	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	return &tok, nil
}

// UserInfo calls the OIDC userinfo endpoint with the given access token.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (*UserClaims, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.BaseURL+"/application/o/userinfo/", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.HTTPClient.Do(req) //nolint:gosec // URL is built from server config, not user input
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authentik userinfo %d: %s", resp.StatusCode, string(body))
	}
	var claims UserClaims
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}
	return &claims, nil
}

// CreateUser provisions a new internal Authentik user and sets their password
// via the core admin API. The caller should follow up with PasswordLogin to
// obtain the OIDC sub for upserting the local user row.
func (c *Client) CreateUser(ctx context.Context, email, name, password string) error {
	if c.AdminToken == "" {
		return fmt.Errorf("authentik admin token not configured")
	}

	createBody, _ := json.Marshal(map[string]any{
		"username":  email,
		"email":     email,
		"name":      name,
		"is_active": true,
		"type":      "internal",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/api/v3/core/users/", bytes.NewReader(createBody))
	if err != nil {
		return err
	}
	c.addAdminAuth(req)

	pk, err := c.doCreateUser(req)
	if err != nil {
		return err
	}

	// Authentik's user create endpoint does NOT accept the password inline;
	// we set it via the dedicated set_password endpoint.
	setBody, _ := json.Marshal(map[string]string{"password": password})
	setURL := fmt.Sprintf("%s/api/v3/core/users/%d/set_password/", c.BaseURL, pk)
	req2, err := http.NewRequestWithContext(ctx, http.MethodPost, setURL, bytes.NewReader(setBody))
	if err != nil {
		return err
	}
	c.addAdminAuth(req2)

	resp, err := c.HTTPClient.Do(req2)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentik set_password %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (c *Client) addAdminAuth(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
}

func (c *Client) doCreateUser(req *http.Request) (int, error) {
	resp, err := c.HTTPClient.Do(req) //nolint:gosec // URL is built from server config, not user input
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("authentik create user %d: %s", resp.StatusCode, string(body))
	}
	var u struct {
		PK int `json:"pk"`
	}
	if err := json.Unmarshal(body, &u); err != nil {
		return 0, fmt.Errorf("decode create user response: %w", err)
	}
	return u.PK, nil
}

// SourceAuthURL returns the OIDC authorize URL that, thanks to the `source`
// query parameter, makes Authentik immediately bounce to the federated
// provider (Google / Facebook / etc) without showing its own UI. The caller
// is responsible for the rest of the OIDC parameters and the redirect URI.
func (c *Client) SourceAuthURL(redirectURI, sourceSlug, state string) string {
	q := url.Values{
		"client_id":     {c.ClientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {state},
		"source":        {sourceSlug},
	}
	return c.BaseURL + "/application/o/authorize/?" + q.Encode()
}
