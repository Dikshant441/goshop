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
	"net/http/cookiejar"
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
	// FlowSlug is the slug of the Authentik authentication flow used for
	// headless password verification via /api/v3/flows/executor/. The flow
	// must contain only an Identification Stage + Password Stage (and
	// optionally a User Login Stage). MFA/consent/captcha stages break the
	// programmatic call.
	FlowSlug string

	HTTPClient *http.Client
}

// Config bundles everything needed to construct a Client.
type Config struct {
	BaseURL      string // e.g. https://auth.example.com
	ClientID     string // OAuth2 application client_id (unused with flow executor; kept for future)
	ClientSecret string // OAuth2 application client_secret (unused; kept for future)
	AdminToken   string // long-lived API token with user-write scope
	FlowSlug     string // authentication flow slug, e.g. "goshop-ropg"
}

func New(cfg Config) *Client {
	return &Client{
		BaseURL:      strings.TrimRight(cfg.BaseURL, "/"),
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		AdminToken:   cfg.AdminToken,
		FlowSlug:     cfg.FlowSlug,
		HTTPClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

// UserClaims is the subset of OIDC userinfo we care about.
type UserClaims struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// flowChallenge is the minimal subset of an Authentik flow-executor response
// we care about. After password submission either:
//   - component == "xak-flow-redirect" → auth succeeded
//   - component == "ak-stage-password" with response_errors → bad password
//   - component == "ak-stage-access-denied" or similar → user blocked
type flowChallenge struct {
	Component      string                      `json:"component"`
	PendingUser    string                      `json:"pending_user"`
	ResponseErrors map[string][]flowFieldError `json:"response_errors"`
}

type flowFieldError struct {
	String string `json:"string"`
	Code   string `json:"code"`
}

// PasswordLogin verifies email+password against Authentik using the flow
// executor API. Authentik's ROPG (/application/o/token/ with grant_type=
// password) is reserved for app-password tokens, not real user passwords —
// the flow executor is the supported headless path.
//
// Steps:
//  1. GET  /api/v3/flows/executor/<flow>/?query=          → identification challenge + session cookie
//  2. POST same URL with {"uid_field": email}             → password challenge
//  3. POST same URL with {"password": password}           → redirect (success) or password error
//
// On success the user is looked up via the admin API to obtain the OIDC sub.
func (c *Client) PasswordLogin(ctx context.Context, email, password string) (*UserClaims, error) {
	if c.FlowSlug == "" {
		return nil, fmt.Errorf("authentik flow slug not configured")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{Timeout: 10 * time.Second, Jar: jar}
	flowURL := fmt.Sprintf("%s/api/v3/flows/executor/%s/?query=", c.BaseURL, url.PathEscape(c.FlowSlug))

	// 1. Init session — discard body; we just need the cookie.
	if _, err := c.flowCall(ctx, httpClient, http.MethodGet, flowURL, nil); err != nil {
		return nil, fmt.Errorf("flow init: %w", err)
	}

	// 2. Submit identifier.
	idResp, err := c.flowCall(ctx, httpClient, http.MethodPost, flowURL,
		map[string]string{"uid_field": email})
	if err != nil {
		return nil, fmt.Errorf("flow identification: %w", err)
	}
	if idResp.Component != "ak-stage-password" {
		// Identification stage rejected the user (unknown username/email).
		return nil, fmt.Errorf("authentik: unexpected stage after identification: %s", idResp.Component)
	}

	// 3. Submit password.
	pwResp, err := c.flowCall(ctx, httpClient, http.MethodPost, flowURL,
		map[string]string{"password": password})
	if err != nil {
		return nil, fmt.Errorf("flow password: %w", err)
	}
	if pwResp.Component != "xak-flow-redirect" {
		// Most likely "ak-stage-password" with response_errors.password = "Invalid password".
		if errs, ok := pwResp.ResponseErrors["password"]; ok && len(errs) > 0 {
			return nil, fmt.Errorf("authentik: %s", errs[0].String)
		}
		return nil, fmt.Errorf("authentik: auth not completed at stage %s", pwResp.Component)
	}

	// Auth succeeded — pull the user record (sub + canonical email + name)
	// from the admin API. Avoids needing an access token.
	return c.LookupUserByEmail(ctx, email)
}

// flowCall does one round-trip against /api/v3/flows/executor/. The session
// cookie is automatically attached/captured by the client's cookie jar.
func (c *Client) flowCall(
	ctx context.Context, client *http.Client, method, target string, body any,
) (*flowChallenge, error) {
	var reader io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req) //nolint:gosec // URL is built from server config, not user input
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("flow executor %d: %s", resp.StatusCode, string(raw))
	}
	var ch flowChallenge
	if err := json.Unmarshal(raw, &ch); err != nil {
		return nil, fmt.Errorf("decode challenge: %w", err)
	}
	return &ch, nil
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

// LookupUserByEmail asks the admin API for the user with the given email and
// returns their OIDC-compatible claims (uuid → sub). Used after CreateUser so
// callers don't have to rely on the ROPG flow — which Authentik validates
// against the provider's redirect_uris and frequently 400s with
// "invalid_grant" on freshly-provisioned users.
func (c *Client) LookupUserByEmail(ctx context.Context, email string) (*UserClaims, error) {
	if c.AdminToken == "" {
		return nil, fmt.Errorf("authentik admin token not configured")
	}
	q := url.Values{"email": {email}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.BaseURL+"/api/v3/core/users/?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	c.addAdminAuth(req)

	resp, err := c.HTTPClient.Do(req) //nolint:gosec // URL is built from server config, not user input
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authentik user lookup %d: %s", resp.StatusCode, string(body))
	}
	var page struct {
		Results []struct {
			UUID  string `json:"uuid"`
			Email string `json:"email"`
			Name  string `json:"name"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("decode user lookup response: %w", err)
	}
	if len(page.Results) == 0 {
		return nil, fmt.Errorf("authentik user lookup: no user with email %s", email)
	}
	u := page.Results[0]
	return &UserClaims{Sub: u.UUID, Email: u.Email, Name: u.Name}, nil
}
