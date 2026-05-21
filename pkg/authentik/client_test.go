package authentik

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAuthentik spins up an httptest.Server that mimics the subset of
// Authentik endpoints the client touches.
type fakeAuthentik struct {
	*httptest.Server

	// scriptedFlow lets each test push a sequence of responses for the
	// /api/v3/flows/executor/<slug>/ endpoint. Each successive request
	// (GET → POST uid → POST password) consumes the next entry.
	scriptedFlow []flowResp

	// adminUsers is the canned response body for GET /api/v3/core/users/.
	adminUsersBody string
	adminUsersCode int

	// createUserBody/Code drive POST /api/v3/core/users/.
	createUserBody string
	createUserCode int

	// setPwCode drives POST /api/v3/core/users/{pk}/set_password/.
	setPwCode int

	// counters
	flowHits, setPwHits, createHits, lookupHits int
}

type flowResp struct {
	status int
	body   string
}

func newFake(t *testing.T) *fakeAuthentik {
	t.Helper()
	fa := &fakeAuthentik{}
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v3/flows/executor/", func(w http.ResponseWriter, _ *http.Request) {
		if len(fa.scriptedFlow) == 0 {
			http.Error(w, "no scripted response", http.StatusInternalServerError)
			return
		}
		next := fa.scriptedFlow[0]
		fa.scriptedFlow = fa.scriptedFlow[1:]
		fa.flowHits++
		w.Header().Set("Content-Type", "application/json")
		// Set a session cookie on the first hit so cookiejar has something to
		// echo back. Authentik does the same.
		if fa.flowHits == 1 {
			http.SetCookie(w, &http.Cookie{Name: "authentik_session", Value: "abc"})
		}
		w.WriteHeader(next.status)
		_, _ = io.WriteString(w, next.body)
	})

	mux.HandleFunc("/api/v3/core/users/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			fa.lookupHits++
			code := fa.adminUsersCode
			if code == 0 {
				code = http.StatusOK
			}
			w.WriteHeader(code)
			_, _ = io.WriteString(w, fa.adminUsersBody)
		case http.MethodPost:
			// Either user create or set_password — distinguish by path suffix.
			if strings.HasSuffix(r.URL.Path, "/set_password/") {
				fa.setPwHits++
				code := fa.setPwCode
				if code == 0 {
					code = http.StatusNoContent
				}
				w.WriteHeader(code)
				return
			}
			fa.createHits++
			code := fa.createUserCode
			if code == 0 {
				code = http.StatusCreated
			}
			w.WriteHeader(code)
			_, _ = io.WriteString(w, fa.createUserBody)
		}
	})

	fa.Server = httptest.NewServer(mux)
	t.Cleanup(fa.Close)
	return fa
}

// scriptHappyFlow loads the 3-step success sequence: identification challenge,
// password challenge, success redirect.
func (fa *fakeAuthentik) scriptHappyFlow() {
	fa.scriptedFlow = []flowResp{
		{status: 200, body: `{"component":"ak-stage-identification"}`},
		{status: 200, body: `{"component":"ak-stage-password","pending_user":"u@x.test"}`},
		{status: 200, body: `{"component":"xak-flow-redirect","to":"/"}`},
	}
}

func newClient(base string) *Client {
	return New(Config{
		BaseURL:      base + "/", // trailing slash exercises TrimRight
		ClientID:     "cid",
		ClientSecret: "csec",
		AdminToken:   "tok",
		FlowSlug:     "goshop-ropg",
	})
}

// New / config wiring
// ==========================================================================

func TestNew_TrimsTrailingSlash(t *testing.T) {
	c := New(Config{BaseURL: "https://x.example/"})
	assert.Equal(t, "https://x.example", c.BaseURL)
	assert.NotNil(t, c.HTTPClient)
}

// PasswordLogin
// ==========================================================================

func TestPasswordLogin_Success(t *testing.T) {
	fa := newFake(t)
	fa.scriptHappyFlow()
	fa.adminUsersBody = `{"results":[{"uuid":"sub-1","email":"u@x.test","name":"U"}]}`

	c := newClient(fa.URL)
	claims, err := c.PasswordLogin(context.Background(), "u@x.test", "pw")

	require.NoError(t, err)
	assert.Equal(t, &UserClaims{Sub: "sub-1", Email: "u@x.test", Name: "U"}, claims)
	assert.Equal(t, 3, fa.flowHits, "must call flow executor 3 times")
	assert.Equal(t, 1, fa.lookupHits, "must look up user after auth")
}

func TestPasswordLogin_NoFlowSlug(t *testing.T) {
	c := New(Config{BaseURL: "http://x"}) // FlowSlug empty
	_, err := c.PasswordLogin(context.Background(), "u@x.test", "pw")
	assert.ErrorContains(t, err, "flow slug not configured")
}

func TestPasswordLogin_FlowInitFails(t *testing.T) {
	fa := newFake(t)
	fa.scriptedFlow = []flowResp{{status: 500, body: `boom`}}

	c := newClient(fa.URL)
	_, err := c.PasswordLogin(context.Background(), "u@x.test", "pw")
	assert.ErrorContains(t, err, "flow init")
}

func TestPasswordLogin_UnknownUser(t *testing.T) {
	// Identification stage returns the identification component again
	// (Authentik does this when the user doesn't exist and the stage is set
	// to obscure that fact). Anything that isn't ak-stage-password is a
	// rejection from our point of view.
	fa := newFake(t)
	fa.scriptedFlow = []flowResp{
		{status: 200, body: `{"component":"ak-stage-identification"}`},
		{status: 200, body: `{"component":"ak-stage-access-denied"}`},
	}

	c := newClient(fa.URL)
	_, err := c.PasswordLogin(context.Background(), "ghost@x.test", "pw")
	assert.ErrorContains(t, err, "unexpected stage after identification")
}

func TestPasswordLogin_IdentificationCallFails(t *testing.T) {
	fa := newFake(t)
	fa.scriptedFlow = []flowResp{
		{status: 200, body: `{"component":"ak-stage-identification"}`},
		{status: 500, body: `boom`},
	}

	c := newClient(fa.URL)
	_, err := c.PasswordLogin(context.Background(), "u@x.test", "pw")
	assert.ErrorContains(t, err, "flow identification")
}

func TestPasswordLogin_PasswordCallFails(t *testing.T) {
	fa := newFake(t)
	fa.scriptedFlow = []flowResp{
		{status: 200, body: `{"component":"ak-stage-identification"}`},
		{status: 200, body: `{"component":"ak-stage-password"}`},
		{status: 500, body: `boom`},
	}

	c := newClient(fa.URL)
	_, err := c.PasswordLogin(context.Background(), "u@x.test", "pw")
	assert.ErrorContains(t, err, "flow password")
}

func TestPasswordLogin_InvalidPassword(t *testing.T) {
	fa := newFake(t)
	fa.scriptedFlow = []flowResp{
		{status: 200, body: `{"component":"ak-stage-identification"}`},
		{status: 200, body: `{"component":"ak-stage-password"}`},
		{status: 200, body: `{"component":"ak-stage-password","response_errors":{"password":[{"string":"Invalid password","code":"invalid"}]}}`},
	}

	c := newClient(fa.URL)
	_, err := c.PasswordLogin(context.Background(), "u@x.test", "wrong")
	assert.ErrorContains(t, err, "Invalid password")
}

func TestPasswordLogin_UnexpectedStageAfterPassword(t *testing.T) {
	// No response_errors → falls through to generic "auth not completed".
	fa := newFake(t)
	fa.scriptedFlow = []flowResp{
		{status: 200, body: `{"component":"ak-stage-identification"}`},
		{status: 200, body: `{"component":"ak-stage-password"}`},
		{status: 200, body: `{"component":"ak-stage-captcha"}`},
	}

	c := newClient(fa.URL)
	_, err := c.PasswordLogin(context.Background(), "u@x.test", "pw")
	assert.ErrorContains(t, err, "auth not completed at stage ak-stage-captcha")
}

func TestPasswordLogin_LookupFailsAfterAuth(t *testing.T) {
	fa := newFake(t)
	fa.scriptHappyFlow()
	fa.adminUsersBody = `{"results":[]}` // no match → lookup error path

	c := newClient(fa.URL)
	_, err := c.PasswordLogin(context.Background(), "u@x.test", "pw")
	assert.ErrorContains(t, err, "no user with email")
}

// flowCall edge cases (driven through PasswordLogin to keep tests black-box).
// ==========================================================================

func TestFlowCall_MalformedJSON(t *testing.T) {
	fa := newFake(t)
	fa.scriptedFlow = []flowResp{{status: 200, body: `not json`}}

	c := newClient(fa.URL)
	_, err := c.PasswordLogin(context.Background(), "u@x.test", "pw")
	assert.ErrorContains(t, err, "decode challenge")
}

func TestFlowCall_InvalidURLRequestBuild(t *testing.T) {
	// A control character in the URL forces http.NewRequestWithContext to
	// error before we ever hit the network. Exercises the err-from-NewRequest
	// branch in flowCall.
	c := New(Config{BaseURL: "http://x\x7f", FlowSlug: "s"})
	_, err := c.PasswordLogin(context.Background(), "u@x.test", "pw")
	assert.Error(t, err)
}

func TestFlowCall_NetworkError(t *testing.T) {
	// Point at a closed server — client.Do returns an error.
	fa := newFake(t)
	fa.scriptHappyFlow()
	base := fa.URL
	fa.Close()

	c := newClient(base)
	_, err := c.PasswordLogin(context.Background(), "u@x.test", "pw")
	assert.Error(t, err)
}

// LookupUserByEmail
// ==========================================================================

func TestLookupUserByEmail_Success(t *testing.T) {
	fa := newFake(t)
	fa.adminUsersBody = `{"results":[{"uuid":"sub","email":"u@x.test","name":"U"}]}`

	c := newClient(fa.URL)
	claims, err := c.LookupUserByEmail(context.Background(), "u@x.test")

	require.NoError(t, err)
	assert.Equal(t, "sub", claims.Sub)
	assert.Equal(t, "u@x.test", claims.Email)
	assert.Equal(t, "U", claims.Name)
}

func TestLookupUserByEmail_NoAdminToken(t *testing.T) {
	c := New(Config{BaseURL: "http://x"})
	_, err := c.LookupUserByEmail(context.Background(), "u@x.test")
	assert.ErrorContains(t, err, "admin token not configured")
}

func TestLookupUserByEmail_NonOK(t *testing.T) {
	fa := newFake(t)
	fa.adminUsersCode = http.StatusUnauthorized
	fa.adminUsersBody = `{"detail":"nope"}`

	c := newClient(fa.URL)
	_, err := c.LookupUserByEmail(context.Background(), "u@x.test")
	assert.ErrorContains(t, err, "user lookup 401")
}

func TestLookupUserByEmail_NoResults(t *testing.T) {
	fa := newFake(t)
	fa.adminUsersBody = `{"results":[]}`

	c := newClient(fa.URL)
	_, err := c.LookupUserByEmail(context.Background(), "u@x.test")
	assert.ErrorContains(t, err, "no user with email")
}

func TestLookupUserByEmail_MalformedJSON(t *testing.T) {
	fa := newFake(t)
	fa.adminUsersBody = `garbage`

	c := newClient(fa.URL)
	_, err := c.LookupUserByEmail(context.Background(), "u@x.test")
	assert.ErrorContains(t, err, "decode user lookup")
}

func TestLookupUserByEmail_RequestBuildFails(t *testing.T) {
	c := New(Config{BaseURL: "http://x\x7f", AdminToken: "t"})
	_, err := c.LookupUserByEmail(context.Background(), "u@x.test")
	assert.Error(t, err)
}

func TestLookupUserByEmail_NetworkError(t *testing.T) {
	fa := newFake(t)
	base := fa.URL
	fa.Close()

	c := newClient(base)
	_, err := c.LookupUserByEmail(context.Background(), "u@x.test")
	assert.Error(t, err)
}

// CreateUser
// ==========================================================================

func TestCreateUser_Success(t *testing.T) {
	fa := newFake(t)
	fa.createUserBody = `{"pk":42}`

	c := newClient(fa.URL)
	err := c.CreateUser(context.Background(), "u@x.test", "U", "pw")

	require.NoError(t, err)
	assert.Equal(t, 1, fa.createHits)
	assert.Equal(t, 1, fa.setPwHits)
}

func TestCreateUser_NoAdminToken(t *testing.T) {
	c := New(Config{BaseURL: "http://x"})
	err := c.CreateUser(context.Background(), "u@x.test", "U", "pw")
	assert.ErrorContains(t, err, "admin token not configured")
}

func TestCreateUser_CreateFails(t *testing.T) {
	fa := newFake(t)
	fa.createUserCode = http.StatusBadRequest
	fa.createUserBody = `{"detail":"bad"}`

	c := newClient(fa.URL)
	err := c.CreateUser(context.Background(), "u@x.test", "U", "pw")
	assert.ErrorContains(t, err, "create user 400")
}

func TestCreateUser_CreateResponseMalformed(t *testing.T) {
	fa := newFake(t)
	fa.createUserBody = `garbage`

	c := newClient(fa.URL)
	err := c.CreateUser(context.Background(), "u@x.test", "U", "pw")
	assert.ErrorContains(t, err, "decode create user")
}

func TestCreateUser_SetPasswordFails(t *testing.T) {
	fa := newFake(t)
	fa.createUserBody = `{"pk":7}`
	fa.setPwCode = http.StatusBadRequest

	c := newClient(fa.URL)
	err := c.CreateUser(context.Background(), "u@x.test", "U", "pw")
	assert.ErrorContains(t, err, "set_password 400")
}

func TestCreateUser_SetPasswordOK200Accepted(t *testing.T) {
	// Authentik returns 204 in normal flow but 200 is also acceptable.
	fa := newFake(t)
	fa.createUserBody = `{"pk":7}`
	fa.setPwCode = http.StatusOK

	c := newClient(fa.URL)
	err := c.CreateUser(context.Background(), "u@x.test", "U", "pw")
	assert.NoError(t, err)
}

func TestCreateUser_CreateRequestBuildFails(t *testing.T) {
	c := New(Config{BaseURL: "http://x\x7f", AdminToken: "t"})
	err := c.CreateUser(context.Background(), "u@x.test", "U", "pw")
	assert.Error(t, err)
}

func TestCreateUser_CreateNetworkError(t *testing.T) {
	fa := newFake(t)
	base := fa.URL
	fa.Close()
	c := newClient(base)
	err := c.CreateUser(context.Background(), "u@x.test", "U", "pw")
	assert.Error(t, err)
}

func TestCreateUser_SetPasswordNetworkError(t *testing.T) {
	// Close the server right after create succeeds — set_password call then
	// fails on the network. Achieved by serving the create response and then
	// making the set_password handler hijack & close the connection.
	mux := http.NewServeMux()
	var setPwHit bool
	mux.HandleFunc("/api/v3/core/users/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/set_password/") {
			setPwHit = true
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "no hijack", 500)
				return
			}
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"pk":1}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newClient(srv.URL)
	err := c.CreateUser(context.Background(), "u@x.test", "U", "pw")
	assert.Error(t, err)
	assert.True(t, setPwHit)
}

// Sanity: ensure the request bodies the client sends match expectations.
func TestCreateUser_RequestBodiesAreCorrect(t *testing.T) {
	var createBody, setBody map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/core/users/", func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		if strings.HasSuffix(r.URL.Path, "/set_password/") {
			_ = json.Unmarshal(buf, &setBody)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.Unmarshal(buf, &createBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"pk":9}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newClient(srv.URL)
	require.NoError(t, c.CreateUser(context.Background(), "u@x.test", "U", "pw"))

	assert.Equal(t, "u@x.test", createBody["username"])
	assert.Equal(t, "u@x.test", createBody["email"])
	assert.Equal(t, "U", createBody["name"])
	assert.Equal(t, true, createBody["is_active"])
	assert.Equal(t, "internal", createBody["type"])
	assert.Equal(t, "pw", setBody["password"])
}
