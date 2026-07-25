package authclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestClient spins up an httptest server with handler h and returns a Client
// pointed at it (retries/backoff tuned for fast tests).
func newTestClient(t *testing.T, h http.HandlerFunc, opts ...Option) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	base := []Option{WithBackoff(time.Millisecond, 5*time.Millisecond)}
	c := New(srv.URL, append(base, opts...)...)
	return c, srv
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- Login / token flows ----

func TestLogin(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/login" || r.Method != http.MethodPost {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if req.Email != "a@b.com" || req.Password != "pw" {
			t.Errorf("bad login body: %+v", req)
		}
		writeJSON(w, 200, TokenSet{
			AccessToken:  "acc",
			RefreshToken: "ref",
			TokenType:    "bearer",
			ExpiresIn:    3600,
			User:         TokenUserInfo{ID: "u1", Email: "a@b.com"},
		})
	})
	tok, err := c.Login(context.Background(), LoginRequest{Email: "a@b.com", Password: "pw"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if tok.AccessToken != "acc" || tok.User.ID != "u1" {
		t.Errorf("unexpected token set: %+v", tok)
	}
}

func TestRefreshSendsRefreshToken(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var req RefreshRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.RefreshToken != "rtok" {
			t.Errorf("refresh token not forwarded: %q", req.RefreshToken)
		}
		writeJSON(w, 200, TokenSet{AccessToken: "new"})
	})
	tok, err := c.Refresh(context.Background(), "rtok")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if tok.AccessToken != "new" {
		t.Errorf("got %q", tok.AccessToken)
	}
}

func TestSwitchOrganizationSendsAuth(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer usertok" {
			t.Errorf("auth header = %q", got)
		}
		var req SwitchOrganizationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.OrgID != "org2" {
			t.Errorf("org id = %q", req.OrgID)
		}
		writeJSON(w, 200, TokenSet{AccessToken: "scoped", User: TokenUserInfo{OrgID: "org2"}})
	})
	tok, err := c.SwitchOrganization(context.Background(), "usertok", "org2")
	if err != nil {
		t.Fatalf("SwitchOrganization: %v", err)
	}
	if tok.User.OrgID != "org2" {
		t.Errorf("org not scoped: %+v", tok)
	}
}

// ---- Token validation / authorize (table-driven) ----

func TestValidateTokenAndAuthorize(t *testing.T) {
	tests := []struct {
		name        string
		resp        Actor
		action      string
		resource    Resource
		wantAllowed bool
		wantPerm    bool // HasPermission("x.read")
	}{
		{
			name:        "valid with permission",
			resp:        Actor{Valid: true, UserID: "u1", Permissions: []string{"x.read"}},
			action:      "x.read",
			wantAllowed: true,
			wantPerm:    true,
		},
		{
			name:        "valid but resource-scoped",
			resp:        Actor{Valid: true, UserID: "u1"},
			action:      "world.write",
			resource:    Resource{Type: "world", ID: "w1"},
			wantAllowed: true,
		},
		{
			name:        "invalid token",
			resp:        Actor{Valid: false, Error: "expired"},
			action:      "x.read",
			wantAllowed: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/auth/validate-token" {
					t.Errorf("path = %s", r.URL.Path)
				}
				var req TokenValidationRequest
				_ = json.NewDecoder(r.Body).Decode(&req)
				if req.ExpectedAudience != "game" {
					t.Errorf("expected audience not applied: %q", req.ExpectedAudience)
				}
				writeJSON(w, 200, tt.resp)
			}, WithExpectedAudience("game"))

			actor, err := c.ValidateToken(context.Background(), "tok")
			if err != nil {
				t.Fatalf("ValidateToken: %v", err)
			}
			if actor.Valid != tt.resp.Valid {
				t.Errorf("valid = %v want %v", actor.Valid, tt.resp.Valid)
			}
			if actor.HasPermission("x.read") != tt.wantPerm {
				t.Errorf("HasPermission = %v want %v", actor.HasPermission("x.read"), tt.wantPerm)
			}

			allowed, err := c.Authorize(context.Background(), "tok", tt.action, tt.resource)
			if err != nil {
				t.Fatalf("Authorize: %v", err)
			}
			if allowed != tt.wantAllowed {
				t.Errorf("Authorize = %v want %v", allowed, tt.wantAllowed)
			}
		})
	}
}

func TestAuthorizeForwardsResourceAndPermission(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var req TokenValidationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if len(req.RequiredPermissions) != 1 || req.RequiredPermissions[0] != "world.write" {
			t.Errorf("required perms = %v", req.RequiredPermissions)
		}
		if req.ResourceType != "world" || req.ResourceID != "w1" {
			t.Errorf("resource = %s/%s", req.ResourceType, req.ResourceID)
		}
		writeJSON(w, 200, Actor{Valid: true})
	})
	ok, err := c.Authorize(context.Background(), "tok", "world.write", Resource{Type: "world", ID: "w1"})
	if err != nil || !ok {
		t.Fatalf("Authorize ok=%v err=%v", ok, err)
	}
}

func TestValidateAPIKey(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var req ValidateAPIKeyRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.APIKey != "ab0t_sk_123" {
			t.Errorf("api key = %q", req.APIKey)
		}
		writeJSON(w, 200, APIKeyValidation{Valid: true, UserID: "svc", Permissions: []string{"users.read"}})
	})
	v, err := c.ValidateAPIKey(context.Background(), ValidateAPIKeyRequest{APIKey: "ab0t_sk_123"})
	if err != nil {
		t.Fatalf("ValidateAPIKey: %v", err)
	}
	if !v.Valid || v.UserID != "svc" {
		t.Errorf("unexpected: %+v", v)
	}
}

// TestAPIKeyCredentialRouting proves that an ab0t_sk_ credential is resolved at
// /auth/validate-api-key (NOT /auth/validate-token, which the auth service does
// not use for API keys), for BOTH Authorize (the route-gating primitive the
// game's authz.Gate.Require uses) and ValidateToken (the identity primitive
// Gate.Authenticate uses). Without this routing a valid agent key would be
// rejected 401/403 under AUTH_ENFORCE=true. A user JWT still hits validate-token.
func TestAPIKeyCredentialRouting(t *testing.T) {
	const agentKey = "ab0t_sk_TEST_FAKE_agent1" // fixture, not a real credential

	t.Run("Authorize routes API key to validate-api-key", func(t *testing.T) {
		var hitPath string
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			hitPath = r.URL.Path
			var req ValidateAPIKeyRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.APIKey != agentKey {
				t.Errorf("api key = %q", req.APIKey)
			}
			if len(req.RequiredPermissions) != 1 || req.RequiredPermissions[0] != "living_city.send.bot" {
				t.Errorf("required perms = %v", req.RequiredPermissions)
			}
			if req.ExpectedAudience != "living-city" {
				t.Errorf("expected_audience = %q", req.ExpectedAudience)
			}
			writeJSON(w, 200, APIKeyValidation{Valid: true, UserID: "svc", OrgID: "org1"})
		}, WithExpectedAudience("living-city"))

		ok, err := c.Authorize(context.Background(), agentKey, "living_city.send.bot", Resource{Type: "bot", ID: "alice"})
		if err != nil || !ok {
			t.Fatalf("Authorize ok=%v err=%v", ok, err)
		}
		if hitPath != "/auth/validate-api-key" {
			t.Fatalf("API key hit %q, want /auth/validate-api-key", hitPath)
		}
	})

	t.Run("Authorize denies API key missing the permission", func(t *testing.T) {
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, APIKeyValidation{Valid: false, Reason: "Missing required permissions"})
		}, WithExpectedAudience("living-city"))
		ok, err := c.Authorize(context.Background(), agentKey, "living_city.delete.bot", Resource{Type: "bot"})
		if err != nil {
			t.Fatalf("err=%v", err)
		}
		if ok {
			t.Fatal("expected deny for a permission the key lacks")
		}
	})

	t.Run("ValidateToken routes API key and adapts to Actor", func(t *testing.T) {
		var hitPath string
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			hitPath = r.URL.Path
			writeJSON(w, 200, APIKeyValidation{Valid: true, UserID: "svc", OrgID: "org1", Permissions: []string{"living_city.send.bot"}})
		}, WithExpectedAudience("living-city"))
		actor, err := c.ValidateToken(context.Background(), agentKey)
		if err != nil || actor == nil || !actor.Valid {
			t.Fatalf("ValidateToken actor=%+v err=%v", actor, err)
		}
		if actor.OrgID != "org1" || hitPath != "/auth/validate-api-key" {
			t.Fatalf("org=%q path=%q", actor.OrgID, hitPath)
		}
	})

	t.Run("JWT still routes to validate-token", func(t *testing.T) {
		var hitPath string
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			hitPath = r.URL.Path
			writeJSON(w, 200, Actor{Valid: true, UserID: "user1"})
		})
		if _, err := c.ValidateToken(context.Background(), "eyJ.jwt.token"); err != nil {
			t.Fatalf("err=%v", err)
		}
		if hitPath != "/auth/validate-token" {
			t.Fatalf("JWT hit %q, want /auth/validate-token", hitPath)
		}
	})
}

func TestIntrospectFormEncoded(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			t.Errorf("content-type = %q", ct)
		}
		_ = r.ParseForm()
		if r.Form.Get("token") != "tok" || r.Form.Get("token_type_hint") != "access_token" {
			t.Errorf("form = %v", r.Form)
		}
		writeJSON(w, 200, Introspection{Active: true, Subject: "u1"})
	})
	in, err := c.Introspect(context.Background(), "tok", "access_token")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !in.Active || in.Subject != "u1" {
		t.Errorf("unexpected: %+v", in)
	}
}

// ---- Error paths (table-driven) ----

func TestErrorClassification(t *testing.T) {
	tests := []struct {
		name           string
		status         int
		body           string
		wantCode       string
		wantMsg        string
		isUnauthorized bool
		isForbidden    bool
		isNotFound     bool
		isValidation   bool
		isRateLimited  bool
		isServer       bool
		isRetryable    bool
	}{
		{
			name:           "401 oauth envelope",
			status:         401,
			body:           `{"error":"invalid_token","error_description":"token expired"}`,
			wantCode:       "invalid_token",
			wantMsg:        "token expired",
			isUnauthorized: true,
		},
		{
			name:        "403 forbidden",
			status:      403,
			body:        `{"detail":"missing permission world.write"}`,
			wantMsg:     "missing permission world.write",
			isForbidden: true,
		},
		{
			name:       "404 not found",
			status:     404,
			body:       `{"message":"no such user","code":"not_found"}`,
			wantCode:   "not_found",
			wantMsg:    "no such user",
			isNotFound: true,
		},
		{
			name:         "422 fastapi list detail",
			status:       422,
			body:         `{"detail":[{"msg":"field required","type":"value_error.missing"}]}`,
			wantCode:     "value_error.missing",
			wantMsg:      "field required",
			isValidation: true,
		},
		{
			name:          "429 rate limited",
			status:        429,
			body:          `{"error":"rate_limited"}`,
			wantCode:      "rate_limited",
			isRateLimited: true,
			isRetryable:   true,
		},
		{
			name:        "500 server error",
			status:      500,
			body:        `internal`,
			isServer:    true,
			isRetryable: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Disable retries so each error surfaces immediately.
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Request-ID", "rid-123")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}, WithMaxRetries(0))

			_, err := c.Me(context.Background(), "tok")
			if err == nil {
				t.Fatal("expected error")
			}
			ae, ok := AsAPIError(err)
			if !ok {
				t.Fatalf("not an APIError: %v", err)
			}
			if ae.StatusCode != tt.status {
				t.Errorf("status = %d want %d", ae.StatusCode, tt.status)
			}
			if ae.RequestID != "rid-123" {
				t.Errorf("request id = %q", ae.RequestID)
			}
			if tt.wantCode != "" && ae.Code != tt.wantCode {
				t.Errorf("code = %q want %q", ae.Code, tt.wantCode)
			}
			if tt.wantMsg != "" && ae.Message != tt.wantMsg {
				t.Errorf("message = %q want %q", ae.Message, tt.wantMsg)
			}
			if IsUnauthorized(err) != tt.isUnauthorized {
				t.Errorf("IsUnauthorized = %v", IsUnauthorized(err))
			}
			if IsForbidden(err) != tt.isForbidden {
				t.Errorf("IsForbidden = %v", IsForbidden(err))
			}
			if IsNotFound(err) != tt.isNotFound {
				t.Errorf("IsNotFound = %v", IsNotFound(err))
			}
			if IsValidationError(err) != tt.isValidation {
				t.Errorf("IsValidationError = %v", IsValidationError(err))
			}
			if IsRateLimited(err) != tt.isRateLimited {
				t.Errorf("IsRateLimited = %v", IsRateLimited(err))
			}
			if IsServerError(err) != tt.isServer {
				t.Errorf("IsServerError = %v", IsServerError(err))
			}
			if IsRetryable(err) != tt.isRetryable {
				t.Errorf("IsRetryable = %v", IsRetryable(err))
			}
			if StatusCode(err) != tt.status {
				t.Errorf("StatusCode = %d", StatusCode(err))
			}
			// Error() string should be non-empty and mention the endpoint.
			if !strings.Contains(err.Error(), "/auth/me") {
				t.Errorf("Error() missing endpoint: %s", err.Error())
			}
		})
	}
}

func TestNonAPIErrorHelpers(t *testing.T) {
	if IsUnauthorized(context.Canceled) || IsRetryable(context.Canceled) {
		t.Error("non-APIError should not classify")
	}
	if StatusCode(context.Canceled) != 0 {
		t.Error("StatusCode of non-APIError should be 0")
	}
	if _, ok := AsAPIError(context.Canceled); ok {
		t.Error("AsAPIError should be false")
	}
}

// ---- Retry / backoff behavior ----

func TestRetryOn503ThenSuccess(t *testing.T) {
	var calls int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(503)
			return
		}
		writeJSON(w, 200, User{ID: "u1"})
	}, WithMaxRetries(3))

	u, err := c.Me(context.Background(), "tok")
	if err != nil {
		t.Fatalf("Me: %v", err)
	}
	if u.ID != "u1" {
		t.Errorf("user = %+v", u)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("calls = %d want 3", got)
	}
}

func TestRetryExhaustionReturnsError(t *testing.T) {
	var calls int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(500)
	}, WithMaxRetries(2))

	_, err := c.Me(context.Background(), "tok")
	if !IsServerError(err) {
		t.Fatalf("want server error, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 3 { // initial + 2 retries
		t.Errorf("calls = %d want 3", got)
	}
}

func TestNoRetryOn400(t *testing.T) {
	var calls int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(400)
	}, WithMaxRetries(3))
	_, _ = c.Me(context.Background(), "tok")
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("calls = %d want 1 (400 not retryable)", got)
	}
}

func TestPostRetriesOn5xxAndReplaysBody(t *testing.T) {
	// POST is non-idempotent, so a raw transport failure is not retried, but a
	// 5xx response is (the server reported it and the buffered body replays).
	var calls int32
	var bodies []string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		var req LoginRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		bodies = append(bodies, req.Email)
		if n < 2 {
			w.WriteHeader(502)
			return
		}
		writeJSON(w, 200, TokenSet{AccessToken: "ok"})
	}, WithMaxRetries(2))

	tok, err := c.Login(context.Background(), LoginRequest{Email: "x@y.com", Password: "p"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if tok.AccessToken != "ok" {
		t.Errorf("token = %+v", tok)
	}
	for _, b := range bodies {
		if b != "x@y.com" {
			t.Errorf("body not replayed correctly: %q", b)
		}
	}
}

func TestContextCancellationStopsRetries(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}, WithMaxRetries(5), WithBackoff(50*time.Millisecond, time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := c.Me(ctx, "tok")
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

// ---- OAuth flows ----

func TestOAuthAuthorizeURL(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/oauth/google/authorize" {
			t.Errorf("path = %s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("redirect_uri") != "https://app/cb" || q.Get("state") != "xyz" {
			t.Errorf("query = %v", q)
		}
		if q.Get("code_challenge") != "chal" || q.Get("code_challenge_method") != "S256" {
			t.Errorf("pkce missing: %v", q)
		}
		writeJSON(w, 200, OAuthAuthorize{AuthorizationURL: "https://idp/auth?x=1", State: "xyz"})
	})
	res, err := c.OAuthAuthorizeURL(context.Background(), OAuthAuthorizeParams{
		Provider:            "google",
		RedirectURI:         "https://app/cb",
		State:               "xyz",
		CodeChallenge:       "chal",
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("OAuthAuthorizeURL: %v", err)
	}
	if res.AuthorizationURL == "" || res.Provider != "google" {
		t.Errorf("unexpected: %+v", res)
	}
}

func TestOAuthAuthorizeRequiresProvider(t *testing.T) {
	c := New("http://example.invalid")
	_, err := c.OAuthAuthorizeURL(context.Background(), OAuthAuthorizeParams{})
	if !IsBadRequest(err) {
		t.Errorf("want 400, got %v", err)
	}
}

func TestOAuthCallbackExchangesCode(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/oauth/okta/callback" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = r.ParseForm()
		if r.Form.Get("code") != "authcode" || r.Form.Get("state") != "st" {
			t.Errorf("form = %v", r.Form)
		}
		writeJSON(w, 200, TokenSet{AccessToken: "acc", User: TokenUserInfo{ID: "u9"}})
	})
	tok, err := c.OAuthCallback(context.Background(), OAuthCallbackParams{
		Provider: "okta", Code: "authcode", State: "st",
	})
	if err != nil {
		t.Fatalf("OAuthCallback: %v", err)
	}
	if tok.User.ID != "u9" {
		t.Errorf("token = %+v", tok)
	}
}

func TestOAuthCallbackIdPError(t *testing.T) {
	c := New("http://example.invalid")
	_, err := c.OAuthCallback(context.Background(), OAuthCallbackParams{
		Provider: "okta", Error: "access_denied", ErrorDescription: "user cancelled",
	})
	ae, ok := AsAPIError(err)
	if !ok || ae.Code != "access_denied" {
		t.Fatalf("want access_denied APIError, got %v", err)
	}
}

// ---- Revoke / logout ----

func TestRevokeTokenAuthenticatesCaller(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/revoke" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer caller" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["token"] != "victim" || body["token_type_hint"] != "refresh_token" {
			t.Errorf("body = %v", body)
		}
		writeJSON(w, 200, RevokeResult{Revoked: true})
	})
	res, err := c.RevokeToken(context.Background(), "caller", "victim", "refresh_token")
	if err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if !res.Revoked {
		t.Error("not revoked")
	}
}

func TestRevokePublicEmptyBody(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200) // empty body per RFC 7009
	})
	if err := c.RevokeTokenPublic(context.Background(), "tok", ""); err != nil {
		t.Fatalf("RevokeTokenPublic: %v", err)
	}
}

func TestLogout(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, LogoutResult{Success: true, Message: "bye"})
	})
	res, err := c.Logout(context.Background(), "tok")
	if err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if !res.Success {
		t.Error("not success")
	}
}

// ---- JWKS fetch + caching ----

func TestJWKSCaching(t *testing.T) {
	var calls int32
	set := JWKS{Keys: []JWK{{Kty: "RSA", Kid: "k1", Alg: "RS256", N: "n", E: "AQAB"}}}
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.URL.Path != "/.well-known/jwks.json" {
			t.Errorf("path = %s", r.URL.Path)
		}
		writeJSON(w, 200, set)
	})

	for i := 0; i < 3; i++ {
		got, err := c.JWKS(context.Background())
		if err != nil {
			t.Fatalf("JWKS: %v", err)
		}
		if _, ok := got.Key("k1"); !ok {
			t.Fatal("k1 not found")
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("fetches = %d want 1 (cached)", got)
	}

	// Force refresh increments fetch count.
	if _, err := c.RefreshJWKS(context.Background()); err != nil {
		t.Fatalf("RefreshJWKS: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("fetches = %d want 2 after refresh", got)
	}
}

func TestSigningKeyRefreshesOnUnknownKid(t *testing.T) {
	var calls int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		// First fetch returns k1; after rotation, k2 appears.
		keys := []JWK{{Kid: "k1"}}
		if n >= 2 {
			keys = append(keys, JWK{Kid: "k2"})
		}
		writeJSON(w, 200, JWKS{Keys: keys})
	})

	if _, err := c.JWKS(context.Background()); err != nil { // prime cache with k1
		t.Fatalf("prime: %v", err)
	}
	k, err := c.SigningKey(context.Background(), "k2")
	if err != nil {
		t.Fatalf("SigningKey: %v", err)
	}
	if k.Kid != "k2" {
		t.Errorf("kid = %q", k.Kid)
	}
}

func TestSigningKeyNotFound(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, JWKS{Keys: []JWK{{Kid: "k1"}}})
	})
	_, err := c.SigningKey(context.Background(), "missing")
	if !IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
}

// ---- Options / construction ----

func TestServiceAPIKeyFallback(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer ab0t_sk_svc" {
			t.Errorf("auth = %q (api key fallback)", got)
		}
		writeJSON(w, 200, PermissionDecision{Allowed: true})
	}, WithAPIKey("ab0t_sk_svc"))

	dec, err := c.CheckPermission(context.Background(),
		PermissionCheckRequest{UserID: "u1", Permission: "x.read"}, "")
	if err != nil {
		t.Fatalf("CheckPermission: %v", err)
	}
	if !dec.Allowed {
		t.Error("not allowed")
	}
}

func TestNewDefaultsAndIsAPIKey(t *testing.T) {
	c := New("")
	if c.BaseURL() != DefaultBaseURL {
		t.Errorf("base url = %q", c.BaseURL())
	}
	if !IsAPIKey("ab0t_sk_abc") || IsAPIKey("eyJhbGc...") {
		t.Error("IsAPIKey misclassified")
	}
}

func TestUserAgentHeader(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "myservice/2.0" {
			t.Errorf("ua = %q", r.Header.Get("User-Agent"))
		}
		writeJSON(w, 200, User{ID: "u1"})
	}, WithUserAgent("myservice/2.0"))
	if _, err := c.Me(context.Background(), "t"); err != nil {
		t.Fatalf("Me: %v", err)
	}
}
