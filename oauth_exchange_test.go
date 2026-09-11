package authclient

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
)

// oauth_exchange_test.go — unit tests for the additive RFC 8693 token-exchange
// (on-behalf-of) helper. Covers (a) TokenExchangeForm correctness incl.
// defaulted token-types + options, (b) ExchangeToken round-tripping a §2.2.1
// body and surfacing issued_token_type, (c) OAuth error-envelope mapping, and
// (d) a guard that the additive helper leaves OAuthToken's wire form untouched.

// (a) TokenExchangeForm sets the URN grant_type, subject_token, both defaulted
// token-types, the audience, and the optional scope/actor_token.
func TestTokenExchangeForm_Defaults(t *testing.T) {
	form := TokenExchangeForm("subject-tok", "disksearch")

	if got := form.Get("grant_type"); got != GrantTypeTokenExchange {
		t.Errorf("grant_type = %q, want %q", got, GrantTypeTokenExchange)
	}
	if got := form.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("grant_type URN drifted: %q", got)
	}
	if got := form.Get("subject_token"); got != "subject-tok" {
		t.Errorf("subject_token = %q", got)
	}
	if got := form.Get("subject_token_type"); got != TokenTypeAccessToken {
		t.Errorf("subject_token_type = %q, want default access_token", got)
	}
	if got := form.Get("requested_token_type"); got != TokenTypeAccessToken {
		t.Errorf("requested_token_type = %q, want default access_token", got)
	}
	if got := form.Get("audience"); got != "disksearch" {
		t.Errorf("audience = %q", got)
	}
	// No optionals set by default.
	if _, ok := form["scope"]; ok {
		t.Errorf("scope should be unset by default, got %q", form.Get("scope"))
	}
	if _, ok := form["actor_token"]; ok {
		t.Errorf("actor_token should be unset by default")
	}
}

// (a) options: scope + actor_token (+ its required type) + token-type overrides.
func TestTokenExchangeForm_Options(t *testing.T) {
	form := TokenExchangeForm("subject-tok", "disksearch",
		WithScope("resource:read"),
		WithActorToken("actor-tok"),
		WithSubjectTokenType(TokenTypeIDToken),
		WithRequestedTokenType(TokenTypeRefreshToken),
	)

	if got := form.Get("scope"); got != "resource:read" {
		t.Errorf("scope = %q", got)
	}
	if got := form.Get("actor_token"); got != "actor-tok" {
		t.Errorf("actor_token = %q", got)
	}
	if got := form.Get("actor_token_type"); got != TokenTypeAccessToken {
		t.Errorf("actor_token_type = %q, want access_token (RFC 8693 §2.1 requires it)", got)
	}
	if got := form.Get("subject_token_type"); got != TokenTypeIDToken {
		t.Errorf("subject_token_type override = %q, want id_token", got)
	}
	if got := form.Get("requested_token_type"); got != TokenTypeRefreshToken {
		t.Errorf("requested_token_type override = %q, want refresh_token", got)
	}
	// Audience still present alongside options.
	if got := form.Get("audience"); got != "disksearch" {
		t.Errorf("audience = %q", got)
	}
}

// TokenExchangeForm omits audience when empty (server-side/default-audience case).
func TestTokenExchangeForm_EmptyAudience(t *testing.T) {
	form := TokenExchangeForm("subject-tok", "")
	if _, ok := form["audience"]; ok {
		t.Errorf("audience should be omitted when empty, got %q", form.Get("audience"))
	}
}

// (b) ExchangeToken posts the form to the token endpoint and decodes the §2.2.1
// body, populating IssuedTokenType (the field TokenResponse drops).
func TestExchangeToken_RoundTrip(t *testing.T) {
	var gotForm url.Values
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/oauth/token" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		writeJSON(w, 200, map[string]any{
			"access_token":      "minted-obo-token",
			"issued_token_type": TokenTypeAccessToken,
			"token_type":        "Bearer",
			"expires_in":        900,
			"scope":             "resource:read",
			// refresh_token deliberately present on the wire but not surfaced.
			"refresh_token": "should-be-ignored",
		})
	})

	resp, err := c.ExchangeToken(context.Background(), "subject-tok", "disksearch", WithScope("resource:read"))
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if resp.AccessToken != "minted-obo-token" {
		t.Errorf("AccessToken = %q", resp.AccessToken)
	}
	if resp.IssuedTokenType != TokenTypeAccessToken {
		t.Errorf("IssuedTokenType = %q, want %q (must be surfaced)", resp.IssuedTokenType, TokenTypeAccessToken)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType = %q", resp.TokenType)
	}
	if resp.ExpiresIn != 900 {
		t.Errorf("ExpiresIn = %d", resp.ExpiresIn)
	}
	if resp.Scope != "resource:read" {
		t.Errorf("Scope = %q", resp.Scope)
	}

	// The wire form the server received carries the URN + defaults + option.
	if gotForm.Get("grant_type") != GrantTypeTokenExchange {
		t.Errorf("wire grant_type = %q", gotForm.Get("grant_type"))
	}
	if gotForm.Get("subject_token_type") != TokenTypeAccessToken {
		t.Errorf("wire subject_token_type = %q", gotForm.Get("subject_token_type"))
	}
	if gotForm.Get("audience") != "disksearch" {
		t.Errorf("wire audience = %q", gotForm.Get("audience"))
	}
	if gotForm.Get("scope") != "resource:read" {
		t.Errorf("wire scope = %q", gotForm.Get("scope"))
	}
}

// (c) ExchangeToken maps the OAuth error envelope (RFC 6749 {"error", ...})
// through the shared APIError path — same as OAuthToken.
func TestExchangeToken_ErrorEnvelope(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_target",
			"error_description": "audience is not a registered service_audience for this org",
		})
	})

	resp, err := c.ExchangeToken(context.Background(), "subject-tok", "not-registered")
	if err == nil {
		t.Fatalf("expected error, got resp=%+v", resp)
	}
	ae, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if ae.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d", ae.StatusCode)
	}
	if ae.Code != "invalid_target" {
		t.Errorf("Code = %q, want invalid_target", ae.Code)
	}
	if !IsBadRequest(err) {
		t.Errorf("IsBadRequest = false")
	}
}

// (d) Guard: the additive exchange helper does not change OAuthToken's wire
// form. A refresh_token grant built the classic way must still post exactly
// grant_type=refresh_token with no token-exchange fields leaking in.
func TestOAuthToken_UnchangedByExchangeAdditions(t *testing.T) {
	var gotForm url.Values
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/oauth/token" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		writeJSON(w, 200, TokenResponse{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 900})
	})

	classic := url.Values{}
	classic.Set("grant_type", "refresh_token")
	classic.Set("refresh_token", "rt")

	resp, err := c.OAuthToken(context.Background(), classic)
	if err != nil {
		t.Fatalf("OAuthToken: %v", err)
	}
	if resp.AccessToken != "at" || resp.TokenType != "Bearer" || resp.ExpiresIn != 900 {
		t.Errorf("TokenResponse decode drifted: %+v", resp)
	}
	if gotForm.Get("grant_type") != "refresh_token" {
		t.Errorf("wire grant_type = %q, want refresh_token", gotForm.Get("grant_type"))
	}
	for _, leak := range []string{"subject_token", "subject_token_type", "requested_token_type", "audience"} {
		if _, ok := gotForm[leak]; ok {
			t.Errorf("token-exchange field %q leaked into OAuthToken form", leak)
		}
	}
}
