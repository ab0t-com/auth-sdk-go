// Package authclienttest provides test doubles for the ab0t Auth Service client.
//
// The root package exposes Validator and Authorizer as two-method interfaces
// precisely so consumers can test without a live auth service. In practice every
// consumer then writes the same two fakes by hand — and writes them slightly
// differently, usually missing the case that matters most: what the handler does
// when the auth service is UNREACHABLE. That path is the one where a mistake means
// an outage silently unlocks the write surface, and it is the one people forget to
// test because it takes effort to simulate.
//
// So it ships here, and simulating it is one line.
//
//	gate := myapp.Gate{V: authclienttest.Deny(), A: authclienttest.Unavailable()}
//	// assert the handler answers 503, not 200
//
// Three doubles, for three different jobs:
//
//   - Fake — implements the interfaces directly. Fast, no network. Use it to test
//     YOUR code's reaction to allow / deny / unavailable.
//   - Server — an httptest-backed fake auth service. Use it to test the REAL
//     client end to end, including its retry, decoding and error handling.
//   - TokenEndpoint — a scripted fake token endpoint. Use it to test code that
//     calls TokenFor: what was sent, and how each server answer is surfaced.
//
// This is a separate package on purpose: nothing here is imported by the root
// package, so it cannot affect the dependency surface or the binary of anyone who
// only uses the client.
package authclienttest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"

	auth "github.com/ab0t-com/auth-sdk-go"
)

// ErrUnavailable is the canned "the auth service is down" error.
var ErrUnavailable = errors.New("authclienttest: auth service unavailable")

// Call records one invocation, so a test can assert what was asked as well as
// what came back — e.g. that the ACTION was actually sent, not just that the
// handler returned 200.
type Call struct {
	Method   string // "ValidateToken" or "Authorize"
	Token    string
	Action   string        // Authorize only
	Resource auth.Resource // Authorize only
}

// Fake implements both auth.Validator and auth.Authorizer with canned answers.
// The zero value denies everything and validates nothing, which is the safe
// default: a test that forgets to configure it fails closed rather than passing
// for the wrong reason.
//
// Safe for concurrent use.
type Fake struct {
	// Actor is returned by ValidateToken. Nil means "no identity".
	Actor *auth.Actor
	// ValidateErr, when set, is returned by ValidateToken.
	ValidateErr error
	// Allow is returned by Authorize.
	Allow bool
	// AuthorizeErr, when set, is returned by Authorize — use it to simulate an
	// unreachable auth service, the case most worth testing.
	AuthorizeErr error

	// AllowOnly, when non-empty, overrides Allow: only these actions are allowed.
	AllowOnly []string

	mu    sync.Mutex
	calls []Call
}

var (
	_ auth.Validator  = (*Fake)(nil)
	_ auth.Authorizer = (*Fake)(nil)
)

// ValidateToken implements auth.Validator.
func (f *Fake) ValidateToken(_ context.Context, token string) (*auth.Actor, error) {
	f.record(Call{Method: "ValidateToken", Token: token})
	if f.ValidateErr != nil {
		return nil, f.ValidateErr
	}
	return f.Actor, nil
}

// Authorize implements auth.Authorizer.
func (f *Fake) Authorize(_ context.Context, token, action string, res auth.Resource) (bool, error) {
	f.record(Call{Method: "Authorize", Token: token, Action: action, Resource: res})
	if f.AuthorizeErr != nil {
		return false, f.AuthorizeErr
	}
	if len(f.AllowOnly) > 0 {
		for _, a := range f.AllowOnly {
			if a == action {
				return true, nil
			}
		}
		return false, nil
	}
	return f.Allow, nil
}

func (f *Fake) record(c Call) {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
}

// Calls returns a copy of everything asked of this Fake, in order.
func (f *Fake) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.calls...)
}

// Reset clears the recorded calls, leaving the configured answers in place.
func (f *Fake) Reset() {
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
}

// ---- Ready-made doubles for the three cases every handler should be tested against ----

// Allow returns a Fake that allows everything, with a valid identity.
func Allow() *Fake {
	return &Fake{Allow: true, Actor: &auth.Actor{Valid: true, UserID: "test-user", OrgID: "test-org"}}
}

// Deny returns a Fake that denies everything but still resolves an identity —
// an authenticated caller without the permission, i.e. a 403, not a 401.
func Deny() *Fake {
	return &Fake{Allow: false, Actor: &auth.Actor{Valid: true, UserID: "test-user", OrgID: "test-org"}}
}

// Unavailable returns a Fake that errors on every call, simulating an auth service
// that is down.
//
// This is the case worth testing hardest. A handler that answers 200 here has a
// fail-open bug: an auth-service blip silently unlocks whatever it was guarding.
// The correct answer is 503 — "I could not decide" — which is honest and alertable.
func Unavailable() *Fake {
	return &Fake{ValidateErr: ErrUnavailable, AuthorizeErr: ErrUnavailable}
}

// ---- A fake auth SERVICE, for testing the real client ----

// Server is an httptest-backed stand-in for the auth service. Use it when you want
// to exercise the real *auth.Client — its retry logic, decoding and error mapping —
// rather than substituting the interfaces.
//
//	srv := authclienttest.NewServer()
//	defer srv.Close()
//	client := auth.New(srv.URL())
type Server struct {
	srv *httptest.Server

	mu sync.Mutex
	// Valid controls what /auth/validate-token and /auth/validate-api-key answer.
	valid bool
	actor auth.Actor
	// status, when non-zero, is returned for every request (to simulate outages).
	status int
	reqs   []string
}

// NewServer starts a fake auth service that validates every credential.
// Call Close when done.
func NewServer() *Server {
	s := &Server{valid: true, actor: auth.Actor{Valid: true, UserID: "test-user", OrgID: "test-org"}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	status, valid, actor := s.status, s.valid, s.actor
	s.reqs = append(s.reqs, r.Method+" "+r.URL.Path)
	s.mu.Unlock()

	if status != 0 {
		http.Error(w, `{"detail":"simulated failure"}`, status)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	switch {
	case strings.HasSuffix(r.URL.Path, "/validate-token"), strings.HasSuffix(r.URL.Path, "/validate-api-key"):
		a := actor
		a.Valid = valid
		_ = json.NewEncoder(w).Encode(a)
	case strings.HasSuffix(r.URL.Path, "/permissions/check"), strings.HasSuffix(r.URL.Path, "/auth/check-permission"):
		// The resource-scoped PDP: a resource-scoped Authorize routes here.
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": valid, "scope": "object"})
	case strings.Contains(r.URL.Path, "/zanzibar/") && strings.HasSuffix(r.URL.Path, "/check"):
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": valid})
	default:
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "ok"})
	}
}

// URL is the base URL to hand to auth.New.
//
// Since auth-sdk-go v0.12.0 a client built with auth.New(srv.URL()) has the
// validation cache ON, so a test that flips this server's answer mid-test
// (SetValid, SetStatus, SetActor) keeps seeing the cached answer for up to the
// TTL. Build the client with NewClient — or pass auth.WithValidationCache(0)
// yourself — when the test changes the server's answer.
func (s *Server) URL() string { return s.srv.URL }

// NewClient returns a real *auth.Client pointed at this server with the
// validation cache DISABLED, so every SetValid / SetStatus / SetActor is seen by
// the very next call. opts are applied after that default, so passing
// auth.WithValidationCache(ttl) re-enables a cache when a test wants to exercise
// one.
func (s *Server) NewClient(opts ...auth.Option) *auth.Client {
	return auth.New(s.URL(), append([]auth.Option{auth.WithValidationCache(0)}, opts...)...)
}

// Close shuts the server down.
func (s *Server) Close() { s.srv.Close() }

// SetValid controls whether credentials validate.
func (s *Server) SetValid(v bool) {
	s.mu.Lock()
	s.valid = v
	s.mu.Unlock()
}

// SetActor controls the identity returned for a valid credential.
func (s *Server) SetActor(a auth.Actor) {
	s.mu.Lock()
	s.actor = a
	s.mu.Unlock()
}

// SetStatus makes every request fail with this HTTP status. Pass 0 to stop.
// Use 503 to exercise your retry and fail-closed handling.
func (s *Server) SetStatus(code int) {
	s.mu.Lock()
	s.status = code
	s.mu.Unlock()
}

// Requests returns "METHOD /path" for every request received, in order — so a test
// can assert which endpoint the client chose (a JWT and an ab0t_sk_ key go to
// different ones, and getting that wrong is silent).
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.reqs...)
}

// ---- A fake TOKEN ENDPOINT, for testing code that calls TokenFor ----

// TokenRequest records one call to the fake token endpoint.
type TokenRequest struct {
	// GrantType is the grant_type form value.
	GrantType string
	// Form is the full form body.
	Form url.Values
	// ClientID / ClientSecret are what arrived in HTTP Basic (empty when the
	// request carried no Basic header).
	ClientID     string
	ClientSecret string
	// APIKey is any X-API-Key header that arrived — a token-endpoint call should
	// carry none, and a test can assert that.
	APIKey string
}

// TokenAnswer is one scripted reply: an HTTP status and a JSON body.
type TokenAnswer struct {
	Status int
	Body   any
}

// TokenOK is a 200 token response (no refresh_token, like the real endpoint for
// client credentials and token exchange).
func TokenOK(accessToken string, expiresIn int, scope string) TokenAnswer {
	body := map[string]any{"access_token": accessToken, "token_type": "Bearer", "expires_in": expiresIn}
	if scope != "" {
		body["scope"] = scope
	}
	return TokenAnswer{Status: http.StatusOK, Body: body}
}

// TokenError is an RFC 6749 §5.2 error reply. suberror may be empty.
func TokenError(status int, code, suberror string) TokenAnswer {
	body := map[string]any{"error": code, "error_description": "scripted"}
	if suberror != "" {
		body["suberror"] = suberror
	}
	return TokenAnswer{Status: status, Body: body}
}

// TokenEndpoint is an httptest-backed fake of the auth service's token endpoint
// (POST /auth/oauth/token) and its RFC 8414 metadata, so consumers can test the
// real TokenFor — pattern choice, client authentication, caching and error
// mapping — with no live service.
//
//	te := authclienttest.NewTokenEndpoint()
//	defer te.Close()
//	te.Script(authclienttest.TokenError(400, "invalid_target", "consent_required"))
//	c := auth.New(te.URL(), auth.WithClientCredentials("app", "secret"))
//	_, err := c.TokenFor(ctx, "https://b.example", "b.read", auth.StaticSession(tok))
//	var consent *auth.ConsentRequired // errors.As(err, &consent) == true
//
// Scripted answers are consumed in order; when none are queued, the endpoint
// issues a fresh token ("fake-at-<n>", expires_in 900, scope echoed). SetHandler
// replaces both with a function for full control. Safe for concurrent use.
type TokenEndpoint struct {
	srv *httptest.Server

	mu      sync.Mutex
	queue   []TokenAnswer
	handler func(TokenRequest) TokenAnswer
	reqs    []TokenRequest
	issued  int
}

// NewTokenEndpoint starts the fake. Call Close when done.
func NewTokenEndpoint() *TokenEndpoint {
	t := &TokenEndpoint{}
	t.srv = httptest.NewServer(http.HandlerFunc(t.handle))
	return t
}

// URL is the base URL to hand to auth.New.
func (t *TokenEndpoint) URL() string { return t.srv.URL }

// Close shuts the fake down.
func (t *TokenEndpoint) Close() { t.srv.Close() }

// Script queues answers, consumed one per token-endpoint call.
func (t *TokenEndpoint) Script(answers ...TokenAnswer) {
	t.mu.Lock()
	t.queue = append(t.queue, answers...)
	t.mu.Unlock()
}

// SetHandler answers every token-endpoint call with fn (nil restores scripting).
func (t *TokenEndpoint) SetHandler(fn func(TokenRequest) TokenAnswer) {
	t.mu.Lock()
	t.handler = fn
	t.mu.Unlock()
}

// Requests returns every token-endpoint call received, in order.
func (t *TokenEndpoint) Requests() []TokenRequest {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]TokenRequest(nil), t.reqs...)
}

func (t *TokenEndpoint) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet && r.URL.Path == "/.well-known/oauth-authorization-server" {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           t.srv.URL,
			"authorization_endpoint":           t.srv.URL + "/auth/authorize",
			"token_endpoint":                   t.srv.URL + "/auth/oauth/token",
			"code_challenge_methods_supported": []string{"S256"},
		})
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/auth/oauth/token" {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail":"not found"}`))
		return
	}
	_ = r.ParseForm()
	req := TokenRequest{GrantType: r.PostForm.Get("grant_type"), Form: r.PostForm, APIKey: r.Header.Get("X-API-Key")}
	req.ClientID, req.ClientSecret, _ = r.BasicAuth()

	t.mu.Lock()
	t.reqs = append(t.reqs, req)
	var ans TokenAnswer
	switch {
	case t.handler != nil:
		h := t.handler
		t.mu.Unlock()
		ans = h(req)
		t.mu.Lock()
	case len(t.queue) > 0:
		ans = t.queue[0]
		t.queue = t.queue[1:]
	default:
		t.issued++
		ans = TokenOK("fake-at-"+strconv.Itoa(t.issued), 900, req.Form.Get("scope"))
	}
	t.mu.Unlock()

	if ans.Status == 0 {
		ans.Status = http.StatusOK
	}
	if m, ok := ans.Body.(map[string]any); ok && ans.Status == http.StatusOK && req.GrantType == auth.GrantTypeTokenExchange {
		if _, set := m["issued_token_type"]; !set {
			m["issued_token_type"] = auth.TokenTypeAccessToken
		}
	}
	w.WriteHeader(ans.Status)
	_ = json.NewEncoder(w).Encode(ans.Body)
}
