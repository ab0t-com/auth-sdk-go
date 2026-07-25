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
// Two doubles, for two different jobs:
//
//   - Fake — implements the interfaces directly. Fast, no network. Use it to test
//     YOUR code's reaction to allow / deny / unavailable.
//   - Server — an httptest-backed fake auth service. Use it to test the REAL
//     client end to end, including its retry, decoding and error handling.
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
	case strings.Contains(r.URL.Path, "/zanzibar/") && strings.HasSuffix(r.URL.Path, "/check"):
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": valid})
	default:
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "message": "ok"})
	}
}

// URL is the base URL to hand to auth.New.
func (s *Server) URL() string { return s.srv.URL }

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
