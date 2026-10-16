// Package authmw is net/http middleware that gates routes on the ab0t Auth Service.
//
// # WHY THIS IS A PACKAGE AND NOT AN EXAMPLE
//
// This middleware previously existed only in examples/gate/main.go — which means
// every consumer copy-pastes it, every consumer inherits whatever was wrong with
// it that day, and no consumer gets the fix. For a component whose failure mode is
// "the write surface is silently unlocked", copy-paste is the wrong distribution
// mechanism.
//
// # THE ONE DECISION THAT MATTERS
//
// When the auth service cannot be reached, this middleware answers **503**, not
// 200. "I could not decide" is not "yes". A gate that allows on error turns an
// auth-service blip into an open door, and does it quietly — the requests succeed,
// so nothing pages anyone.
//
// That is the default and it is not an option you can forget: FailOpen must be set
// deliberately, and doing so is documented as a mistake.
//
// The other half of the same rule: an INVALID credential is a 401, never a 503.
// The auth service answering "this token is not valid" — as {valid:false}, or as
// an HTTP 401 — is a definite answer about the credential, not an outage, so
// clients are told to re-authenticate rather than to retry.
//
// # STATUS CODES
//
//	                   no credential   invalid credential   denied   auth unreachable
//	Authenticate       anonymous (*)   401                  —        503
//	RequireIdentity    401             401                  —        503
//	Require            401             401 (**)             403      503
//
// (*) the request continues with no identity; the route decides what that means.
// (**) when the auth service answers 401. A service that answers {valid:false}
// makes Authorize return "not allowed", which Require reports as 403; put
// Authenticate or RequireIdentity in front when invalid credentials must be 401.
//
// "auth unreachable" is any error that is not a definite answer: network
// failures, timeouts, 429, 5xx, an open breaker. FailOpen lets those through
// (and only those); it never lets an invalid or denied credential through.
//
// Usage:
//
//	gate := &authmw.Gate{V: client, A: client}
//	mux.Handle("POST /admin", gate.Require("admin.write", "service", adminHandler))
//	http.ListenAndServe(":8080", gate.Authenticate(mux))
//
// A JSON API where every route needs a caller, with the caller's permissions:
//
//	client := auth.New("", auth.WithExpectedJWTAudience("my-service"))
//	gate := &authmw.Gate{V: client, A: client, IncludePermissions: true, WriteDenial: authmw.JSONDenial}
//	http.ListenAndServe(":8080", gate.RequireIdentity(mux)) // handlers read authmw.Identity(r.Context()).Permissions
package authmw

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	auth "github.com/ab0t-com/auth-sdk-go"
)

// defaultAPIKeyHeader is the header an API key is read from when no
// Authorization header is sent and Gate.APIKeyHeader is empty.
const defaultAPIKeyHeader = "X-API-Key"

// Gate holds the auth interfaces plus the failure policy.
//
// Depend on auth.Validator / auth.Authorizer, never on *auth.Client — that is what
// makes handlers testable against authclienttest.Fake with no live service.
type Gate struct {
	// V resolves a credential to an identity. May be nil for Authenticate (no
	// identity is attached); RequireIdentity cannot decide without it (503).
	V auth.Validator
	// A decides whether a credential may perform an action. Required by Require.
	A auth.Authorizer

	// FailOpen allows the request through when the auth service errors.
	//
	// LEAVE THIS FALSE. Setting it means an auth-service outage silently unlocks
	// every route this gate protects, and because the requests succeed, nothing
	// alerts. It exists only for a deliberate, temporary, documented degradation.
	// It never lets an invalid or denied credential through.
	FailOpen bool

	// OnDeny, when set, is called before a denial is written — for logging or
	// metrics. It must not write to w.
	OnDeny func(r *http.Request, action string, status int, err error)

	// ResourceID extracts the resource id from a request. Defaults to
	// r.PathValue("id").
	ResourceID func(*http.Request) string

	// IncludePermissions asks the auth service for the caller's permissions when
	// it validates a user JWT, so Identity(ctx).Permissions is populated for JWT
	// callers as it already is for API keys. Off by default (a JWT identity then
	// carries no permissions).
	//
	// It needs V to also implement
	//
	//	ValidateTokenWith(context.Context, auth.TokenValidationRequest) (*auth.Actor, error)
	//
	// which *auth.Client does. A V without it (authclienttest.Fake, for one)
	// cannot answer the question, so a JWT request is treated as "could not
	// evaluate" — 503, like any other failure to decide — rather than attaching
	// an identity whose permissions were silently dropped. Test this setting with
	// authclienttest.Server and a real client.
	IncludePermissions bool

	// WriteDenial, when set, writes every denial (status plus a short, static
	// message such as "invalid token") instead of http.Error's plain text. Use
	// JSONDenial for {"error":"<message>"}. It is called after OnDeny.
	WriteDenial func(w http.ResponseWriter, r *http.Request, status int, msg string)

	// APIKeyHeader is the header an API key is read from when the request has no
	// Authorization header. Empty means "X-API-Key". Authorization always wins
	// when both are sent.
	APIKeyHeader string
}

type ctxKey struct{}

// Identity returns the verified caller attached by Authenticate or
// RequireIdentity, or nil if the request is anonymous.
func Identity(ctx context.Context) *auth.Actor {
	a, _ := ctx.Value(ctxKey{}).(*auth.Actor)
	return a
}

// Bearer extracts the credential from an Authorization header. It may be a user
// JWT or an agent/service key (ab0t_sk_…) — the service resolves either. The
// "Bearer" scheme is matched case-insensitively (RFC 7235), so "bearer x" works;
// a header with no Bearer scheme is returned whole, as before. The gate itself
// reads Credential, which also accepts X-API-Key.
func Bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	if len(h) >= 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return strings.TrimSpace(h)
}

// Credential returns the caller's credential: the Authorization header (as
// Bearer reads it) when present, else the X-API-Key header — the header mesh
// consumers are told to send their service key in. Authorization wins when both
// are sent, so callers that already use it see no change. The value is handed to
// the Validator / Authorizer, which resolve a JWT or an ab0t_sk_ key alike.
//
// A Gate with APIKeyHeader set reads that header instead of X-API-Key.
func Credential(r *http.Request) string {
	return credentialFrom(r, defaultAPIKeyHeader)
}

func credentialFrom(r *http.Request, apiKeyHeader string) string {
	if tok := Bearer(r); tok != "" {
		return tok
	}
	return strings.TrimSpace(r.Header.Get(apiKeyHeader))
}

func (g *Gate) credential(r *http.Request) string {
	h := g.APIKeyHeader
	if h == "" {
		h = defaultAPIKeyHeader
	}
	return credentialFrom(r, h)
}

func (g *Gate) resourceID(r *http.Request) string {
	if g.ResourceID != nil {
		return g.ResourceID(r)
	}
	return r.PathValue("id")
}

func (g *Gate) deny(w http.ResponseWriter, r *http.Request, action string, status int, msg string, err error) {
	if g.OnDeny != nil {
		g.OnDeny(r, action, status, err)
	}
	if g.WriteDenial != nil {
		g.WriteDenial(w, r, status, msg)
		return
	}
	http.Error(w, msg, status)
}

// JSONDenial is a ready WriteDenial: it writes {"error":"<msg>"} with
// Content-Type application/json and the given status. The message is one of the
// gate's static strings ("auth required", "invalid token", "forbidden",
// "auth unavailable", "authz unavailable") — never request input.
func JSONDenial(w http.ResponseWriter, _ *http.Request, status int, msg string) {
	body, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{msg})
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}

// definiteNo reports whether a validation error is the auth service's answer
// about the credential (401 / 403) rather than a failure to answer.
func definiteNo(err error) bool {
	return auth.IsUnauthorized(err) || auth.IsForbidden(err)
}

// tokenValidatorWith is the richer validation call IncludePermissions needs;
// *auth.Client implements it.
type tokenValidatorWith interface {
	ValidateTokenWith(ctx context.Context, req auth.TokenValidationRequest) (*auth.Actor, error)
}

var errNoPermissionValidator = errors.New("authmw: IncludePermissions is set but the Validator has no ValidateTokenWith; cannot return permissions")

func (g *Gate) validate(ctx context.Context, tok string) (*auth.Actor, error) {
	if g.IncludePermissions && !auth.IsAPIKey(tok) {
		vw, ok := g.V.(tokenValidatorWith)
		if !ok {
			return nil, errNoPermissionValidator
		}
		// ExpectedAudience is left empty so the client applies its configured
		// JWT audience, exactly as ValidateToken does.
		return vw.ValidateTokenWith(ctx, auth.TokenValidationRequest{Token: tok, IncludePermissions: true})
	}
	return g.V.ValidateToken(ctx, tok)
}

// identify is the shared core of Authenticate and RequireIdentity.
func (g *Gate) identify(w http.ResponseWriter, r *http.Request, next http.Handler, required bool) {
	tok := g.credential(r)
	if tok == "" {
		if required {
			g.deny(w, r, "", http.StatusUnauthorized, "auth required", nil)
			return
		}
		next.ServeHTTP(w, r)
		return
	}
	if g.V == nil {
		if !required {
			next.ServeHTTP(w, r)
			return
		}
		// Requiring a caller with no validator wired cannot produce a decision.
		if g.FailOpen {
			next.ServeHTTP(w, r)
			return
		}
		g.deny(w, r, "", http.StatusServiceUnavailable, "auth unavailable", nil)
		return
	}
	actor, err := g.validate(r.Context(), tok)
	if err != nil {
		if definiteNo(err) {
			// The service answered: this credential is not valid.
			g.deny(w, r, "", http.StatusUnauthorized, "invalid token", err)
			return
		}
		// Could not decide. Not "anonymous", not "allowed".
		if g.FailOpen {
			next.ServeHTTP(w, r)
			return
		}
		g.deny(w, r, "", http.StatusServiceUnavailable, "auth unavailable", err)
		return
	}
	if actor == nil || !actor.Valid {
		g.deny(w, r, "", http.StatusUnauthorized, "invalid token", nil)
		return
	}
	next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, actor)))
}

// Authenticate attaches an identity when a credential is present (Authorization,
// else X-API-Key — see Credential).
//
// A MISSING credential is not an error here — the request continues anonymously
// and the route decides what that means, so read-only and public routes keep
// working. An INVALID credential is a 401: someone presented something and it did
// not check out, which is worth saying rather than silently ignoring. An auth
// service that cannot answer is a 503 (unless FailOpen).
func (g *Gate) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.identify(w, r, next, false)
	})
}

// RequireIdentity is Authenticate for routes where every request needs a caller:
//
//	401 no credential · 401 invalid credential · 503 auth service unreachable · else next, with Identity set
//
// FailOpen is honoured exactly as in Authenticate (an unreachable auth service
// lets the request through with no identity). Wrap a whole router with it:
//
//	http.ListenAndServe(":8080", gate.RequireIdentity(mux))
func (g *Gate) RequireIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.identify(w, r, next, true)
	})
}

// Require gates a handler on (action, resourceType). The credential is read with
// Credential (Authorization, else X-API-Key):
//
//	401 no credential · 401 invalid credential (the auth service answered 401) ·
//	403 denied · 503 auth service unreachable · else the handler
//
// The 503 is the important one. See the package doc.
func (g *Gate) Require(action, resourceType string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := g.credential(r)
		if tok == "" {
			g.deny(w, r, action, http.StatusUnauthorized, "auth required", nil)
			return
		}
		if g.A == nil {
			// Enforcing with no authorizer wired cannot produce a decision. Saying
			// so is better than defaulting either way.
			if g.FailOpen {
				h(w, r)
				return
			}
			g.deny(w, r, action, http.StatusServiceUnavailable, "authz unavailable", nil)
			return
		}
		ok, err := g.A.Authorize(r.Context(), tok, action, auth.Resource{
			Type: resourceType,
			ID:   g.resourceID(r),
		})
		if err != nil {
			switch {
			case auth.IsUnauthorized(err):
				g.deny(w, r, action, http.StatusUnauthorized, "invalid token", err)
			case auth.IsForbidden(err):
				g.deny(w, r, action, http.StatusForbidden, "forbidden", err)
			case g.FailOpen:
				h(w, r)
			default:
				g.deny(w, r, action, http.StatusServiceUnavailable, "authz unavailable", err)
			}
			return
		}
		if !ok {
			g.deny(w, r, action, http.StatusForbidden, "forbidden", nil)
			return
		}
		h(w, r)
	}
}

// RequireFunc is Require as a middleware, for routers that compose
// func(http.Handler) http.Handler.
func (g *Gate) RequireFunc(action, resourceType string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return g.Require(action, resourceType, next.ServeHTTP)
	}
}
