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
// Usage:
//
//	gate := &authmw.Gate{V: client, A: client}
//	mux.Handle("POST /admin", gate.Require("admin.write", "service", adminHandler))
//	http.ListenAndServe(":8080", gate.Authenticate(mux))
package authmw

import (
	"context"
	"net/http"
	"strings"

	auth "github.com/ab0t-com/auth-sdk-go"
)

// Gate holds the auth interfaces plus the failure policy.
//
// Depend on auth.Validator / auth.Authorizer, never on *auth.Client — that is what
// makes handlers testable against authclienttest.Fake with no live service.
type Gate struct {
	// V resolves a credential to an identity. May be nil (no identity is attached).
	V auth.Validator
	// A decides whether a credential may perform an action. Required by Require.
	A auth.Authorizer

	// FailOpen allows the request through when the auth service errors.
	//
	// LEAVE THIS FALSE. Setting it means an auth-service outage silently unlocks
	// every route this gate protects, and because the requests succeed, nothing
	// alerts. It exists only for a deliberate, temporary, documented degradation.
	FailOpen bool

	// OnDeny, when set, is called before a denial is written — for logging or
	// metrics. It must not write to w.
	OnDeny func(r *http.Request, action string, status int, err error)

	// ResourceID extracts the resource id from a request. Defaults to
	// r.PathValue("id").
	ResourceID func(*http.Request) string
}

type ctxKey struct{}

// Identity returns the verified caller attached by Authenticate, or nil if the
// request is anonymous.
func Identity(ctx context.Context) *auth.Actor {
	a, _ := ctx.Value(ctxKey{}).(*auth.Actor)
	return a
}

// Bearer extracts the credential from an Authorization header. It may be a user
// JWT or an agent/service key (ab0t_sk_…) — the service resolves either.
func Bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
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
	http.Error(w, msg, status)
}

// Authenticate attaches an identity when a credential is present.
//
// A MISSING credential is not an error here — the request continues anonymously
// and the route decides what that means, so read-only and public routes keep
// working. An INVALID credential is a 401: someone presented something and it did
// not check out, which is worth saying rather than silently ignoring.
func (g *Gate) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := Bearer(r)
		if tok == "" || g.V == nil {
			next.ServeHTTP(w, r)
			return
		}
		actor, err := g.V.ValidateToken(r.Context(), tok)
		if err != nil {
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
	})
}

// Require gates a handler on (action, resourceType):
//
//	401 no credential · 403 denied · 503 auth service unreachable · else the handler
//
// The 503 is the important one. See the package doc.
func (g *Gate) Require(action, resourceType string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := Bearer(r)
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
			if g.FailOpen {
				h(w, r)
				return
			}
			g.deny(w, r, action, http.StatusServiceUnavailable, "authz unavailable", err)
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
