// Command gate is a complete, runnable example of the thing this SDK is mostly
// used for: putting an ab0t Auth Service check in front of an HTTP route.
//
// It shows the two primitives that matter and the three rules that keep them
// safe — depend on the interfaces, fail closed, and check the boolean as well as
// the error.
//
//	go run ./examples/gate
//	curl -i localhost:8080/public
//	curl -i localhost:8080/admin
//	curl -i -H 'Authorization: Bearer <token-or-ab0t_sk_key>' localhost:8080/admin
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"

	auth "github.com/ab0t-com/auth-sdk-go"
)

// gate holds the two INTERFACES, never *auth.Client. That is what lets you test
// your handlers against fakes with no live auth service.
type gate struct {
	v          auth.Validator
	a          auth.Authorizer
	failClosed bool
}

type actorKey struct{}

// identity returns the verified caller, or nil for an anonymous request.
func identity(ctx context.Context) *auth.Actor {
	a, _ := ctx.Value(actorKey{}).(*auth.Actor)
	return a
}

func bearer(r *http.Request) string {
	return strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
}

// authenticate attaches an identity when a credential is present. A missing
// credential is not an error here — the route decides what anonymous means.
func (g *gate) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tok := bearer(r); tok != "" {
			actor, err := g.v.ValidateToken(r.Context(), tok)
			if err != nil || actor == nil || !actor.Valid {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), actorKey{}, actor))
		}
		next.ServeHTTP(w, r)
	})
}

// require gates a handler on (action, resource).
//
// Note the error handling: a broken auth service must NOT become an allow. With
// failClosed it answers 503 — "we could not decide" — which is honest, and which
// an operator can alert on. Returning 200 here would mean an auth-service blip
// silently unlocks the route.
func (g *gate) require(action, resourceType string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			http.Error(w, "auth required", http.StatusUnauthorized)
			return
		}
		ok, err := g.a.Authorize(r.Context(), tok, action, auth.Resource{
			Type: resourceType,
			ID:   r.PathValue("id"),
		})
		if err != nil {
			if g.failClosed {
				http.Error(w, "authz unavailable", http.StatusServiceUnavailable)
				return
			}
			log.Printf("authz: failing OPEN after service error: %v", err)
		} else if !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

func main() {
	// "" uses auth.DefaultBaseURL (the production service).
	// The service key is this service's own ab0t_sk_ credential; per-call user
	// tokens always override it.
	client := auth.New(
		os.Getenv("AUTH_SERVICE_URL"),
		auth.WithAPIKey(os.Getenv("AUTH_SERVICE_KEY")),
		auth.WithExpectedAudience("my-service"), // reject tokens minted for someone else
	)

	// *Client satisfies both interfaces.
	g := &gate{v: client, a: client, failClosed: true}

	mux := http.NewServeMux()

	// Open route — no credential needed.
	mux.HandleFunc("GET /public", func(w http.ResponseWriter, r *http.Request) {
		if a := identity(r.Context()); a != nil {
			_, _ = w.Write([]byte("hello " + a.UserID + " (org " + a.OrgID + ")\n"))
			return
		}
		_, _ = w.Write([]byte("hello anonymous\n"))
	})

	// Gated route. The credential may be a user JWT *or* an agent/service key
	// (ab0t_sk_…) — Authorize resolves either, so agents are first-class.
	mux.HandleFunc("POST /admin", g.require("admin.write", "service", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("authorized\n"))
	}))

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", g.authenticate(mux)))
}
