// Package reviewed is the same consumer AFTER review for v0.12.1 — every site
// resolved one of the documented ways. migrate-check.sh must exit 0 on it:
//
//	bash ../../migrate-check.sh .
package reviewed

import (
	"net/http"

	auth "github.com/ab0t-com/auth-sdk-go"
	"github.com/ab0t-com/auth-sdk-go/authmw"
)

func newServer(mux *http.ServeMux) http.Handler {
	client := auth.New("", auth.WithExpectedJWTAudience("svc")) // JWTs only; mesh keys carry no audience
	gate := &authmw.Gate{
		V: client, A: client,
		IncludePermissions: true, // JWT callers get their permissions
		// authsdk:v0.12.1-reviewed — temporary degradation, owner-approved; invalid credentials are refused now
		FailOpen:    true,
		WriteDenial: authmw.JSONDenial,
	}
	return gate.RequireIdentity(mux)
}

func handle(w http.ResponseWriter, r *http.Request) {
	caller := authmw.Identity(r.Context())
	for _, p := range caller.Permissions {
		if p == "docs.write" {
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	w.WriteHeader(http.StatusForbidden)
}
