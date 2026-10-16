// Package unreviewed is a v0.12.0 consumer snippet used ONLY to verify that
// migrate-check.sh flags what to look at for v0.12.1. It lives under testdata/,
// which the Go toolchain ignores. Run:
//
//	bash ../../migrate-check.sh .
//
// and expect a non-zero exit with R1, R2 and R3 findings.
package unreviewed

import (
	"net/http"

	auth "github.com/ab0t-com/auth-sdk-go"
	"github.com/ab0t-com/auth-sdk-go/authmw"
)

func newServer(mux *http.ServeMux) http.Handler {
	client := auth.New("", auth.WithExpectedAudience("svc"))   // INFO: also applies to mesh API keys
	gate := &authmw.Gate{V: client, A: client, FailOpen: true} // R1
	return gate.Authenticate(mux)
}

func handle(w http.ResponseWriter, r *http.Request) {
	caller := authmw.Identity(r.Context())
	for _, p := range caller.Permissions { // R2: JWT callers carry no permissions without IncludePermissions
		if p == "docs.write" {
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	w.WriteHeader(http.StatusForbidden)
}
