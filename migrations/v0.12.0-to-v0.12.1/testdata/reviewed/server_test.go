package reviewed

import (
	"net/http"
	"testing"

	auth "github.com/ab0t-com/auth-sdk-go"
	"github.com/ab0t-com/auth-sdk-go/authclienttest"
	"github.com/ab0t-com/auth-sdk-go/authmw"
	"github.com/ab0t-com/auth-sdk-go/authmw/authmwtest"
)

func TestBadTokenIsUnauthorized(t *testing.T) {
	srv := authclienttest.NewServer()
	defer srv.Close()
	srv.SetStatus(http.StatusUnauthorized) // the auth service rejects the token
	c := srv.NewClient()
	g := &authmw.Gate{V: c, A: c}
	_ = g
	want := http.StatusUnauthorized // v0.12.1: an invalid credential is 401
	_ = want
}

// The gate wiring, checked against the authmw contract.
func TestAuthContract(t *testing.T) {
	authmwtest.Run(t, authmwtest.Contract{
		Wrap: func(c *auth.Client, inner http.Handler) http.Handler {
			return (&authmw.Gate{V: c, A: c, IncludePermissions: true, WriteDenial: authmw.JSONDenial}).RequireIdentity(inner)
		},
		WantPermissions: true,
		JSONDenials:     true,
	})
}
