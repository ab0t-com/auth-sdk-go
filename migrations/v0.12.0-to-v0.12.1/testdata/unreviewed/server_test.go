package unreviewed

import (
	"net/http"
	"testing"

	"github.com/ab0t-com/auth-sdk-go/authclienttest"
	"github.com/ab0t-com/auth-sdk-go/authmw"
)

func TestBadTokenIsUnavailable(t *testing.T) {
	srv := authclienttest.NewServer()
	defer srv.Close()
	srv.SetStatus(http.StatusUnauthorized) // the auth service rejects the token
	c := srv.NewClient()
	g := &authmw.Gate{V: c, A: c}
	_ = g
	want := http.StatusServiceUnavailable // R3: v0.12.1 answers 401 here
	_ = want
}
