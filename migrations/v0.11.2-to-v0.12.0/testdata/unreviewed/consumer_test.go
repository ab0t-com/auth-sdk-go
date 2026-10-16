package unreviewed

import (
	"testing"

	auth "github.com/ab0t-com/auth-sdk-go"
	"github.com/ab0t-com/auth-sdk-go/authclienttest"
)

func TestFlipsTheFake(t *testing.T) {
	srv := authclienttest.NewServer()
	defer srv.Close()
	client := auth.New(srv.URL()) // R3: flips below are not seen for up to the TTL
	_ = client
	srv.SetValid(false)
}
