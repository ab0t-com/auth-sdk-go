package reviewed

import (
	"testing"

	"github.com/ab0t-com/auth-sdk-go/authclienttest"
)

func TestFlipsTheFake(t *testing.T) {
	srv := authclienttest.NewServer()
	defer srv.Close()
	client := srv.NewClient() // cache off: every flip is seen by the next call
	_ = client
	srv.SetValid(false)
}
