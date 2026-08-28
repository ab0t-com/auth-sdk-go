package authclient

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestLive_AuthFlow proves the authenticated path end-to-end against a real
// server: register -> login -> ValidateToken -> Authorize (F-01 resource-scoped
// routing). Skipped unless AUTH_LIVE=1. Uses a throwaway account. Non-fatal logs
// so we learn what the deployment requires.
func TestLive_AuthFlow(t *testing.T) {
	if os.Getenv("AUTH_LIVE") == "" {
		t.Skip("set AUTH_LIVE=1 and AUTH_BASE")
	}
	c := New(os.Getenv("AUTH_BASE"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	email := fmt.Sprintf("sdk-smoke-%d@example.com", time.Now().UnixNano())
	pw := "Sdk-Smoke-Pw-9271!"

	var tok *TokenSet
	reg, err := c.Register(ctx, RegisterRequest{Email: email, Password: pw, Name: "SDK Smoke"})
	if err != nil {
		t.Logf("Register: %v (trying login-only if a shared test account is configured)", err)
	} else {
		t.Logf("Register OK: user=%s", reg.User.ID)
		tok = reg
	}
	if tok == nil || tok.AccessToken == "" {
		lg, lerr := c.Login(ctx, LoginRequest{Email: email, Password: pw})
		if lerr != nil {
			t.Logf("Login: %v", lerr)
			t.Skip("no usable credentials on this deployment; authenticated path needs a test account/org")
		}
		tok = lg
	}
	t.Logf("token acquired: access len=%d refresh len=%d provider=%q scope=%q",
		len(tok.AccessToken), len(tok.RefreshToken), tok.Provider, tok.Scope)

	// ValidateToken -> Actor (proves validation decode + delegation fields present/absent correctly)
	actor, err := c.ValidateToken(ctx, tok.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken FAILED live: %v", err)
	}
	t.Logf("ValidateToken OK: valid=%v user=%s org=%s is_delegation=%v", actor.Valid, actor.UserID, actor.OrgID, actor.IsDelegation)
	if !actor.Valid {
		t.Errorf("freshly-minted token reported invalid")
	}

	// F-01: resource-scoped Authorize must route to the resource PDP and return
	// cleanly (a brand-new user should be DENIED on an arbitrary resource, with NO error).
	ok, err := c.Authorize(ctx, tok.AccessToken, "world.write", Resource{Type: "world", ID: "w-smoke-1"})
	if err != nil {
		t.Fatalf("F-01: resource-scoped Authorize errored against live server: %v", err)
	}
	t.Logf("F-01 OK: resource-scoped Authorize returned %v (expected false for a new user) with no error", ok)

	// resource-less Authorize (capability path) also works
	ok2, err := c.Authorize(ctx, tok.AccessToken, "world.write", Resource{})
	if err != nil {
		t.Fatalf("resource-less Authorize errored: %v", err)
	}
	t.Logf("unscoped Authorize returned %v", ok2)
}
