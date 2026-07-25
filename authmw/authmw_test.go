package authmw_test

// The middleware is tested THROUGH the exported test doubles, exactly as a
// consumer would test their own handlers. If this is awkward to write, the doubles
// are wrong — so this file is a test of both.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	auth "github.com/ab0t-com/auth-sdk-go"
	"github.com/ab0t-com/auth-sdk-go/authclienttest"
	"github.com/ab0t-com/auth-sdk-go/authmw"
)

func ok(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

func do(t *testing.T, h http.Handler, authHeader string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestRequire_StatusMatrix(t *testing.T) {
	cases := []struct {
		name   string
		fake   *authclienttest.Fake
		header string
		want   int
	}{
		{"no credential -> 401", authclienttest.Allow(), "", http.StatusUnauthorized},
		{"allowed -> 200", authclienttest.Allow(), "Bearer jwt", http.StatusOK},
		{"denied -> 403", authclienttest.Deny(), "Bearer jwt", http.StatusForbidden},
		// The one that matters: an outage must not read as permission.
		{"auth service down -> 503", authclienttest.Unavailable(), "Bearer jwt", http.StatusServiceUnavailable},
		{"agent key allowed -> 200", authclienttest.Allow(), "Bearer ab0t_sk_agent", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := &authmw.Gate{V: tc.fake, A: tc.fake}
			if got := do(t, g.Require("world.write", "world", ok), tc.header); got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

// FailOpen exists, but turning it on must be the only way to get an allow out of
// an outage. This test is what stops the default drifting.
func TestRequire_FailOpenIsOptIn(t *testing.T) {
	down := authclienttest.Unavailable()

	closed := &authmw.Gate{V: down, A: down}
	if got := do(t, closed.Require("world.write", "world", ok), "Bearer jwt"); got != http.StatusServiceUnavailable {
		t.Fatalf("DEFAULT IS FAIL-OPEN: got %d, want 503 — an outage must never read as allowed", got)
	}

	open := &authmw.Gate{V: down, A: down, FailOpen: true}
	if got := do(t, open.Require("world.write", "world", ok), "Bearer jwt"); got != http.StatusOK {
		t.Errorf("FailOpen=true got %d, want 200", got)
	}
}

func TestRequire_NoAuthorizerIsUnavailableNotAllowed(t *testing.T) {
	g := &authmw.Gate{V: authclienttest.Allow()} // A is nil
	if got := do(t, g.Require("world.write", "world", ok), "Bearer jwt"); got != http.StatusServiceUnavailable {
		t.Errorf("got %d, want 503 — no authorizer wired cannot mean 'allowed'", got)
	}
}

// The action must reach the authorizer. If it stopped being sent, every
// authenticated caller would be authorized for everything — and every status-code
// assertion above would still pass.
func TestRequire_ForwardsActionAndResource(t *testing.T) {
	f := authclienttest.Allow()
	g := &authmw.Gate{V: f, A: f, ResourceID: func(*http.Request) string { return "r7" }}
	_ = do(t, g.Require("economy.transfer", "wallet", ok), "Bearer jwt")

	calls := f.Calls()
	var found bool
	for _, c := range calls {
		if c.Method == "Authorize" {
			found = true
			if c.Action != "economy.transfer" {
				t.Errorf("action = %q, want economy.transfer", c.Action)
			}
			if c.Resource != (auth.Resource{Type: "wallet", ID: "r7"}) {
				t.Errorf("resource = %+v", c.Resource)
			}
		}
	}
	if !found {
		t.Fatal("Authorize was never called")
	}
}

func TestAuthenticate(t *testing.T) {
	t.Run("no credential passes through anonymously", func(t *testing.T) {
		g := &authmw.Gate{V: authclienttest.Allow()}
		var seen *auth.Actor
		h := g.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = authmw.Identity(r.Context())
			w.WriteHeader(http.StatusOK)
		}))
		if got := do(t, h, ""); got != http.StatusOK {
			t.Fatalf("got %d, want 200 — a missing credential is not an error here", got)
		}
		if seen != nil {
			t.Error("identity attached for an anonymous request")
		}
	})

	t.Run("valid credential attaches the identity", func(t *testing.T) {
		g := &authmw.Gate{V: authclienttest.Allow()}
		var seen *auth.Actor
		h := g.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = authmw.Identity(r.Context())
			w.WriteHeader(http.StatusOK)
		}))
		if got := do(t, h, "Bearer jwt"); got != http.StatusOK {
			t.Fatalf("got %d", got)
		}
		if seen == nil || !seen.Valid || seen.UserID == "" {
			t.Errorf("identity not attached: %+v", seen)
		}
	})

	t.Run("invalid credential -> 401", func(t *testing.T) {
		g := &authmw.Gate{V: &authclienttest.Fake{Actor: &auth.Actor{Valid: false}}}
		if got := do(t, g.Authenticate(http.HandlerFunc(ok)), "Bearer bad"); got != http.StatusUnauthorized {
			t.Errorf("got %d, want 401", got)
		}
	})

	t.Run("auth service down -> 503, not anonymous", func(t *testing.T) {
		g := &authmw.Gate{V: authclienttest.Unavailable()}
		if got := do(t, g.Authenticate(http.HandlerFunc(ok)), "Bearer jwt"); got != http.StatusServiceUnavailable {
			t.Errorf("got %d, want 503 — an unreachable service must not silently downgrade to anonymous", got)
		}
	})
}

// Server drives the REAL client, so the client's own decoding and endpoint routing
// are exercised rather than substituted.
func TestWithRealClientAgainstFakeServer(t *testing.T) {
	srv := authclienttest.NewServer()
	defer srv.Close()

	client := auth.New(srv.URL(), auth.WithMaxRetries(0))
	g := &authmw.Gate{V: client, A: client}

	if got := do(t, g.Require("world.write", "world", ok), "Bearer jwt"); got != http.StatusOK {
		t.Errorf("got %d, want 200", got)
	}
	srv.SetValid(false)
	if got := do(t, g.Require("world.write", "world", ok), "Bearer jwt"); got != http.StatusForbidden {
		t.Errorf("got %d, want 403 when the service says invalid", got)
	}
	srv.SetStatus(http.StatusInternalServerError)
	if got := do(t, g.Require("world.write", "world", ok), "Bearer jwt"); got != http.StatusServiceUnavailable {
		t.Errorf("got %d, want 503 when the service 500s", got)
	}

	// A JWT and an agent key must go to DIFFERENT endpoints; getting that wrong is
	// silent, because both would just deny.
	srv.SetStatus(0)
	srv.SetValid(true)
	_ = do(t, g.Require("world.write", "world", ok), "Bearer ab0t_sk_agent")
	var sawAPIKeyPath bool
	for _, r := range srv.Requests() {
		if r == "POST /auth/validate-api-key" {
			sawAPIKeyPath = true
		}
	}
	if !sawAPIKeyPath {
		t.Errorf("agent key did not reach /auth/validate-api-key; requests were %v", srv.Requests())
	}
}
