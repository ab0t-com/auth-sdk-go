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

// Consumers on the mesh are told to send their key in X-API-Key. A gate that read
// only Authorization saw no credential from a consumer that followed the docs.
func TestGate_AcceptsXAPIKey(t *testing.T) {
	f := authclienttest.Allow()
	g := &authmw.Gate{V: f, A: f}
	h := g.Authenticate(g.Require("world.write", "world", ok))

	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("X-API-Key", "ab0t_sk_consumer")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("X-API-Key only: got %d, want 200", rec.Code)
	}
	var sawValidate, sawAuthorize bool
	for _, c := range f.Calls() {
		if c.Token != "ab0t_sk_consumer" {
			t.Errorf("%s got credential %q, want the X-API-Key value", c.Method, c.Token)
		}
		sawValidate = sawValidate || c.Method == "ValidateToken"
		sawAuthorize = sawAuthorize || c.Method == "Authorize"
	}
	if !sawValidate || !sawAuthorize {
		t.Errorf("calls = %+v, want ValidateToken and Authorize", f.Calls())
	}
}

// Authorization keeps priority: existing callers that send it see no change.
func TestGate_AuthorizationWinsOverXAPIKey(t *testing.T) {
	f := authclienttest.Allow()
	g := &authmw.Gate{V: f, A: f}
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("Authorization", "Bearer user-jwt")
	req.Header.Set("X-API-Key", "ab0t_sk_consumer")
	rec := httptest.NewRecorder()
	g.Require("world.write", "world", ok).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	if calls := f.Calls(); len(calls) != 1 || calls[0].Token != "user-jwt" {
		t.Errorf("calls = %+v, want the Authorization credential", calls)
	}
	if got := authmw.Credential(req); got != "user-jwt" {
		t.Errorf("Credential = %q", got)
	}
	if got := authmw.Bearer(req); got != "user-jwt" {
		t.Errorf("Bearer = %q (must be unchanged)", got)
	}
}

func TestGate_XAPIKeyDeniedAndMissing(t *testing.T) {
	g := &authmw.Gate{V: authclienttest.Deny(), A: authclienttest.Deny()}
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("X-API-Key", "ab0t_sk_consumer")
	rec := httptest.NewRecorder()
	g.Require("world.write", "world", ok).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("denied key: got %d, want 403", rec.Code)
	}
	down := &authmw.Gate{V: authclienttest.Unavailable(), A: authclienttest.Unavailable()}
	rec = httptest.NewRecorder()
	down.Require("world.write", "world", ok).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("auth down with X-API-Key: got %d, want 503", rec.Code)
	}
	// Bearer stays Authorization-only.
	if authmw.Bearer(req) != "" {
		t.Error("Bearer must not read X-API-Key")
	}
}
