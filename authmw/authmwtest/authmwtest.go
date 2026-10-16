// Package authmwtest checks that YOUR service's authmw gate keeps the auth
// contract, from your own test suite.
//
// A gate is a few lines of configuration, and each line can quietly break the
// contract: a 503 where a client should re-authenticate, a 200 where the auth
// service was down, a cache that is not there. Run drives your real middleware
// stack against a fake auth service and fails your test on any deviation:
//
//	case                                                   expected
//	no credential                                          401 (handler runs anonymously with AllowAnonymous)
//	invalid JWT (the auth service answers HTTP 401)        401
//	invalid API key (the auth service answers {valid:false}) 401
//	auth service answers 503 / is unreachable              503, and the failure is NOT cached
//	valid JWT / valid API key                              your handler runs with authmw.Identity set
//	                                                       (and the JWT's permissions, with WantPermissions)
//	the same valid credential N times                      no auth calls after the first request
//	the same invalid JWT N times                           no auth calls after the first request
//	every denial, with JSONDenials                         Content-Type application/json, {"error":"…"}
//
// Usage — Wrap builds your gate exactly as production does, around the inner
// handler the suite supplies, using the client the suite supplies:
//
//	func TestAuthContract(t *testing.T) {
//		authmwtest.Run(t, authmwtest.Contract{
//			Wrap: func(c *auth.Client, inner http.Handler) http.Handler {
//				gate := &authmw.Gate{V: c, A: c, IncludePermissions: true, WriteDenial: authmw.JSONDenial}
//				return gate.RequireIdentity(inner) // your production wiring
//			},
//			WantPermissions: true,
//			JSONDenials:     true,
//		})
//	}
//
// The contract assumes an identity gate (Gate.Authenticate or
// Gate.RequireIdentity) is in the stack, since that is what attaches the
// identity and turns an invalid credential into 401. A Gate.Require may sit
// behind it; the fake auth service allows every action for a valid credential.
//
// Each case gets a fresh fake auth service and a fresh client with the SDK's
// default validation cache, so the cases are independent. The package depends
// only on the standard library and the SDK.
package authmwtest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/ab0t-com/auth-sdk-go"
	"github.com/ab0t-com/auth-sdk-go/authmw"
)

// Contract describes the gate under test.
type Contract struct {
	// Wrap returns your middleware stack around inner, built from client — the
	// same wiring production uses. Required.
	Wrap func(client *auth.Client, inner http.Handler) http.Handler

	// Method and Path of the request sent through the stack. Defaults: GET "/".
	Method string
	Path   string

	// AllowAnonymous: the gate lets a request with no credential through
	// (Gate.Authenticate alone). Default false: no credential must be 401.
	AllowAnonymous bool

	// WantPermissions: a valid JWT must reach the handler with its permissions
	// (Gate.IncludePermissions). The fake auth service returns a JWT's
	// permissions only when they are asked for, as the real one does.
	WantPermissions bool

	// JSONDenials: every denial must be a JSON body {"error":"…"} with
	// Content-Type application/json (Gate.WriteDenial = authmw.JSONDenial).
	JSONDenials bool

	// Repeat is N for the "same credential N times" cases. Default 5.
	Repeat int
}

// Credentials the fake auth service knows.
const (
	// ValidAPIKey validates, with permission Permission.
	ValidAPIKey = "ab0t_sk_authmwtest_valid"
	// InvalidAPIKey is answered 200 {"valid":false}.
	InvalidAPIKey = "ab0t_sk_authmwtest_invalid"
	// Permission is the permission a valid credential holds.
	Permission = "authmwtest.read"
)

// ValidJWT returns a JWT-shaped credential the fake auth service accepts.
// InvalidJWT returns one it answers with HTTP 401. Neither is signed: the fake
// decides by value, as a stand-in for the real service.
func ValidJWT() string   { return validJWT }
func InvalidJWT() string { return invalidJWT }

// Built once per process, so every call returns the same string.
var (
	validJWT   = fakeJWT("authmwtest-user")
	invalidJWT = fakeJWT("authmwtest-nobody")
)

func fakeJWT(sub string) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT","kid":"authmwtest"}`))
	p, _ := json.Marshal(map[string]any{"sub": sub, "exp": time.Now().Add(24 * time.Hour).Unix()})
	return h + "." + base64.RawURLEncoding.EncodeToString(p) + ".c2ln"
}

// Run checks the contract and reports every deviation on t (with Errorf, so
// one run shows all of them). It does not stop t.
func Run(t testing.TB, c Contract) {
	t.Helper()
	if c.Wrap == nil {
		t.Errorf("authmwtest: Contract.Wrap is required")
		return
	}
	if c.Method == "" {
		c.Method = http.MethodGet
	}
	if c.Path == "" {
		c.Path = "/"
	}
	if c.Repeat <= 0 {
		c.Repeat = 5
	}

	// no credential
	{
		h := newHarness(c)
		res := h.send("")
		switch {
		case c.AllowAnonymous && (!res.ran || res.identity != nil):
			t.Errorf("authmwtest [no credential]: status %d, handler ran=%v identity=%v — want the handler to run anonymously (AllowAnonymous)", res.status, res.ran, res.identity != nil)
		case !c.AllowAnonymous:
			h.wantDenied(t, "no credential", res, http.StatusUnauthorized)
		}
		h.close()
	}

	// invalid JWT: the auth service answers HTTP 401
	{
		h := newHarness(c)
		h.wantDenied(t, "invalid JWT (auth answers 401)", h.send("Bearer "+InvalidJWT()), http.StatusUnauthorized)
		h.close()
	}

	// invalid API key: the auth service answers 200 {valid:false}
	{
		h := newHarness(c)
		h.wantDenied(t, "invalid API key (auth answers valid:false)", h.send("Bearer "+InvalidAPIKey), http.StatusUnauthorized)
		h.close()
	}

	// auth service down: 503, never cached
	{
		h := newHarness(c)
		h.fake.setDown(true)
		h.wantDenied(t, "auth answers 503", h.send("Bearer "+ValidJWT()), http.StatusServiceUnavailable)
		first := h.fake.calls()
		h.wantDenied(t, "auth answers 503 (repeat)", h.send("Bearer "+ValidJWT()), http.StatusServiceUnavailable)
		if h.fake.calls() == first {
			t.Errorf("authmwtest [auth answers 503]: the repeat made no auth call — a failure must never be cached")
		}
		h.close()
	}
	{
		h := newHarness(c)
		h.fake.srv.Close() // nothing listening: a network failure
		h.wantDenied(t, "auth unreachable", h.send("Bearer "+ValidJWT()), http.StatusServiceUnavailable)
	}

	// valid credentials reach the handler with an identity; repeats are cached
	for _, tc := range []struct {
		name, header string
		perms        bool
	}{
		{"valid JWT", "Bearer " + ValidJWT(), c.WantPermissions},
		{"valid API key", "Bearer " + ValidAPIKey, true},
	} {
		h := newHarness(c)
		res := h.send(tc.header)
		if !res.ran || res.status >= 400 {
			t.Errorf("authmwtest [%s]: status %d, handler ran=%v — want the handler to run", tc.name, res.status, res.ran)
			h.close()
			continue
		}
		if res.identity == nil || !res.identity.Valid {
			t.Errorf("authmwtest [%s]: handler ran without an identity — is Authenticate or RequireIdentity in the stack?", tc.name)
		} else if tc.perms && !contains(res.identity.Permissions, Permission) {
			t.Errorf("authmwtest [%s]: identity permissions = %v, want %q (Gate.IncludePermissions?)", tc.name, res.identity.Permissions, Permission)
		}
		first := h.fake.calls()
		for i := 1; i < c.Repeat; i++ {
			h.send(tc.header)
		}
		if n := h.fake.calls(); n != first {
			t.Errorf("authmwtest [%s ×%d]: %d auth calls after the first request, want 0 — use the client the suite passes to Wrap (validation cache on)", tc.name, c.Repeat, n-first)
		}
		h.close()
	}

	// the same invalid JWT N times: one auth call, then the cached "not valid"
	{
		h := newHarness(c)
		h.send("Bearer " + InvalidJWT())
		first := h.fake.calls()
		for i := 1; i < c.Repeat; i++ {
			h.wantDenied(t, fmt.Sprintf("invalid JWT, repeat %d", i), h.send("Bearer "+InvalidJWT()), http.StatusUnauthorized)
		}
		if n := h.fake.calls(); n != first {
			t.Errorf("authmwtest [invalid JWT ×%d]: %d auth calls after the first request, want 0 — a definite 401 is cached for the negative TTL", c.Repeat, n-first)
		}
		h.close()
	}
}

// ---- harness ----

type result struct {
	status   int
	header   http.Header
	body     string
	ran      bool
	identity *auth.Actor
}

type harness struct {
	c       Contract
	fake    *fakeAuth
	handler http.Handler

	mu       sync.Mutex
	ran      bool
	identity *auth.Actor
}

func newHarness(c Contract) *harness {
	h := &harness{c: c, fake: newFakeAuth()}
	client := auth.New(h.fake.srv.URL, auth.WithMaxRetries(0), auth.WithTimeout(5*time.Second))
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.ran, h.identity = true, authmw.Identity(r.Context())
		h.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	h.handler = c.Wrap(client, inner)
	return h
}

func (h *harness) close() { h.fake.srv.Close() }

func (h *harness) send(authorization string) result {
	h.mu.Lock()
	h.ran, h.identity = false, nil
	h.mu.Unlock()
	req := httptest.NewRequest(h.c.Method, h.c.Path, nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	h.mu.Lock()
	defer h.mu.Unlock()
	return result{status: rec.Code, header: rec.Header(), body: rec.Body.String(), ran: h.ran, identity: h.identity}
}

func (h *harness) wantDenied(t testing.TB, name string, res result, want int) {
	t.Helper()
	if res.status != want {
		t.Errorf("authmwtest [%s]: status %d, want %d", name, res.status, want)
	}
	if res.ran {
		t.Errorf("authmwtest [%s]: the handler ran — a denied request must not reach it", name)
	}
	if !h.c.JSONDenials {
		return
	}
	if ct := res.header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("authmwtest [%s]: Content-Type %q, want application/json (Gate.WriteDenial = authmw.JSONDenial?)", name, ct)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(res.body), &body); err != nil || body.Error == "" {
		t.Errorf("authmwtest [%s]: body %q, want {\"error\":\"…\"}", name, res.body)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// ---- fake auth service ----

type fakeAuth struct {
	srv *httptest.Server

	mu   sync.Mutex
	down bool
	n    int
}

func newFakeAuth() *fakeAuth {
	f := &fakeAuth{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

func (f *fakeAuth) setDown(v bool) { f.mu.Lock(); f.down = v; f.mu.Unlock() }

func (f *fakeAuth) calls() int { f.mu.Lock(); defer f.mu.Unlock(); return f.n }

func (f *fakeAuth) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.n++
	down := f.down
	f.mu.Unlock()
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	if down {
		reply(http.StatusServiceUnavailable, map[string]any{"detail": "Service temporarily unavailable"})
		return
	}
	var body struct {
		Token               string   `json:"token"`
		APIKey              string   `json:"api_key"`
		IncludePermissions  bool     `json:"include_permissions"`
		RequiredPermissions []string `json:"required_permissions"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	valid := map[string]any{"valid": true, "user_id": "authmwtest-user", "org_id": "authmwtest-org"}
	switch r.URL.Path {
	case "/auth/validate-token":
		if body.Token != ValidJWT() {
			reply(http.StatusUnauthorized, map[string]any{"detail": "Invalid token"})
			return
		}
		if body.IncludePermissions || len(body.RequiredPermissions) > 0 {
			valid["permissions"] = []string{Permission}
		}
		reply(http.StatusOK, valid)
	case "/auth/validate-api-key":
		if body.APIKey != ValidAPIKey {
			reply(http.StatusOK, map[string]any{"valid": false, "error": "API key not found"})
			return
		}
		valid["permissions"] = []string{Permission}
		reply(http.StatusOK, valid)
	case "/permissions/check":
		reply(http.StatusOK, map[string]any{"allowed": true})
	default:
		reply(http.StatusNotFound, map[string]any{"detail": "Not Found"})
	}
}
