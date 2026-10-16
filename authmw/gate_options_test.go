package authmw_test

// gate_options_test.go — the opt-in Gate settings added in v0.12.1:
// IncludePermissions, RequireIdentity, WriteDenial / JSONDenial, APIKeyHeader,
// and the case-insensitive Bearer scheme. Each default is asserted unchanged.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	auth "github.com/ab0t-com/auth-sdk-go"
	"github.com/ab0t-com/auth-sdk-go/authclienttest"
	"github.com/ab0t-com/auth-sdk-go/authmw"
	"github.com/ab0t-com/auth-sdk-go/authmw/authmwtest"
)

// ---- IncludePermissions ----

// userJWT is a JWT-shaped credential; permsAuth accepts any token.
const userJWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1MSJ9.c2ln"

// permsAuth answers validate-token with permissions ONLY when the request asks
// for them (include_permissions), as the auth service does, and records each
// request body.
type permsAuth struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []map[string]any
}

func newPermsAuth(t *testing.T) *permsAuth {
	t.Helper()
	p := &permsAuth{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		p.mu.Lock()
		p.reqs = append(p.reqs, map[string]any{"path": r.URL.Path, "body": body})
		p.mu.Unlock()
		out := map[string]any{"valid": true, "user_id": "u1", "org_id": "o1"}
		switch {
		case r.URL.Path == "/auth/validate-api-key":
			out["permissions"] = []string{"key.perm"}
		case body["include_permissions"] == true:
			out["permissions"] = []string{"docs.read", "docs.write"}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *permsAuth) count() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.reqs) }

func identityOf(t *testing.T, h func(http.Handler) http.Handler, authorization string) (int, *auth.Actor) {
	t.Helper()
	var seen *auth.Actor
	rec := serve(h(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = authmw.Identity(r.Context())
		w.WriteHeader(http.StatusOK)
	})), authorization)
	return rec.Code, seen
}

func TestGate_IncludePermissionsGivesJWTCallersTheirPermissions(t *testing.T) {
	p := newPermsAuth(t)
	c := auth.New(p.srv.URL, auth.WithMaxRetries(0))

	// Default (unchanged): a JWT identity carries no permissions.
	off := &authmw.Gate{V: c}
	if code, a := identityOf(t, off.Authenticate, "Bearer "+userJWT); code != 200 || a == nil || len(a.Permissions) != 0 {
		t.Fatalf("default: code=%d actor=%+v — want an identity with no permissions (unchanged)", code, a)
	}

	on := &authmw.Gate{V: c, IncludePermissions: true}
	code, a := identityOf(t, on.Authenticate, "Bearer "+userJWT)
	if code != 200 || a == nil || strings.Join(a.Permissions, ",") != "docs.read,docs.write" {
		t.Fatalf("IncludePermissions: code=%d actor=%+v — want the JWT's permissions", code, a)
	}
	// The richer answer is cached under its own key: repeats cost nothing, and it
	// never leaks into a caller that did not ask for permissions.
	n := p.count()
	for i := 0; i < 3; i++ {
		identityOf(t, on.Authenticate, "Bearer "+userJWT)
	}
	if p.count() != n {
		t.Errorf("auth calls grew from %d to %d — the permissions answer must be cached", n, p.count())
	}
	if _, a := identityOf(t, off.Authenticate, "Bearer "+userJWT); a == nil || len(a.Permissions) != 0 {
		t.Errorf("a gate without IncludePermissions got %+v — the cache must key on include_permissions", a)
	}

	// API keys go to validate-api-key as before (which always returns permissions).
	if code, a := identityOf(t, on.RequireIdentity, "Bearer ab0t_sk_svc"); code != 200 || a == nil || len(a.Permissions) != 1 || a.Permissions[0] != "key.perm" {
		t.Errorf("API key with IncludePermissions: code=%d actor=%+v", code, a)
	}
	p.mu.Lock()
	last := p.reqs[len(p.reqs)-1]
	p.mu.Unlock()
	if last["path"] != "/auth/validate-api-key" {
		t.Errorf("API key went to %v, want /auth/validate-api-key", last["path"])
	}
}

func TestGate_IncludePermissionsWithoutARicherValidatorFailsClosed(t *testing.T) {
	f := authclienttest.Allow() // implements ValidateToken only
	var denyErr error
	g := &authmw.Gate{V: f, IncludePermissions: true, OnDeny: func(_ *http.Request, _ string, _ int, err error) { denyErr = err }}
	if code, a := identityOf(t, g.Authenticate, "Bearer jwt"); code != http.StatusServiceUnavailable || a != nil {
		t.Fatalf("code=%d actor=%+v — want 503: an identity whose permissions were silently dropped must not be attached", code, a)
	}
	if denyErr == nil || !strings.Contains(denyErr.Error(), "ValidateTokenWith") {
		t.Errorf("OnDeny err = %v, want one naming the missing ValidateTokenWith", denyErr)
	}
	// An API key does not need the richer call.
	if code, _ := identityOf(t, g.Authenticate, "Bearer ab0t_sk_svc"); code != 200 {
		t.Errorf("API key: code=%d, want 200", code)
	}
}

// ---- RequireIdentity ----

func TestRequireIdentity_StatusMatrix(t *testing.T) {
	cases := []struct {
		name     string
		gate     *authmw.Gate
		header   string
		want     int
		identity bool
	}{
		{"no credential -> 401", &authmw.Gate{V: authclienttest.Allow()}, "", 401, false},
		{"invalid credential -> 401", &authmw.Gate{V: &authclienttest.Fake{Actor: &auth.Actor{Valid: false}}}, "Bearer bad", 401, false},
		{"auth down -> 503", &authmw.Gate{V: authclienttest.Unavailable()}, "Bearer jwt", 503, false},
		{"auth down + FailOpen -> through, no identity", &authmw.Gate{V: authclienttest.Unavailable(), FailOpen: true}, "Bearer jwt", 200, false},
		{"no validator -> 503", &authmw.Gate{}, "Bearer jwt", 503, false},
		{"valid -> handler with identity", &authmw.Gate{V: authclienttest.Allow()}, "Bearer jwt", 200, true},
		{"invalid + FailOpen -> still 401", &authmw.Gate{V: &authclienttest.Fake{Actor: &auth.Actor{Valid: false}}, FailOpen: true}, "Bearer bad", 401, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, a := identityOf(t, tc.gate.RequireIdentity, tc.header)
			if code != tc.want {
				t.Errorf("got %d, want %d", code, tc.want)
			}
			if (a != nil) != tc.identity {
				t.Errorf("identity attached = %v, want %v", a != nil, tc.identity)
			}
		})
	}
	// Authenticate is unchanged: no credential still passes anonymously.
	if code, a := identityOf(t, (&authmw.Gate{V: authclienttest.Allow()}).Authenticate, ""); code != 200 || a != nil {
		t.Errorf("Authenticate with no credential: code=%d identity=%v — must stay anonymous pass-through", code, a != nil)
	}
}

// ---- WriteDenial / JSONDenial ----

func TestGate_JSONDenialWritesStaticJSONBodies(t *testing.T) {
	cases := []struct {
		name string
		gate *authmw.Gate
		h    func(*authmw.Gate) http.Handler
		hdr  string
		code int
		msg  string
	}{
		{"401 no credential", &authmw.Gate{V: authclienttest.Allow()}, func(g *authmw.Gate) http.Handler { return g.RequireIdentity(http.HandlerFunc(ok)) }, "", 401, "auth required"},
		{"401 invalid", &authmw.Gate{V: &authclienttest.Fake{Actor: &auth.Actor{Valid: false}}}, func(g *authmw.Gate) http.Handler { return g.Authenticate(http.HandlerFunc(ok)) }, "Bearer <script>", 401, "invalid token"},
		{"403 denied", &authmw.Gate{A: authclienttest.Deny()}, func(g *authmw.Gate) http.Handler { return g.Require("x.write", "x", ok) }, "Bearer jwt", 403, "forbidden"},
		{"503 down", &authmw.Gate{V: authclienttest.Unavailable()}, func(g *authmw.Gate) http.Handler { return g.Authenticate(http.HandlerFunc(ok)) }, "Bearer jwt", 503, "auth unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Default (unchanged): http.Error plain text.
			rec := serve(tc.h(tc.gate), tc.hdr)
			if rec.Code != tc.code || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") || strings.TrimSpace(rec.Body.String()) != tc.msg {
				t.Errorf("default: %d %q %q — want %d text/plain %q", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String(), tc.code, tc.msg)
			}
			tc.gate.WriteDenial = authmw.JSONDenial
			rec = serve(tc.h(tc.gate), tc.hdr)
			if rec.Code != tc.code || rec.Header().Get("Content-Type") != "application/json" {
				t.Errorf("JSON: %d %q, want %d application/json", rec.Code, rec.Header().Get("Content-Type"), tc.code)
			}
			if got, want := strings.TrimSpace(rec.Body.String()), `{"error":"`+tc.msg+`"}`; got != want {
				t.Errorf("JSON body %s, want %s (static, no echo of input)", got, want)
			}
		})
	}
}

func TestGate_WriteDenialIsCalledAfterOnDeny(t *testing.T) {
	var order []string
	g := &authmw.Gate{
		V:      authclienttest.Unavailable(),
		OnDeny: func(*http.Request, string, int, error) { order = append(order, "OnDeny") },
		WriteDenial: func(w http.ResponseWriter, _ *http.Request, status int, msg string) {
			order = append(order, "WriteDenial")
			w.WriteHeader(status)
		},
	}
	serve(g.Authenticate(http.HandlerFunc(ok)), "Bearer jwt")
	if strings.Join(order, ",") != "OnDeny,WriteDenial" {
		t.Errorf("order = %v", order)
	}
}

// ---- Bearer scheme + API-key header ----

func TestBearer_SchemeIsCaseInsensitive(t *testing.T) {
	for in, want := range map[string]string{
		"Bearer tok":          "tok",
		"bearer tok":          "tok",
		"BEARER tok":          "tok",
		"bEaReR   tok  ":      "tok",
		"ab0t_sk_raw":         "ab0t_sk_raw", // no scheme: the whole value, as before
		"Basic dXNlcjpwYXNz":  "Basic dXNlcjpwYXNz",
		"Bearertok":           "Bearertok",
		"":                    "",
		"  Bearer leading-sp": "Bearer leading-sp", // unchanged from before
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if in != "" {
			req.Header.Set("Authorization", in)
		}
		if got := authmw.Bearer(req); got != want {
			t.Errorf("Bearer(%q) = %q, want %q", in, got, want)
		}
	}
	f := authclienttest.Allow()
	g := &authmw.Gate{V: f, A: f}
	if rec := serve(g.Require("x.read", "x", ok), "bearer user-jwt"); rec.Code != 200 {
		t.Fatalf("lower-case scheme: %d", rec.Code)
	}
	if calls := f.Calls(); len(calls) != 1 || calls[0].Token != "user-jwt" {
		t.Errorf("calls = %+v, want the token without the scheme", calls)
	}
}

func TestGate_APIKeyHeaderIsConfigurable(t *testing.T) {
	f := authclienttest.Allow()
	g := &authmw.Gate{V: f, A: f, APIKeyHeader: "X-Service-Key"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Service-Key", "ab0t_sk_custom")
	req.Header.Set("X-API-Key", "ab0t_sk_default_header")
	rec := httptest.NewRecorder()
	g.Require("x.read", "x", ok).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("custom header: %d", rec.Code)
	}
	if calls := f.Calls(); len(calls) != 1 || calls[0].Token != "ab0t_sk_custom" {
		t.Errorf("calls = %+v, want the X-Service-Key value", calls)
	}
	// Authorization still wins.
	f.Reset()
	req.Header.Set("Authorization", "Bearer user-jwt")
	g.Require("x.read", "x", ok).ServeHTTP(httptest.NewRecorder(), req)
	if calls := f.Calls(); len(calls) != 1 || calls[0].Token != "user-jwt" {
		t.Errorf("calls = %+v, want Authorization to win", calls)
	}
	// The default is unchanged: X-API-Key, and the package-level Credential reads it.
	if got := authmw.Credential(httptest.NewRequest(http.MethodGet, "/", nil)); got != "" {
		t.Errorf("Credential on an empty request = %q", got)
	}
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("X-API-Key", "ab0t_sk_d")
	f.Reset()
	(&authmw.Gate{V: f, A: f}).Require("x.read", "x", ok).ServeHTTP(httptest.NewRecorder(), r2)
	if calls := f.Calls(); len(calls) != 1 || calls[0].Token != "ab0t_sk_d" {
		t.Errorf("default header: calls = %+v", calls)
	}
}

// ---- the documented JSON-API setup passes the conformance suite ----

func TestConformance_JSONAPIWithRequireIdentityAndPermissions(t *testing.T) {
	authmwtest.Run(t, authmwtest.Contract{
		Wrap: func(c *auth.Client, inner http.Handler) http.Handler {
			gate := &authmw.Gate{V: c, A: c, IncludePermissions: true, WriteDenial: authmw.JSONDenial}
			return gate.RequireIdentity(inner)
		},
		WantPermissions: true,
		JSONDenials:     true,
	})
}

func TestConformance_AuthenticateAloneAllowsAnonymous(t *testing.T) {
	authmwtest.Run(t, authmwtest.Contract{
		Wrap: func(c *auth.Client, inner http.Handler) http.Handler {
			return (&authmw.Gate{V: c}).Authenticate(inner)
		},
		AllowAnonymous: true,
	})
}

// A gate that drops permissions or JSON bodies is reported, not passed.
func TestConformance_CatchesMissingPermissionsAndTextDenials(t *testing.T) {
	rec := &recordingTB{TB: t}
	authmwtest.Run(rec, authmwtest.Contract{
		Wrap: func(c *auth.Client, inner http.Handler) http.Handler {
			return (&authmw.Gate{V: c}).RequireIdentity(inner) // neither setting
		},
		WantPermissions: true,
		JSONDenials:     true,
	})
	if !rec.has("[valid JWT]: identity permissions") || !rec.has("want application/json") {
		t.Fatalf("the conformance suite did not report the missing settings; it reported:\n%v", rec.errs)
	}
}
