package authmw_test

// hardening_20261016_test.go — adversarial status-classification tests for the
// v0.12.1 gate (owner instruction 2026-10-16: "robust testing, no assumptions").
//
// Every row drives a REAL *auth.Client (default validation cache, no retries)
// against an httptest auth double that answers validate-token in one specific
// SHAPE — a status, a body, a stall, a dropped connection — and asserts the
// status each gate entry point gives the caller, with and without FailOpen.
//
// The two invariants under test:
//   1. Only a DEFINITE answer about the credential is a 401/403. Everything
//      else (any other 4xx, 429, 5xx, undecodable 200, timeout, reset) is 503.
//   2. FailOpen admits only the 503 rows. It never runs the handler for a row
//      whose non-FailOpen answer is 401 or 403.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/ab0t-com/auth-sdk-go"
	"github.com/ab0t-com/auth-sdk-go/authmw"
)

const hJWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJoYXJkZW4ifQ.c2ln"

// shapeAuth answers /auth/validate-token (and validate-api-key) with one scripted
// shape; /permissions/check always allows, so the resource-scoped Require is
// decided by the validate-token shape alone.
type shapeAuth struct {
	srv   *httptest.Server
	calls int32
}

type shape struct {
	name   string
	status int    // 0 = 200
	body   string // raw body
	stall  bool   // hold the request until the client gives up
	reset  bool   // hijack and close the connection
}

func newShapeAuth(t *testing.T, s shape) *shapeAuth {
	t.Helper()
	a := &shapeAuth{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/permissions/check" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"allowed":true}`))
			return
		}
		atomic.AddInt32(&a.calls, 1)
		switch {
		case s.stall:
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
			return
		case s.reset:
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Errorf("no hijacker")
				return
			}
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		st := s.status
		if st == 0 {
			st = 200
		}
		w.WriteHeader(st)
		_, _ = w.Write([]byte(s.body))
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *shapeAuth) n() int { return int(atomic.LoadInt32(&a.calls)) }

func (a *shapeAuth) client() *auth.Client {
	return auth.New(a.srv.URL, auth.WithMaxRetries(0), auth.WithTimeout(300*time.Millisecond))
}

type gateKind int

const (
	gkAuthenticate gateKind = iota
	gkRequireIdentity
	gkRequire
	gkRequireResource
)

func (k gateKind) String() string {
	return [...]string{"Authenticate", "RequireIdentity", "Require", "Require(resource)"}[k]
}

func wrap(g *authmw.Gate, k gateKind, inner http.HandlerFunc) http.Handler {
	switch k {
	case gkAuthenticate:
		return g.Authenticate(inner)
	case gkRequireIdentity:
		return g.RequireIdentity(inner)
	case gkRequire:
		return g.Require("doc.read", "", inner)
	default:
		return g.Require("doc.read", "doc", inner)
	}
}

func TestHardening_AuthAnswerShapeMatrix(t *testing.T) {
	// want: Authenticate, RequireIdentity, Require, Require(resource)
	const U, F, S, OK = 401, 403, 503, 200
	rows := []struct {
		s    shape
		want [4]int
	}{
		{shape{name: "200 valid", body: `{"valid":true,"user_id":"u1","org_id":"o1"}`}, [4]int{OK, OK, OK, OK}},
		{shape{name: "200 valid:false", body: `{"valid":false,"error":"bad"}`}, [4]int{U, U, F, F}},
		{shape{name: "200 empty object", body: `{}`}, [4]int{U, U, F, F}},
		{shape{name: "200 empty body", body: ``}, [4]int{U, U, F, F}},
		{shape{name: "200 null", body: `null`}, [4]int{U, U, F, F}},
		{shape{name: "200 truncated JSON", body: `{"valid":tr`}, [4]int{S, S, S, S}},
		{shape{name: "200 wrong type valid", body: `{"valid":"true","user_id":"u1"}`}, [4]int{S, S, S, S}},
		{shape{name: "200 HTML", body: `<html>proxy error</html>`}, [4]int{S, S, S, S}},
		{shape{name: "200 JSON array", body: `[{"valid":true}]`}, [4]int{S, S, S, S}},
		{shape{name: "401", status: 401, body: `{"detail":"Invalid token"}`}, [4]int{U, U, U, U}},
		{shape{name: "401 non-JSON", status: 401, body: `nope`}, [4]int{U, U, U, U}},
		{shape{name: "403", status: 403, body: `{"detail":"Forbidden"}`}, [4]int{U, U, F, F}},
		{shape{name: "400", status: 400, body: `{"detail":"bad"}`}, [4]int{S, S, S, S}},
		{shape{name: "404", status: 404, body: `{"detail":"Not Found"}`}, [4]int{S, S, S, S}},
		{shape{name: "405", status: 405, body: ``}, [4]int{S, S, S, S}},
		{shape{name: "409", status: 409, body: `{}`}, [4]int{S, S, S, S}},
		{shape{name: "422", status: 422, body: `{"detail":[{"msg":"x","type":"y"}]}`}, [4]int{S, S, S, S}},
		{shape{name: "429", status: 429, body: `{"detail":"slow down"}`}, [4]int{S, S, S, S}},
		{shape{name: "500", status: 500, body: `{"detail":"boom"}`}, [4]int{S, S, S, S}},
		{shape{name: "502", status: 502, body: `bad gateway`}, [4]int{S, S, S, S}},
		{shape{name: "503", status: 503, body: `{"detail":"Service temporarily unavailable"}`}, [4]int{S, S, S, S}},
		{shape{name: "504", status: 504, body: ``}, [4]int{S, S, S, S}},
		{shape{name: "timeout", stall: true}, [4]int{S, S, S, S}},
		{shape{name: "connection reset", reset: true}, [4]int{S, S, S, S}},
	}
	for _, row := range rows {
		row := row
		for k := gkAuthenticate; k <= gkRequireResource; k++ {
			for _, failOpen := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/failOpen=%v", row.s.name, k, failOpen), func(t *testing.T) {
					a := newShapeAuth(t, row.s)
					c := a.client()
					g := &authmw.Gate{V: c, A: c, FailOpen: failOpen}
					var ran int32
					var sawIdentity *auth.Actor
					h := wrap(g, k, func(w http.ResponseWriter, r *http.Request) {
						atomic.AddInt32(&ran, 1)
						sawIdentity = authmw.Identity(r.Context())
						w.WriteHeader(OK)
					})
					want := row.want[k]
					rec := serve(h, "Bearer "+hJWT)
					switch {
					case want == S && failOpen:
						// "could not decide" + FailOpen: the handler runs.
						if rec.Code != OK || atomic.LoadInt32(&ran) != 1 {
							t.Fatalf("FailOpen on a could-not-decide row: code=%d ran=%d, want 200 + handler", rec.Code, ran)
						}
						if (k == gkAuthenticate || k == gkRequireIdentity) && sawIdentity != nil {
							t.Fatalf("FailOpen attached an identity %+v for an undecided credential", sawIdentity)
						}
					default:
						if rec.Code != want {
							t.Fatalf("code = %d (%q), want %d", rec.Code, strings.TrimSpace(rec.Body.String()), want)
						}
						wantRan := int32(0)
						if want == OK {
							wantRan = 1
						}
						if got := atomic.LoadInt32(&ran); got != wantRan {
							t.Fatalf("handler ran %d times, want %d (failOpen=%v) — a rejected credential must never reach the handler", got, wantRan, failOpen)
						}
						if want == OK && (k == gkAuthenticate || k == gkRequireIdentity) && (sawIdentity == nil || sawIdentity.UserID != "u1") {
							t.Fatalf("identity = %+v, want u1", sawIdentity)
						}
					}
					// A could-not-decide answer is never cached: the next request asks again.
					if want == S {
						before := a.n()
						_ = serve(h, "Bearer "+hJWT)
						if a.n() != before+1 {
							t.Fatalf("validate calls %d → %d on a repeat — an undecided answer was cached", before, a.n())
						}
					}
				})
			}
		}
	}
}

// fnValidator / fnAuthorizer let a test hand the gate an arbitrary answer,
// including error shapes the real client never produces today (wrapped errors,
// (true, err), (nil, nil)).
type fnValidator func(context.Context, string) (*auth.Actor, error)

func (f fnValidator) ValidateToken(ctx context.Context, tok string) (*auth.Actor, error) {
	return f(ctx, tok)
}

type fnAuthorizer func(context.Context, string, string, auth.Resource) (bool, error)

func (f fnAuthorizer) Authorize(ctx context.Context, tok, action string, res auth.Resource) (bool, error) {
	return f(ctx, tok, action, res)
}

func TestHardening_ErrorShapesFromCustomInterfaces(t *testing.T) {
	api := func(code int) error { return &auth.APIError{StatusCode: code, Endpoint: "/auth/validate-token"} }
	vcases := []struct {
		name  string
		actor *auth.Actor
		err   error
		want  int // RequireIdentity, failOpen=false
	}{
		{"nil,nil", nil, nil, 401},
		{"invalid actor", &auth.Actor{Valid: false, UserID: "u1"}, nil, 401},
		{"wrapped 401", nil, fmt.Errorf("layer: %w", api(401)), 401},
		{"double-wrapped 403", nil, fmt.Errorf("a: %w", fmt.Errorf("b: %w", api(403))), 401},
		{"joined 401", nil, errors.Join(errors.New("x"), api(401)), 401},
		{"valid actor + 401 error", &auth.Actor{Valid: true, UserID: "u1"}, api(401), 401},
		{"valid actor + 503 error", &auth.Actor{Valid: true, UserID: "u1"}, api(503), 503},
		{"deadline", nil, context.DeadlineExceeded, 503},
		{"canceled", nil, context.Canceled, 503},
		{"plain error", nil, errors.New("dial tcp: refused"), 503},
		{"404 APIError", nil, api(404), 503},
		{"zero-status APIError", nil, &auth.APIError{}, 503},
	}
	for _, tc := range vcases {
		for _, failOpen := range []bool{false, true} {
			t.Run(fmt.Sprintf("validator/%s/failOpen=%v", tc.name, failOpen), func(t *testing.T) {
				v := fnValidator(func(context.Context, string) (*auth.Actor, error) { return tc.actor, tc.err })
				g := &authmw.Gate{V: v, FailOpen: failOpen}
				var ran bool
				var id *auth.Actor
				rec := serve(g.RequireIdentity(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					ran, id = true, authmw.Identity(r.Context())
				})), "Bearer x")
				if failOpen && tc.want == 503 {
					if !ran || id != nil {
						t.Fatalf("FailOpen + undecided: ran=%v identity=%+v, want handler with NO identity", ran, id)
					}
					return
				}
				if rec.Code != tc.want || ran {
					t.Fatalf("code=%d ran=%v, want %d and the handler NOT run", rec.Code, ran, tc.want)
				}
			})
		}
	}

	acases := []struct {
		name    string
		allowed bool
		err     error
		want    int
	}{
		{"allowed", true, nil, 200},
		{"denied", false, nil, 403},
		{"(true, 503) is NOT an allow", true, api(503), 503},
		{"(true, 401)", true, api(401), 401},
		{"(true, 403)", true, api(403), 403},
		{"wrapped 401", false, fmt.Errorf("w: %w", api(401)), 401},
		{"wrapped 403", false, fmt.Errorf("w: %w", api(403)), 403},
		{"429", false, api(429), 503},
		{"deadline", false, context.DeadlineExceeded, 503},
		{"404", false, api(404), 503},
	}
	for _, tc := range acases {
		for _, failOpen := range []bool{false, true} {
			t.Run(fmt.Sprintf("authorizer/%s/failOpen=%v", tc.name, failOpen), func(t *testing.T) {
				a := fnAuthorizer(func(context.Context, string, string, auth.Resource) (bool, error) { return tc.allowed, tc.err })
				g := &authmw.Gate{A: a, FailOpen: failOpen}
				ran := false
				rec := serve(g.Require("x.write", "x", func(w http.ResponseWriter, _ *http.Request) { ran = true }), "Bearer x")
				if failOpen && tc.want == 503 {
					if !ran {
						t.Fatal("FailOpen + undecided: handler did not run")
					}
					return
				}
				if tc.want == 200 {
					if !ran {
						t.Fatalf("allowed: handler did not run (code %d)", rec.Code)
					}
					return
				}
				if rec.Code != tc.want || ran {
					t.Fatalf("code=%d ran=%v, want %d and NOT run", rec.Code, ran, tc.want)
				}
			})
		}
	}
}

// ---- Bearer / credential parsing ----

func TestHardening_BearerParsingAdversarial(t *testing.T) {
	long := strings.Repeat("A", 64<<10)
	for _, tc := range []struct{ in, want string }{
		{"Bearer", "Bearer"},       // no space, no token: returned whole (documented)
		{"Bearer ", ""},            // scheme with an empty token
		{"Bearer      ", ""},       // only whitespace after the scheme
		{"Bearer\tx", "Bearer\tx"}, // TAB is not the scheme separator here
		{"Bearer  x", "x"},         // multiple spaces collapse via TrimSpace
		{"Bearer x y", "x y"},      // inner space preserved (service decides)
		{"Bearer tökén", "tökén"},  // non-ASCII token preserved byte for byte
		{"Bëarer x", "Bëarer x"},   // non-ASCII scheme is not "Bearer"
		{"BeArEr x", "x"},          // case-insensitive
		{"Bearer " + long, long},   // very long token not truncated
		{"   ", ""},                // whitespace-only header
		{"Basic Zm9vOmJhcg==", "Basic Zm9vOmJhcg=="},
		{"Bearer x", "Bearer x"}, // NBSP is not a space
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header["Authorization"] = []string{tc.in} // set raw: Header.Set would not trim either, but be explicit
		got := authmw.Bearer(req)
		if got != tc.want {
			show := tc.in
			if len(show) > 40 {
				show = show[:40] + "…"
			}
			t.Errorf("Bearer(%q) = %q (len %d), want len %d", show, got[:min(len(got), 40)], len(got), len(tc.want))
		}
	}
}

func TestHardening_EmptyBearerNeverValidatesAnEmptyCredential(t *testing.T) {
	var calls []string
	var mu sync.Mutex
	v := fnValidator(func(_ context.Context, tok string) (*auth.Actor, error) {
		mu.Lock()
		calls = append(calls, tok)
		mu.Unlock()
		return &auth.Actor{Valid: true, UserID: "from-" + tok}, nil
	})
	g := &authmw.Gate{V: v}

	// "Bearer " alone → no credential → 401 "auth required", the validator is never called.
	rec := serve(g.RequireIdentity(http.HandlerFunc(ok)), "Bearer ")
	if rec.Code != 401 || len(calls) != 0 {
		t.Fatalf("empty bearer: code=%d calls=%q, want 401 and no validation", rec.Code, calls)
	}
	if !strings.Contains(rec.Body.String(), "auth required") {
		t.Fatalf("body %q, want the static 'auth required'", rec.Body.String())
	}

	// "Bearer " + X-API-Key → the key is the credential (Authorization yielded nothing).
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer ")
	req.Header.Set("X-API-Key", "  ab0t_sk_k1  ")
	w := httptest.NewRecorder()
	var id *auth.Actor
	g.RequireIdentity(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { id = authmw.Identity(r.Context()) })).ServeHTTP(w, req)
	if id == nil || id.UserID != "from-ab0t_sk_k1" {
		t.Fatalf("identity=%+v calls=%q, want the trimmed X-API-Key validated", id, calls)
	}

	// A very long token reaches the validator intact.
	long := "ab0t_sk_" + strings.Repeat("z", 32<<10)
	calls = nil
	_ = serve(g.Authenticate(http.HandlerFunc(ok)), "Bearer "+long)
	if len(calls) != 1 || calls[0] != long {
		t.Fatalf("long token: validator saw %d calls, len=%d, want 1 call with the token intact", len(calls), len(calls[0]))
	}
}

// ---- JWT-only audience through a real gate ----

func TestHardening_GateJWTAudienceNeverSentForAPIKeys(t *testing.T) {
	p := newPermsAuth(t)
	c := auth.New(p.srv.URL, auth.WithMaxRetries(0), auth.WithValidationCache(0), auth.WithExpectedJWTAudience("svc-jwt"))
	for _, include := range []bool{false, true} {
		g := &authmw.Gate{V: c, A: c, IncludePermissions: include}
		p.mu.Lock()
		p.reqs = nil
		p.mu.Unlock()
		if rec := serve(g.RequireIdentity(http.HandlerFunc(ok)), "Bearer "+userJWT); rec.Code != 200 {
			t.Fatalf("JWT: %d", rec.Code)
		}
		if rec := serve(g.RequireIdentity(http.HandlerFunc(ok)), "Bearer ab0t_sk_svc_key"); rec.Code != 200 {
			t.Fatalf("API key: %d", rec.Code)
		}
		p.mu.Lock()
		reqs := append([]map[string]any(nil), p.reqs...)
		p.mu.Unlock()
		if len(reqs) != 2 {
			t.Fatalf("include=%v: %d auth requests, want 2", include, len(reqs))
		}
		for _, r := range reqs {
			body, _ := r["body"].(map[string]any)
			aud, has := body["expected_audience"]
			switch r["path"] {
			case "/auth/validate-token":
				if aud != "svc-jwt" {
					t.Errorf("include=%v: JWT validation carried expected_audience=%v, want svc-jwt", include, aud)
				}
			case "/auth/validate-api-key":
				if has {
					t.Errorf("include=%v: API-key validation carried expected_audience=%v — the JWT-only audience leaked onto a service key", include, aud)
				}
			default:
				t.Errorf("unexpected path %v", r["path"])
			}
		}
	}
}
