package authmw_test

// invalid_credential_test.go — an invalid credential is a 401, an outage is a
// 503, and the two are told apart by CAUSE. These tests drive the REAL client
// against an httptest auth double, and use only the Gate API that existed before
// v0.12.1, so the same file runs (and goes red) against the older middleware.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	auth "github.com/ab0t-com/auth-sdk-go"
	"github.com/ab0t-com/auth-sdk-go/authmw"
	"github.com/ab0t-com/auth-sdk-go/authmw/authmwtest"
)

const badJWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJub2JvZHkifQ.c2ln"

// statusAuth answers validate-token with a fixed status and the auth service's
// error body, counting calls.
type statusAuth struct {
	srv    *httptest.Server
	status int32
	calls  int32
}

func newStatusAuth(t *testing.T, status int) *statusAuth {
	t.Helper()
	s := &statusAuth{status: int32(status)}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&s.calls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(int(atomic.LoadInt32(&s.status)))
		_, _ = w.Write([]byte(`{"detail":"Invalid token"}`))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *statusAuth) n() int { return int(atomic.LoadInt32(&s.calls)) }

// client is a REAL client with the default validation cache, as a service builds it.
func (s *statusAuth) client() *auth.Client { return auth.New(s.srv.URL, auth.WithMaxRetries(0)) }

func serve(h http.Handler, authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuthenticate_InvalidJWTAnswered401IsUnauthorizedNot503(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := newStatusAuth(t, status)
			c := s.client()
			gate := &authmw.Gate{V: c, A: c}
			var denied []int
			gate.OnDeny = func(_ *http.Request, _ string, st int, _ error) { denied = append(denied, st) }
			rec := serve(gate.Authenticate(http.HandlerFunc(ok)), "Bearer "+badJWT)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("auth answered %d for the token: authmw said %d %q, want 401 — an invalid credential is not an outage",
					status, rec.Code, rec.Body.String())
			}
			if len(denied) != 1 || denied[0] != http.StatusUnauthorized {
				t.Errorf("OnDeny saw %v, want [401]", denied)
			}
		})
	}
}

func TestRequire_InvalidJWTAnswered401IsUnauthorized_ForbiddenStays403(t *testing.T) {
	for _, tc := range []struct{ auth, want int }{
		{http.StatusUnauthorized, http.StatusUnauthorized},
		{http.StatusForbidden, http.StatusForbidden},
	} {
		t.Run(fmt.Sprint(tc.auth), func(t *testing.T) {
			s := newStatusAuth(t, tc.auth)
			c := s.client()
			gate := &authmw.Gate{V: c, A: c}
			for _, res := range []string{"", "doc"} { // unscoped and resource-scoped Authorize
				rec := serve(gate.Require("doc.read", res, ok), "Bearer "+badJWT)
				if rec.Code != tc.want {
					t.Errorf("resource %q: auth answered %d, authmw said %d, want %d", res, tc.auth, rec.Code, tc.want)
				}
			}
		})
	}
}

// FailOpen covers "could not decide", never "the service said no".
func TestFailOpen_NeverAdmitsAnInvalidJWT(t *testing.T) {
	s := newStatusAuth(t, http.StatusUnauthorized)
	c := s.client()
	gate := &authmw.Gate{V: c, A: c, FailOpen: true}
	if rec := serve(gate.Require("doc.write", "", ok), "Bearer "+badJWT); rec.Code != http.StatusUnauthorized {
		t.Errorf("Require + FailOpen, auth answered 401: %d, want 401 — the handler must not run for an invalid credential", rec.Code)
	}
	ran := false
	h := gate.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { ran = true }))
	if rec := serve(h, "Bearer "+badJWT); rec.Code != http.StatusUnauthorized || ran {
		t.Errorf("Authenticate + FailOpen, auth answered 401: %d (handler ran=%v), want 401", rec.Code, ran)
	}
}

func TestAuthenticate_AuthOutageIsStill503AndNeverCached(t *testing.T) {
	for _, status := range []int{429, 500, 502, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := newStatusAuth(t, status)
			c := s.client()
			gate := &authmw.Gate{V: c, A: c}
			for i := 0; i < 3; i++ {
				if rec := serve(gate.Authenticate(http.HandlerFunc(ok)), "Bearer "+badJWT); rec.Code != http.StatusServiceUnavailable {
					t.Fatalf("request %d: auth answered %d, authmw said %d, want 503", i, status, rec.Code)
				}
				if rec := serve(gate.Require("doc.read", "", ok), "Bearer "+badJWT); rec.Code != http.StatusServiceUnavailable {
					t.Fatalf("Require request %d: auth answered %d, authmw said %d, want 503", i, status, rec.Code)
				}
			}
			if s.n() != 6 {
				t.Errorf("auth calls = %d for 6 requests during an outage, want 6 — a failure must never be cached", s.n())
			}
		})
	}
	t.Run("unreachable", func(t *testing.T) {
		s := newStatusAuth(t, 200)
		c := s.client()
		s.srv.Close()
		gate := &authmw.Gate{V: c, A: c}
		if rec := serve(gate.Authenticate(http.HandlerFunc(ok)), "Bearer "+badJWT); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("auth unreachable: authmw said %d, want 503", rec.Code)
		}
	})
}

func TestAuthenticate_BadJWTStormCostsOneAuthCall(t *testing.T) {
	s := newStatusAuth(t, http.StatusUnauthorized)
	c := s.client()
	gate := &authmw.Gate{V: c, A: c}
	h := gate.Authenticate(http.HandlerFunc(ok))

	const n = 20
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); codes[i] = serve(h, "Bearer "+badJWT).Code }(i)
	}
	wg.Wait()
	for i, code := range codes {
		if code != http.StatusUnauthorized {
			t.Fatalf("request %d: %d, want 401", i, code)
		}
	}
	if s.n() != 1 {
		t.Fatalf("auth calls = %d for %d identical bad JWTs, want 1 — a definite 401 is cached for the negative TTL", s.n(), n)
	}
}

// The SDK's own gate passes the reusable conformance suite it ships.
func TestConformance_AuthenticateThenRequire(t *testing.T) {
	authmwtest.Run(t, authmwtest.Contract{
		Wrap: func(c *auth.Client, inner http.Handler) http.Handler {
			gate := &authmw.Gate{V: c, A: c}
			return gate.Authenticate(gate.Require("doc.read", "doc", inner.ServeHTTP))
		},
	})
}

// The conformance suite must be able to FAIL: run it against a gate with the
// pre-v0.12.1 defect (every validation error answered 503) and require it to
// report that.
func TestConformance_CatchesAGateThatAnswers503ForAnInvalidJWT(t *testing.T) {
	rec := &recordingTB{TB: t}
	authmwtest.Run(rec, authmwtest.Contract{
		Wrap: func(c *auth.Client, inner http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tok := authmw.Credential(r)
				if tok == "" {
					http.Error(w, "auth required", http.StatusUnauthorized)
					return
				}
				a, err := c.ValidateToken(r.Context(), tok)
				switch {
				case err != nil:
					http.Error(w, "auth unavailable", http.StatusServiceUnavailable) // the defect
				case !a.Valid:
					http.Error(w, "invalid token", http.StatusUnauthorized)
				default:
					inner.ServeHTTP(w, r)
				}
			})
		},
	})
	if !rec.has("[invalid JWT (auth answers 401)]: status 503, want 401") {
		t.Fatalf("the conformance suite did not report the 503-for-an-invalid-JWT defect; it reported:\n%v", rec.errs)
	}
}

// recordingTB captures Errorf instead of failing, so a test can assert what the
// conformance suite reports.
type recordingTB struct {
	testing.TB
	mu   sync.Mutex
	errs []string
}

func (r *recordingTB) Helper() {}

func (r *recordingTB) Errorf(format string, args ...any) {
	r.mu.Lock()
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
	r.mu.Unlock()
}

func (r *recordingTB) has(sub string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.errs {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}
