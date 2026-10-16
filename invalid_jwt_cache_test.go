package authclient

// invalid_jwt_cache_test.go — a DEFINITE 401 from POST /auth/validate-token is a
// "not valid" answer, not an outage: it is cached for the negative TTL like a
// {valid:false}, and handed back as the same error. Every other error stays
// uncached. Asserted on the number of requests the auth double received.

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// statusAuth answers every request with status and the auth service's error
// body, counting requests per path.
type statusAuth struct {
	status int32
	token  int32 // validate-token calls
	key    int32 // validate-api-key calls
}

func (s *statusAuth) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case pToken:
			atomic.AddInt32(&s.token, 1)
		case pKey:
			atomic.AddInt32(&s.key, 1)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		writeJSON(w, int(atomic.LoadInt32(&s.status)), map[string]any{"detail": "Invalid token"})
	}
}

func (s *statusAuth) n() int { return int(atomic.LoadInt32(&s.token)) }

func TestValidateToken_Definite401IsCachedForTheNegativeTTL(t *testing.T) {
	s := &statusAuth{status: http.StatusUnauthorized}
	c, _ := newTestClient(t, s.handler(t), WithMaxRetries(0)) // default cache
	clock := newTestClock(c)
	ctx := context.Background()

	ask := func(what string) *APIError {
		t.Helper()
		a, err := c.ValidateToken(ctx, testJWT)
		if a != nil || !IsUnauthorized(err) {
			t.Fatalf("%s: actor=%+v err=%v — want (nil, a 401 *APIError), exactly as an uncached call returns", what, a, err)
		}
		ae, _ := AsAPIError(err)
		if ae.Endpoint != pToken || ae.Message != "Invalid token" {
			t.Fatalf("%s: error = %+v — the cached error must be the service's own answer", what, ae)
		}
		return ae
	}

	first := ask("first call")
	for i := 0; i < 9; i++ {
		ask(fmt.Sprintf("repeat %d", i))
	}
	if s.n() != 1 {
		t.Fatalf("validate-token calls = %d for 10 identical bad tokens, want 1 — a definite 401 is a cacheable \"not valid\"", s.n())
	}
	// The cache hands out copies: a caller mutating its error cannot alter the entry.
	first.StatusCode = http.StatusInternalServerError
	ask("after a caller mutated its copy")

	clock.advance(DefaultTokenValidationNegativeTTL - time.Second)
	ask("inside the negative TTL")
	if s.n() != 1 {
		t.Fatalf("calls = %d inside the %s negative TTL, want 1", s.n(), DefaultTokenValidationNegativeTTL)
	}
	clock.advance(2 * time.Second)
	ask("after the negative TTL")
	if s.n() != 2 {
		t.Fatalf("calls = %d after the negative TTL, want 2 — the negative TTL bounds it", s.n())
	}

	// WithFreshValidation still always asks.
	if _, err := c.ValidateToken(WithFreshValidation(ctx), testJWT); !IsUnauthorized(err) {
		t.Fatalf("fresh: %v", err)
	}
	if s.n() != 3 {
		t.Fatalf("calls = %d, want 3 — WithFreshValidation bypasses the cache", s.n())
	}

	// A permission decision on the same bad token: one call, then cached too.
	for i := 0; i < 3; i++ {
		if ok, err := c.Authorize(ctx, testJWT, "users.read", Resource{}); ok || !IsUnauthorized(err) {
			t.Fatalf("Authorize #%d: ok=%v err=%v, want false + the 401", i, ok, err)
		}
	}
	if s.n() != 4 {
		t.Fatalf("calls = %d, want 4 — Authorize on a bad token is cached as a negative decision", s.n())
	}
}

func TestValidateToken_OnlyADefinite401IsCached(t *testing.T) {
	for _, status := range []int{400, 403, 404, 422, 429, 500, 502, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := &statusAuth{status: int32(status)}
			c, _ := newTestClient(t, s.handler(t), WithMaxRetries(0))
			for i := 0; i < 3; i++ {
				if a, err := c.ValidateToken(context.Background(), testJWT); a != nil || StatusCode(err) != status {
					t.Fatalf("call %d: actor=%+v err=%v, want the %d error", i, a, err, status)
				}
			}
			if s.n() != 3 {
				t.Fatalf("validate-token calls = %d, want 3 — a %d is not a definite \"not valid\" and is never cached", s.n(), status)
			}
		})
	}
}

func TestValidateToken_401NegativeFollowsTheCacheConfiguration(t *testing.T) {
	cases := []struct {
		name  string
		opt   Option
		calls int
	}{
		{"cache off", WithValidationCache(0), 3},
		{"explicit, negatives opted out", WithValidationCacheOptions(ValidationCacheOptions{TTL: time.Minute, NegativeTTL: -1}), 3},
		{"explicit, default negative TTL", WithValidationCache(time.Minute), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &statusAuth{status: http.StatusUnauthorized}
			c, _ := newTestClient(t, s.handler(t), WithMaxRetries(0), tc.opt)
			for i := 0; i < 3; i++ {
				if _, err := c.ValidateToken(context.Background(), testJWT); !IsUnauthorized(err) {
					t.Fatalf("call %d: %v", i, err)
				}
			}
			if s.n() != tc.calls {
				t.Fatalf("calls = %d, want %d", s.n(), tc.calls)
			}
		})
	}
}

// validate-api-key answers an invalid key 200 {valid:false}; a 401 there is not
// the documented "not valid" shape, so it is NOT cached.
func TestValidateAPIKey_401IsNotCached(t *testing.T) {
	s := &statusAuth{status: http.StatusUnauthorized}
	c, _ := newTestClient(t, s.handler(t), WithMaxRetries(0))
	for i := 0; i < 3; i++ {
		if _, err := c.ValidateAPIKey(context.Background(), ValidateAPIKeyRequest{APIKey: tKey}); !IsUnauthorized(err) {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if n := atomic.LoadInt32(&s.key); n != 3 {
		t.Fatalf("validate-api-key calls = %d, want 3", n)
	}
}

// A definite 401 replaces a live positive entry when it arrives on a fresh call
// (the fresh answer refreshes the shared entry, as for any answer).
func TestValidateToken_Fresh401ReplacesACachedValid(t *testing.T) {
	s := &scriptedAuth{valid: true, allowed: true, calls: map[string]int{}}
	c, _ := defaultClient(t, s)
	ctx := context.Background()
	if a, err := c.ValidateToken(ctx, testJWT); err != nil || !a.Valid {
		t.Fatalf("warm: %+v %v", a, err)
	}
	s.set(func(s *scriptedAuth) { s.status = http.StatusUnauthorized })
	if _, err := c.ValidateToken(WithFreshValidation(ctx), testJWT); !IsUnauthorized(err) {
		t.Fatalf("fresh: %v", err)
	}
	if a, err := c.ValidateToken(ctx, testJWT); a != nil || !IsUnauthorized(err) {
		t.Fatalf("after the fresh 401: actor=%+v err=%v — the cached valid must have been replaced", a, err)
	}
	expectCalls(t, s, pToken, 2, "the plain call after the fresh 401 is served from the cache")
}
