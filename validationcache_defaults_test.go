package authclient

// validationcache_defaults_test.go — the v0.12.0 owner-approved defaults, one test
// per rule. Every assertion is on the number of requests the auth service actually
// received (per endpoint), with a controllable clock instead of sleeps.
//
//	rule                                             test
//	default-on, per-question positive TTLs           TestDefaultTTL_*
//	per-question negative TTLs                       TestDefaultNegativeTTL_*
//	positive capped at the JWT's own exp             TestDefaultTokenPositiveCappedAtJWTExp
//	errors / 429 / 5xx never cached                  TestDefaultNeverCachesErrors
//	fail closed after a failed refresh               TestDefaultFailsClosedAfterExpiry
//	opt-out                                          TestOptOutZeroTTL
//	explicit configuration overrides the defaults    TestExplicitConfigOverridesDefaults
//	per-call bypass                                  TestFreshValidation*
//	resource-scoped Authorize PDP decision cached    TestDefaultAuthorizeResource*

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"
)

// scriptedAuth serves validate-token, validate-api-key and permissions/check with
// a per-endpoint answer, counting requests per endpoint.
type scriptedAuth struct {
	mu      sync.Mutex
	valid   bool // validate-token / validate-api-key "valid"
	allowed bool // permissions/check "allowed"
	status  int  // non-zero: every request fails with this status
	calls   map[string]int
}

func newScriptedAuth() *scriptedAuth {
	return &scriptedAuth{valid: true, allowed: true, calls: map[string]int{}}
}

func (s *scriptedAuth) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.calls[r.URL.Path]++
		valid, allowed, status := s.valid, s.allowed, s.status
		s.mu.Unlock()
		if status != 0 {
			writeJSON(w, status, map[string]any{"detail": "scripted failure"})
			return
		}
		switch r.URL.Path {
		case "/auth/validate-token", "/auth/validate-api-key":
			writeJSON(w, 200, map[string]any{"valid": valid, "user_id": "u1", "org_id": "o1"})
		case "/permissions/check":
			writeJSON(w, 200, map[string]any{"allowed": allowed})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}
}

func (s *scriptedAuth) set(f func(*scriptedAuth)) { s.mu.Lock(); f(s); s.mu.Unlock() }

func (s *scriptedAuth) n(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[path]
}

const (
	pToken = "/auth/validate-token"
	pKey   = "/auth/validate-api-key"
	pCheck = "/permissions/check"
	tKey   = "ab0t_sk_live_defaults_test"
)

// jwtWithExp builds a JWT-SHAPED (unsigned) token whose payload carries exp. The
// cache only reads exp to cap an entry; signature is irrelevant to the server
// double, which answers whatever it is scripted to.
func jwtWithExp(exp time.Time) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k"}`))
	p, _ := json.Marshal(map[string]any{"sub": "u1", "exp": exp.Unix()})
	return h + "." + base64.RawURLEncoding.EncodeToString(p) + ".sig"
}

// defaultClient is a client with NO cache option (the v0.12.0 default) and a
// controllable clock.
func defaultClient(t *testing.T, s *scriptedAuth, opts ...Option) (*Client, *testClock) {
	t.Helper()
	c, _ := newTestClient(t, s.handler(t), append([]Option{WithMaxRetries(0)}, opts...)...)
	if c.vcache == nil {
		t.Fatal("no validation cache on a client with no cache option — the default must be ON")
	}
	return c, newTestClock(c)
}

// expectCalls asserts the per-endpoint call count.
func expectCalls(t *testing.T, s *scriptedAuth, path string, want int, why string) {
	t.Helper()
	if got := s.n(path); got != want {
		t.Fatalf("%s calls = %d, want %d — %s", path, got, want, why)
	}
}

// ttlBoundary drives one question at t0, t0+pos-1s (must be cached) and
// t0+pos+1s (must refetch).
func ttlBoundary(t *testing.T, s *scriptedAuth, clock *testClock, path string, ttl time.Duration, ask func() error) {
	t.Helper()
	if err := ask(); err != nil {
		t.Fatalf("warm: %v", err)
	}
	expectCalls(t, s, path, 1, "the first question must reach the service")
	clock.advance(ttl - time.Second)
	if err := ask(); err != nil {
		t.Fatalf("inside ttl: %v", err)
	}
	expectCalls(t, s, path, 1, fmt.Sprintf("served from cache inside the %s TTL", ttl))
	clock.advance(2 * time.Second)
	if err := ask(); err != nil {
		t.Fatalf("after ttl: %v", err)
	}
	expectCalls(t, s, path, 2, fmt.Sprintf("the %s TTL is the revocation bound and must be honoured", ttl))
}

// ---- positive TTLs, per question ----

func TestDefaultTTL_ValidateAPIKey60s(t *testing.T) {
	s := newScriptedAuth()
	c, clock := defaultClient(t, s)
	ttlBoundary(t, s, clock, pKey, DefaultAPIKeyValidationTTL, func() error {
		v, err := c.ValidateAPIKey(context.Background(), ValidateAPIKeyRequest{APIKey: tKey})
		if err == nil && !v.Valid {
			err = fmt.Errorf("want valid")
		}
		return err
	})
	if DefaultAPIKeyValidationTTL != 60*time.Second || DefaultAPIKeyValidationNegativeTTL != 10*time.Second {
		t.Fatalf("API-key defaults = %s/%s, owner-approved 60s/10s", DefaultAPIKeyValidationTTL, DefaultAPIKeyValidationNegativeTTL)
	}
}

func TestDefaultTTL_ValidateTokenWithAPIKeyIs60s(t *testing.T) {
	// ValidateToken with an ab0t_sk_ key is an API-key identity question.
	s := newScriptedAuth()
	c, clock := defaultClient(t, s)
	ttlBoundary(t, s, clock, pKey, DefaultAPIKeyValidationTTL, func() error {
		_, err := c.ValidateToken(context.Background(), tKey)
		return err
	})
}

func TestDefaultTTL_ValidateToken15s(t *testing.T) {
	s := newScriptedAuth()
	c, clock := defaultClient(t, s)
	ttlBoundary(t, s, clock, pToken, DefaultTokenValidationTTL, func() error {
		_, err := c.ValidateToken(context.Background(), testJWT)
		return err
	})
	if DefaultTokenValidationTTL != 15*time.Second || DefaultTokenValidationNegativeTTL != 5*time.Second {
		t.Fatalf("token defaults = %s/%s, owner-approved 15s/5s", DefaultTokenValidationTTL, DefaultTokenValidationNegativeTTL)
	}
}

func TestDefaultTTL_AuthorizeUnscopedJWT15s(t *testing.T) {
	s := newScriptedAuth()
	c, clock := defaultClient(t, s)
	ttlBoundary(t, s, clock, pToken, DefaultAuthorizeTTL, func() error {
		ok, err := c.Authorize(context.Background(), testJWT, "users.read", Resource{})
		if err == nil && !ok {
			err = fmt.Errorf("want allowed")
		}
		return err
	})
	if DefaultAuthorizeTTL != 15*time.Second || DefaultAuthorizeNegativeTTL != 5*time.Second {
		t.Fatalf("authorize defaults = %s/%s, owner-approved 15s/5s", DefaultAuthorizeTTL, DefaultAuthorizeNegativeTTL)
	}
}

func TestDefaultTTL_AuthorizeUnscopedAPIKeyIs15sNot60s(t *testing.T) {
	// Authorize with an API key is a PERMISSION decision: 15 s, not the 60 s an
	// API key's identity gets.
	s := newScriptedAuth()
	c, clock := defaultClient(t, s)
	ttlBoundary(t, s, clock, pKey, DefaultAuthorizeTTL, func() error {
		_, err := c.Authorize(context.Background(), tKey, "users.read", Resource{})
		return err
	})
}

func TestDefaultTTL_ValidateAPIKeyWithRequiredPermissionsIs15s(t *testing.T) {
	s := newScriptedAuth()
	c, clock := defaultClient(t, s)
	ttlBoundary(t, s, clock, pKey, DefaultAuthorizeTTL, func() error {
		_, err := c.ValidateAPIKey(context.Background(), ValidateAPIKeyRequest{APIKey: tKey, RequiredPermissions: []string{"users.read"}})
		return err
	})
}

// ---- negative TTLs, per question ----

func negativeBoundary(t *testing.T, s *scriptedAuth, clock *testClock, path string, neg time.Duration, ask func() (bool, error)) {
	t.Helper()
	s.set(func(s *scriptedAuth) { s.valid, s.allowed = false, false })
	if ok, err := ask(); err != nil || ok {
		t.Fatalf("warm: ok=%v err=%v, want a denial", ok, err)
	}
	clock.advance(neg - time.Second)
	if ok, err := ask(); err != nil || ok {
		t.Fatalf("inside negative ttl: ok=%v err=%v", ok, err)
	}
	expectCalls(t, s, path, 1, fmt.Sprintf("a denial is cached for its %s negative TTL", neg))
	// The grant happens; it must be noticed once the negative TTL passes.
	s.set(func(s *scriptedAuth) { s.valid, s.allowed = true, true })
	clock.advance(2 * time.Second)
	if ok, err := ask(); err != nil || !ok {
		t.Fatalf("after negative ttl: ok=%v err=%v, want the new grant seen", ok, err)
	}
	expectCalls(t, s, path, 2, fmt.Sprintf("the %s negative TTL must expire", neg))
}

func TestDefaultNegativeTTL_ValidateAPIKey10s(t *testing.T) {
	s := newScriptedAuth()
	c, clock := defaultClient(t, s)
	negativeBoundary(t, s, clock, pKey, DefaultAPIKeyValidationNegativeTTL, func() (bool, error) {
		v, err := c.ValidateAPIKey(context.Background(), ValidateAPIKeyRequest{APIKey: tKey})
		if err != nil {
			return false, err
		}
		return v.Valid, nil
	})
}

func TestDefaultNegativeTTL_ValidateToken5s(t *testing.T) {
	s := newScriptedAuth()
	c, clock := defaultClient(t, s)
	negativeBoundary(t, s, clock, pToken, DefaultTokenValidationNegativeTTL, func() (bool, error) {
		a, err := c.ValidateToken(context.Background(), testJWT)
		if err != nil {
			return false, err
		}
		return a.Valid, nil
	})
}

func TestDefaultNegativeTTL_Authorize5s(t *testing.T) {
	s := newScriptedAuth()
	c, clock := defaultClient(t, s)
	negativeBoundary(t, s, clock, pToken, DefaultAuthorizeNegativeTTL, func() (bool, error) {
		return c.Authorize(context.Background(), testJWT, "users.read", Resource{})
	})
}

// ---- exp cap ----

func TestDefaultTokenPositiveCappedAtJWTExp(t *testing.T) {
	s := newScriptedAuth()
	c, clock := defaultClient(t, s)
	tok := jwtWithExp(clock.Now().Add(6 * time.Second)) // expires well inside the 15 s TTL

	if _, err := c.ValidateToken(context.Background(), tok); err != nil {
		t.Fatalf("warm: %v", err)
	}
	clock.advance(5 * time.Second)
	if _, err := c.ValidateToken(context.Background(), tok); err != nil {
		t.Fatalf("before exp: %v", err)
	}
	expectCalls(t, s, pToken, 1, "cached until the token's exp")
	clock.advance(2 * time.Second) // now past exp, still inside 15 s
	if _, err := c.ValidateToken(context.Background(), tok); err != nil {
		t.Fatalf("after exp: %v", err)
	}
	expectCalls(t, s, pToken, 2, "a positive entry must never outlive the token's own exp")
}

func TestDefaultTokenAlreadyExpiredJWTNotStored(t *testing.T) {
	s := newScriptedAuth()
	c, clock := defaultClient(t, s)
	tok := jwtWithExp(clock.Now().Add(-time.Minute))
	for i := 0; i < 2; i++ {
		if _, err := c.ValidateToken(context.Background(), tok); err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
	}
	expectCalls(t, s, pToken, 2, "a token past its exp must never be served from cache")
}

func TestDefaultTokenExpLaterThanTTLDoesNotExtend(t *testing.T) {
	// The unverified exp may only SHORTEN an entry, never lengthen it.
	s := newScriptedAuth()
	c, clock := defaultClient(t, s)
	tok := jwtWithExp(clock.Now().Add(time.Hour))
	if _, err := c.ValidateToken(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	clock.advance(DefaultTokenValidationTTL + time.Second)
	if _, err := c.ValidateToken(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	expectCalls(t, s, pToken, 2, "a far exp must not extend the 15 s TTL")
}

// ---- errors never cached; fail closed ----

func TestDefaultNeverCachesErrors(t *testing.T) {
	for _, status := range []int{429, 500, 502, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := newScriptedAuth()
			s.status = status
			c, _ := defaultClient(t, s)
			ctx := context.Background()
			for i := 0; i < 3; i++ {
				if _, err := c.ValidateToken(ctx, testJWT); err == nil {
					t.Fatalf("ValidateToken #%d: want an error from %d", i, status)
				}
				if _, err := c.ValidateAPIKey(ctx, ValidateAPIKeyRequest{APIKey: tKey}); err == nil {
					t.Fatalf("ValidateAPIKey #%d: want an error from %d", i, status)
				}
				if ok, err := c.Authorize(ctx, testJWT, "users.read", Resource{}); err == nil || ok {
					t.Fatalf("Authorize #%d: ok=%v err=%v, want false + error (fail closed)", i, ok, err)
				}
			}
			expectCalls(t, s, pToken, 6, "an error is never cached (3 ValidateToken + 3 Authorize)")
			expectCalls(t, s, pKey, 3, "an error is never cached")
		})
	}
}

func TestDefaultFailsClosedAfterExpiry(t *testing.T) {
	s := newScriptedAuth()
	c, clock := defaultClient(t, s)
	ctx := context.Background()
	if _, err := c.ValidateAPIKey(ctx, ValidateAPIKeyRequest{APIKey: tKey}); err != nil {
		t.Fatal(err)
	}
	if ok, err := c.Authorize(ctx, testJWT, "users.read", Resource{}); err != nil || !ok {
		t.Fatalf("warm authorize: %v %v", ok, err)
	}
	s.set(func(s *scriptedAuth) { s.status = 503 })
	clock.advance(DefaultAPIKeyValidationTTL + time.Second) // past every TTL
	if _, err := c.ValidateAPIKey(ctx, ValidateAPIKeyRequest{APIKey: tKey}); err == nil {
		t.Fatal("ValidateAPIKey: an expired decision must NOT be served through an outage")
	}
	if ok, err := c.Authorize(ctx, testJWT, "users.read", Resource{}); err == nil || ok {
		t.Fatalf("Authorize: ok=%v err=%v — must fail closed once the entry expired", ok, err)
	}
}

// ---- opt-out / explicit override ----

func TestOptOutZeroTTL(t *testing.T) {
	s := newScriptedAuth()
	c, _ := newTestClient(t, s.handler(t), WithValidationCache(0))
	if c.ValidationCacheStats().Enabled || c.vcache != nil {
		t.Fatal("WithValidationCache(0) must leave no cache allocated (the pre-v0.12.0 behaviour)")
	}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		_, _ = c.ValidateToken(ctx, testJWT)
		_, _ = c.ValidateAPIKey(ctx, ValidateAPIKeyRequest{APIKey: tKey})
		_, _ = c.Authorize(ctx, testJWT, "users.read", Resource{Type: "doc", ID: "d1"})
	}
	expectCalls(t, s, pToken, 4, "opted out: every validation (incl. Authorize subject resolution) is an HTTP call")
	expectCalls(t, s, pKey, 2, "opted out")
	expectCalls(t, s, pCheck, 2, "opted out")
}

func TestOptOutWithOptionsZeroTTL(t *testing.T) {
	s := newScriptedAuth()
	c, _ := newTestClient(t, s.handler(t), WithValidationCacheOptions(ValidationCacheOptions{TTL: 0, NegativeTTL: time.Second}))
	if c.vcache != nil {
		t.Fatal("WithValidationCacheOptions{TTL:0} must disable the cache")
	}
}

func TestOptOutOrderIndependentOfOtherOptions(t *testing.T) {
	s := newScriptedAuth()
	c, _ := newTestClient(t, s.handler(t), WithValidationCache(0), WithExpectedAudience("svc"), WithMaxRetries(1))
	if c.vcache != nil {
		t.Fatal("a later unrelated option must not resurrect the default cache")
	}
}

func TestExplicitConfigOverridesDefaults(t *testing.T) {
	s := newScriptedAuth()
	c, clock := defaultClient(t, s, WithValidationCache(2*time.Minute))
	if !c.vcache.explicit {
		t.Fatal("explicit configuration not recorded")
	}
	ctx := context.Background()
	// One TTL for every question: an API key, a JWT, a permission decision all
	// live 2 minutes — not 60 s / 15 s / 15 s.
	_, _ = c.ValidateAPIKey(ctx, ValidateAPIKeyRequest{APIKey: tKey})
	_, _ = c.ValidateToken(ctx, testJWT)
	_, _ = c.Authorize(ctx, testJWT, "users.read", Resource{})
	clock.advance(90 * time.Second)
	_, _ = c.ValidateAPIKey(ctx, ValidateAPIKeyRequest{APIKey: tKey})
	_, _ = c.ValidateToken(ctx, testJWT)
	_, _ = c.Authorize(ctx, testJWT, "users.read", Resource{})
	expectCalls(t, s, pKey, 1, "explicit 2m TTL applies to API keys")
	expectCalls(t, s, pToken, 2, "explicit 2m TTL applies to JWTs and permission decisions")
	clock.advance(31 * time.Second)
	_, _ = c.ValidateAPIKey(ctx, ValidateAPIKeyRequest{APIKey: tKey})
	expectCalls(t, s, pKey, 2, "and expires at 2m")
}

func TestExplicitConfigLaterOptionWins(t *testing.T) {
	s := newScriptedAuth()
	c, _ := newTestClient(t, s.handler(t), WithValidationCache(time.Minute), WithValidationCache(0))
	if c.vcache != nil {
		t.Fatal("the last cache option must win (0 = off)")
	}
	c2, _ := newTestClient(t, s.handler(t), WithValidationCache(0), WithValidationCache(time.Minute))
	if c2.vcache == nil || !c2.vcache.explicit {
		t.Fatal("the last cache option must win (1m = explicit on)")
	}
}

// ---- per-call bypass ----

func TestFreshValidationBypassesAndRefreshes(t *testing.T) {
	s := newScriptedAuth()
	c, _ := defaultClient(t, s)
	ctx := context.Background()

	if _, err := c.ValidateAPIKey(ctx, ValidateAPIKeyRequest{APIKey: tKey}); err != nil {
		t.Fatal(err)
	}
	// The key is revoked at the service.
	s.set(func(s *scriptedAuth) { s.valid = false })

	v, err := c.ValidateAPIKey(ctx, ValidateAPIKeyRequest{APIKey: tKey})
	if err != nil || !v.Valid {
		t.Fatalf("plain call inside the TTL: want the cached valid (documented latency), got %+v %v", v, err)
	}
	expectCalls(t, s, pKey, 1, "plain call served from cache")

	v, err = c.ValidateAPIKey(WithFreshValidation(ctx), ValidateAPIKeyRequest{APIKey: tKey})
	if err != nil || v.Valid {
		t.Fatalf("fresh call: want the service's NOT valid, got %+v %v", v, err)
	}
	expectCalls(t, s, pKey, 2, "a fresh call always reaches the service")

	// The fresh answer refreshed the shared entry: a plain call now sees it too.
	v, err = c.ValidateAPIKey(ctx, ValidateAPIKeyRequest{APIKey: tKey})
	if err != nil || v.Valid {
		t.Fatalf("plain call after fresh: want NOT valid, got %+v %v", v, err)
	}
	expectCalls(t, s, pKey, 2, "the fresh answer is stored for everyone else")
}

func TestFreshValidationOnTokenAndAuthorize(t *testing.T) {
	s := newScriptedAuth()
	c, _ := defaultClient(t, s)
	fresh := WithFreshValidation(context.Background())
	for i := 0; i < 3; i++ {
		if _, err := c.ValidateToken(fresh, testJWT); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Authorize(fresh, testJWT, "users.read", Resource{Type: "doc", ID: "d1"}); err != nil {
			t.Fatal(err)
		}
	}
	expectCalls(t, s, pToken, 6, "every fresh ValidateToken + Authorize subject resolution asks the service")
	expectCalls(t, s, pCheck, 3, "every fresh resource-scoped Authorize asks the PDP")
}

func TestFreshValidationErrorDoesNotPoisonOrServeStale(t *testing.T) {
	s := newScriptedAuth()
	c, _ := defaultClient(t, s)
	ctx := context.Background()
	if _, err := c.ValidateToken(ctx, testJWT); err != nil {
		t.Fatal(err)
	}
	s.set(func(s *scriptedAuth) { s.status = 503 })
	if _, err := c.ValidateToken(WithFreshValidation(ctx), testJWT); err == nil {
		t.Fatal("a fresh call must surface the outage, never the cached answer")
	}
}

func TestFreshValidationWithCacheDisabledIsInert(t *testing.T) {
	s := newScriptedAuth()
	c, _ := newTestClient(t, s.handler(t), WithValidationCache(0))
	if _, err := c.ValidateToken(WithFreshValidation(context.Background()), testJWT); err != nil {
		t.Fatal(err)
	}
	expectCalls(t, s, pToken, 1, "fresh with no cache is a normal call")
}

// ---- resource-scoped Authorize: the PDP decision ----

func TestDefaultAuthorizeResourceDecisionCached15s(t *testing.T) {
	s := newScriptedAuth()
	c, clock := defaultClient(t, s)
	ask := func(res Resource) (bool, error) {
		return c.Authorize(context.Background(), testJWT, "doc.read", res)
	}
	d1 := Resource{Type: "doc", ID: "d1"}
	if ok, err := ask(d1); err != nil || !ok {
		t.Fatalf("warm: %v %v", ok, err)
	}
	clock.advance(DefaultAuthorizeTTL - time.Second)
	if ok, err := ask(d1); err != nil || !ok {
		t.Fatalf("inside ttl: %v %v", ok, err)
	}
	expectCalls(t, s, pCheck, 1, "the PDP decision is cached for 15 s by default")
	// A different resource is a different question.
	if _, err := ask(Resource{Type: "doc", ID: "d2"}); err != nil {
		t.Fatal(err)
	}
	expectCalls(t, s, pCheck, 2, "another resource must not reuse the decision")
	// The grant is revoked; after 15 s the cache must re-ask and deny.
	s.set(func(s *scriptedAuth) { s.allowed = false })
	clock.advance(2 * time.Second)
	if ok, err := ask(d1); err != nil || ok {
		t.Fatalf("after ttl: ok=%v err=%v, want the revocation seen", ok, err)
	}
	// Denial cached 5 s.
	clock.advance(DefaultAuthorizeNegativeTTL - time.Second)
	_, _ = ask(d1)
	n := s.n(pCheck)
	clock.advance(2 * time.Second)
	_, _ = ask(d1)
	if s.n(pCheck) != n+1 {
		t.Fatalf("denial must expire after its 5 s negative TTL")
	}
}

func TestExplicitConfigDoesNotCacheResourcePDP(t *testing.T) {
	// Pre-v0.12.0 scope, kept for consumers that configured the cache themselves.
	s := newScriptedAuth()
	c, _ := newTestClient(t, s.handler(t), WithValidationCache(time.Minute))
	for i := 0; i < 3; i++ {
		if _, err := c.Authorize(context.Background(), testJWT, "doc.read", Resource{Type: "doc", ID: "d1"}); err != nil {
			t.Fatal(err)
		}
	}
	expectCalls(t, s, pToken, 1, "subject resolution is cached under an explicit config")
	expectCalls(t, s, pCheck, 3, "the PDP call is NOT cached under an explicit config (unchanged)")
}

func TestDefaultAuthorizeResourcePDPErrorFailsClosedNotCached(t *testing.T) {
	s := newScriptedAuth()
	c, _ := defaultClient(t, s)
	ctx := context.Background()
	// Warm the subject resolution, then make only the PDP fail.
	if _, err := c.ValidateToken(ctx, testJWT); err != nil {
		t.Fatal(err)
	}
	h := s.handler(t)
	c2, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == pCheck {
			s.set(func(s *scriptedAuth) { s.calls[pCheck]++ })
			writeJSON(w, 503, map[string]any{"detail": "pdp down"})
			return
		}
		h(w, r)
	}, WithMaxRetries(0))
	for i := 0; i < 2; i++ {
		ok, err := c2.Authorize(ctx, testJWT, "doc.read", Resource{Type: "doc", ID: "d1"})
		if err == nil || ok {
			t.Fatalf("#%d: ok=%v err=%v, want false + error", i, ok, err)
		}
	}
	expectCalls(t, s, pCheck, 2, "a PDP error is never cached")
}

func TestInvalidateValidationDropsResourceDecision(t *testing.T) {
	s := newScriptedAuth()
	c, _ := defaultClient(t, s)
	ctx := context.Background()
	res := Resource{Type: "doc", ID: "d1"}
	_, _ = c.Authorize(ctx, testJWT, "doc.read", res)
	c.InvalidateValidation(testJWT)
	_, _ = c.Authorize(ctx, testJWT, "doc.read", res)
	expectCalls(t, s, pCheck, 2, "InvalidateValidation(token) must drop the resource-scoped decision too")
	expectCalls(t, s, pToken, 2, "and the subject resolution")
}

func TestDefaultCacheIsBounded(t *testing.T) {
	c := New("http://unused.invalid")
	if c.vcache.maxEntries != DefaultValidationCacheMaxEntries {
		t.Fatalf("default bound = %d, want %d", c.vcache.maxEntries, DefaultValidationCacheMaxEntries)
	}
}
