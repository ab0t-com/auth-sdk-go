package authclient

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These tests are written against the three ways a validation cache goes wrong
// (see validationcache.go): it answers for the wrong request, it fails open, or
// it outlives the credential. Each has its own test, and each asserts on the
// number of HTTP requests the auth service actually received — not on an
// internal counter — because "no round trip" is the entire claim.

const testJWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1MSJ9.sig"

// countingValidator serves /auth/validate-token and /auth/validate-api-key,
// counting requests and letting a test choose the answer.
type countingValidator struct {
	calls  int32
	mu     sync.Mutex
	actor  Actor
	apikey APIKeyValidation
	status int
}

func (s *countingValidator) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&s.calls, 1)
		s.mu.Lock()
		defer s.mu.Unlock()
		status := s.status
		if status == 0 {
			status = 200
		}
		switch r.URL.Path {
		case "/auth/validate-token":
			writeJSON(w, status, s.actor)
		case "/auth/validate-api-key":
			writeJSON(w, status, s.apikey)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}
}

func (s *countingValidator) n() int { return int(atomic.LoadInt32(&s.calls)) }

// ---- the default: no cache, no behavior change ----

func TestValidationCacheDisabledByDefault(t *testing.T) {
	srv := &countingValidator{actor: Actor{Valid: true, UserID: "u1", OrgID: "o1"}}
	c, _ := newTestClient(t, srv.handler(t))

	if stats := c.ValidationCacheStats(); stats.Enabled {
		t.Fatalf("cache enabled without WithValidationCache — upgrading the SDK must not change auth semantics")
	}
	for i := 0; i < 3; i++ {
		if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
			t.Fatalf("ValidateToken: %v", err)
		}
	}
	if srv.n() != 3 {
		t.Errorf("auth calls = %d, want 3 (no cache configured)", srv.n())
	}
}

func TestValidationCacheZeroTTLDisables(t *testing.T) {
	srv := &countingValidator{actor: Actor{Valid: true, UserID: "u1"}}
	c, _ := newTestClient(t, srv.handler(t), WithValidationCache(0))
	if c.ValidationCacheStats().Enabled {
		t.Fatalf("WithValidationCache(0) must disable the cache, not fall back to a default TTL")
	}
	for i := 0; i < 2; i++ {
		if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
			t.Fatalf("ValidateToken: %v", err)
		}
	}
	if srv.n() != 2 {
		t.Errorf("auth calls = %d, want 2", srv.n())
	}
	// Disabled must also mean the API surface is inert rather than panicking.
	c.InvalidateValidation(testJWT)
	c.ResetValidationCache()
}

// ---- the claim: a repeat validation makes no HTTP request ----

func TestValidationCacheServesRepeatFromCache(t *testing.T) {
	srv := &countingValidator{actor: Actor{Valid: true, UserID: "u1", OrgID: "o1", Permissions: []string{"audit.events.create"}}}
	c, _ := newTestClient(t, srv.handler(t), WithValidationCache(time.Minute))

	first, err := c.ValidateToken(context.Background(), testJWT)
	if err != nil {
		t.Fatalf("first ValidateToken: %v", err)
	}
	second, err := c.ValidateToken(context.Background(), testJWT)
	if err != nil {
		t.Fatalf("second ValidateToken: %v", err)
	}
	if srv.n() != 1 {
		t.Fatalf("auth calls = %d, want 1 — the second validation must not reach the network", srv.n())
	}
	if !second.Valid || second.UserID != first.UserID || second.OrgID != first.OrgID {
		t.Errorf("cached actor = %+v, want the same decision as %+v", second, first)
	}
	stats := c.ValidationCacheStats()
	if stats.Hits != 1 || stats.Misses != 1 {
		t.Errorf("stats = %+v, want 1 hit / 1 miss", stats)
	}
}

func TestValidationCacheCoversAPIKeys(t *testing.T) {
	srv := &countingValidator{apikey: APIKeyValidation{Valid: true, UserID: "svc", OrgID: "o1"}}
	c, _ := newTestClient(t, srv.handler(t), WithValidationCache(time.Minute))

	const key = "ab0t_sk_live_abc"
	for i := 0; i < 4; i++ {
		a, err := c.ValidateToken(context.Background(), key)
		if err != nil {
			t.Fatalf("ValidateToken(api key) #%d: %v", i, err)
		}
		if !a.Valid || a.OrgID != "o1" {
			t.Fatalf("actor #%d = %+v, want valid with org o1", i, a)
		}
	}
	if srv.n() != 1 {
		t.Errorf("auth calls = %d, want 1 — API keys are the primary ingest auth mode and must cache", srv.n())
	}
}

func TestValidationCacheSharedBetweenValidateAPIKeyAndValidateToken(t *testing.T) {
	srv := &countingValidator{apikey: APIKeyValidation{Valid: true, UserID: "svc", OrgID: "o1", Permissions: []string{"p"}}}
	c, _ := newTestClient(t, srv.handler(t), WithValidationCache(time.Minute))
	const key = "ab0t_sk_live_abc"

	v, err := c.ValidateAPIKey(context.Background(), ValidateAPIKeyRequest{APIKey: key})
	if err != nil {
		t.Fatalf("ValidateAPIKey: %v", err)
	}
	a, err := c.ValidateToken(context.Background(), key)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if srv.n() != 1 {
		t.Errorf("auth calls = %d, want 1 — both entry points describe the same decision", srv.n())
	}
	if v.OrgID != a.OrgID || v.UserID != a.UserID || v.Valid != a.Valid {
		t.Errorf("APIKeyValidation %+v and Actor %+v disagree; the Actor round trip is meant to be lossless", v, a)
	}
	if len(v.Permissions) != 1 || v.Permissions[0] != "p" {
		t.Errorf("Permissions = %v, want [p] through the cache", v.Permissions)
	}
}

// ---- failure mode 1: answering for the wrong request ----

func TestValidationCacheKeysOnRequestShape(t *testing.T) {
	cases := []struct {
		name string
		a, b TokenValidationRequest
	}{
		{"different token", TokenValidationRequest{Token: testJWT}, TokenValidationRequest{Token: "other.jwt.sig"}},
		{"different audience", TokenValidationRequest{Token: testJWT, ExpectedAudience: "audit"}, TokenValidationRequest{Token: testJWT, ExpectedAudience: "billing"}},
		{"different permission", TokenValidationRequest{Token: testJWT, RequiredPermissions: []string{"a"}}, TokenValidationRequest{Token: testJWT, RequiredPermissions: []string{"b"}}},
		{"permission order", TokenValidationRequest{Token: testJWT, RequiredPermissions: []string{"a", "b"}}, TokenValidationRequest{Token: testJWT, RequiredPermissions: []string{"b", "a"}}},
		{"no permission vs one", TokenValidationRequest{Token: testJWT}, TokenValidationRequest{Token: testJWT, RequiredPermissions: []string{"a"}}},
		{"different resource type", TokenValidationRequest{Token: testJWT, ResourceType: "x"}, TokenValidationRequest{Token: testJWT, ResourceType: "y"}},
		{"different resource id", TokenValidationRequest{Token: testJWT, ResourceType: "x", ResourceID: "1"}, TokenValidationRequest{Token: testJWT, ResourceType: "x", ResourceID: "2"}},
		{"include permissions flag", TokenValidationRequest{Token: testJWT}, TokenValidationRequest{Token: testJWT, IncludePermissions: true}},
		// The concatenation hazard: {"a","bc"} and {"ab","c"} join to the same
		// bytes without length prefixes. A collision here applies one request's
		// authorization decision to a different request.
		{"concatenation collision", TokenValidationRequest{Token: testJWT, RequiredPermissions: []string{"a", "bc"}}, TokenValidationRequest{Token: testJWT, RequiredPermissions: []string{"ab", "c"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &countingValidator{actor: Actor{Valid: true, UserID: "u1"}}
			c, _ := newTestClient(t, srv.handler(t), WithValidationCache(time.Minute))
			if _, err := c.ValidateTokenWith(context.Background(), tc.a); err != nil {
				t.Fatalf("a: %v", err)
			}
			if _, err := c.ValidateTokenWith(context.Background(), tc.b); err != nil {
				t.Fatalf("b: %v", err)
			}
			if srv.n() != 2 {
				t.Errorf("auth calls = %d, want 2 — these are different questions and must not share a cache entry", srv.n())
			}
		})
	}
}

func TestValidationCacheSeparatesTokenAndAPIKeyNamespaces(t *testing.T) {
	// A credential that is BOTH api-key-prefixed and JWT-shaped exercises the
	// kind prefix in the key: the two endpoints answer different questions.
	const dotty = "ab0t_sk_live_a.b.c"
	srv := &countingValidator{
		actor:  Actor{Valid: true, UserID: "as-token"},
		apikey: APIKeyValidation{Valid: true, UserID: "as-key"},
	}
	c, _ := newTestClient(t, srv.handler(t), WithValidationCache(time.Minute))

	byKey, err := c.ValidateAPIKey(context.Background(), ValidateAPIKeyRequest{APIKey: dotty})
	if err != nil {
		t.Fatalf("ValidateAPIKey: %v", err)
	}
	byToken, err := c.ValidateTokenWith(context.Background(), TokenValidationRequest{Token: dotty})
	if err != nil {
		t.Fatalf("ValidateTokenWith: %v", err)
	}
	if srv.n() != 2 {
		t.Fatalf("auth calls = %d, want 2 — the two validation endpoints must not share an entry", srv.n())
	}
	if byKey.UserID != "as-key" || byToken.UserID != "as-token" {
		t.Errorf("cross-endpoint bleed: key=%q token=%q", byKey.UserID, byToken.UserID)
	}
}

func TestValidationCacheReturnsACopy(t *testing.T) {
	srv := &countingValidator{actor: Actor{Valid: true, UserID: "u1", Permissions: []string{"a"}, Audience: []string{"audit"}}}
	c, _ := newTestClient(t, srv.handler(t), WithValidationCache(time.Minute))

	first, err := c.ValidateToken(context.Background(), testJWT)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	first.Permissions[0] = "TAMPERED"
	first.Permissions = append(first.Permissions, "extra")
	first.Audience[0] = "TAMPERED"
	first.OrgID = "other-org"

	second, err := c.ValidateToken(context.Background(), testJWT)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if len(second.Permissions) != 1 || second.Permissions[0] != "a" {
		t.Errorf("Permissions = %v — a caller mutated the cached decision for everyone else", second.Permissions)
	}
	if second.Audience[0] != "audit" {
		t.Errorf("Audience = %v — cached slice was shared, not copied", second.Audience)
	}
	if second.OrgID != "" {
		t.Errorf("OrgID = %q — cached struct was shared, not copied", second.OrgID)
	}
}

// ---- failure mode 2: failing open ----

func TestValidationCacheNeverCachesErrors(t *testing.T) {
	srv := &countingValidator{status: 500, actor: Actor{Valid: true}}
	c, _ := newTestClient(t, srv.handler(t), WithValidationCache(time.Minute), WithMaxRetries(0))

	for i := 0; i < 3; i++ {
		if _, err := c.ValidateToken(context.Background(), testJWT); err == nil {
			t.Fatalf("call %d: want an error from a 500", i)
		}
	}
	if srv.n() != 3 {
		t.Errorf("auth calls = %d, want 3 — a failed validation must never be cached in either direction", srv.n())
	}
	if e := c.ValidationCacheStats().Entries; e != 1 {
		// One empty entry is created as the single-flight slot; it must hold no
		// decision.
		t.Logf("entries = %d (single-flight slot)", e)
	}
}

func TestValidationCacheDoesNotServeStaleThroughAnOutage(t *testing.T) {
	// A good decision, then the service breaks. Once the entry expires the cache
	// must stop answering rather than extend every credential it has seen.
	srv := &countingValidator{actor: Actor{Valid: true, UserID: "u1"}}
	c, _ := newTestClient(t, srv.handler(t), WithValidationCache(time.Minute), WithMaxRetries(0))
	clock := newTestClock(c)

	if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
		t.Fatalf("warm: %v", err)
	}
	srv.mu.Lock()
	srv.status = 503
	srv.mu.Unlock()

	// Still inside the TTL: served from cache, no call.
	if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
		t.Fatalf("within ttl: %v", err)
	}
	if srv.n() != 1 {
		t.Fatalf("auth calls = %d, want 1 within the TTL", srv.n())
	}

	clock.advance(2 * time.Minute)
	if _, err := c.ValidateToken(context.Background(), testJWT); err == nil {
		t.Fatal("want an error: an expired decision must NOT be served through an auth outage")
	}
}

// ---- failure mode 3: outliving the credential ----

func TestValidationCacheExpiresOnTTL(t *testing.T) {
	srv := &countingValidator{actor: Actor{Valid: true, UserID: "u1"}}
	c, _ := newTestClient(t, srv.handler(t), WithValidationCache(30*time.Second))
	clock := newTestClock(c)

	if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
		t.Fatalf("warm: %v", err)
	}
	clock.advance(29 * time.Second)
	if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
		t.Fatalf("inside ttl: %v", err)
	}
	if srv.n() != 1 {
		t.Fatalf("auth calls = %d, want 1 at t+29s", srv.n())
	}
	clock.advance(2 * time.Second)
	if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
		t.Fatalf("after ttl: %v", err)
	}
	if srv.n() != 2 {
		t.Errorf("auth calls = %d, want 2 at t+31s — the TTL is the revocation bound and must be honored", srv.n())
	}
}

func TestValidationCacheNegativesGetTheirOwnShorterTTL(t *testing.T) {
	srv := &countingValidator{actor: Actor{Valid: false, Error: "missing permission"}}
	c, _ := newTestClient(t, srv.handler(t),
		WithValidationCacheOptions(ValidationCacheOptions{TTL: time.Minute, NegativeTTL: 5 * time.Second}))
	clock := newTestClock(c)

	if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
		t.Fatalf("warm: %v", err)
	}
	clock.advance(3 * time.Second)
	if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
		t.Fatalf("inside negative ttl: %v", err)
	}
	if srv.n() != 1 {
		t.Fatalf("auth calls = %d, want 1 inside the negative TTL", srv.n())
	}
	clock.advance(3 * time.Second)
	if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
		t.Fatalf("after negative ttl: %v", err)
	}
	if srv.n() != 2 {
		t.Errorf("auth calls = %d, want 2 — a denial that has since been fixed must not wait out the positive TTL", srv.n())
	}
}

func TestValidationCacheNegativeTTLCanBeOptedOut(t *testing.T) {
	srv := &countingValidator{actor: Actor{Valid: false}}
	c, _ := newTestClient(t, srv.handler(t),
		WithValidationCacheOptions(ValidationCacheOptions{TTL: time.Minute, NegativeTTL: -1}))
	for i := 0; i < 3; i++ {
		if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if srv.n() != 3 {
		t.Errorf("auth calls = %d, want 3 — a negative TTL of -1 opts out of caching denials", srv.n())
	}
}

func TestValidationCacheCappedByCredentialExpiry(t *testing.T) {
	base := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	// The token dies in 10s; the TTL says 10 minutes. Expiry must win.
	srv := &countingValidator{actor: Actor{Valid: true, UserID: "u1", ExpiresAt: base.Add(10 * time.Second).Format(time.RFC3339)}}
	c, _ := newTestClient(t, srv.handler(t), WithValidationCache(10*time.Minute))
	clock := newTestClockAt(c, base)

	if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
		t.Fatalf("warm: %v", err)
	}
	clock.advance(5 * time.Second)
	if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	if srv.n() != 1 {
		t.Fatalf("auth calls = %d, want 1 before the token expires", srv.n())
	}
	clock.advance(10 * time.Second)
	if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
	if srv.n() != 2 {
		t.Errorf("auth calls = %d, want 2 — the cache must never make an EXPIRED token look valid", srv.n())
	}
}

func TestValidationCacheAlreadyExpiredCredentialIsNotStored(t *testing.T) {
	base := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	srv := &countingValidator{actor: Actor{Valid: true, ExpiresAt: base.Add(-time.Hour).Format(time.RFC3339)}}
	c, _ := newTestClient(t, srv.handler(t), WithValidationCache(time.Minute))
	newTestClockAt(c, base)

	for i := 0; i < 2; i++ {
		if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if srv.n() != 2 {
		t.Errorf("auth calls = %d, want 2 — a decision that is already expired must not be stored", srv.n())
	}
}

func TestParseActorExpiry(t *testing.T) {
	want := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		in     string
		ok     bool
		expect time.Time
	}{
		{"2026-08-23T12:00:00Z", true, want},
		{"2026-08-23T12:00:00+00:00", true, want},
		{"2026-08-23T12:00:00", true, want},
		{"2026-08-23 12:00:00", true, want},
		{fmt.Sprint(want.Unix()), true, want},
		{"", false, time.Time{}},
		{"not-a-time", false, time.Time{}},
		{"0", false, time.Time{}},
	}
	for _, tc := range cases {
		got, ok := parseActorExpiry(tc.in)
		if ok != tc.ok {
			t.Errorf("parseActorExpiry(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if ok && !got.Equal(tc.expect) {
			t.Errorf("parseActorExpiry(%q) = %v, want %v", tc.in, got, tc.expect)
		}
	}
}

func TestValidationCacheUnparseableExpiryFallsBackToTTL(t *testing.T) {
	// An unrecognized expires_at must neither be read as "no expiry" nor as
	// "already expired": the TTL simply stands alone.
	srv := &countingValidator{actor: Actor{Valid: true, ExpiresAt: "whenever"}}
	c, _ := newTestClient(t, srv.handler(t), WithValidationCache(time.Minute))
	clock := newTestClock(c)

	if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
		t.Fatalf("warm: %v", err)
	}
	if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
		t.Fatalf("repeat: %v", err)
	}
	if srv.n() != 1 {
		t.Fatalf("auth calls = %d, want 1 — an unparseable expiry must not defeat the cache", srv.n())
	}
	clock.advance(2 * time.Minute)
	if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
		t.Fatalf("after ttl: %v", err)
	}
	if srv.n() != 2 {
		t.Errorf("auth calls = %d, want 2 — an unparseable expiry must not become 'no expiry'", srv.n())
	}
}

// ---- revocation, bounds, and concurrency ----

func TestInvalidateValidationDropsEveryShapeForOneCredential(t *testing.T) {
	srv := &countingValidator{actor: Actor{Valid: true, UserID: "u1"}}
	c, _ := newTestClient(t, srv.handler(t), WithValidationCache(time.Minute))
	ctx := context.Background()

	shapes := []TokenValidationRequest{
		{Token: testJWT},
		{Token: testJWT, RequiredPermissions: []string{"a"}},
		{Token: testJWT, ResourceType: "r", ResourceID: "1"},
	}
	for _, s := range shapes {
		if _, err := c.ValidateTokenWith(ctx, s); err != nil {
			t.Fatalf("warm %+v: %v", s, err)
		}
	}
	other := "other.jwt.sig"
	if _, err := c.ValidateTokenWith(ctx, TokenValidationRequest{Token: other}); err != nil {
		t.Fatalf("warm other: %v", err)
	}
	if srv.n() != 4 {
		t.Fatalf("auth calls = %d, want 4 after warming", srv.n())
	}

	c.InvalidateValidation(testJWT)

	for _, s := range shapes {
		if _, err := c.ValidateTokenWith(ctx, s); err != nil {
			t.Fatalf("post-invalidate %+v: %v", s, err)
		}
	}
	if srv.n() != 7 {
		t.Errorf("auth calls = %d, want 7 — every shape of the revoked credential must be dropped", srv.n())
	}
	// The unrelated credential must be untouched: revocation is targeted.
	if _, err := c.ValidateTokenWith(ctx, TokenValidationRequest{Token: other}); err != nil {
		t.Fatalf("other post-invalidate: %v", err)
	}
	if srv.n() != 7 {
		t.Errorf("auth calls = %d, want 7 — invalidating one credential must not evict others", srv.n())
	}
}

func TestResetValidationCacheDropsEverything(t *testing.T) {
	srv := &countingValidator{actor: Actor{Valid: true}}
	c, _ := newTestClient(t, srv.handler(t), WithValidationCache(time.Minute))
	if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
		t.Fatalf("warm: %v", err)
	}
	c.ResetValidationCache()
	if e := c.ValidationCacheStats().Entries; e != 0 {
		t.Errorf("Entries = %d after reset, want 0", e)
	}
	if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
		t.Fatalf("post-reset: %v", err)
	}
	if srv.n() != 2 {
		t.Errorf("auth calls = %d, want 2", srv.n())
	}
}

func TestValidationCacheIsBounded(t *testing.T) {
	// A cache keyed by credential is a slow leak keyed by tenant unless bounded.
	srv := &countingValidator{actor: Actor{Valid: true}}
	const max = 16
	c, _ := newTestClient(t, srv.handler(t),
		WithValidationCacheOptions(ValidationCacheOptions{TTL: time.Hour, MaxEntries: max}))

	for i := 0; i < max*8; i++ {
		tok := fmt.Sprintf("tok-%d.b.c", i)
		if _, err := c.ValidateToken(context.Background(), tok); err != nil {
			t.Fatalf("validate %d: %v", i, err)
		}
	}
	if got := c.ValidationCacheStats().Entries; got > max {
		t.Errorf("Entries = %d, want <= %d — the cache must not grow without bound", got, max)
	}
}

func TestValidationCacheSingleFlight(t *testing.T) {
	// A cold cache under load must make ONE call, not one per goroutine.
	release := make(chan struct{})
	var calls int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		<-release
		writeJSON(w, 200, Actor{Valid: true, UserID: "u1"})
	}, WithValidationCache(time.Minute))

	const n = 12
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = c.ValidateToken(context.Background(), testJWT)
		}(i)
	}
	// Let the first request reach the handler, then release it; the rest should
	// find a warm entry rather than each issuing their own POST.
	for atomic.LoadInt32(&calls) == 0 {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("auth calls = %d, want 1 — a cold-start stampede must collapse to one round trip", got)
	}
}

func TestValidationCacheConcurrentUseIsSafe(t *testing.T) {
	// Run under -race: mixed reads, writes, invalidation and reset.
	srv := &countingValidator{actor: Actor{Valid: true, UserID: "u1", Permissions: []string{"a"}}}
	c, _ := newTestClient(t, srv.handler(t),
		WithValidationCacheOptions(ValidationCacheOptions{TTL: time.Second, MaxEntries: 8}))

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				tok := fmt.Sprintf("tok-%d.b.c", (i+j)%12)
				if _, err := c.ValidateToken(context.Background(), tok); err != nil {
					t.Errorf("validate: %v", err)
					return
				}
				switch j % 10 {
				case 3:
					c.InvalidateValidation(tok)
				case 7:
					_ = c.ValidationCacheStats()
				case 9:
					c.ResetValidationCache()
				}
			}
		}(i)
	}
	wg.Wait()
}

// ---- Authorize rides the same cache ----

func TestAuthorizeUsesTheCache(t *testing.T) {
	srv := &countingValidator{
		actor:  Actor{Valid: true},
		apikey: APIKeyValidation{Valid: true},
	}
	c, _ := newTestClient(t, srv.handler(t), WithValidationCache(time.Minute))
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		ok, err := c.Authorize(ctx, testJWT, "audit.events.create", Resource{})
		if err != nil || !ok {
			t.Fatalf("Authorize jwt #%d: ok=%v err=%v", i, ok, err)
		}
	}
	if srv.n() != 1 {
		t.Errorf("auth calls = %d after 3 JWT Authorize, want 1", srv.n())
	}

	for i := 0; i < 3; i++ {
		ok, err := c.Authorize(ctx, "ab0t_sk_live_abc", "audit.events.create", Resource{})
		if err != nil || !ok {
			t.Fatalf("Authorize key #%d: ok=%v err=%v", i, ok, err)
		}
	}
	if srv.n() != 2 {
		t.Errorf("auth calls = %d after adding 3 API-key Authorize, want 2", srv.n())
	}

	// A different action is a different question.
	if _, err := c.Authorize(ctx, testJWT, "audit.events.delete", Resource{}); err != nil {
		t.Fatalf("Authorize other action: %v", err)
	}
	if srv.n() != 3 {
		t.Errorf("auth calls = %d, want 3 — a different permission must not reuse the decision", srv.n())
	}
}

// ---- the gate's proof mechanism: an Observer sees nothing on a cache hit ----

func TestCacheHitEmitsNoRequestInfo(t *testing.T) {
	// This is exactly how the Phase 0.1 gate proves "no HTTP request": the SDK's
	// Observer fires once per completed HTTP attempt, so a cached validation
	// produces no event at all.
	srv := &countingValidator{actor: Actor{Valid: true, UserID: "u1"}}
	var events int32
	c, _ := newTestClient(t, srv.handler(t),
		WithValidationCache(time.Minute),
		WithObserver(func(RequestInfo) { atomic.AddInt32(&events, 1) }))

	if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
		t.Fatalf("first: %v", err)
	}
	after := atomic.LoadInt32(&events)
	if after != 1 {
		t.Fatalf("observer events after first validation = %d, want 1", after)
	}
	if _, err := c.ValidateToken(context.Background(), testJWT); err != nil {
		t.Fatalf("second: %v", err)
	}
	if got := atomic.LoadInt32(&events); got != 1 {
		t.Errorf("observer events after second validation = %d, want still 1 — the cache hit must make no HTTP attempt", got)
	}
}

// ---- test clock ----

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock(c *Client) *testClock {
	return newTestClockAt(c, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
}

// newTestClockAt installs a controllable clock on the client's validation cache
// so TTL behaviour is asserted by advancing time, not by sleeping.
func newTestClockAt(c *Client, start time.Time) *testClock {
	tc := &testClock{now: start}
	c.vcache.now = tc.Now
	return tc
}

func (t *testClock) Now() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.now
}

func (t *testClock) advance(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.now = t.now.Add(d)
}
