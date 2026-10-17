package authclient

// hardening_cache_20261016_test.go — adversarial, black-box tests of the v0.12.0 /
// v0.12.1 validation cache (owner instruction 2026-10-16: "robust testing, no
// assumptions"). Every assertion is on what the auth double RECEIVED or on the
// answer the caller got — never on an internal counter alone.
//
//	claim (CHANGELOG 0.12.0/0.12.1)                          test
//	key covers EVERY input — no cross-request answers         TestHardening_NoCrossRequestAnswers_Property
//	   (direct, on the key builder, incl. separator attacks)  TestHardening_ValidationKeyInjective_Property
//	   (resource-scoped Authorize, every input)               TestHardening_AuthorizeResourceNoCrossAnswers_Property
//	positive entry never outlives the token's exp             TestHardening_TTLNeverExceedsTokenExp_Grid
//	errors (every non-401 shape) never cached, every endpoint TestHardening_ErrorsNeverCached_EveryEndpointEveryShape
//	one request per key under concurrency, no cross-talk      TestHardening_SingleFlightNoCrossTalk (-race)
//	only a validate-token 401 is a cached negative             TestHardening_Only401FromValidateTokenIsCached

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// echoAuth answers validate-token / validate-api-key with a user_id that is a
// digest of EVERY field of the request body, and /permissions/check with an
// "allowed" that is a deterministic function of every field. A cache that served
// one request's answer to another request would hand back the wrong digest.
type echoAuth struct {
	calls int64
	delay time.Duration
}

func digestOf(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%d:%s|", len(p), p)
	}
	return hex.EncodeToString(h.Sum(nil))[:24]
}

func (e *echoAuth) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&e.calls, 1)
		if e.delay > 0 {
			time.Sleep(e.delay)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		str := func(k string) string { s, _ := body[k].(string); return s }
		perms := func() string { b, _ := json.Marshal(body["required_permissions"]); return string(b) }
		switch r.URL.Path {
		case "/auth/validate-token":
			inc := fmt.Sprint(body["include_permissions"] == true)
			writeJSON(w, 200, map[string]any{"valid": true,
				"user_id": "u-" + digestOf("tok", str("token"), str("expected_audience"), perms(), inc),
				"org_id":  "o-" + digestOf(str("token"))})
		case "/auth/validate-api-key":
			writeJSON(w, 200, map[string]any{"valid": true,
				"user_id": "u-" + digestOf("key", str("api_key"), str("expected_audience"), perms()),
				"org_id":  "o-" + digestOf(str("api_key"))})
		case "/permissions/check":
			d := digestOf(str("user_id"), str("org_id"), str("permission"), str("resource_type"), str("resource_id"))
			writeJSON(w, 200, map[string]any{"allowed": d[0] < '8'})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}
}

// pick returns a random element from a deliberately tiny, collision-prone alphabet
// that includes the key builder's own separators and length-prefix lookalikes.
var nastyStrings = []string{"", "a", "b", "ab", "a|b", "1:a", "2:ab", "\x1e", "a\x1e", "\x1e1\x1ea", "0", "1", "true", "false", "a b", "é", "ab0t_sk_x"}

func pick(r *rand.Rand, xs []string) string { return xs[r.Intn(len(xs))] }

func randPerms(r *rand.Rand) []string {
	n := r.Intn(4)
	if n == 0 {
		if r.Intn(2) == 0 {
			return nil
		}
		return []string{}
	}
	out := make([]string, n)
	for i := range out {
		out[i] = pick(r, nastyStrings)
	}
	return out
}

func TestHardening_ValidationKeyInjective_Property(t *testing.T) {
	// Canonical form of the tuple (nil and empty perms are the same question).
	canon := func(kind, cred, aud string, perms []string, inc bool) string {
		b, _ := json.Marshal([]any{kind, cred, aud, append([]string{}, perms...), inc})
		return string(b)
	}
	kinds := []string{"validate-token", "validate-api-key", "authorize-resource", "", "x"}
	r := rand.New(rand.NewSource(20261016))
	seen := map[string]string{}
	for i := 0; i < 60000; i++ {
		kind, cred, aud := pick(r, kinds), pick(r, nastyStrings), pick(r, nastyStrings)
		perms, inc := randPerms(r), r.Intn(2) == 0
		k := validationKey(kind, cred, aud, perms, inc)
		c := canon(kind, cred, aud, perms, inc)
		if prev, ok := seen[k]; ok && prev != c {
			t.Fatalf("KEY COLLISION: %s and %s share key %s — one request's decision would be served to the other", prev, c, k)
		}
		seen[k] = c
		// The credential occupies the prefix InvalidateValidation relies on.
		if !strings.HasPrefix(k, credentialFingerprint(cred)) {
			t.Fatalf("key for cred %q lacks the credential fingerprint prefix", cred)
		}
		if cred != "" && strings.Contains(k, cred) && len(cred) > 3 {
			t.Fatalf("raw credential %q appears in the cache key", cred)
		}
	}
	if len(seen) < 10000 {
		t.Fatalf("only %d distinct tuples generated — the property ran on too little input to mean anything", len(seen))
	}

	// Hand-built separator attacks: without the length prefix these serialize to
	// identical bytes.
	attacks := []struct {
		a, b [3]any // aud, perms, include
	}{
		{[3]any{"A", []string{"B", "0"}, false}, [3]any{"A\x1e2\x1eB", []string{}, false}},
		{[3]any{"x", []string{"a", "bc"}, true}, [3]any{"x", []string{"ab", "c"}, true}},
		{[3]any{"", []string{"true"}, false}, [3]any{"", []string{}, true}},
		{[3]any{"1:a", []string(nil), false}, [3]any{"", []string{"a"}, false}},
	}
	for _, at := range attacks {
		ka := validationKey("validate-token", "cred", at.a[0].(string), at.a[1].([]string), at.a[2].(bool))
		kb := validationKey("validate-token", "cred", at.b[0].(string), at.b[1].([]string), at.b[2].(bool))
		if ka == kb {
			t.Fatalf("separator attack collides: %q vs %q", at.a, at.b)
		}
	}
	// Sensitivity: changing ANY single input changes the key.
	base := validationKey("validate-token", "c", "aud", []string{"p1", "p2"}, false)
	for name, k := range map[string]string{
		"kind":     validationKey("validate-api-key", "c", "aud", []string{"p1", "p2"}, false),
		"cred":     validationKey("validate-token", "d", "aud", []string{"p1", "p2"}, false),
		"aud":      validationKey("validate-token", "c", "aud2", []string{"p1", "p2"}, false),
		"perm":     validationKey("validate-token", "c", "aud", []string{"p1", "p3"}, false),
		"order":    validationKey("validate-token", "c", "aud", []string{"p2", "p1"}, false),
		"count":    validationKey("validate-token", "c", "aud", []string{"p1"}, false),
		"include":  validationKey("validate-token", "c", "aud", []string{"p1", "p2"}, true),
		"aud→perm": validationKey("validate-token", "c", "", []string{"aud", "p1", "p2"}, false),
	} {
		if k == base {
			t.Errorf("changing %s did not change the cache key", name)
		}
	}
}

func TestHardening_NoCrossRequestAnswers_Property(t *testing.T) {
	e := &echoAuth{}
	for _, opts := range [][]Option{
		nil, // the v0.12.0 default cache
		{WithValidationCache(time.Minute)},
	} {
		c, _ := newTestClient(t, e.handler(t), append([]Option{WithMaxRetries(0)}, opts...)...)
		r := rand.New(rand.NewSource(7))
		ctx := context.Background()
		toks := []string{testJWT, testJWT + "x", "ab0t_sk_k1", "ab0t_sk_k2", "eyJ.a.b", "opaque"}
		for i := 0; i < 1500; i++ {
			tok, aud, perms, inc := pick(r, toks), pick(r, nastyStrings), randPerms(r), r.Intn(2) == 0
			switch r.Intn(3) {
			case 0:
				a, err := c.ValidateTokenWith(ctx, TokenValidationRequest{Token: tok, ExpectedAudience: aud, RequiredPermissions: perms, IncludePermissions: inc})
				if err != nil {
					t.Fatal(err)
				}
				pj, _ := json.Marshal(perms)
				if len(perms) == 0 {
					pj = []byte("null")
				}
				want := "u-" + digestOf("tok", tok, aud, string(pj), fmt.Sprint(inc))
				if a.UserID != want {
					t.Fatalf("iter %d ValidateTokenWith(%q,aud=%q,perms=%q,inc=%v): got %s want %s — answer of a different request served", i, tok, aud, perms, inc, a.UserID, want)
				}
			case 1:
				v, err := c.ValidateAPIKey(ctx, ValidateAPIKeyRequest{APIKey: tok, ExpectedAudience: aud, RequiredPermissions: perms})
				if err != nil {
					t.Fatal(err)
				}
				pj, _ := json.Marshal(perms)
				if len(perms) == 0 {
					pj = []byte("null")
				}
				want := "u-" + digestOf("key", tok, aud, string(pj))
				if v.UserID != want {
					t.Fatalf("iter %d ValidateAPIKey(%q,aud=%q,perms=%q): got %s want %s", i, tok, aud, perms, v.UserID, want)
				}
			default:
				a, err := c.ValidateToken(ctx, tok)
				if err != nil {
					t.Fatal(err)
				}
				var want string
				if IsAPIKey(tok) {
					want = "u-" + digestOf("key", tok, "", "null")
				} else {
					want = "u-" + digestOf("tok", tok, "", "null", "false")
				}
				if a.UserID != want {
					t.Fatalf("iter %d ValidateToken(%q): got %s want %s", i, tok, a.UserID, want)
				}
			}
		}
		if st := c.ValidationCacheStats(); st.Hits == 0 {
			t.Fatalf("no cache hits in 1500 calls over a tiny input space — the property ran without the cache engaged")
		}
	}
}

func TestHardening_AuthorizeResourceNoCrossAnswers_Property(t *testing.T) {
	e := &echoAuth{}
	c, _ := newTestClient(t, e.handler(t), WithMaxRetries(0)) // default cache: PDP decisions cached too
	ref, _ := newTestClient(t, e.handler(t), WithMaxRetries(0), WithValidationCache(0))
	r := rand.New(rand.NewSource(99))
	ctx := context.Background()
	toks := []string{testJWT, testJWT + "y", "ab0t_sk_a", "ab0t_sk_b"}
	types := []string{"doc", "doc|x", "", "d", "oc"}
	ids := []string{"1", "", "doc", "1|2", "\x1e", "12"}
	actions := []string{"doc.read", "doc.write", "doc", ""}
	for i := 0; i < 1200; i++ {
		tok, act := pick(r, toks), pick(r, actions)
		res := Resource{Type: pick(r, types), ID: pick(r, ids)}
		got, err := c.Authorize(ctx, tok, act, res)
		if err != nil {
			t.Fatal(err)
		}
		want, err := ref.Authorize(ctx, tok, act, res)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("iter %d Authorize(%q,%q,%+v): cached client said %v, uncached said %v — a decision was served for a different question", i, tok, act, res, got, want)
		}
	}
	if c.ValidationCacheStats().Hits == 0 {
		t.Fatal("cache never hit — property is vacuous")
	}
}

// ---- TTL never exceeds the token's exp ----

func TestHardening_TTLNeverExceedsTokenExp_Grid(t *testing.T) {
	t0 := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	for _, cfg := range []struct {
		name string
		opts []Option
		ttl  time.Duration
		call func(c *Client, tok string) error
	}{
		{"default ValidateToken", nil, DefaultTokenValidationTTL, func(c *Client, tok string) error {
			_, err := c.ValidateToken(context.Background(), tok)
			return err
		}},
		{"default Authorize unscoped", nil, DefaultAuthorizeTTL, func(c *Client, tok string) error {
			_, err := c.Authorize(context.Background(), tok, "a.read", Resource{})
			return err
		}},
		{"explicit 60s ValidateToken", []Option{WithValidationCache(60 * time.Second)}, 60 * time.Second, func(c *Client, tok string) error {
			_, err := c.ValidateToken(context.Background(), tok)
			return err
		}},
	} {
		for _, off := range []int{-60, -1, 0, 1, 2, 5, 14, 15, 16, 59, 60, 61, 3600} {
			exp := t0.Add(time.Duration(off) * time.Second)
			limit := t0.Add(cfg.ttl)
			if exp.Before(limit) {
				limit = exp
			}
			stored := exp.After(t0)
			// probes: just before and exactly at the limit (and t0 itself)
			probes := []time.Duration{0}
			if stored {
				probes = append(probes, limit.Sub(t0)-time.Nanosecond, limit.Sub(t0))
			}
			for _, p := range probes {
				t.Run(fmt.Sprintf("%s/exp%+ds/probe%v", cfg.name, off, p), func(t *testing.T) {
					s := newScriptedAuth()
					c, _ := newTestClient(t, s.handler(t), append([]Option{WithMaxRetries(0)}, cfg.opts...)...)
					clock := newTestClockAt(c, t0)
					tok := jwtWithExp(exp)
					if err := cfg.call(c, tok); err != nil {
						t.Fatal(err)
					}
					clock.advance(p)
					if err := cfg.call(c, tok); err != nil {
						t.Fatal(err)
					}
					total := s.n(pToken)
					servedFromCache := total == 1
					wantCached := stored && t0.Add(p).Before(limit)
					if servedFromCache != wantCached {
						t.Fatalf("exp=t0%+ds probe=t0+%v: served from cache=%v, want %v (limit %v) — a positive must never outlive min(TTL, exp)",
							off, p, servedFromCache, wantCached, limit.Sub(t0))
					}
				})
			}
		}
	}
}

// ---- errors never cached: every endpoint, every non-definite shape ----

type flexAuth struct {
	mu     sync.Mutex
	status map[string]int
	body   map[string]string
	stall  map[string]bool
	calls  map[string]int
}

func newFlexAuth() *flexAuth {
	return &flexAuth{status: map[string]int{}, body: map[string]string{}, stall: map[string]bool{}, calls: map[string]int{}}
}

func (f *flexAuth) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls[r.URL.Path]++
		st, body, stall := f.status[r.URL.Path], f.body[r.URL.Path], f.stall[r.URL.Path]
		f.mu.Unlock()
		if stall {
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
			return
		}
		if st == 0 {
			st = 200
		}
		if body == "" && st == 200 {
			switch r.URL.Path {
			case pCheck:
				body = `{"allowed":true}`
			default:
				body = `{"valid":true,"user_id":"u1","org_id":"o1"}`
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(st)
		_, _ = w.Write([]byte(body))
	}
}

func (f *flexAuth) n(p string) int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls[p] }

func TestHardening_ErrorsNeverCached_EveryEndpointEveryShape(t *testing.T) {
	type sh struct {
		name   string
		status int
		body   string
		stall  bool
	}
	shapes := []sh{
		{"400", 400, `{"detail":"bad"}`, false},
		{"403", 403, `{"detail":"no"}`, false},
		{"404", 404, `{"detail":"Not Found"}`, false},
		{"409", 409, `{}`, false},
		{"422", 422, `{"detail":[]}`, false},
		{"429", 429, `{"detail":"slow"}`, false},
		{"500", 500, `x`, false},
		{"502", 502, ``, false},
		{"503", 503, `{"detail":"Service temporarily unavailable"}`, false},
		{"504", 504, ``, false},
		{"200 truncated JSON", 200, `{"valid":tr`, false},
		{"200 wrong type", 200, `{"valid":"yes"}`, false},
		{"timeout", 0, "", true},
	}
	ctx := context.Background()
	calls := []struct {
		name string
		path string // the endpoint the shape is applied to
		run  func(c *Client) error
	}{
		{"ValidateToken(JWT)", pToken, func(c *Client) error { _, err := c.ValidateToken(ctx, testJWT); return err }},
		{"ValidateTokenWith(perms)", pToken, func(c *Client) error {
			_, err := c.ValidateTokenWith(ctx, TokenValidationRequest{Token: testJWT, RequiredPermissions: []string{"p"}})
			return err
		}},
		{"ValidateToken(key)", pKey, func(c *Client) error { _, err := c.ValidateToken(ctx, tKey); return err }},
		{"ValidateAPIKey", pKey, func(c *Client) error {
			_, err := c.ValidateAPIKey(ctx, ValidateAPIKeyRequest{APIKey: tKey})
			return err
		}},
		{"Authorize(JWT)", pToken, func(c *Client) error { _, err := c.Authorize(ctx, testJWT, "a", Resource{}); return err }},
		{"Authorize(JWT,res) subject", pToken, func(c *Client) error {
			_, err := c.Authorize(ctx, testJWT, "a", Resource{Type: "d", ID: "1"})
			return err
		}},
		{"Authorize(JWT,res) PDP", pCheck, func(c *Client) error {
			_, err := c.Authorize(ctx, testJWT, "a", Resource{Type: "d", ID: "1"})
			return err
		}},
		{"Authorize(key,res) PDP", pCheck, func(c *Client) error { _, err := c.Authorize(ctx, tKey, "a", Resource{Type: "d", ID: "1"}); return err }},
	}
	for _, call := range calls {
		for _, s := range shapes {
			t.Run(call.name+"/"+s.name, func(t *testing.T) {
				f := newFlexAuth()
				body := s.body
				if call.path == pCheck {
					body = strings.ReplaceAll(body, `"valid"`, `"allowed"`) // the PDP's own field
				}
				f.status[call.path], f.body[call.path], f.stall[call.path] = s.status, body, s.stall
				c, _ := newTestClient(t, f.handler(), WithMaxRetries(0), WithTimeout(250*time.Millisecond))
				for i := 0; i < 3; i++ {
					if err := call.run(c); err == nil {
						t.Fatalf("attempt %d: shape %s produced no error", i, s.name)
					}
				}
				if got := f.n(call.path); got != 3 {
					t.Fatalf("%s received %d requests for 3 calls under %s — an error answer was cached", call.path, got, s.name)
				}
			})
		}
	}
}

// Only a validate-token 401 is a cached negative — the same status on the other
// endpoints is never cached, and a 401 never turns into a "valid".
func TestHardening_Only401FromValidateTokenIsCached(t *testing.T) {
	ctx := context.Background()
	f := newFlexAuth()
	f.status[pToken], f.body[pToken] = 401, `{"detail":"Invalid token"}`
	f.status[pKey], f.body[pKey] = 401, `{"detail":"Invalid key"}`
	c, _ := newTestClient(t, f.handler(), WithMaxRetries(0))
	clock := newTestClock(c)
	for i := 0; i < 5; i++ {
		a, err := c.ValidateToken(ctx, testJWT)
		if !IsUnauthorized(err) || a != nil {
			t.Fatalf("JWT %d: actor=%+v err=%v, want nil + 401", i, a, err)
		}
		if _, err := c.ValidateToken(ctx, tKey); !IsUnauthorized(err) {
			t.Fatalf("key %d: err=%v, want 401", i, err)
		}
	}
	if f.n(pToken) != 1 || f.n(pKey) != 5 {
		t.Fatalf("validate-token=%d (want 1, cached negative) validate-api-key=%d (want 5, never cached)", f.n(pToken), f.n(pKey))
	}
	// The service now says valid: still denied until the negative TTL lapses, then valid.
	f.mu.Lock()
	f.status[pToken], f.body[pToken] = 0, ""
	f.mu.Unlock()
	clock.advance(DefaultTokenValidationNegativeTTL - time.Millisecond)
	if _, err := c.ValidateToken(ctx, testJWT); !IsUnauthorized(err) {
		t.Fatalf("inside negative TTL: err=%v, want the cached 401", err)
	}
	clock.advance(2 * time.Millisecond)
	a, err := c.ValidateToken(ctx, testJWT)
	if err != nil || a == nil || !a.Valid {
		t.Fatalf("after negative TTL: actor=%+v err=%v, want a fresh valid", a, err)
	}
	// A cached 401 handed out is a copy: mutating it must not alter the next hit.
	f.mu.Lock()
	f.status[pToken], f.body[pToken] = 401, `{"detail":"Invalid token"}`
	f.mu.Unlock()
	_, _ = c.ValidateToken(ctx, testJWT+"z")   // fetch: caches the 401
	_, err = c.ValidateToken(ctx, testJWT+"z") // hit: a copy of the cached error
	ae, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("cached 401 is not an *APIError: %T %v", err, err)
	}
	ae.StatusCode = 200
	_, err2 := c.ValidateToken(ctx, testJWT+"z")
	if !IsUnauthorized(err2) {
		t.Fatalf("mutating a returned cached error changed the next hit: %v", err2)
	}
}

// ---- single flight with no cross-talk under -race ----

func TestHardening_SingleFlightNoCrossTalk(t *testing.T) {
	var calls int64
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		time.Sleep(30 * time.Millisecond) // hold the flight open so callers pile up
		var body struct {
			Token  string `json:"token"`
			APIKey string `json:"api_key"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		writeJSON(w, 200, map[string]any{"valid": true, "user_id": "u-" + body.Token + body.APIKey,
			"permissions": []string{"p-" + body.Token + body.APIKey}})
	}, WithMaxRetries(0))
	const creds, per = 12, 25
	var wg sync.WaitGroup
	var bad int64
	start := make(chan struct{})
	for i := 0; i < creds; i++ {
		cred := fmt.Sprintf("%s%d", testJWT, i)
		if i%2 == 1 {
			cred = fmt.Sprintf("ab0t_sk_k%d", i)
		}
		for j := 0; j < per; j++ {
			wg.Add(1)
			go func(cred string) {
				defer wg.Done()
				<-start
				a, err := c.ValidateToken(context.Background(), cred)
				if err != nil || a.UserID != "u-"+cred || len(a.Permissions) != 1 || a.Permissions[0] != "p-"+cred {
					atomic.AddInt64(&bad, 1)
					return
				}
				a.Permissions[0] = "MUTATED" // must not leak into anyone else's copy
			}(cred)
		}
	}
	close(start)
	wg.Wait()
	if bad := atomic.LoadInt64(&bad); bad != 0 {
		t.Fatalf("%d of %d callers got another credential's answer (or a mutated copy)", bad, creds*per)
	}
	if calls := atomic.LoadInt64(&calls); calls != creds {
		t.Fatalf("auth calls = %d for %d distinct credentials × %d concurrent callers, want exactly %d", calls, creds, per, creds)
	}
}
