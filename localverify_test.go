package authclient

// localverify_test.go — VerifyAccessTokenLocal accept / reject rules. Real RSA keys
// are generated per run and served from an httptest JWKS endpoint that counts
// fetches, so "no network on the hot path" and "unknown kid refetches at most once a
// minute" are asserted on actual requests.

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	lvKeysOnce sync.Once
	lvKey1     *rsa.PrivateKey
	lvKey2     *rsa.PrivateKey
	lvWeak     *rsa.PrivateKey
)

func lvKeys(t *testing.T) {
	t.Helper()
	lvKeysOnce.Do(func() {
		var err error
		if lvKey1, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if lvKey2, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if lvWeak, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
			panic(err)
		}
	})
}

func rsaJWK(kid string, pub *rsa.PublicKey) JWK {
	return JWK{
		Kty: "RSA", Use: "sig", Alg: "RS256", Kid: kid,
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// jwksDouble serves /.well-known/jwks.json and counts fetches.
type jwksDouble struct {
	mu      sync.Mutex
	keys    []JWK
	status  int
	fetches int
}

func (j *jwksDouble) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwks.json" {
			t.Errorf("unexpected request %s — local verification must not call anything but the JWKS", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		j.mu.Lock()
		j.fetches++
		keys, status := append([]JWK(nil), j.keys...), j.status
		j.mu.Unlock()
		if status != 0 {
			writeJSON(w, status, map[string]any{"detail": "down"})
			return
		}
		writeJSON(w, 200, JWKS{Keys: keys})
	}
}

func (j *jwksDouble) n() int { j.mu.Lock(); defer j.mu.Unlock(); return j.fetches }

func (j *jwksDouble) set(keys ...JWK) { j.mu.Lock(); j.keys = keys; j.mu.Unlock() }

var lvNow = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

// lvSetup returns a client whose JWKS serves k1, a JWKS double, and a mutable
// clock shared by the verifier and the JWKS cache.
func lvSetup(t *testing.T, opts ...Option) (*Client, *jwksDouble, *testClock) {
	t.Helper()
	lvKeys(t)
	j := &jwksDouble{keys: []JWK{rsaJWK("k1", &lvKey1.PublicKey)}}
	c, _ := newTestClient(t, j.handler(t), append([]Option{WithMaxRetries(0)}, opts...)...)
	clock := &testClock{now: lvNow}
	c.jwks.now = clock.Now
	return c, j, clock
}

func lvOpts(clock *testClock, o LocalVerifyOptions) LocalVerifyOptions {
	o.now = clock.Now
	return o
}

func b64json(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func signRS(priv *rsa.PrivateKey, hdr, claims map[string]any) string {
	signing := b64json(hdr) + "." + b64json(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func stdHeader() map[string]any { return map[string]any{"alg": "RS256", "kid": "k1", "typ": "JWT"} }

// stdClaims is an auth-service-shaped access token issued at lvNow.
func stdClaims(base string) map[string]any {
	return map[string]any{
		"sub": "user-1", "email": "u@example.com", "name": "U", "type": "access",
		"iat": lvNow.Unix(), "exp": lvNow.Add(15 * time.Minute).Unix(),
		"iss": LegacyAccessTokenIssuer, "aud": []string{"svc-a", "LOCAL:org-1"},
		"org_id": "org-1", "client_id": "ab0t-first-party", "jti": "sess-1",
	}
}

func with(m map[string]any, kv ...any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	for i := 0; i < len(kv); i += 2 {
		k := kv[i].(string)
		if kv[i+1] == nil {
			delete(out, k)
		} else {
			out[k] = kv[i+1]
		}
	}
	return out
}

func wantReason(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted; want rejection %q", reason)
	}
	if !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("err = %v; want errors.Is(ErrInvalidAccessToken)", err)
	}
	var ae *AccessTokenError
	if !errors.As(err, &ae) || ae.Reason != reason {
		t.Fatalf("err = %v; want reason %q", err, reason)
	}
}

// ---- accept ----

func TestLocalVerifyAcceptsValidToken(t *testing.T) {
	c, j, clock := lvSetup(t)
	tok := signRS(lvKey1, stdHeader(), stdClaims(c.BaseURL()))
	got, err := c.VerifyAccessTokenLocal(context.Background(), tok, lvOpts(clock, LocalVerifyOptions{Audience: "svc-a"}))
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if got.Subject != "user-1" || got.Email != "u@example.com" || got.OrgID != "org-1" || got.SessionID != "sess-1" ||
		got.Type != "access" || got.KeyID != "k1" || got.ClientID != "ab0t-first-party" || got.Issuer != LegacyAccessTokenIssuer {
		t.Fatalf("claims = %+v", got)
	}
	if !got.ExpiresAt.Equal(lvNow.Add(15*time.Minute)) || !got.IssuedAt.Equal(lvNow) || len(got.Audience) != 2 {
		t.Fatalf("times/aud = %v %v %v", got.ExpiresAt, got.IssuedAt, got.Audience)
	}
	if got.IsDelegation() {
		t.Fatal("an access token is not a delegation")
	}
	if j.n() != 1 {
		t.Fatalf("jwks fetches = %d, want 1", j.n())
	}
}

func TestLocalVerifyNoNetworkOnHotPath(t *testing.T) {
	c, j, clock := lvSetup(t)
	tok := signRS(lvKey1, stdHeader(), stdClaims(c.BaseURL()))
	for i := 0; i < 100; i++ {
		if _, err := c.VerifyAccessTokenLocal(context.Background(), tok, lvOpts(clock, LocalVerifyOptions{})); err != nil {
			t.Fatal(err)
		}
	}
	if j.n() != 1 {
		t.Fatalf("jwks fetches = %d after 100 verifications, want 1 (the key set is cached)", j.n())
	}
	clock.advance(11 * time.Minute) // past the 10 min JWKS TTL
	if _, err := c.VerifyAccessTokenLocal(context.Background(), tok, lvOpts(clock, LocalVerifyOptions{Leeway: -1})); err != nil {
		t.Fatal(err)
	}
	if j.n() != 2 {
		t.Fatalf("jwks fetches = %d, want 2 once the 10 min JWKS TTL passed", j.n())
	}
}

func TestLocalVerifyAcceptsTypAtJWTAndStringAudAndMissingType(t *testing.T) {
	c, _, clock := lvSetup(t)
	hdr := with(stdHeader(), "typ", "at+jwt")
	tok := signRS(lvKey1, hdr, with(stdClaims(""), "aud", "svc-a", "type", nil))
	got, err := c.VerifyAccessTokenLocal(context.Background(), tok, lvOpts(clock, LocalVerifyOptions{Audience: "svc-a"}))
	if err != nil {
		t.Fatalf("rejected: %v", err)
	}
	if len(got.Audience) != 1 || got.Audience[0] != "svc-a" || got.Type != "" {
		t.Fatalf("claims = %+v", got)
	}
}

// ---- signature / algorithm ----

func TestLocalVerifyRejectsBadSignature(t *testing.T) {
	c, _, clock := lvSetup(t)
	// Signed by a different key under the trusted kid.
	tok := signRS(lvKey2, stdHeader(), stdClaims(""))
	_, err := c.VerifyAccessTokenLocal(context.Background(), tok, lvOpts(clock, LocalVerifyOptions{}))
	wantReason(t, err, "bad_signature")

	// A good token whose payload was altered after signing.
	good := signRS(lvKey1, stdHeader(), stdClaims(""))
	parts := strings.Split(good, ".")
	parts[1] = b64json(with(stdClaims(""), "sub", "admin"))
	_, err = c.VerifyAccessTokenLocal(context.Background(), strings.Join(parts, "."), lvOpts(clock, LocalVerifyOptions{}))
	wantReason(t, err, "bad_signature")
}

func TestLocalVerifyRejectsWrongAlgorithms(t *testing.T) {
	c, _, clock := lvSetup(t)
	claims := b64json(stdClaims(""))
	for _, alg := range []string{"none", "None", "NONE", "HS256", "HS512", "RS512", "PS256", "ES256", "rs256", ""} {
		t.Run("alg="+alg, func(t *testing.T) {
			tok := b64json(map[string]any{"alg": alg, "kid": "k1"}) + "." + claims + ".AAAA"
			_, err := c.VerifyAccessTokenLocal(context.Background(), tok, lvOpts(clock, LocalVerifyOptions{}))
			wantReason(t, err, "unsupported_alg")
		})
	}
	t.Run("alg absent", func(t *testing.T) {
		tok := b64json(map[string]any{"kid": "k1"}) + "." + claims + ".AAAA"
		_, err := c.VerifyAccessTokenLocal(context.Background(), tok, lvOpts(clock, LocalVerifyOptions{}))
		wantReason(t, err, "unsupported_alg")
	})
}

func TestLocalVerifyRejectsHS256KeyConfusion(t *testing.T) {
	// The classic attack: HMAC-sign with the RSA PUBLIC key as the secret.
	c, _, clock := lvSetup(t)
	jwk := rsaJWK("k1", &lvKey1.PublicKey)
	signing := b64json(map[string]any{"alg": "HS256", "kid": "k1"}) + "." + b64json(stdClaims(""))
	mac := hmac.New(sha256.New, []byte(jwk.N))
	mac.Write([]byte(signing))
	tok := signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	_, err := c.VerifyAccessTokenLocal(context.Background(), tok, lvOpts(clock, LocalVerifyOptions{}))
	wantReason(t, err, "unsupported_alg")
}

func TestLocalVerifyRejectsUnsupportedHeaders(t *testing.T) {
	c, _, clock := lvSetup(t)
	for name, hdr := range map[string]map[string]any{
		"crit":     with(stdHeader(), "crit", []string{"exp"}),
		"typ JWE":  with(stdHeader(), "typ", "JWE"),
		"typ json": with(stdHeader(), "typ", "application/json"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.VerifyAccessTokenLocal(context.Background(), signRS(lvKey1, hdr, stdClaims("")), lvOpts(clock, LocalVerifyOptions{}))
			wantReason(t, err, "unsupported_header")
		})
	}
	_, err := c.VerifyAccessTokenLocal(context.Background(), signRS(lvKey1, with(stdHeader(), "kid", nil), stdClaims("")), lvOpts(clock, LocalVerifyOptions{}))
	wantReason(t, err, "missing_kid")
}

// ---- keys ----

func TestLocalVerifyUnknownKidRefetchesAtMostOncePerMinute(t *testing.T) {
	c, j, clock := lvSetup(t)
	ctx := context.Background()
	unknown := signRS(lvKey2, with(stdHeader(), "kid", "k-unknown"), stdClaims(""))

	_, err := c.VerifyAccessTokenLocal(ctx, unknown, lvOpts(clock, LocalVerifyOptions{}))
	wantReason(t, err, "unknown_kid")
	if j.n() != 2 {
		t.Fatalf("fetches = %d, want 2 (initial + one unknown-kid refetch)", j.n())
	}
	for i := 0; i < 20; i++ {
		clock.advance(2 * time.Second) // 40 s total: still inside the 1 min cooldown
		_, err = c.VerifyAccessTokenLocal(ctx, unknown, lvOpts(clock, LocalVerifyOptions{}))
		wantReason(t, err, "unknown_kid")
	}
	if j.n() != 2 {
		t.Fatalf("fetches = %d, want still 2 — random kids must not amplify into JWKS fetches", j.n())
	}
	clock.advance(21 * time.Second) // 61 s since the forced refetch
	_, err = c.VerifyAccessTokenLocal(ctx, unknown, lvOpts(clock, LocalVerifyOptions{}))
	wantReason(t, err, "unknown_kid")
	if j.n() != 3 {
		t.Fatalf("fetches = %d, want 3 — after the cooldown one more refetch is allowed", j.n())
	}
}

func TestLocalVerifyKeyRotationPickedUpByUnknownKidRefetch(t *testing.T) {
	c, j, clock := lvSetup(t)
	ctx := context.Background()
	if _, err := c.VerifyAccessTokenLocal(ctx, signRS(lvKey1, stdHeader(), stdClaims("")), lvOpts(clock, LocalVerifyOptions{})); err != nil {
		t.Fatal(err)
	}
	// The service rotates to k2.
	j.set(rsaJWK("k1", &lvKey1.PublicKey), rsaJWK("k2", &lvKey2.PublicKey))
	rotated := signRS(lvKey2, with(stdHeader(), "kid", "k2"), stdClaims(""))
	got, err := c.VerifyAccessTokenLocal(ctx, rotated, lvOpts(clock, LocalVerifyOptions{}))
	if err != nil {
		t.Fatalf("token from the rotated key rejected: %v", err)
	}
	if got.KeyID != "k2" || j.n() != 2 {
		t.Fatalf("kid=%s fetches=%d, want k2 after exactly one refetch", got.KeyID, j.n())
	}
}

func TestLocalVerifyRejectsUnsuitableKeys(t *testing.T) {
	lvKeys(t)
	weak := rsaJWK("k1", &lvWeak.PublicKey)
	enc := rsaJWK("k1", &lvKey1.PublicKey)
	enc.Use = "enc"
	wrongAlg := rsaJWK("k1", &lvKey1.PublicKey)
	wrongAlg.Alg = "RS512"
	ec := JWK{Kty: "EC", Kid: "k1", Crv: "P-256", X: "AA", Y: "AA"}
	for name, tc := range map[string]struct {
		key  JWK
		priv *rsa.PrivateKey
	}{"1024-bit": {weak, lvWeak}, "use=enc": {enc, lvKey1}, "alg=RS512": {wrongAlg, lvKey1}, "EC": {ec, lvKey1}} {
		t.Run(name, func(t *testing.T) {
			c, j, clock := lvSetup(t)
			j.set(tc.key)
			_, err := c.VerifyAccessTokenLocal(context.Background(), signRS(tc.priv, stdHeader(), stdClaims("")), lvOpts(clock, LocalVerifyOptions{}))
			wantReason(t, err, "unsupported_key")
		})
	}
}

func TestLocalVerifyJWKSUnavailableIsNotATokenVerdict(t *testing.T) {
	c, j, clock := lvSetup(t)
	j.mu.Lock()
	j.status = 503
	j.mu.Unlock()
	_, err := c.VerifyAccessTokenLocal(context.Background(), signRS(lvKey1, stdHeader(), stdClaims("")), lvOpts(clock, LocalVerifyOptions{}))
	if err == nil {
		t.Fatal("accepted with no key set")
	}
	if errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("err = %v — an unreachable JWKS is 'could not evaluate' (503), never an invalid-token verdict (401)", err)
	}
	if !IsServerError(err) {
		t.Fatalf("err = %v, want the underlying 503", err)
	}
}

func TestLocalVerifyServesLastGoodKeySetThroughOutage(t *testing.T) {
	c, j, clock := lvSetup(t)
	tok := signRS(lvKey1, stdHeader(), stdClaims(""))
	if _, err := c.VerifyAccessTokenLocal(context.Background(), tok, lvOpts(clock, LocalVerifyOptions{})); err != nil {
		t.Fatal(err)
	}
	j.mu.Lock()
	j.status = 503
	j.mu.Unlock()
	clock.advance(11 * time.Minute) // JWKS TTL lapsed; the token itself is still inside its 15 min
	if _, err := c.VerifyAccessTokenLocal(context.Background(), tok, lvOpts(clock, LocalVerifyOptions{})); err != nil {
		t.Fatalf("a refresh failure must keep serving the last good (public) key set: %v", err)
	}
	if j.n() != 2 {
		t.Fatalf("fetches = %d, want 2 (the refresh WAS attempted and failed)", j.n())
	}
}

// ---- claims ----

func TestLocalVerifyIssuer(t *testing.T) {
	c, _, clock := lvSetup(t)
	ctx := context.Background()
	verify := func(iss any, o LocalVerifyOptions) error {
		_, err := c.VerifyAccessTokenLocal(ctx, signRS(lvKey1, stdHeader(), with(stdClaims(""), "iss", iss)), lvOpts(clock, o))
		return err
	}
	if err := verify(c.BaseURL(), LocalVerifyOptions{}); err != nil {
		t.Fatalf("the client's base URL is a default issuer: %v", err)
	}
	wantReason(t, verify("https://evil.example", LocalVerifyOptions{}), "issuer")
	wantReason(t, verify(nil, LocalVerifyOptions{}), "issuer")
	if err := verify("https://auth.example", LocalVerifyOptions{Issuers: []string{"https://auth.example"}}); err != nil {
		t.Fatalf("custom issuer: %v", err)
	}
	wantReason(t, verify(LegacyAccessTokenIssuer, LocalVerifyOptions{Issuers: []string{"https://auth.example"}}), "issuer")
	wantReason(t, verify(42, LocalVerifyOptions{}), "malformed")
}

func TestLocalVerifyAudience(t *testing.T) {
	ctx := context.Background()
	c, _, clock := lvSetup(t)
	tok := signRS(lvKey1, stdHeader(), stdClaims(""))
	if _, err := c.VerifyAccessTokenLocal(ctx, tok, lvOpts(clock, LocalVerifyOptions{})); err != nil {
		t.Fatalf("no audience expected → not checked: %v", err)
	}
	_, err := c.VerifyAccessTokenLocal(ctx, tok, lvOpts(clock, LocalVerifyOptions{Audience: "svc-b"}))
	wantReason(t, err, "audience")
	_, err = c.VerifyAccessTokenLocal(ctx, tok, lvOpts(clock, LocalVerifyOptions{Audience: "svc"})) // no prefix matching
	wantReason(t, err, "audience")
	noAud := signRS(lvKey1, stdHeader(), with(stdClaims(""), "aud", nil))
	_, err = c.VerifyAccessTokenLocal(ctx, noAud, lvOpts(clock, LocalVerifyOptions{Audience: "svc-a"}))
	wantReason(t, err, "audience")

	// The client's WithExpectedAudience is the fallback.
	c2, _, clock2 := lvSetup(t, WithExpectedAudience("svc-b"))
	_, err = c2.VerifyAccessTokenLocal(ctx, tok, lvOpts(clock2, LocalVerifyOptions{}))
	wantReason(t, err, "audience")
	if _, err := c2.VerifyAccessTokenLocal(ctx, tok, lvOpts(clock2, LocalVerifyOptions{Audience: "svc-a"})); err != nil {
		t.Fatalf("opts.Audience overrides the client default: %v", err)
	}
	badAud := signRS(lvKey1, stdHeader(), with(stdClaims(""), "aud", []any{"svc-a", 7}))
	_, err = c.VerifyAccessTokenLocal(ctx, badAud, lvOpts(clock, LocalVerifyOptions{}))
	wantReason(t, err, "malformed")
}

func TestLocalVerifyExpiry(t *testing.T) {
	c, _, clock := lvSetup(t)
	ctx := context.Background()
	at := func(exp time.Time) string {
		return signRS(lvKey1, stdHeader(), with(stdClaims(""), "exp", exp.Unix(), "iat", exp.Add(-15*time.Minute).Unix()))
	}
	// Expired 10 s ago: inside the default 30 s leeway.
	if _, err := c.VerifyAccessTokenLocal(ctx, at(lvNow.Add(-10*time.Second)), lvOpts(clock, LocalVerifyOptions{})); err != nil {
		t.Fatalf("10 s past exp with 30 s default leeway: %v", err)
	}
	_, err := c.VerifyAccessTokenLocal(ctx, at(lvNow.Add(-31*time.Second)), lvOpts(clock, LocalVerifyOptions{}))
	wantReason(t, err, "expired")
	// Exactly at exp + leeway is already expired (RFC 7519: not ON or after).
	_, err = c.VerifyAccessTokenLocal(ctx, at(lvNow.Add(-DefaultLocalVerifyLeeway)), lvOpts(clock, LocalVerifyOptions{}))
	wantReason(t, err, "expired")
	// Leeway is clamped to 60 s: asking for 10 minutes does not accept a token 2 minutes dead.
	_, err = c.VerifyAccessTokenLocal(ctx, at(lvNow.Add(-2*time.Minute)), lvOpts(clock, LocalVerifyOptions{Leeway: 10 * time.Minute}))
	wantReason(t, err, "expired")
	if _, err := c.VerifyAccessTokenLocal(ctx, at(lvNow.Add(-59*time.Second)), lvOpts(clock, LocalVerifyOptions{Leeway: 10 * time.Minute})); err != nil {
		t.Fatalf("59 s past exp with the clamped 60 s leeway: %v", err)
	}
	// Negative leeway = none.
	_, err = c.VerifyAccessTokenLocal(ctx, at(lvNow.Add(-time.Second)), lvOpts(clock, LocalVerifyOptions{Leeway: -1}))
	wantReason(t, err, "expired")
	// exp is required and must be a number.
	_, err = c.VerifyAccessTokenLocal(ctx, signRS(lvKey1, stdHeader(), with(stdClaims(""), "exp", nil)), lvOpts(clock, LocalVerifyOptions{}))
	wantReason(t, err, "missing_claim")
	_, err = c.VerifyAccessTokenLocal(ctx, signRS(lvKey1, stdHeader(), with(stdClaims(""), "exp", "tomorrow")), lvOpts(clock, LocalVerifyOptions{}))
	wantReason(t, err, "malformed")
}

func TestLocalVerifyNotBeforeAndIssuedAt(t *testing.T) {
	c, _, clock := lvSetup(t)
	ctx := context.Background()
	verify := func(kv ...any) error {
		_, err := c.VerifyAccessTokenLocal(ctx, signRS(lvKey1, stdHeader(), with(stdClaims(""), kv...)), lvOpts(clock, LocalVerifyOptions{}))
		return err
	}
	wantReason(t, verify("nbf", lvNow.Add(2*time.Minute).Unix()), "not_yet_valid")
	if err := verify("nbf", lvNow.Add(20*time.Second).Unix()); err != nil {
		t.Fatalf("nbf 20 s ahead is inside the 30 s leeway: %v", err)
	}
	wantReason(t, verify("iat", lvNow.Add(5*time.Minute).Unix()), "not_yet_valid")
	wantReason(t, verify("nbf", "soon"), "malformed")
}

func TestLocalVerifyTokenType(t *testing.T) {
	c, _, clock := lvSetup(t)
	ctx := context.Background()
	verify := func(o LocalVerifyOptions, kv ...any) (*AccessTokenClaims, error) {
		return c.VerifyAccessTokenLocal(ctx, signRS(lvKey1, stdHeader(), with(stdClaims(""), kv...)), lvOpts(clock, o))
	}
	_, err := verify(LocalVerifyOptions{}, "type", "refresh")
	wantReason(t, err, "token_type")
	_, err = verify(LocalVerifyOptions{AllowDelegation: true}, "type", "refresh")
	wantReason(t, err, "token_type")
	_, err = verify(LocalVerifyOptions{}, "type", "sso_domain")
	wantReason(t, err, "token_type")
	_, err = verify(LocalVerifyOptions{}, "type", 1)
	wantReason(t, err, "malformed")

	act := map[string]any{"sub": "actor-9"}
	_, err = verify(LocalVerifyOptions{}, "type", "delegation", "act", act, "scope", []string{"users.read"})
	wantReason(t, err, "token_type")
	got, err := verify(LocalVerifyOptions{AllowDelegation: true}, "type", "delegation", "act", act, "scope", "users.read docs.read")
	if err != nil {
		t.Fatalf("delegation with AllowDelegation: %v", err)
	}
	if !got.IsDelegation() || got.Actor["sub"] != "actor-9" || len(got.Scope) != 2 {
		t.Fatalf("delegation claims = %+v", got)
	}
	_, err = verify(LocalVerifyOptions{AllowDelegation: true}, "type", "delegation", "act", nil)
	wantReason(t, err, "missing_claim")
}

func TestLocalVerifyRequiresSubject(t *testing.T) {
	c, _, clock := lvSetup(t)
	_, err := c.VerifyAccessTokenLocal(context.Background(), signRS(lvKey1, stdHeader(), with(stdClaims(""), "sub", nil)), lvOpts(clock, LocalVerifyOptions{}))
	wantReason(t, err, "missing_claim")
}

func TestLocalVerifyMalformedInputs(t *testing.T) {
	c, j, clock := lvSetup(t)
	for name, tok := range map[string]string{
		"empty":          "",
		"two parts":      "a.b",
		"bad b64 header": "!!!." + b64json(stdClaims("")) + ".AAAA",
		"header not obj": base64.RawURLEncoding.EncodeToString([]byte("[1]")) + "." + b64json(stdClaims("")) + ".AAAA",
		"whitespace":     "a .b.c",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.VerifyAccessTokenLocal(context.Background(), tok, lvOpts(clock, LocalVerifyOptions{}))
			wantReason(t, err, "malformed")
		})
	}
	_, err := c.VerifyAccessTokenLocal(context.Background(), strings.Repeat("a", 20000)+".b.c", lvOpts(clock, LocalVerifyOptions{}))
	wantReason(t, err, "too_large")
	if j.n() != 0 {
		t.Fatalf("jwks fetches = %d — a malformed token must be rejected before any network call", j.n())
	}
}

func TestLocalVerifyErrorNeverLeaksTheToken(t *testing.T) {
	c, _, clock := lvSetup(t)
	tok := signRS(lvKey2, stdHeader(), stdClaims(""))
	_, err := c.VerifyAccessTokenLocal(context.Background(), tok, lvOpts(clock, LocalVerifyOptions{}))
	if err == nil || strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), "user-1") {
		t.Fatalf("error %q must not contain the token or claim values", err)
	}
}

// ---- the documented difference: ValidateToken is NOT local ----

func TestValidateTokenStillAsksTheServerForALocallyValidToken(t *testing.T) {
	// A token that verifies locally but whose SESSION is gone at the service
	// (logout): ValidateToken must report the service's answer, not the local one.
	lvKeys(t)
	j := &jwksDouble{keys: []JWK{rsaJWK("k1", &lvKey1.PublicKey)}}
	var validateCalls int
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/validate-token" {
			validateCalls++
			writeJSON(w, 200, map[string]any{"valid": false, "error": "Session not found or expired"})
			return
		}
		j.handler(t)(w, r)
	})
	clock := &testClock{now: lvNow}
	c.jwks.now = clock.Now
	tok := signRS(lvKey1, stdHeader(), stdClaims(""))

	if _, err := c.VerifyAccessTokenLocal(context.Background(), tok, lvOpts(clock, LocalVerifyOptions{})); err != nil {
		t.Fatalf("local verify: %v", err)
	}
	a, err := c.ValidateToken(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if a.Valid || validateCalls != 1 {
		t.Fatalf("ValidateToken valid=%v calls=%d — it must ask the service (session-backed), not verify locally", a.Valid, validateCalls)
	}
}
