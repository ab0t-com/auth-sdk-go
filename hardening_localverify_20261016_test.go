package authclient

// hardening_localverify_20261016_test.go — attacks on VerifyAccessTokenLocal
// (v0.12.0) beyond localverify_test.go: header-embedded keys, signature
// re-encoding, kid storms under concurrency, cooldown during a JWKS outage,
// exact ±1 s leeway boundaries, size boundary, key-parameter edge cases.
//
// Tests that expose a defect are in hardening_knownbugs_20261016_test.go.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	lv2047Once sync.Once
	lv2047     *rsa.PrivateKey
)

func key2047(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	lv2047Once.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2047)
		if err != nil {
			panic(err)
		}
		lv2047 = k
	})
	if lv2047.N.BitLen() != 2047 {
		t.Fatalf("generated modulus is %d bits, want 2047", lv2047.N.BitLen())
	}
	return lv2047
}

func verifyAt(t *testing.T, c *Client, clock *testClock, tok string, o LocalVerifyOptions) error {
	t.Helper()
	_, err := c.VerifyAccessTokenLocal(context.Background(), tok, lvOpts(clock, o))
	return err
}

func TestHardening_LV_HeaderEmbeddedKeysAreNeverTrusted(t *testing.T) {
	c, j, clock := lvSetup(t)
	var attackerHits int32
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attackerHits, 1)
		writeJSON(w, 200, JWKS{Keys: []JWK{rsaJWK("k1", &lvKey2.PublicKey)}})
	}))
	defer attacker.Close()
	evilJWK := rsaJWK("k1", &lvKey2.PublicKey)
	for name, hdr := range map[string]map[string]any{
		"jwk":            with(stdHeader(), "jwk", evilJWK),
		"jku":            with(stdHeader(), "jku", attacker.URL+"/.well-known/jwks.json"),
		"x5u":            with(stdHeader(), "x5u", attacker.URL+"/cert.pem"),
		"jku+jwk+newkid": with(stdHeader(), "kid", "attacker", "jwk", evilJWK, "jku", attacker.URL),
	} {
		t.Run(name, func(t *testing.T) {
			tok := signRS(lvKey2, hdr, stdClaims("")) // signed with the ATTACKER's key
			err := verifyAt(t, c, clock, tok, LocalVerifyOptions{})
			if err == nil {
				t.Fatal("ACCEPTED a token signed by a key supplied in its own header")
			}
			if !errors.Is(err, ErrInvalidAccessToken) {
				t.Fatalf("err %v, want an invalid-token verdict", err)
			}
		})
	}
	if n := atomic.LoadInt32(&attackerHits); n != 0 {
		t.Fatalf("verifier contacted the attacker-named URL %d times", n)
	}
	if j.n() > 2 {
		t.Fatalf("jwks fetches = %d, want ≤ 2", j.n())
	}
}

func TestHardening_LV_RS256HeaderWithHMACSignatureIsBadSignature(t *testing.T) {
	// alg says RS256 (passes the alg gate), but the "signature" is an HMAC keyed
	// with the public key's modulus, DER, and JWK JSON — every common confusion.
	c, _, clock := lvSetup(t)
	jwk := rsaJWK("k1", &lvKey1.PublicKey)
	jwkJSON, _ := json.Marshal(jwk)
	for name, secret := range map[string][]byte{
		"n":       []byte(jwk.N),
		"n-bytes": lvKey1.PublicKey.N.Bytes(),
		"jwk":     jwkJSON,
	} {
		signing := b64json(stdHeader()) + "." + b64json(stdClaims(""))
		mac := hmacSHA256(secret, []byte(signing))
		tok := signing + "." + base64.RawURLEncoding.EncodeToString(mac)
		err := verifyAt(t, c, clock, tok, LocalVerifyOptions{})
		wantReasonNamed(t, name, err, "bad_signature")
	}
}

func wantReasonNamed(t *testing.T, name string, err error, reason string) {
	t.Helper()
	var ae *AccessTokenError
	if err == nil || !errors.As(err, &ae) || ae.Reason != reason {
		t.Fatalf("%s: err = %v, want reason %q", name, err, reason)
	}
}

func TestHardening_LV_StructuralAttacksRejectedWithoutNetwork(t *testing.T) {
	c, j, clock := lvSetup(t)
	good := signRS(lvKey1, stdHeader(), stdClaims(""))
	p := strings.Split(good, ".")
	noneHdr := b64json(map[string]any{"alg": "none", "kid": "k1"})
	for name, tok := range map[string]string{
		"alg none, empty sig":  noneHdr + "." + p[1] + ".",
		"alg none, no sig dot": noneHdr + "." + p[1],
		"JWE 5 segments":       p[0] + "." + p[1] + "." + p[2] + ".x.y",
		"4 segments":           good + ".x",
		"newline inside":       p[0] + "\n." + p[1] + "." + p[2],
		"empty header":         "." + p[1] + "." + p[2],
		"empty payload":        p[0] + ".." + p[2],
		"std base64 (+/)":      strings.ReplaceAll(strings.ReplaceAll(p[0], "-", "+"), "_", "/") + "." + p[1] + "." + p[2] + "+/",
	} {
		err := verifyAt(t, c, clock, tok, LocalVerifyOptions{})
		var ae *AccessTokenError
		if err == nil || !errors.As(err, &ae) {
			t.Fatalf("%s: err = %v, want an invalid-token verdict", name, err)
		}
		if ae.Reason != "malformed" && ae.Reason != "unsupported_alg" {
			t.Fatalf("%s: reason %q, want malformed/unsupported_alg", name, ae.Reason)
		}
	}
	if j.n() != 0 {
		t.Fatalf("jwks fetched %d times for structurally invalid tokens, want 0", j.n())
	}
	// crit present in ANY form (even empty list / null) is rejected.
	for _, crit := range []any{[]string{}, "exp", map[string]any{}} {
		err := verifyAt(t, c, clock, signRS(lvKey1, with(stdHeader(), "crit", crit), stdClaims("")), LocalVerifyOptions{})
		wantReasonNamed(t, fmt.Sprintf("crit=%v", crit), err, "unsupported_header")
	}
}

func TestHardening_LV_SignatureWithExtraLeadingZeroRejected(t *testing.T) {
	c, _, clock := lvSetup(t)
	good := signRS(lvKey1, stdHeader(), stdClaims(""))
	p := strings.Split(good, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(p[2])
	for name, s := range map[string][]byte{
		"leading 0x00":  append([]byte{0}, sig...),
		"trailing 0x00": append(append([]byte{}, sig...), 0),
		"truncated":     sig[1:],
	} {
		tok := p[0] + "." + p[1] + "." + base64.RawURLEncoding.EncodeToString(s)
		wantReasonNamed(t, name, verifyAt(t, c, clock, tok, LocalVerifyOptions{}), "bad_signature")
	}
}

func TestHardening_LV_ConcurrentUnknownKidStormIsOneRefetch(t *testing.T) {
	c, j, clock := lvSetup(t)
	ctx := context.Background()
	if _, err := c.VerifyAccessTokenLocal(ctx, signRS(lvKey1, stdHeader(), stdClaims("")), lvOpts(clock, LocalVerifyOptions{})); err != nil {
		t.Fatal(err)
	}
	// Pre-sign a pool of tokens with random kids (signing is the slow part).
	toks := make([]string, 16)
	for i := range toks {
		toks[i] = signRS(lvKey2, with(stdHeader(), "kid", fmt.Sprintf("rand-%d", i)), stdClaims(""))
	}
	var wg sync.WaitGroup
	var wrong int32
	for g := 0; g < 64; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 8; i++ {
				_, err := c.VerifyAccessTokenLocal(ctx, toks[(g+i)%len(toks)], lvOpts(clock, LocalVerifyOptions{}))
				var ae *AccessTokenError
				if !errors.As(err, &ae) || ae.Reason != "unknown_kid" {
					atomic.AddInt32(&wrong, 1)
				}
			}
		}(g)
	}
	wg.Wait()
	if wrong != 0 {
		t.Fatalf("%d verifications did not answer unknown_kid", wrong)
	}
	if j.n() != 2 {
		t.Fatalf("jwks fetches = %d after 512 concurrent random-kid tokens, want 2 (warm + one cooldown-bounded refetch)", j.n())
	}
	// A valid k1 token still verifies during the storm window, with no fetch.
	if err := verifyAt(t, c, clock, signRS(lvKey1, stdHeader(), stdClaims("")), LocalVerifyOptions{}); err != nil || j.n() != 2 {
		t.Fatalf("valid token after storm: err=%v fetches=%d", err, j.n())
	}
}

func TestHardening_LV_CooldownHoldsWhileJWKSIsDown(t *testing.T) {
	c, j, clock := lvSetup(t)
	good := signRS(lvKey1, stdHeader(), stdClaims(""))
	if err := verifyAt(t, c, clock, good, LocalVerifyOptions{}); err != nil {
		t.Fatal(err)
	}
	j.mu.Lock()
	j.status = 503
	j.mu.Unlock()
	unknown := signRS(lvKey2, with(stdHeader(), "kid", "new"), stdClaims(""))
	wantReason(t, verifyAt(t, c, clock, unknown, LocalVerifyOptions{}), "unknown_kid")
	if j.n() != 2 {
		t.Fatalf("fetches = %d, want 2 (the forced refetch was attempted)", j.n())
	}
	for i := 0; i < 30; i++ {
		clock.advance(time.Second)
		wantReason(t, verifyAt(t, c, clock, unknown, LocalVerifyOptions{}), "unknown_kid")
		if err := verifyAt(t, c, clock, good, LocalVerifyOptions{}); err != nil {
			t.Fatalf("known-kid token rejected during JWKS outage: %v", err)
		}
	}
	if j.n() != 2 {
		t.Fatalf("fetches = %d during a JWKS outage inside the cooldown, want still 2 — a failing service must not be hammered", j.n())
	}
}

func TestHardening_LV_TimeBoundariesExactlyPlusMinusOneSecond(t *testing.T) {
	c, _, clock := lvSetup(t)
	tok := func(kv ...any) string {
		return signRS(lvKey1, stdHeader(), with(stdClaims(""), kv...))
	}
	sec := func(d int) int64 { return lvNow.Add(time.Duration(d) * time.Second).Unix() }
	for _, tc := range []struct {
		name   string
		leeway time.Duration
		claim  string
		off    int // seconds relative to now
		accept bool
	}{
		// exp: accepted while now < exp+leeway
		{"exp default -29", 0, "exp", -29, true},
		{"exp default -30", 0, "exp", -30, false},
		{"exp default -31", 0, "exp", -31, false},
		{"exp 10s -9", 10 * time.Second, "exp", -9, true},
		{"exp 10s -10", 10 * time.Second, "exp", -10, false},
		{"exp 60s -59", 60 * time.Second, "exp", -59, true},
		{"exp 60s -60", 60 * time.Second, "exp", -60, false},
		{"exp 61s→60 -60", 61 * time.Second, "exp", -60, false},
		{"exp none +1", -1, "exp", 1, true},
		{"exp none 0", -1, "exp", 0, false},
		// nbf: accepted while nbf <= now+leeway
		{"nbf default +30", 0, "nbf", 30, true},
		{"nbf default +31", 0, "nbf", 31, false},
		{"nbf 10s +10", 10 * time.Second, "nbf", 10, true},
		{"nbf 10s +11", 10 * time.Second, "nbf", 11, false},
		{"nbf 61s→60 +61", 61 * time.Second, "nbf", 61, false},
		{"nbf none 0", -1, "nbf", 0, true},
		{"nbf none +1", -1, "nbf", 1, false},
		// iat: same rule as nbf
		{"iat default +30", 0, "iat", 30, true},
		{"iat default +31", 0, "iat", 31, false},
		{"iat none +1", -1, "iat", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kv := []any{tc.claim, sec(tc.off)}
			if tc.claim != "iat" {
				kv = append(kv, "iat", sec(-60)) // keep iat out of the way
			}
			if tc.claim == "exp" {
				kv[len(kv)-1] = sec(tc.off - 900)
			}
			err := verifyAt(t, c, clock, tok(kv...), LocalVerifyOptions{Leeway: tc.leeway})
			if tc.accept && err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if !tc.accept {
				want := "not_yet_valid"
				if tc.claim == "exp" {
					want = "expired"
				}
				wantReason(t, err, want)
			}
		})
	}
	// Fractional NumericDate: nbf = now + 30.5 s is past the 30 s leeway.
	wantReason(t, verifyAt(t, c, clock, tok("nbf", json.Number(fmt.Sprintf("%d.5", sec(30)))), LocalVerifyOptions{}), "not_yet_valid")
	// Absurd / out-of-range exp values never verify.
	for _, v := range []any{json.Number("1e300"), json.Number("1e19"), json.Number("0"), json.Number("-1"), true, []int{1}} {
		err := verifyAt(t, c, clock, tok("exp", v), LocalVerifyOptions{})
		if err == nil {
			t.Fatalf("exp=%v accepted", v)
		}
	}
}

func TestHardening_LV_IssuerAndAudienceExactness(t *testing.T) {
	c, _, clock := lvSetup(t)
	tok := func(kv ...any) string { return signRS(lvKey1, stdHeader(), with(stdClaims(""), kv...)) }
	for _, iss := range []string{LegacyAccessTokenIssuer + " ", " " + LegacyAccessTokenIssuer, strings.ToUpper(LegacyAccessTokenIssuer),
		c.BaseURL() + "/", strings.TrimPrefix(c.BaseURL(), "http://"), "ab0t-auth-service\x00"} {
		wantReasonNamed(t, fmt.Sprintf("iss=%q", iss), verifyAt(t, c, clock, tok("iss", iss), LocalVerifyOptions{}), "issuer")
	}
	// An Issuers list containing "" never makes a missing iss acceptable.
	wantReasonNamed(t, "iss absent, Issuers={\"\"}", verifyAt(t, c, clock, tok("iss", nil), LocalVerifyOptions{Issuers: []string{""}}), "issuer")

	for _, tc := range []struct {
		aud    any
		want   string
		accept bool
	}{
		{"svc-a", "svc-a", true},
		{[]string{"x", "svc-a", "y"}, "svc-a", true},
		{[]string{"svc-a "}, "svc-a", false},
		{[]string{"SVC-A"}, "svc-a", false},
		{"svc-a svc-b", "svc-a", false}, // a space-joined string is ONE audience
		{[]string{}, "svc-a", false},
		{"", "svc-a", false},
		{[]string{"svc-a"}, "svc-a\x00", false},
		{map[string]any{"svc-a": true}, "svc-a", false},
	} {
		err := verifyAt(t, c, clock, tok("aud", tc.aud), LocalVerifyOptions{Audience: tc.want})
		if tc.accept != (err == nil) {
			t.Fatalf("aud=%v want=%q: err=%v, accept want %v", tc.aud, tc.want, err, tc.accept)
		}
	}
}

func TestHardening_LV_TokenTypeVariants(t *testing.T) {
	c, _, clock := lvSetup(t)
	act := map[string]any{"sub": "agent"}
	for _, typ := range []any{"Refresh", "REFRESH", "refresh ", "access ", "Access", "id", "delegation ", ""} {
		err := verifyAt(t, c, clock, signRS(lvKey1, stdHeader(), with(stdClaims(""), "type", typ, "act", act)), LocalVerifyOptions{AllowDelegation: true})
		if typ == "" {
			if err != nil {
				t.Fatalf("type=\"\" (pre-claim token) rejected: %v", err)
			}
			continue
		}
		wantReasonNamed(t, fmt.Sprintf("type=%q", typ), err, "token_type")
	}
	// act must be an object; a string actor is malformed, never silently dropped.
	err := verifyAt(t, c, clock, signRS(lvKey1, stdHeader(), with(stdClaims(""), "type", "delegation", "act", "agent")), LocalVerifyOptions{AllowDelegation: true})
	wantReason(t, err, "malformed")
}

func TestHardening_LV_KeyParameterEdges(t *testing.T) {
	lvKeys(t)
	k47 := key2047(t)
	e := func(n int64) string { return base64.RawURLEncoding.EncodeToString(big.NewInt(n).Bytes()) }
	base := rsaJWK("k1", &lvKey1.PublicKey)
	mut := func(f func(*JWK)) JWK { k := base; f(&k); return k }
	for name, tc := range map[string]struct {
		key  JWK
		priv *rsa.PrivateKey
	}{
		"2047-bit":       {rsaJWK("k1", &k47.PublicKey), k47},
		"e=1":            {mut(func(k *JWK) { k.E = e(1) }), lvKey1},
		"e=2 (even)":     {mut(func(k *JWK) { k.E = e(2) }), lvKey1},
		"e 5 bytes":      {mut(func(k *JWK) { k.E = base64.RawURLEncoding.EncodeToString([]byte{1, 0, 0, 0, 1}) }), lvKey1},
		"empty n":        {mut(func(k *JWK) { k.N = "" }), lvKey1},
		"kty oct":        {JWK{Kty: "oct", Kid: "k1"}, lvKey1},
		"kty rsa (case)": {mut(func(k *JWK) { k.Kty = "rsa" }), lvKey1},
		"use SIG (case)": {mut(func(k *JWK) { k.Use = "SIG" }), lvKey1},
	} {
		t.Run(name, func(t *testing.T) {
			c, j, clock := lvSetup(t)
			j.set(tc.key)
			wantReason(t, verifyAt(t, c, clock, signRS(tc.priv, stdHeader(), stdClaims("")), LocalVerifyOptions{}), "unsupported_key")
		})
	}
	// A modulus with a leading zero byte is still a 2048-bit key: accepted.
	c, j, clock := lvSetup(t)
	lz := base
	lz.N = base64.RawURLEncoding.EncodeToString(append([]byte{0}, lvKey1.PublicKey.N.Bytes()...))
	j.set(lz)
	if err := verifyAt(t, c, clock, signRS(lvKey1, stdHeader(), stdClaims("")), LocalVerifyOptions{}); err != nil {
		t.Fatalf("leading-zero modulus rejected: %v", err)
	}
	// Two keys with the same kid: the first listed decides (a weak first key fails closed).
	c2, j2, clock2 := lvSetup(t)
	j2.set(rsaJWK("k1", &lvWeak.PublicKey), base)
	wantReason(t, verifyAt(t, c2, clock2, signRS(lvKey1, stdHeader(), stdClaims("")), LocalVerifyOptions{}), "unsupported_key")
}

func TestHardening_LV_SizeBoundaryIsInclusive(t *testing.T) {
	c, _, clock := lvSetup(t)
	const sigLen = 342 // RS256 / 2048-bit signature, base64url
	hdrFor := func(hpad int) map[string]any { return with(stdHeader(), "x", strings.Repeat("h", hpad)) }
	clFor := func(pad int) map[string]any { return with(stdClaims(""), "pad", strings.Repeat("p", pad)) }
	length := func(hpad, pad int) int { return len(b64json(hdrFor(hpad))) + 1 + len(b64json(clFor(pad))) + 1 + sigLen }
	var at, over string
	for hpad := 0; hpad < 4 && (at == "" || over == ""); hpad++ {
		for pad := 11000; pad < 13000; pad++ {
			switch length(hpad, pad) {
			case maxLocalVerifyTokenBytes:
				if at == "" {
					at = signRS(lvKey1, hdrFor(hpad), clFor(pad))
				}
			case maxLocalVerifyTokenBytes + 1:
				if over == "" {
					over = signRS(lvKey1, hdrFor(hpad), clFor(pad))
				}
			}
		}
	}
	if len(at) != maxLocalVerifyTokenBytes || len(over) != maxLocalVerifyTokenBytes+1 {
		t.Fatalf("constructed lengths %d / %d", len(at), len(over))
	}
	if at == "" || over == "" {
		t.Fatalf("could not construct tokens of exactly %d and %d bytes", maxLocalVerifyTokenBytes, maxLocalVerifyTokenBytes+1)
	}
	if err := verifyAt(t, c, clock, at, LocalVerifyOptions{}); err != nil {
		t.Fatalf("a correctly signed %d-byte token (the documented limit) was rejected: %v", len(at), err)
	}
	wantReason(t, verifyAt(t, c, clock, over, LocalVerifyOptions{}), "too_large")
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
