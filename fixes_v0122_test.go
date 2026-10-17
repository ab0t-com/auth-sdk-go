package authclient

// v0.12.2 — the edges of the F-1 / F-2 / F-3 fixes that the known-bug tests do not pin
// (tickets/20261016_test_hardening_findings/TICKET.md).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// F-1: the cut-off is the year 9999. At the edge a NumericDate is still a date (a far nbf is "not yet valid", not
// "malformed"); one second past it is malformed; a far exp is refused as malformed instead of reading as expired
// by accident; an ordinary token still verifies.
func TestV0122_NumericDateRange(t *testing.T) {
	c, _, clock := lvSetup(t)
	verify := func(claims map[string]any) error {
		_, err := c.VerifyAccessTokenLocal(context.Background(), signRS(lvKey1, stdHeader(), claims), lvOpts(clock, LocalVerifyOptions{}))
		return err
	}
	if err := verify(stdClaims("")); err != nil {
		t.Fatalf("an ordinary token was refused: %v", err)
	}
	wantReason(t, verify(with(stdClaims(""), "nbf", json.Number("253402300799"))), "not_yet_valid")
	wantReason(t, verify(with(stdClaims(""), "nbf", json.Number("253402300800"))), "malformed")
	wantReason(t, verify(with(stdClaims(""), "iat", json.Number("1e19"))), "malformed")
	wantReason(t, verify(with(stdClaims(""), "exp", json.Number("1e300"))), "malformed")
}

// F-2: every token segment is strict (no padding, canonical). The header and payload are covered too; the JWKS key
// fields stay lenient, so a key served with padding still verifies tokens.
func TestV0122_TokenSegmentsStrict_KeysLenient(t *testing.T) {
	c, _, clock := lvSetup(t)
	good := signRS(lvKey1, stdHeader(), stdClaims(""))
	p := strings.Split(good, ".")
	verify := func(tok string) error {
		_, err := c.VerifyAccessTokenLocal(context.Background(), tok, lvOpts(clock, LocalVerifyOptions{}))
		return err
	}
	if err := verify(good); err != nil {
		t.Fatalf("the canonical token was refused: %v", err)
	}
	for _, tok := range []string{
		p[0] + "=." + p[1] + "." + p[2],                       // padded header
		p[0] + "." + p[1] + "=." + p[2],                       // padded payload
		p[0] + "." + p[1] + "." + p[2][:10] + "=" + p[2][10:], // '=' inside the signature
	} {
		wantReason(t, verify(tok), "malformed")
	}

	// a JWKS whose n is served WITH base64 padding still loads (only token segments are strict). The JWKS is
	// fetched lazily, so setting the double's keys before the first verify means the padded key is the one served.
	k := rsaJWK("k1", &lvKey1.PublicKey)
	if len(k.N)%4 == 0 {
		t.Fatal("test construction: a 2048-bit modulus should need padding")
	}
	for len(k.N)%4 != 0 {
		k.N += "="
	}
	c2, jd2, clock2 := lvSetup(t)
	jd2.set(k)
	if _, err := c2.VerifyAccessTokenLocal(context.Background(), good, lvOpts(clock2, LocalVerifyOptions{})); err != nil {
		t.Fatalf("a JWKS key with padded n no longer loads: %v", err)
	}
	if jd2.n() == 0 {
		t.Fatal("the padded JWKS was never fetched — the check above proved nothing")
	}
}

// F-3: the bound holds during AND after a burst of concurrent cold misses, and evicting an in-flight entry never
// costs a caller its answer — every one of the burst's callers still gets the service's "valid".
func TestV0122_CacheBoundHoldsAndEveryCallerAnswered(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int64
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-release
		writeJSON(w, 200, map[string]any{"valid": true, "user_id": "u"})
	}, WithMaxRetries(0), WithValidationCacheOptions(ValidationCacheOptions{TTL: time.Minute, MaxEntries: 4}))

	const n = 40
	var wg sync.WaitGroup
	var answered atomic.Int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a, err := c.ValidateToken(context.Background(), fmt.Sprintf("%sburst%d", testJWT, i))
			if err == nil && a != nil && a.Valid {
				answered.Add(1)
			}
		}(i)
	}
	peak := 0
	for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if e := c.ValidationCacheStats().Entries; e > peak {
			peak = e
		}
	}
	close(release)
	wg.Wait()
	if peak > 4 {
		t.Errorf("MaxEntries=4 exceeded during the burst: peak %d", peak)
	}
	if e := c.ValidationCacheStats().Entries; e > 4 {
		t.Errorf("MaxEntries=4 exceeded after the burst: %d", e)
	}
	if answered.Load() != n {
		t.Errorf("only %d of %d burst callers got their answer — evicting an in-flight entry cost a caller its result", answered.Load(), n)
	}
	if calls.Load() != n {
		t.Errorf("distinct credentials: want exactly %d auth calls, got %d", n, calls.Load())
	}
}
