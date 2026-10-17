package authclient

// hardening_knownbugs_20261016_test.go — tests written 2026-10-16 that FAIL on
// v0.12.1 because they expose a defect. Each is skipped by default (so `make
// check` stays a meaningful gate for everything else) and names its ticket.
// Run them — and watch them go red — with:
//
//	AUTH_SDK_RUN_KNOWN_BUGS=1 go test -run TestKnownBug -v .
//
// When a ticket is fixed, delete its skip line: the test becomes the regression gate.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func knownBug(t *testing.T, ticket string) {
	t.Helper()
	if os.Getenv("AUTH_SDK_RUN_KNOWN_BUGS") == "" {
		t.Skipf("KNOWN BUG — %s (set AUTH_SDK_RUN_KNOWN_BUGS=1 to run)", ticket)
	}
}

const ticketLV = "tickets/20261016_test_hardening_findings/TICKET.md F-1"
const ticketSig = "tickets/20261016_test_hardening_findings/TICKET.md F-2"
const ticketBound = "tickets/20261016_test_hardening_findings/TICKET.md F-3"

// F-1: a NumericDate beyond int64 seconds wraps to the distant past, so an
// nbf / iat far in the future reads as "long ago" and passes.
func TestKnownBug_LV_HugeNotBeforeWrapsIntoThePast(t *testing.T) {
	// F-1 FIXED in v0.12.2 — always runs now (RED on the published v0.12.1, GREEN after).
	c, _, clock := lvSetup(t)
	for _, claim := range []string{"nbf", "iat"} {
		for _, v := range []string{"1e19", "9.3e18", "1e300"} {
			tok := signRS(lvKey1, stdHeader(), with(stdClaims(""), claim, json.Number(v)))
			_, err := c.VerifyAccessTokenLocal(context.Background(), tok, lvOpts(clock, LocalVerifyOptions{}))
			if err == nil {
				t.Errorf("%s=%s (far future) ACCEPTED — want not_yet_valid or malformed", claim, v)
			}
		}
	}
}

// F-2: the signature segment is decoded leniently (trailing '=' stripped,
// non-zero padding bits ignored), so one signed token has many accepted string
// forms. Anything keyed on the token string (a deny-list, the SDK's own
// validation cache, a replay set) sees them as different tokens.
func TestKnownBug_LV_SignatureSegmentIsMalleable(t *testing.T) {
	// F-2 FIXED in v0.12.2 — always runs now.
	c, _, clock := lvSetup(t)
	good := signRS(lvKey1, stdHeader(), stdClaims(""))
	p := strings.Split(good, ".")
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := p[2][len(p[2])-1]
	idx := strings.IndexByte(alpha, last)
	alt := alpha[idx^1] // flips a padding bit only: decodes to the same bytes in non-strict mode
	variants := map[string]string{
		"trailing '='":          good + "=",
		"trailing '=='":         good + "==",
		"non-canonical last ch": p[0] + "." + p[1] + "." + p[2][:len(p[2])-1] + string(alt),
	}
	orig, _ := base64.RawURLEncoding.DecodeString(p[2])
	altDec, _ := base64.RawURLEncoding.DecodeString(p[2][:len(p[2])-1] + string(alt))
	if string(orig) != string(altDec) {
		t.Fatalf("test construction: the altered signature decodes differently — not a malleability probe")
	}
	for name, tok := range variants {
		if tok == good {
			t.Fatalf("%s: variant identical to original", name)
		}
		if _, err := c.VerifyAccessTokenLocal(context.Background(), tok, lvOpts(clock, LocalVerifyOptions{})); err == nil {
			t.Errorf("%s: a re-encoded copy of a signed token was ACCEPTED — want malformed (RFC 7515 base64url, no padding, canonical)", name)
		}
	}
}

// F-3: the validation cache bound (MaxEntries; 4096 by default) is exceeded by
// concurrent cold misses — in-flight entries cannot be evicted — and is not
// restored afterwards: each later insert evicts at most ONE live entry.
func TestKnownBug_ValidationCacheBoundExceededUnderConcurrency(t *testing.T) {
	// F-3 FIXED in v0.12.2 — always runs now.
	release := make(chan struct{})
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		writeJSON(w, 200, map[string]any{"valid": true, "user_id": "u"})
	}, WithMaxRetries(0), WithValidationCacheOptions(ValidationCacheOptions{TTL: time.Minute, MaxEntries: 4}))
	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = c.ValidateToken(context.Background(), fmt.Sprintf("%s%d", testJWT, i))
		}(i)
	}
	// sample the map while the burst is in flight (with the bound enforced it never reaches n, so watch for a
	// fixed window rather than waiting for n entries)
	peak := 0
	for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if e := c.ValidationCacheStats().Entries; e > peak {
			peak = e
		}
	}
	close(release)
	wg.Wait()
	for i := 0; i < 3; i++ { // later, ordinary inserts
		_, _ = c.ValidateToken(context.Background(), fmt.Sprintf("%slater%d", testJWT, i))
	}
	after := c.ValidationCacheStats().Entries
	if peak > 4 || after > 4 {
		t.Errorf("MaxEntries=4: peak %d entries during the burst, %d after it and 3 more inserts — the bound is not enforced", peak, after)
	}
}
