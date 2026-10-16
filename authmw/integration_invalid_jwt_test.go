//go:build integration

package authmw_test

// integration_invalid_jwt_test.go — authmw against a REAL, LOCAL auth service:
// an invalid JWT is a 401 (never a 503), a storm of one invalid JWT costs at most
// one auth call per negative TTL, and an unreachable auth service is a 503 that
// is not cached. Excluded from `go test ./...` and `make check` by the
// `integration` build tag; it refuses any base URL that is not local.
//
//	AUTH_SDK_IT_BASE_URL=http://localhost:8001 go test -tags integration -run TestIntegrationAuthmw -v ./authmw/
//
// It uses only the Gate API that predates v0.12.1, so the same file can be run
// against older middleware. Note what it can and cannot show: an auth service
// that answers an invalid JWT with 200 {"valid":false} gives 401 on every
// version; the 503-for-an-invalid-JWT defect needs a service that answers HTTP
// 401, which the unit tests (invalid_credential_test.go) script directly.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/ab0t-com/auth-sdk-go"
	"github.com/ab0t-com/auth-sdk-go/authmw"
)

func itBase(t *testing.T) string {
	t.Helper()
	base := os.Getenv("AUTH_SDK_IT_BASE_URL")
	if base == "" {
		base = "http://localhost:8001"
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("AUTH_SDK_IT_BASE_URL %q: %v", base, err)
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1", "host.docker.internal":
	default:
		t.Fatalf("REFUSING: %s is not a local auth service", base)
	}
	return strings.TrimRight(base, "/")
}

// itEngine reports which engine answers at base (for the log only) and SKIPs
// with VOID when the service or its dependencies are not healthy: an unhealthy
// fixture is not a verdict on the SDK.
func itEngine(t *testing.T, base string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/health", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Skipf("VOID: %s/health unreachable: %v", base, err)
	}
	defer resp.Body.Close()
	var h struct {
		Status       string            `json:"status"`
		Version      string            `json:"version"`
		Dependencies map[string]string `json:"dependencies"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&h)
	if resp.StatusCode != 200 {
		t.Skipf("VOID: %s/health = %d", base, resp.StatusCode)
	}
	for dep, st := range h.Dependencies {
		if st != "healthy" {
			t.Skipf("VOID: %s dependency %s is %q", base, dep, st)
		}
	}
	return h.Version
}

// validateCounter counts the client's validate-token / validate-api-key HTTP
// attempts and the statuses the service answered them with.
type validateCounter struct {
	mu       sync.Mutex
	n        int
	statuses map[int]int
}

func (v *validateCounter) observe(i auth.RequestInfo) {
	if i.Endpoint != "/auth/validate-token" && i.Endpoint != "/auth/validate-api-key" {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.n++
	if v.statuses == nil {
		v.statuses = map[int]int{}
	}
	v.statuses[i.Status]++
}

func (v *validateCounter) count() (int, map[int]int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	cp := map[int]int{}
	for k, n := range v.statuses {
		cp[k] = n
	}
	return v.n, cp
}

// garbageJWT is well-formed (three base64url segments, RS256 header, sub, exp
// in the future, the auth service's issuer) but signed by nobody. Unique per call.
func garbageJWT(t *testing.T) string {
	t.Helper()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "sdk-it-garbage"})
	p, _ := json.Marshal(map[string]any{
		"sub": "sdk-it-nobody-" + enc(nonce[:6]), "type": "access", "iss": auth.LegacyAccessTokenIssuer,
		"exp": time.Now().Add(10 * time.Minute).Unix(), "iat": time.Now().Unix(), "jti": enc(nonce),
	})
	return enc(h) + "." + enc(p) + "." + enc(append(nonce, nonce...))
}

func send(h http.Handler, authorization string) int {
	req, _ := http.NewRequest(http.MethodGet, "http://svc.local/x", nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := &statusRecorder{header: http.Header{}}
	h.ServeHTTP(rec, req)
	return rec.code
}

type statusRecorder struct {
	header http.Header
	code   int
}

func (r *statusRecorder) Header() http.Header         { return r.header }
func (r *statusRecorder) Write(b []byte) (int, error) { r.WriteHeader(200); return len(b), nil }
func (r *statusRecorder) WriteHeader(c int) {
	if r.code == 0 {
		r.code = c
	}
}

func okHandler(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }

func TestIntegrationAuthmw_InvalidJWTIs401(t *testing.T) {
	base := itBase(t)
	engine := itEngine(t, base)
	vc := &validateCounter{}
	client := auth.New(base, auth.WithMaxRetries(0), auth.WithObserver(vc.observe)) // default cache, as a service builds it
	gate := &authmw.Gate{V: client, A: client}

	bad := garbageJWT(t)
	code := send(gate.Authenticate(http.HandlerFunc(okHandler)), "Bearer "+bad)
	_, statuses := vc.count()
	t.Logf("[%s %s] garbage JWT -> authmw %d; the service answered validate-token with %v (HTTP status -> count)", base, engine, code, statuses)
	if code != http.StatusUnauthorized {
		t.Errorf("[%s] garbage JWT: authmw said %d, want 401 — an invalid credential is never 'auth unavailable'", base, code)
	}
	// Require on another bad JWT (uncached): a denial, never a 503.
	if code := send(gate.Require("users.read", "", okHandler), "Bearer "+garbageJWT(t)); code == http.StatusServiceUnavailable || code < 400 {
		t.Errorf("[%s] Require with a garbage JWT: %d, want a 401/403 denial", base, code)
	}
}

func TestIntegrationAuthmw_BadJWTStormCostsAtMostOneCall(t *testing.T) {
	base := itBase(t)
	engine := itEngine(t, base)
	vc := &validateCounter{}
	client := auth.New(base, auth.WithMaxRetries(0), auth.WithObserver(vc.observe))
	h := (&authmw.Gate{V: client, A: client}).Authenticate(http.HandlerFunc(okHandler))

	bad := garbageJWT(t)
	const n = 10
	for i := 0; i < n; i++ {
		if code := send(h, "Bearer "+bad); code != http.StatusUnauthorized {
			t.Errorf("[%s] request %d: %d, want 401", base, i, code)
		}
	}
	calls, statuses := vc.count()
	t.Logf("[%s %s] %d identical garbage JWTs -> validate calls = %d (statuses %v)", base, engine, n, calls, statuses)
	if calls > 1 {
		t.Errorf("[%s] %d auth calls for %d identical invalid JWTs inside the negative TTL, want <= 1", base, calls, n)
	}
}

func TestIntegrationAuthmw_UnreachableAuthIs503AndNotCached(t *testing.T) {
	itBase(t) // same locality guard, no service needed
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "http://" + l.Addr().String()
	l.Close() // nothing listens there now: connection refused
	vc := &validateCounter{}
	client := auth.New(dead, auth.WithMaxRetries(0), auth.WithTimeout(3*time.Second), auth.WithObserver(func(i auth.RequestInfo) {
		if i.Endpoint == "/auth/validate-token" {
			vc.mu.Lock()
			vc.n++
			vc.mu.Unlock()
		}
	}))
	gate := &authmw.Gate{V: client, A: client}
	h := gate.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	bad := garbageJWT(t)
	for i := 0; i < 3; i++ {
		if code := send(h, "Bearer "+bad); code != http.StatusServiceUnavailable {
			t.Fatalf("auth unreachable, request %d: %d, want 503", i, code)
		}
	}
	if n, _ := vc.count(); n != 3 {
		t.Errorf("validate attempts = %d for 3 requests while unreachable, want 3 — a failure must never be cached", n)
	}
	t.Logf("auth unreachable at %s: 3 requests -> 503 each, 3 validate attempts (not cached)", dead)
}
