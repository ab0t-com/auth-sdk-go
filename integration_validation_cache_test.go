//go:build integration

package authclient

// integration_validation_cache_test.go — the v0.12.0 revocation-latency contract,
// measured against a REAL, LOCAL auth service. Excluded from `go test ./...` and
// `make check` by the `integration` build tag.
//
//	AUTH_SDK_IT_BASE_URL=http://localhost:8001 go test -tags integration -run TestIntegration -v .
//
// Each test creates its own throwaway founder, organization and member, so the
// three run in parallel and leave nothing shared behind. They refuse any base URL
// that is not local (never run them against production).
//
// What is asserted, per test, with an ε of a few seconds for polling + setup:
//
//	TestIntegrationRevokedAPIKey      a deleted API key keeps validating in a DEFAULT client
//	                                  for its 60 s TTL (documented latency), then stops —
//	                                  within 60 s + ε of the cache entry being written;
//	                                  WithFreshValidation and WithValidationCache(0) see the
//	                                  revocation immediately.
//	TestIntegrationRevokedPermission  a revoked permission keeps being allowed for ≤ 15 s + ε
//	                                  (unscoped AND resource-scoped Authorize), then denied;
//	                                  fresh / opted-out clients see it immediately.
//	TestIntegrationLogout             after logout ValidateToken stops within 15 s + ε, while
//	                                  VerifyAccessTokenLocal STILL ACCEPTS the token (until its
//	                                  exp) — the documented difference between the two.
//
// A failure to build the fixture (register, org, login, key mint, grant) is not a
// verdict on the SDK: the test SKIPs with a "VOID:" message. Only an assertion on
// the contract above FAILs.

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const itEpsilon = 4 * time.Second

func itBaseURL(t *testing.T) string {
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
		t.Fatalf("REFUSING: %s is not a local auth service — these tests create users and revoke credentials", base)
	}
	return strings.TrimRight(base, "/")
}

// itFixture is one founder (org admin) + one member in a fresh organization.
type itFixture struct {
	base       string
	setup      *Client // cache OFF: fixture calls must never be cached
	orgID      string
	slug       string
	adminToken string // founder, org-scoped
	memberID   string
	memberMail string
	memberPass string
}

func void(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Skipf("VOID: "+format, args...)
}

func newFixture(t *testing.T, tag string) *itFixture {
	t.Helper()
	base := itBaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f := &itFixture{base: base, setup: New(base, WithValidationCache(0), WithMaxRetries(1))}
	ts := time.Now().UnixNano()
	fMail := fmt.Sprintf("sdkit_%s_founder_%d@test-uj.example.com", tag, ts)
	fPass := fmt.Sprintf("Founder!Aa%d", ts)

	reg, err := f.setup.Register(ctx, RegisterRequest{Email: fMail, Password: fPass, Name: "SDK IT Founder"})
	if err != nil || reg.AccessToken == "" {
		void(t, "founder registration failed on %s: %v", base, err)
	}
	f.slug = fmt.Sprintf("sdkit-%s-%d", tag, ts)
	org, err := f.setup.CreateOrganization(ctx, OrganizationCreate{Name: "SDK IT " + tag, Slug: f.slug}, reg.AccessToken)
	if err != nil || org.ID == "" {
		void(t, "org create failed: %v", err)
	}
	f.orgID = org.ID
	adm, err := f.setup.Login(ctx, LoginRequest{Email: fMail, Password: fPass, OrgID: f.orgID})
	if err != nil || adm.AccessToken == "" {
		void(t, "founder org-scoped login failed: %v", err)
	}
	f.adminToken = adm.AccessToken

	f.memberMail = fmt.Sprintf("sdkit_%s_member_%d@test-uj.example.com", tag, ts)
	f.memberPass = fmt.Sprintf("Member!Aa%d", ts)
	mem, err := f.setup.OrgRegister(ctx, f.slug, OrgRegisterRequest{Email: f.memberMail, Password: f.memberPass, Name: "SDK IT Member"})
	if err != nil || mem.User.ID == "" {
		void(t, "member hosted registration failed: %v", err)
	}
	f.memberID = mem.User.ID
	t.Logf("fixture on %s: org=%s member=%s", base, f.orgID, f.memberID)
	return f
}

func (f *itFixture) memberToken(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ts, err := f.setup.Login(ctx, LoginRequest{Email: f.memberMail, Password: f.memberPass, OrgID: f.orgID})
	if err != nil || ts.AccessToken == "" {
		void(t, "member org-scoped login failed: %v", err)
	}
	return ts.AccessToken
}

// pollUntil calls stopped() every 500 ms until it reports true or the deadline
// passes; it returns when it stopped (zero time if it never did).
func pollUntil(t *testing.T, deadline time.Duration, stopped func() (bool, error)) time.Time {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		done, err := stopped()
		if err != nil {
			t.Fatalf("poll: %v", err)
		}
		if done {
			return time.Now()
		}
		time.Sleep(500 * time.Millisecond)
	}
	return time.Time{}
}

// assertWindow checks the stale window: the default client stopped accepting no
// later than ttl+ε after the cache entry was written, and (lower bound) not before
// ttl−ε — i.e. the cache really held the decision for its documented TTL.
func assertWindow(t *testing.T, what string, populated, revoked, stopped time.Time, ttl time.Duration) {
	t.Helper()
	if stopped.IsZero() {
		t.Fatalf("%s: the default client NEVER stopped accepting within %s — revocation latency unbounded", what, ttl+itEpsilon)
	}
	sincePop, sinceRevoke := stopped.Sub(populated), stopped.Sub(revoked)
	t.Logf("%s: default client stopped %.1fs after revocation (%.1fs after the cache entry was written; TTL %s)",
		what, sinceRevoke.Seconds(), sincePop.Seconds(), ttl)
	if sincePop > ttl+itEpsilon || sinceRevoke > ttl+itEpsilon {
		t.Errorf("%s: stopped %.1fs after revocation / %.1fs after population — want ≤ %s + %s",
			what, sinceRevoke.Seconds(), sincePop.Seconds(), ttl, itEpsilon)
	}
	if sincePop < ttl-itEpsilon {
		t.Errorf("%s: stopped only %.1fs after the entry was written — the default TTL (%s) is not what is cached",
			what, sincePop.Seconds(), ttl)
	}
}

func TestIntegrationRevokedAPIKey(t *testing.T) {
	t.Parallel()
	f := newFixture(t, "key")
	ctx := context.Background()
	key, err := f.setup.CreateAPIKey(ctx, APIKeyCreate{Name: "sdk-it-key", Permissions: []string{"users.read"}}, f.adminToken)
	if err != nil || key.Token == "" || key.ID == "" {
		void(t, "api key mint failed: %v", err)
	}

	dflt := New(f.base, WithMaxRetries(1))  // the v0.12.0 default
	dflt2 := New(f.base, WithMaxRetries(1)) // a second default client, for the fresh bypass
	strict := New(f.base, WithValidationCache(0), WithMaxRetries(1))
	req := ValidateAPIKeyRequest{APIKey: key.Token}

	for _, c := range []*Client{dflt2, dflt} { // dflt last: its entry time is `populated`
		v, err := c.ValidateAPIKey(ctx, req)
		if err != nil || !v.Valid {
			t.Fatalf("fresh key must validate: %+v %v", v, err)
		}
	}
	populated := time.Now()
	if v, err := dflt.ValidateAPIKey(ctx, req); err != nil || !v.Valid {
		t.Fatalf("repeat: %+v %v", v, err)
	}
	if st := dflt.ValidationCacheStats(); !st.Enabled || st.Hits < 1 {
		t.Fatalf("default client stats = %+v — the cache must be ON by default and serve the repeat", st)
	}

	if _, err := f.setup.DeleteAPIKey(ctx, key.ID, f.adminToken); err != nil {
		void(t, "api key revoke failed: %v", err)
	}
	revoked := time.Now()

	// Server truth (no cache) — establishes the service itself revokes promptly.
	if pollUntil(t, 20*time.Second, func() (bool, error) {
		v, err := strict.ValidateAPIKey(ctx, req)
		return err == nil && !v.Valid, nil
	}).IsZero() {
		void(t, "the auth service itself still validates the deleted key after 20 s — cannot attribute latency to the SDK")
	}
	// Documented latency: the default client still accepts right after revocation.
	if v, err := dflt.ValidateAPIKey(ctx, req); err != nil || !v.Valid {
		t.Errorf("default client right after revocation: %+v %v — want the CACHED valid (documented ≤60 s latency)", v, err)
	}
	// Per-call bypass sees it immediately, and refreshes the shared entry.
	if v, err := dflt2.ValidateAPIKey(WithFreshValidation(ctx), req); err != nil || v.Valid {
		t.Errorf("WithFreshValidation right after revocation: %+v %v — want NOT valid", v, err)
	}
	if v, err := dflt2.ValidateAPIKey(ctx, req); err != nil || v.Valid {
		t.Errorf("plain call after the fresh one: %+v %v — the fresh answer must refresh the entry", v, err)
	}

	stopped := pollUntil(t, DefaultAPIKeyValidationTTL+itEpsilon, func() (bool, error) {
		v, err := dflt.ValidateAPIKey(ctx, req)
		if err != nil {
			return false, err
		}
		return !v.Valid, nil
	})
	assertWindow(t, "revoked API key (ValidateAPIKey)", populated, revoked, stopped, DefaultAPIKeyValidationTTL)
}

func TestIntegrationRevokedPermission(t *testing.T) {
	t.Parallel()
	f := newFixture(t, "perm")
	ctx := context.Background()
	const perm = "users.read"
	if _, err := f.setup.GrantPermission(ctx, f.memberID, f.orgID, perm, f.adminToken); err != nil {
		void(t, "grant failed: %v", err)
	}
	tok := f.memberToken(t)
	res := Resource{Type: "doc", ID: "sdk-it-d1"}

	dflt := New(f.base, WithMaxRetries(1))
	dflt2 := New(f.base, WithMaxRetries(1))
	strict := New(f.base, WithValidationCache(0), WithMaxRetries(1))
	both := func(c *Client, ctx context.Context) (bool, bool, error) {
		u, err := c.Authorize(ctx, tok, perm, Resource{})
		if err != nil {
			return false, false, err
		}
		r, err := c.Authorize(ctx, tok, perm, res)
		return u, r, err
	}

	for _, c := range []*Client{dflt2, dflt} {
		u, r, err := both(c, ctx)
		if err != nil || !u || !r {
			void(t, "granted permission not allowed before revocation (unscoped=%v scoped=%v err=%v)", u, r, err)
		}
	}
	populated := time.Now()

	if _, err := f.setup.RevokePermission(ctx, f.memberID, f.orgID, perm, f.adminToken); err != nil {
		void(t, "revoke failed: %v", err)
	}
	revoked := time.Now()

	if pollUntil(t, 20*time.Second, func() (bool, error) {
		u, r, err := both(strict, ctx)
		return err == nil && !u && !r, nil
	}).IsZero() {
		void(t, "the auth service itself still allows the revoked permission after 20 s")
	}
	if u, r, err := both(dflt, ctx); err != nil || !u || !r {
		t.Errorf("default client right after revocation: unscoped=%v scoped=%v err=%v — want the CACHED allow (documented ≤15 s latency)", u, r, err)
	}
	if u, r, err := both(dflt2, WithFreshValidation(ctx)); err != nil || u || r {
		t.Errorf("WithFreshValidation right after revocation: unscoped=%v scoped=%v err=%v — want denied", u, r, err)
	}

	stopped := pollUntil(t, DefaultAuthorizeTTL+itEpsilon, func() (bool, error) {
		u, r, err := both(dflt, ctx)
		if err != nil {
			return false, err
		}
		return !u && !r, nil
	})
	assertWindow(t, "revoked permission (Authorize unscoped + resource-scoped)", populated, revoked, stopped, DefaultAuthorizeTTL)
}

func TestIntegrationLogout(t *testing.T) {
	t.Parallel()
	f := newFixture(t, "logout")
	ctx := context.Background()
	tok := f.memberToken(t)

	dflt := New(f.base, WithMaxRetries(1))  // the v0.12.0 default
	dflt2 := New(f.base, WithMaxRetries(1)) // a second default client, for the fresh bypass
	strict := New(f.base, WithValidationCache(0), WithMaxRetries(1))

	claims, err := dflt.VerifyAccessTokenLocal(ctx, tok, LocalVerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyAccessTokenLocal on a fresh token from %s: %v", f.base, err)
	}
	t.Logf("local verify: sub=%s iss=%s aud=%v exp=%s kid=%s", claims.Subject, claims.Issuer, claims.Audience, claims.ExpiresAt.Format(time.RFC3339), claims.KeyID)
	if claims.Subject != f.memberID || claims.OrgID != f.orgID {
		t.Errorf("local claims sub=%s org=%s, want %s / %s", claims.Subject, claims.OrgID, f.memberID, f.orgID)
	}
	for _, c := range []*Client{dflt2, dflt} { // dflt last: its entry time is `populated`
		if a, err := c.ValidateToken(ctx, tok); err != nil || !a.Valid {
			t.Fatalf("ValidateToken before logout: %+v %v", a, err)
		}
	}
	populated := time.Now()

	if _, err := f.setup.Logout(ctx, tok); err != nil {
		void(t, "logout failed: %v", err)
	}
	revoked := time.Now()

	stoppedFor := func(c *Client, ctx context.Context) (bool, error) {
		a, err := c.ValidateToken(ctx, tok)
		if err != nil {
			if IsUnauthorized(err) {
				return true, nil
			}
			return false, err
		}
		return !a.Valid, nil
	}
	if pollUntil(t, 20*time.Second, func() (bool, error) { return stoppedFor(strict, ctx) }).IsZero() {
		void(t, "the auth service itself still validates the logged-out token after 20 s")
	}
	if done, err := stoppedFor(dflt, ctx); err != nil || done {
		t.Errorf("default client right after logout: stopped=%v err=%v — want the CACHED valid (documented ≤15 s latency)", done, err)
	}
	if done, err := stoppedFor(dflt2, WithFreshValidation(ctx)); err != nil || !done {
		t.Errorf("WithFreshValidation right after logout: stopped=%v err=%v — want invalid", done, err)
	}

	stopped := pollUntil(t, DefaultTokenValidationTTL+itEpsilon, func() (bool, error) { return stoppedFor(dflt, ctx) })
	assertWindow(t, "logged-out session (ValidateToken)", populated, revoked, stopped, DefaultTokenValidationTTL)

	// The documented difference: local verification cannot see logout. The token is
	// logged out at the service (ValidateToken now says so), yet it still verifies
	// locally — and will until its exp.
	lc, err := dflt.VerifyAccessTokenLocal(ctx, tok, LocalVerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyAccessTokenLocal(logged-out token): %v — documented to ACCEPT until exp", err)
	}
	if !lc.ExpiresAt.After(time.Now()) {
		t.Errorf("token exp %s is not in the future", lc.ExpiresAt)
	}
	if done, err := stoppedFor(strict, ctx); err != nil || !done {
		t.Errorf("an uncached ValidateToken must report the logged-out token invalid at the same moment: stopped=%v err=%v", done, err)
	}
	t.Logf("documented difference holds: logged out at the service (ValidateToken=invalid) while VerifyAccessTokenLocal accepts until exp %s (%.0fs from now)",
		lc.ExpiresAt.Format(time.RFC3339), time.Until(lc.ExpiresAt).Seconds())
}
