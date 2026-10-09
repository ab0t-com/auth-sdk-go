package authclient_test

// tokenfor_test.go — TokenFor tested THROUGH the exported token-endpoint fake,
// the way a consumer would test it. Covers: the wire shape of each pattern (and
// of the bridge), client authentication (HTTP Basic, never the service API key),
// caching (key, margin, bound, single flight, no error caching) and the error
// mapping table.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/ab0t-com/auth-sdk-go"
	"github.com/ab0t-com/auth-sdk-go/authclienttest"
)

const (
	tfClientID = "client_app"
	tfSecret   = "s3cr3t-value"
	tfResource = "https://b.service.example"
)

func newTF(t *testing.T, opts ...auth.Option) (*authclienttest.TokenEndpoint, *auth.Client) {
	t.Helper()
	te := authclienttest.NewTokenEndpoint()
	t.Cleanup(te.Close)
	base := []auth.Option{auth.WithClientCredentials(tfClientID, tfSecret), auth.WithMaxRetries(0)}
	return te, auth.New(te.URL(), append(base, opts...)...)
}

// fakeJWT builds an unsigned JWT-shaped token with the given exp (0 = no exp).
func fakeJWT(sub string, exp time.Time) string {
	claims := map[string]any{"sub": sub}
	if !exp.IsZero() {
		claims["exp"] = exp.Unix()
	}
	b, _ := json.Marshal(claims)
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}

func TestTokenFor_RequiresClientCredentials(t *testing.T) {
	c := auth.New("http://127.0.0.1:1")
	if _, err := c.TokenFor(context.Background(), tfResource, "b.read", nil); !errors.Is(err, auth.ErrClientCredentialsRequired) {
		t.Fatalf("got %v, want ErrClientCredentialsRequired", err)
	}
}

// P2: client_credentials + resource + scope, HTTP Basic, and NOT the service API key.
func TestTokenFor_MachineWireShape(t *testing.T) {
	te, c := newTF(t, auth.WithAPIKey("ab0t_sk_service_key"))
	tok, err := c.TokenFor(context.Background(), tfResource, "b.write b.read", nil)
	if err != nil {
		t.Fatal(err)
	}
	reqs := te.Requests()
	if len(reqs) != 1 {
		t.Fatalf("want 1 request, got %d", len(reqs))
	}
	r := reqs[0]
	if r.GrantType != "client_credentials" {
		t.Errorf("grant_type = %q", r.GrantType)
	}
	if r.Form.Get("resource") != tfResource || r.Form.Get("scope") != "b.read b.write" {
		t.Errorf("resource/scope = %q / %q", r.Form.Get("resource"), r.Form.Get("scope"))
	}
	if r.ClientID != tfClientID || r.ClientSecret != tfSecret {
		t.Errorf("Basic client auth missing or wrong: id=%q", r.ClientID)
	}
	if r.APIKey != "" {
		t.Error("the service API key was sent to the token endpoint")
	}
	for _, k := range []string{"client_secret", "subject_token", "actor_token", "audience"} {
		if r.Form.Has(k) {
			t.Errorf("unexpected form field %q", k)
		}
	}
	if tok.AccessToken == "" || tok.Resource != tfResource || tok.Scope != "b.read b.write" || tok.TokenType != "Bearer" {
		t.Errorf("token = %+v", tok)
	}
	if d := time.Until(tok.ExpiresAt); d < 890*time.Second || d > 900*time.Second {
		t.Errorf("ExpiresAt %v from now, want ~900s", d)
	}
}

func TestTokenFor_MachineWithoutResourceOmitsIt(t *testing.T) {
	te, c := newTF(t)
	if _, err := c.TokenFor(context.Background(), "", "", nil); err != nil {
		t.Fatal(err)
	}
	f := te.Requests()[0].Form
	if f.Has("resource") || f.Has("scope") {
		t.Errorf("empty resource/scope must be omitted, form=%v", f)
	}
}

// P3 target shape: client-authenticated exchange, one resource, NO actor_token.
func TestTokenFor_PersonWireShape(t *testing.T) {
	te, c := newTF(t, auth.WithAPIKey("ab0t_sk_service_key"))
	person := fakeJWT("user-1", time.Now().Add(time.Hour))
	if _, err := c.TokenFor(context.Background(), tfResource, "b.read", auth.StaticSession(person)); err != nil {
		t.Fatal(err)
	}
	r := te.Requests()[0]
	want := map[string]string{
		"grant_type":         auth.GrantTypeTokenExchange,
		"subject_token":      person,
		"subject_token_type": auth.TokenTypeAccessToken,
		"resource":           tfResource,
		"scope":              "b.read",
	}
	for k, v := range want {
		if r.Form.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, r.Form.Get(k), v)
		}
	}
	for _, k := range []string{"actor_token", "actor_token_type", "audience", "client_secret"} {
		if r.Form.Has(k) {
			t.Errorf("unexpected form field %q", k)
		}
	}
	if r.ClientID != tfClientID || r.ClientSecret != tfSecret || r.APIKey != "" {
		t.Errorf("client auth: id=%q apikey-present=%v", r.ClientID, r.APIKey != "")
	}
}

func TestTokenFor_PersonRequiresResource(t *testing.T) {
	_, c := newTF(t)
	if _, err := c.TokenFor(context.Background(), "", "b.read", auth.StaticSession("t")); err == nil {
		t.Fatal("want an error for an empty resource on the person pattern")
	}
}

func TestTokenFor_SessionErrors(t *testing.T) {
	_, c := newTF(t)
	boom := errors.New("store down")
	_, err := c.TokenFor(context.Background(), tfResource, "", auth.SessionFunc(func(context.Context) (string, error) { return "", boom }))
	if !errors.Is(err, boom) {
		t.Errorf("session error not propagated: %v", err)
	}
	_, err = c.TokenFor(context.Background(), tfResource, "", auth.StaticSession(""))
	if !errors.Is(err, auth.ErrReauthenticate) {
		t.Errorf("empty session token: got %v, want ErrReauthenticate", err)
	}
}

// Bridge: client_credentials actor token (Basic) → exchange with actor_token + audience.
func TestTokenFor_LegacyBridgeWireShape(t *testing.T) {
	te, c := newTF(t, auth.WithLegacyActorExchange("SELF:org-b"), auth.WithAPIKey("ab0t_sk_service_key"))
	p1 := fakeJWT("user-1", time.Now().Add(time.Hour))
	p2 := fakeJWT("user-2", time.Now().Add(time.Hour))
	tok, err := c.TokenFor(context.Background(), tfResource, "b.read", auth.StaticSession(p1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.TokenFor(context.Background(), tfResource, "b.read", auth.StaticSession(p2)); err != nil {
		t.Fatal(err)
	}
	reqs := te.Requests()
	if len(reqs) != 3 {
		t.Fatalf("want 3 requests (1 actor token reused + 2 exchanges), got %d", len(reqs))
	}
	actor := reqs[0]
	if actor.GrantType != "client_credentials" || actor.ClientID != tfClientID || actor.Form.Has("resource") || actor.Form.Has("scope") {
		t.Errorf("actor-token call = %+v", actor.Form)
	}
	for i, ex := range reqs[1:] {
		if ex.GrantType != auth.GrantTypeTokenExchange {
			t.Fatalf("call %d grant_type = %q", i+2, ex.GrantType)
		}
		if ex.Form.Get("actor_token") != "fake-at-1" || ex.Form.Get("actor_token_type") != auth.TokenTypeAccessToken {
			t.Errorf("call %d: actor_token not the minted actor token", i+2)
		}
		if ex.Form.Get("audience") != "SELF:org-b" || ex.Form.Get("scope") != "b.read" {
			t.Errorf("call %d: audience/scope = %q/%q", i+2, ex.Form.Get("audience"), ex.Form.Get("scope"))
		}
		if ex.ClientID != "" || ex.APIKey != "" {
			t.Errorf("call %d: bridge exchange must carry no client auth / API key", i+2)
		}
	}
	if reqs[1].Form.Get("subject_token") != p1 || reqs[2].Form.Get("subject_token") != p2 {
		t.Error("subject tokens not threaded")
	}
	if tok.Resource != tfResource {
		t.Errorf("Token.Resource = %q", tok.Resource)
	}
}

func TestTokenFor_LegacyBridgeDefaultsAudienceToResource(t *testing.T) {
	te, c := newTF(t, auth.WithLegacyActorExchange(""))
	if _, err := c.TokenFor(context.Background(), "svc-aud", "", auth.StaticSession("p")); err != nil {
		t.Fatal(err)
	}
	if got := te.Requests()[1].Form.Get("audience"); got != "svc-aud" {
		t.Errorf("audience = %q, want the resource", got)
	}
}

func TestTokenFor_LegacyBridgeDoesNotChangeMachinePattern(t *testing.T) {
	te, c := newTF(t, auth.WithLegacyActorExchange("SELF:x"))
	if _, err := c.TokenFor(context.Background(), tfResource, "b.read", nil); err != nil {
		t.Fatal(err)
	}
	if r := te.Requests(); len(r) != 1 || r[0].GrantType != "client_credentials" || r[0].Form.Get("resource") != tfResource {
		t.Errorf("machine pattern changed by the bridge: %+v", r)
	}
}

// ---- caching ----

func TestTokenFor_CachesPerKey(t *testing.T) {
	te, c := newTF(t)
	ctx := context.Background()
	p := fakeJWT("u", time.Now().Add(time.Hour))
	a, _ := c.TokenFor(ctx, tfResource, "b.read b.write", auth.StaticSession(p))
	b, _ := c.TokenFor(ctx, tfResource, "b.write  b.read b.read", auth.StaticSession(p)) // same set
	if a.AccessToken != b.AccessToken || len(te.Requests()) != 1 {
		t.Fatalf("same key not served from cache (requests=%d)", len(te.Requests()))
	}
	c.TokenFor(ctx, tfResource, "b.read", auth.StaticSession(p))                                                // other scope
	c.TokenFor(ctx, "https://c.example", "b.read b.write", auth.StaticSession(p))                               // other resource
	c.TokenFor(ctx, tfResource, "b.read b.write", auth.StaticSession(fakeJWT("u2", time.Now().Add(time.Hour)))) // other person
	c.TokenFor(ctx, tfResource, "b.read b.write", nil)                                                          // other pattern
	if n := len(te.Requests()); n != 5 {
		t.Fatalf("want 5 requests (one per distinct key), got %d", n)
	}
	if s := c.TokenCacheStats(); !s.Enabled || s.Hits != 1 || s.Misses != 5 || s.Entries != 5 {
		t.Errorf("stats = %+v", s)
	}
}

func TestTokenFor_NoCacheInsideRefreshMargin(t *testing.T) {
	te, c := newTF(t)
	te.Script(authclienttest.TokenOK("short-1", 20, ""), authclienttest.TokenOK("short-2", 20, ""))
	a, _ := c.TokenFor(context.Background(), tfResource, "", nil)
	b, _ := c.TokenFor(context.Background(), tfResource, "", nil)
	if a.AccessToken == b.AccessToken || len(te.Requests()) != 2 {
		t.Error("a token expiring within the 30 s margin was served from cache")
	}
}

func TestTokenFor_NotCachedPastPersonsTokenExpiry(t *testing.T) {
	te, c := newTF(t)
	expired := auth.StaticSession(fakeJWT("u", time.Now().Add(-time.Minute)))
	c.TokenFor(context.Background(), tfResource, "", expired)
	c.TokenFor(context.Background(), tfResource, "", expired)
	if n := len(te.Requests()); n != 2 {
		t.Errorf("derived token cached past the person's token expiry (requests=%d)", n)
	}
}

func TestTokenFor_ErrorsNotCached(t *testing.T) {
	te, c := newTF(t)
	te.Script(authclienttest.TokenError(503, "temporarily_unavailable", ""))
	if _, err := c.TokenFor(context.Background(), tfResource, "", nil); !errors.Is(err, auth.ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	tok, err := c.TokenFor(context.Background(), tfResource, "", nil)
	if err != nil {
		t.Fatalf("error was cached: %v", err)
	}
	if n := len(te.Requests()); n != 2 || tok.AccessToken != "fake-at-1" {
		t.Fatalf("second call did not reach the server (requests=%d) — a failure left something in the cache", n)
	}
	if e := c.TokenCacheStats().Entries; e != 1 {
		t.Errorf("entries = %d, want 1 (only the success)", e)
	}
}

func TestTokenFor_LRUBound(t *testing.T) {
	te, c := newTF(t, auth.WithTokenCacheSize(2))
	ctx := context.Background()
	for _, r := range []string{"r1", "r2", "r3", "r1"} {
		if _, err := c.TokenFor(ctx, r, "", nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(te.Requests()); n != 4 {
		t.Errorf("r1 should have been evicted by the bound of 2 (requests=%d)", n)
	}
	if e := c.TokenCacheStats().Entries; e != 2 {
		t.Errorf("entries = %d, want 2", e)
	}
	c.TokenFor(ctx, "r3", "", nil) // most recent survivors: r1, r3
	if n := len(te.Requests()); n != 4 {
		t.Errorf("r3 should still be cached (requests=%d)", n)
	}
}

func TestTokenFor_CacheDisabled(t *testing.T) {
	te, c := newTF(t, auth.WithTokenCacheSize(-1))
	c.TokenFor(context.Background(), tfResource, "", nil)
	c.TokenFor(context.Background(), tfResource, "", nil)
	if n := len(te.Requests()); n != 2 || c.TokenCacheStats().Enabled {
		t.Errorf("cache not disabled (requests=%d)", n)
	}
}

func TestTokenFor_SingleFlight(t *testing.T) {
	te, c := newTF(t)
	release := make(chan struct{})
	var once sync.Once
	te.SetHandler(func(authclienttest.TokenRequest) authclienttest.TokenAnswer {
		<-release
		return authclienttest.TokenOK("shared", 900, "")
	})
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := c.TokenFor(context.Background(), tfResource, "", nil)
			if err == nil && tok.AccessToken != "shared" {
				err = errors.New("wrong token " + tok.AccessToken)
			}
			errs <- err
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(te.Requests()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // let the other callers queue behind the flight
	once.Do(func() { close(release) })
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if n := len(te.Requests()); n != 1 {
		t.Errorf("10 concurrent callers made %d requests, want 1", n)
	}
}

// ---- error mapping ----

func TestTokenFor_ErrorMapping(t *testing.T) {
	person := auth.StaticSession(fakeJWT("u", time.Now().Add(time.Hour)))
	cases := []struct {
		name    string
		answer  authclienttest.TokenAnswer
		session auth.Session
		want    error
	}{
		{"invalid_request → reauth", authclienttest.TokenError(400, "invalid_request", ""), person, auth.ErrReauthenticate},
		{"invalid_grant → reauth", authclienttest.TokenError(400, "invalid_grant", ""), person, auth.ErrReauthenticate},
		{"invalid_target → no connection", authclienttest.TokenError(400, "invalid_target", ""), person, auth.ErrNoConnection},
		{"invalid_scope", authclienttest.TokenError(400, "invalid_scope", ""), person, auth.ErrScopeNotAllowed},
		{"invalid_client 401", authclienttest.TokenError(401, "invalid_client", ""), person, auth.ErrClientAuth},
		{"unauthorized_client 400", authclienttest.TokenError(400, "unauthorized_client", ""), nil, auth.ErrClientNotEnabled},
		{"unauthorized_client 403 (older servers)", authclienttest.TokenError(403, "unauthorized_client", ""), nil, auth.ErrClientNotEnabled},
		{"503 → unavailable", authclienttest.TokenError(503, "temporarily_unavailable", ""), person, auth.ErrUnavailable},
		{"500 → unavailable", authclienttest.TokenAnswer{Status: 500, Body: map[string]any{"detail": "x"}}, nil, auth.ErrUnavailable},
		{"429 → unavailable", authclienttest.TokenError(429, "slow_down", ""), nil, auth.ErrUnavailable},
		{"machine invalid_target", authclienttest.TokenError(400, "invalid_target", ""), nil, auth.ErrNoConnection},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			te, c := newTF(t)
			te.Script(tc.answer)
			_, err := c.TokenFor(context.Background(), tfResource, "b.read", tc.session)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if ae, ok := auth.AsAPIError(err); !ok || ae.StatusCode != tc.answer.Status {
				t.Errorf("the *APIError is not reachable through the sentinel: %v", err)
			}
		})
	}
}

// On the machine pattern invalid_request is a request bug, not "sign in again".
func TestTokenFor_MachineInvalidRequestIsNotReauth(t *testing.T) {
	te, c := newTF(t)
	te.Script(authclienttest.TokenError(400, "invalid_request", ""))
	_, err := c.TokenFor(context.Background(), tfResource, "", nil)
	if errors.Is(err, auth.ErrReauthenticate) {
		t.Fatal("machine-pattern invalid_request mapped to ErrReauthenticate")
	}
	if ae, ok := auth.AsAPIError(err); !ok || ae.Code != "invalid_request" {
		t.Errorf("want the raw APIError, got %v", err)
	}
}

func TestTokenFor_ConsentRequired(t *testing.T) {
	te, c := newTF(t)
	te.Script(authclienttest.TokenError(400, "invalid_target", "consent_required"))
	_, err := c.TokenFor(context.Background(), tfResource, "b.read", auth.StaticSession("p"))
	var consent *auth.ConsentRequired
	if !errors.As(err, &consent) {
		t.Fatalf("got %v, want *ConsentRequired", err)
	}
	if errors.Is(err, auth.ErrNoConnection) {
		t.Error("consent_required must be distinguishable from ErrNoConnection")
	}
	if ae, ok := auth.AsAPIError(err); !ok || ae.SubError != "consent_required" {
		t.Errorf("APIError.SubError not exposed: %v", err)
	}
	verifier, challenge, err := auth.NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(consent.AuthorizationURL("https://a.example/cb", "st8", challenge))
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != te.URL()+"/auth/authorize" {
		t.Errorf("authorization endpoint = %q (must come from the AS metadata)", got)
	}
	q := u.Query()
	want := map[string]string{"response_type": "code", "client_id": tfClientID, "redirect_uri": "https://a.example/cb",
		"scope": "b.read", "resource": tfResource, "state": "st8", "code_challenge": challenge,
		"code_challenge_method": "S256", "prompt": "consent"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	sum := sha256.Sum256([]byte(verifier))
	if challenge != base64.RawURLEncoding.EncodeToString(sum[:]) || len(verifier) != 43 {
		t.Error("NewPKCE: challenge is not S256(verifier) or verifier length != 43")
	}
}

func TestTokenFor_NetworkFailureIsUnavailable(t *testing.T) {
	te, c := newTF(t)
	te.Close()
	if _, err := c.TokenFor(context.Background(), tfResource, "", nil); !errors.Is(err, auth.ErrUnavailable) {
		t.Fatalf("got %v, want ErrUnavailable", err)
	}
}

func TestTokenFor_CancelledContextIsUnavailable(t *testing.T) {
	_, c := newTF(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.TokenFor(ctx, tfResource, "", nil)
	if !errors.Is(err, auth.ErrUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want ErrUnavailable wrapping context.Canceled", err)
	}
}

func TestAPIError_SubErrorParsed(t *testing.T) {
	te, c := newTF(t)
	te.Script(authclienttest.TokenError(400, "invalid_target", "consent_required"))
	_, err := c.OAuthToken(context.Background(), url.Values{"grant_type": {"client_credentials"}})
	ae, ok := auth.AsAPIError(err)
	if !ok || ae.Code != "invalid_target" || ae.SubError != "consent_required" {
		t.Fatalf("got %+v", ae)
	}
}

func TestWithResourceExchangeOption(t *testing.T) {
	f := auth.TokenExchangeForm("sub", "", auth.WithResource(tfResource))
	if f.Get("resource") != tfResource || f.Has("audience") {
		t.Errorf("form = %v", f)
	}
}

// Guard against a regression where the token is put on the URL or logged in an error.
func TestTokenFor_ErrorTextCarriesNoToken(t *testing.T) {
	te, c := newTF(t)
	te.Script(authclienttest.TokenError(400, "invalid_grant", ""))
	person := fakeJWT("u", time.Now().Add(time.Hour))
	_, err := c.TokenFor(context.Background(), tfResource, "", auth.StaticSession(person))
	if strings.Contains(err.Error(), person) || strings.Contains(err.Error(), tfSecret) {
		t.Fatal("error text leaks a credential")
	}
}
