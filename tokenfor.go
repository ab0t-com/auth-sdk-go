package authclient

// tokenfor.go — TokenFor: one call for "give me a token for that resource".
//
// An app on the mesh needs a token for another service in two situations, and
// before this file it had to assemble each one by hand from OAuthToken /
// ExchangeToken form posts, choose the client-authentication method, decide what
// to cache, and work out which of a dozen error codes means "sign the person in
// again". TokenFor does all of that behind one signature:
//
//	tok, err := c.TokenFor(ctx, resource, scope, session)
//
//   - session == nil  → the service calls the resource AS ITSELF
//     (OAuth 2.0 client credentials, RFC 6749 §4.4, with an RFC 8707 resource).
//   - session != nil  → the app calls the resource FOR A SIGNED-IN PERSON
//     (OAuth 2.0 Token Exchange, RFC 8693: the person's token is the
//     subject_token, the app proves who it is with its own client credentials,
//     and no actor_token is sent — the authenticated client IS the actor).
//
// The pattern is chosen by the caller (nil or not), never guessed from claims.
//
// # Bridge for the person-present pattern
//
// The client-authenticated exchange without an actor_token is the target wire
// shape. Until an auth service supports it, WithLegacyActorExchange runs the
// chain that works today — mint the app's own token with client credentials,
// then exchange the person's token presenting it as the actor_token — behind
// the same TokenFor call. Removing the option later is the only change a client
// makes when the service moves on.
//
// # Caching
//
// Tokens are cached in memory, keyed by (pattern, resource, scope set) and, for
// the person-present pattern, a SHA-256 of the person's token — a new sign-in is
// a new key, so one session's token is never handed to another. An entry is
// served until 30 s before it expires (and never past the person's own token
// expiry when that can be read). Entries are bounded (least recently used is
// dropped first), concurrent callers asking for the same key share one request,
// and errors are never cached. There are no refresh tokens on either pattern:
// renewing is simply asking again.
//
// # Errors
//
// Errors are classified from the HTTP status and the OAuth `error` / `suberror`
// members only — never from error_description, which is free text. Branch with
// errors.Is on the sentinels below and errors.As for *ConsentRequired; the
// underlying *APIError stays reachable with errors.As as well.

import (
	"container/list"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---- Public types ----

// Session is a signed-in person's session with YOUR app. TokenFor asks it for a
// currently valid access token (the person's token for your app) each time it
// needs one; implement it over whatever session store you have. A nil Session
// passed to TokenFor means "no person — the service acts as itself".
type Session interface {
	AccessToken(ctx context.Context) (string, error)
}

// StaticSession adapts a token you already hold to Session.
//
//	tok, err := c.TokenFor(ctx, resource, scope, authclient.StaticSession(personToken))
type StaticSession string

// AccessToken implements Session.
func (s StaticSession) AccessToken(context.Context) (string, error) { return string(s), nil }

// SessionFunc adapts a function to Session.
type SessionFunc func(ctx context.Context) (string, error)

// AccessToken implements Session.
func (f SessionFunc) AccessToken(ctx context.Context) (string, error) { return f(ctx) }

// Token is an access token for exactly one resource, as returned by TokenFor.
// Send it as "Authorization: Bearer <AccessToken>" to that resource only.
type Token struct {
	// AccessToken is the bearer token.
	AccessToken string
	// TokenType is the token_type from the token endpoint (normally "Bearer").
	TokenType string
	// Resource is the resource the token was requested for (the TokenFor argument).
	Resource string
	// Scope is the granted scope (space-delimited) when the server reported one,
	// else the requested scope.
	Scope string
	// ExpiresAt is when the token expires (from expires_in). Zero when the server
	// did not say; such a token is not cached.
	ExpiresAt time.Time
}

// Sentinel errors returned (wrapped) by TokenFor. Test with errors.Is.
var (
	// ErrReauthenticate: the person's token was not accepted — expired, revoked,
	// not issued for your app, or not acceptable by policy (for example the person
	// left the organisation). Wire: 400 invalid_request or invalid_grant on the
	// person-present pattern. Get a fresh session (sign the person in again) and
	// retry once. With WithLegacyActorExchange it also covers "this person has no
	// delegation grant for your app" — the service deliberately does not say which.
	ErrReauthenticate = errors.New("authclient: the person's session was not accepted — sign them in again")

	// ErrNoConnection: there is no usable connection from your app to that
	// resource, or the resource is unknown / malformed. Wire: 400 invalid_target.
	// An org admin must approve the connection; the person cannot fix it.
	ErrNoConnection = errors.New("authclient: no usable connection to that resource")

	// ErrScopeNotAllowed: the requested scope exceeds what your app / the
	// connection allows. Wire: 400 invalid_scope. Ask for less, or have the
	// ceiling widened.
	ErrScopeNotAllowed = errors.New("authclient: requested scope is not allowed")

	// ErrClientAuth: your app's client credentials were rejected. Wire: 401 (or
	// 400) invalid_client. Fix or rotate the secret.
	ErrClientAuth = errors.New("authclient: client authentication failed")

	// ErrClientNotEnabled: your app is not registered for the grant type this
	// call needs. Wire: 400 unauthorized_client. Register the grant type.
	ErrClientNotEnabled = errors.New("authclient: client is not enabled for this grant type")

	// ErrUnavailable: the auth service could not answer (5xx / 429 after the
	// transport's own retries and Retry-After, a network failure, or a cancelled
	// context). Back off and retry. Never treat it as allowed, and never fall
	// back to an expired token.
	ErrUnavailable = errors.New("authclient: auth service unavailable")

	// ErrClientCredentialsRequired: TokenFor was called on a client constructed
	// without WithClientCredentials. A configuration error, not a server answer.
	ErrClientCredentialsRequired = errors.New("authclient: TokenFor needs WithClientCredentials(clientID, secret)")
)

// ConsentRequired is returned (errors.As) when the person can approve the
// connection themselves but has not yet done so. Wire: 400 invalid_target with
// "suberror":"consent_required".
//
// Send the person through AuthorizationURL once (a normal authorization request
// with prompt=consent), then call TokenFor again. The URL is built here from the
// auth service's published metadata — the token endpoint never hands out a URL.
type ConsentRequired struct {
	// Resource and Scope are what TokenFor asked for.
	Resource string
	Scope    string
	// ClientID is your app's client id (from WithClientCredentials).
	ClientID string
	// AuthorizationEndpoint is the authorization_endpoint from the auth
	// service's RFC 8414 metadata (or <base URL>/auth/authorize when the
	// metadata could not be read).
	AuthorizationEndpoint string
	// Err is the token-endpoint error that carried the signal.
	Err *APIError
}

func (e *ConsentRequired) Error() string {
	return "authclient: the person must approve access to " + e.Resource + " (consent required)"
}

// Unwrap exposes the underlying *APIError to errors.As.
func (e *ConsentRequired) Unwrap() error {
	if e.Err == nil {
		return nil
	}
	return e.Err
}

// AuthorizationURL builds the authorization request that asks the person to
// approve: response_type=code, your client_id, redirect_uri, the scope, the
// resource (RFC 8707), state, PKCE S256 code_challenge (RFC 7636) and
// prompt=consent. Create the verifier/challenge with NewPKCE and keep the
// verifier for the code exchange at your redirect URI.
func (e *ConsentRequired) AuthorizationURL(redirectURI, state, codeChallenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", e.ClientID)
	q.Set("redirect_uri", redirectURI)
	if e.Scope != "" {
		q.Set("scope", e.Scope)
	}
	if e.Resource != "" {
		q.Set("resource", e.Resource)
	}
	if state != "" {
		q.Set("state", state)
	}
	if codeChallenge != "" {
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", "S256")
	}
	q.Set("prompt", "consent")
	sep := "?"
	if strings.Contains(e.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return e.AuthorizationEndpoint + sep + q.Encode()
}

// NewPKCE returns a fresh RFC 7636 code_verifier (43 chars, 256 bits of
// randomness) and its S256 code_challenge.
func NewPKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// ---- Options ----

// WithClientCredentials sets your app's OAuth client credentials. TokenFor
// sends them to the token endpoint as HTTP Basic (client_secret_basic, RFC 6749
// §2.3.1) and nowhere else. A client configured WithAPIKey does NOT send that
// key on TokenFor's token-endpoint calls.
func WithClientCredentials(clientID, clientSecret string) Option {
	return func(c *Client) {
		c.clientID = clientID
		c.clientSecret = clientSecret
	}
}

// WithLegacyActorExchange makes TokenFor's person-present pattern use the
// exchange that auth services support today: TokenFor first mints your app's
// own token (client credentials, cached), then exchanges the person's token
// presenting it as the RFC 8693 actor_token, with audience set to audience
// (the target's registered service audience — empty means "use the resource
// argument"). It needs the per-person delegation grant that chain requires.
//
// It is a bridge: adopt TokenFor now, and delete this option when the auth
// service accepts the client-authenticated exchange without an actor_token.
// It does not change the no-person pattern.
func WithLegacyActorExchange(audience string) Option {
	return func(c *Client) {
		c.legacyExchange = true
		c.legacyAudience = audience
	}
}

// DefaultTokenCacheSize is the default bound on cached TokenFor tokens.
const DefaultTokenCacheSize = 1024

// tokenRefreshMargin: a cached token is replaced this long before it expires,
// so a token handed out is never about to expire in flight.
const tokenRefreshMargin = 30 * time.Second

// WithTokenCacheSize bounds TokenFor's in-memory cache. 0 keeps the default
// (DefaultTokenCacheSize); a negative value disables caching entirely.
func WithTokenCacheSize(n int) Option {
	return func(c *Client) { c.tokenCacheSize = n }
}

// TokenCacheStats reports TokenFor cache activity.
type TokenCacheStats struct {
	Enabled bool
	Hits    uint64
	Misses  uint64
	Entries int
}

// TokenCacheStats returns a snapshot of TokenFor cache activity.
func (c *Client) TokenCacheStats() TokenCacheStats {
	tc := c.tokens()
	if tc == nil {
		return TokenCacheStats{}
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return TokenCacheStats{Enabled: true, Hits: tc.hits, Misses: tc.misses, Entries: tc.ll.Len()}
}

// ---- TokenFor ----

// TokenFor returns an access token for resource with scope (space-delimited).
//
// session == nil: your service acts as itself — client credentials with
// resource and scope (resource may be empty to accept the client's default
// audience). session != nil: your app acts for the signed-in person — token
// exchange with the person's token as subject_token, your client credentials
// as client authentication, exactly one resource, and no actor_token (or the
// actor-token chain when WithLegacyActorExchange is set).
//
// Requires WithClientCredentials. See the package-level notes in tokenfor.go
// for caching and the sentinel errors for what each failure means.
func (c *Client) TokenFor(ctx context.Context, resource, scope string, session Session) (*Token, error) {
	if c.clientID == "" || c.clientSecret == "" {
		return nil, ErrClientCredentialsRequired
	}
	scope = normalizeScope(scope)

	if session == nil {
		key := tokenCacheKey("p2", c.clientID, resource, scope, "", "")
		return c.cachedToken(ctx, key, time.Time{}, func(ctx context.Context) (*Token, error) {
			return c.clientCredentialsToken(ctx, resource, scope)
		})
	}

	subject, err := session.AccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("authclient: TokenFor: session: %w", err)
	}
	if subject == "" {
		return nil, fmt.Errorf("%w (the session returned no token)", ErrReauthenticate)
	}
	subjectExp := unverifiedJWTExpiry(subject)
	digest := sha256.Sum256([]byte("ab0t-auth-sdk/subject\x00" + subject))
	subjectKey := hex.EncodeToString(digest[:])

	if c.legacyExchange {
		audience := c.legacyAudience
		if audience == "" {
			audience = resource
		}
		if audience == "" {
			return nil, errors.New("authclient: TokenFor: WithLegacyActorExchange needs an audience or a resource")
		}
		key := tokenCacheKey("p3-legacy", c.clientID, resource, scope, audience, subjectKey)
		return c.cachedToken(ctx, key, subjectExp, func(ctx context.Context) (*Token, error) {
			return c.legacyExchangeToken(ctx, subject, resource, audience, scope)
		})
	}

	if resource == "" {
		return nil, errors.New("authclient: TokenFor: a resource is required when acting for a person")
	}
	key := tokenCacheKey("p3", c.clientID, resource, scope, "", subjectKey)
	return c.cachedToken(ctx, key, subjectExp, func(ctx context.Context) (*Token, error) {
		return c.exchangeForPerson(ctx, subject, resource, scope)
	})
}

// clientCredentialsToken is the no-person pattern (and the bridge's actor token).
func (c *Client) clientCredentialsToken(ctx context.Context, resource, scope string) (*Token, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if resource != "" {
		form.Set("resource", resource)
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	tok, err := c.postTokenEndpoint(ctx, form, true)
	if err != nil {
		return nil, c.classifyTokenError(ctx, err, false, resource, scope)
	}
	return tok.toToken(resource, scope), nil
}

// exchangeForPerson is the target person-present wire shape: client-authenticated
// RFC 8693 exchange, one resource, no actor_token.
func (c *Client) exchangeForPerson(ctx context.Context, subject, resource, scope string) (*Token, error) {
	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token", subject)
	form.Set("subject_token_type", TokenTypeAccessToken)
	form.Set("resource", resource)
	if scope != "" {
		form.Set("scope", scope)
	}
	tok, err := c.postTokenEndpoint(ctx, form, true)
	if err != nil {
		return nil, c.classifyTokenError(ctx, err, true, resource, scope)
	}
	return tok.toToken(resource, scope), nil
}

// legacyExchangeToken is the bridge: client-credentials actor token (cached) +
// exchange with actor_token and audience. The exchange call carries no client
// authentication — the actor_token is the app's proof of identity on this chain.
func (c *Client) legacyExchangeToken(ctx context.Context, subject, resource, audience, scope string) (*Token, error) {
	actorKey := tokenCacheKey("actor", c.clientID, "", "", "", "")
	actor, err := c.cachedToken(ctx, actorKey, time.Time{}, func(ctx context.Context) (*Token, error) {
		return c.clientCredentialsToken(ctx, "", "")
	})
	if err != nil {
		return nil, err
	}
	opts := []ExchangeOption{WithActorToken(actor.AccessToken)}
	if scope != "" {
		opts = append(opts, WithScope(scope))
	}
	tok, err := c.postTokenEndpoint(ctx, TokenExchangeForm(subject, audience, opts...), false)
	if err != nil {
		return nil, c.classifyTokenError(ctx, err, true, resource, scope)
	}
	return tok.toToken(resource, scope), nil
}

// tokenEndpointResponse covers both the RFC 6749 §5.1 and RFC 8693 §2.2.1 shapes.
type tokenEndpointResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
	IssuedTokenType string `json:"issued_token_type"`
}

func (r *tokenEndpointResponse) toToken(resource, requestedScope string) *Token {
	t := &Token{AccessToken: r.AccessToken, TokenType: r.TokenType, Resource: resource, Scope: r.Scope}
	if t.Scope == "" {
		t.Scope = requestedScope
	}
	if r.ExpiresIn > 0 {
		t.ExpiresAt = time.Now().Add(time.Duration(r.ExpiresIn) * time.Second)
	}
	return t
}

// postTokenEndpoint POSTs form to /auth/oauth/token. With basic, the client
// credentials go in an HTTP Basic header. No other credential is ever attached:
// the service API key (WithAPIKey) is deliberately not sent here.
//
// The id and secret are not form-urlencoded before Basic encoding: the auth
// service's engines read them verbatim, and its client ids and secrets use only
// URL-safe characters, for which the RFC 6749 §2.3.1 encoding is the identity.
func (c *Client) postTokenEndpoint(ctx context.Context, form url.Values, basic bool) (*tokenEndpointResponse, error) {
	var out tokenEndpointResponse
	prep := func(r *http.Request) {
		c.applyBase(r)
		if basic {
			r.SetBasicAuth(c.clientID, c.clientSecret)
		}
	}
	if err := c.send(ctx, http.MethodPost, "/auth/oauth/token", "application/x-www-form-urlencoded",
		[]byte(form.Encode()), &out, prep); err != nil {
		return nil, err
	}
	if out.AccessToken == "" {
		return nil, &APIError{StatusCode: http.StatusBadGateway, Method: http.MethodPost, Endpoint: "/auth/oauth/token",
			Message: "token endpoint answered 2xx without an access_token"}
	}
	return &out, nil
}

// classifyTokenError maps a token-endpoint failure onto the TokenFor sentinels.
// personPresent selects the invalid_request/invalid_grant → ErrReauthenticate
// rule (on the machine pattern those codes are request bugs and pass through).
func (c *Client) classifyTokenError(ctx context.Context, err error, personPresent bool, resource, scope string) error {
	var ae *APIError
	if !errors.As(err, &ae) {
		// Transport failure or cancelled context: no answer was obtained.
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if ae.StatusCode >= 500 || ae.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("%w: %w", ErrUnavailable, ae)
	}
	switch ae.Code {
	case "invalid_client":
		return fmt.Errorf("%w: %w", ErrClientAuth, ae)
	case "unauthorized_client":
		return fmt.Errorf("%w: %w", ErrClientNotEnabled, ae)
	case "invalid_scope":
		return fmt.Errorf("%w: %w", ErrScopeNotAllowed, ae)
	case "invalid_target":
		if ae.SubError == "consent_required" {
			return &ConsentRequired{Resource: resource, Scope: scope, ClientID: c.clientID,
				AuthorizationEndpoint: c.authorizationEndpoint(ctx), Err: ae}
		}
		return fmt.Errorf("%w: %w", ErrNoConnection, ae)
	case "invalid_request", "invalid_grant":
		if personPresent && ae.StatusCode == http.StatusBadRequest {
			return fmt.Errorf("%w: %w", ErrReauthenticate, ae)
		}
	}
	return ae
}

// authorizationEndpoint reads authorization_endpoint from the RFC 8414 metadata
// (cached after the first success), falling back to <base URL>/auth/authorize.
func (c *Client) authorizationEndpoint(ctx context.Context) string {
	c.tokenMu.Lock()
	cached := c.authzEndpoint
	c.tokenMu.Unlock()
	if cached != "" {
		return cached
	}
	var md AuthorizationServerMetadata
	prep := func(r *http.Request) { c.applyBase(r) }
	if err := c.send(ctx, http.MethodGet, "/.well-known/oauth-authorization-server", "", nil, &md, prep); err == nil &&
		md.AuthorizationEndpoint != "" {
		c.tokenMu.Lock()
		c.authzEndpoint = md.AuthorizationEndpoint
		c.tokenMu.Unlock()
		return md.AuthorizationEndpoint
	}
	return c.baseURL + "/auth/authorize"
}

// ---- cache ----

// tokenCacheKey hashes every input that selects a distinct token. Components are
// length-prefixed so distinct inputs cannot serialize to the same bytes. The
// person's token enters only as a digest, so it is never a map key.
func tokenCacheKey(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteByte(':')
		b.WriteString(p)
		b.WriteByte(0x1e)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// normalizeScope sorts and de-duplicates a space-delimited scope (RFC 6749
// §3.3: scope is an unordered set), so "a b" and "b a" share a cache entry.
func normalizeScope(s string) string {
	f := strings.Fields(s)
	if len(f) <= 1 {
		return strings.Join(f, "")
	}
	sort.Strings(f)
	out := f[:1]
	for _, v := range f[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return strings.Join(out, " ")
}

// unverifiedJWTExpiry reads `exp` from a JWT payload WITHOUT verifying it. It
// is used only to stop a cached derived token outliving the person's own token
// — never for an authorization decision. Zero when unreadable.
func unverifiedJWTExpiry(tok string) time.Time {
	if !LooksLikeJWT(tok) {
		return time.Time{}
	}
	seg := strings.Split(tok, ".")[1]
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp json.Number `json:"exp"`
	}
	if json.Unmarshal(raw, &claims) != nil || claims.Exp == "" {
		return time.Time{}
	}
	f, err := claims.Exp.Float64()
	if err != nil || f <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(f), 0)
}

type tokenCache struct {
	mu       sync.Mutex
	max      int
	ll       *list.List // front = most recently used
	items    map[string]*list.Element
	inflight map[string]*tokenFlight
	now      func() time.Time
	hits     uint64
	misses   uint64
}

type tokenCacheEntry struct {
	key        string
	tok        Token
	freshUntil time.Time
}

type tokenFlight struct {
	done chan struct{}
	tok  *Token
	err  error
	// leaderCancelled: the request failed because the LEADER's context ended.
	// Waiters with live contexts must not inherit that; they retry.
	leaderCancelled bool
}

// tokens returns the cache, creating it lazily; nil when caching is disabled.
func (c *Client) tokens() *tokenCache {
	if c.tokenCacheSize < 0 {
		return nil
	}
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.tcache == nil {
		max := c.tokenCacheSize
		if max == 0 {
			max = DefaultTokenCacheSize
		}
		c.tcache = &tokenCache{max: max, ll: list.New(), items: map[string]*list.Element{},
			inflight: map[string]*tokenFlight{}, now: time.Now}
	}
	return c.tcache
}

// cachedToken serves key from the cache or runs fetch once for all concurrent
// callers. capAt, when non-zero, bounds how long the result may be served.
func (c *Client) cachedToken(ctx context.Context, key string, capAt time.Time, fetch func(context.Context) (*Token, error)) (*Token, error) {
	tc := c.tokens()
	if tc == nil {
		return fetch(ctx)
	}
	for {
		tc.mu.Lock()
		if el, ok := tc.items[key]; ok {
			e := el.Value.(*tokenCacheEntry)
			if tc.now().Before(e.freshUntil) {
				tc.ll.MoveToFront(el)
				tc.hits++
				tok := e.tok
				tc.mu.Unlock()
				return &tok, nil
			}
			tc.ll.Remove(el)
			delete(tc.items, key)
		}
		if f, ok := tc.inflight[key]; ok {
			tc.mu.Unlock()
			select {
			case <-f.done:
				if f.leaderCancelled {
					continue
				}
				if f.err != nil {
					return nil, f.err
				}
				tok := *f.tok
				return &tok, nil
			case <-ctx.Done():
				return nil, fmt.Errorf("%w: %w", ErrUnavailable, ctx.Err())
			}
		}
		f := &tokenFlight{done: make(chan struct{})}
		tc.inflight[key] = f
		tc.misses++
		tc.mu.Unlock()

		tok, err := fetch(ctx)

		tc.mu.Lock()
		delete(tc.inflight, key)
		if err == nil && tok != nil && !tok.ExpiresAt.IsZero() {
			fresh := tok.ExpiresAt.Add(-tokenRefreshMargin)
			if !capAt.IsZero() && capAt.Before(fresh) {
				fresh = capAt
			}
			if tc.now().Before(fresh) {
				tc.items[key] = tc.ll.PushFront(&tokenCacheEntry{key: key, tok: *tok, freshUntil: fresh})
				for tc.ll.Len() > tc.max {
					last := tc.ll.Back()
					tc.ll.Remove(last)
					delete(tc.items, last.Value.(*tokenCacheEntry).key)
				}
			}
		}
		f.tok, f.err = tok, err
		f.leaderCancelled = err != nil && ctx.Err() != nil
		tc.mu.Unlock()
		close(f.done)
		if err != nil {
			return nil, err
		}
		out := *tok
		return &out, nil
	}
}
