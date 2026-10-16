package authclient

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultBaseURL is the production auth service.
const DefaultBaseURL = "https://auth.service.ab0t.com"

// Default transport tuning.
const (
	defaultTimeout    = 15 * time.Second
	defaultMaxRetries = 2
	defaultUserAgent  = "ab0t-auth-sdk-go/" + Version
)

// APIKeyPrefix is the prefix of service-to-service API keys.
const APIKeyPrefix = "ab0t_sk_"

// ---- Interfaces (so callers can depend on behavior, not the concrete client) ----

// Validator resolves a bearer token to an Actor (identity + tenant + perms).
// A resource server's request middleware should depend on this, not on *Client.
type Validator interface {
	ValidateToken(ctx context.Context, token string) (*Actor, error)
}

// Authorizer decides whether a token may perform an action on a resource.
// This is the intended route-gating primitive.
type Authorizer interface {
	Authorize(ctx context.Context, token, action string, resource Resource) (bool, error)
}

// TokenSource supplies (and can refresh) a bearer token. A CLI/agent
// implements or uses this to carry credentials across calls.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Compile-time assertions that *Client satisfies the core interfaces.
var (
	_ Validator  = (*Client)(nil)
	_ Authorizer = (*Client)(nil)
)

// IsAPIKey reports whether a credential is a service API key (vs. a user JWT)
// based on the ab0t_sk_ prefix.
func IsAPIKey(cred string) bool { return strings.HasPrefix(cred, APIKeyPrefix) }

// LooksLikeJWT reports whether a credential has the shape of a JWS compact
// serialization: three non-empty, dot-separated segments and no whitespace.
// It is a SHAPE test, not a validity test — it neither verifies the signature
// nor parses the claims. Use it to decide how to TRANSPORT a credential, never
// to decide whether to trust one.
func LooksLikeJWT(cred string) bool {
	if cred == "" || strings.ContainsAny(cred, " \t\r\n") {
		return false
	}
	parts := strings.Split(cred, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	return true
}

// CredentialHeader reports the header name and value the auth service expects
// for cred, so callers never have to think about it.
//
// WHY THIS EXISTS: the service deliberately keeps the two credential systems on
// separate transports, and gets it wrong in opposite directions on different
// routes. An ab0t_sk_ key presented as "Authorization: Bearer <key>" is rejected
// 401 at the forward-auth edge (an asserted anti-credential-confusion invariant);
// a key presented as a bare "Authorization: <key>" is invisible to the API routes,
// because FastAPI's HTTPBearer only populates credentials for the Bearer scheme.
// X-API-Key is the one transport every API-key-accepting surface reads, so that
// is what we send for keys. JWTs keep Authorization: Bearer, unchanged.
//
// Shape decides, not configuration: an ab0t_sk_ prefix means API key; a JWS
// compact shape means JWT; anything else falls back to Bearer, which is the
// historical behavior and keeps third-party/opaque tokens working.
func CredentialHeader(cred string) (name, value string) {
	switch {
	case cred == "":
		return "", ""
	case IsAPIKey(cred):
		return "X-API-Key", cred
	case LooksLikeJWT(cred):
		return "Authorization", "Bearer " + cred
	default:
		return "Authorization", "Bearer " + cred
	}
}

// ---- Options ----

// Option configures a Client.
type Option func(*Client)

// WithBaseURL overrides the auth service base URL.
func WithBaseURL(u string) Option {
	return func(c *Client) {
		if u != "" {
			c.baseURL = strings.TrimRight(u, "/")
		}
	}
}

// WithAPIKey sets the service API key (prefix "ab0t_sk_") used on calls that
// require service-to-service auth (e.g. CheckPermission). It is transported as
// X-API-Key — the header every API-key-accepting surface reads; see
// CredentialHeader for why not Authorization: Bearer.
// Per-call user tokens always override this default.
func WithAPIKey(key string) Option {
	return func(c *Client) { c.apiKey = key }
}

// WithHTTPClient supplies a custom *http.Client (transport, proxy, etc.).
// If the supplied client has a zero Timeout, the default timeout is applied.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			c.http = h
		}
	}
}

// WithTimeout sets the per-request timeout enforced via the http.Client.
// A non-positive value disables the client-level timeout (callers should then
// rely on context deadlines).
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// WithUserAgent sets the User-Agent header.
func WithUserAgent(ua string) Option {
	return func(c *Client) {
		if ua != "" {
			c.userAgent = ua
		}
	}
}

// WithExpectedAudience sets a default `aud` assertion applied to token/api-key
// validation, ensuring tokens were minted for this service.
//
// It applies to API keys too. A mesh service key minted without an audience is
// then rejected — if your service accepts such keys, use WithExpectedJWTAudience
// instead, which asserts the audience on user JWTs only.
func WithExpectedAudience(aud string) Option {
	return func(c *Client) { c.expectedAudience = aud }
}

// WithExpectedJWTAudience sets a default `aud` assertion applied to user JWTs
// only — ValidateToken / ValidateTokenWith / Authorize with a JWT, and
// VerifyAccessTokenLocal — and never to ab0t_sk_ API keys.
//
// Use it when one route accepts both: user JWTs that must have been minted for
// this service, and mesh service keys, which carry no audience (an audience
// assertion on such a key rejects it). Use WithExpectedAudience when every
// credential, API keys included, must name this service.
//
// For a JWT it takes precedence over WithExpectedAudience; an explicit
// TokenValidationRequest.ExpectedAudience or LocalVerifyOptions.Audience still
// overrides both for that one call.
func WithExpectedJWTAudience(aud string) Option {
	return func(c *Client) { c.expectedJWTAudience = aud }
}

// jwtAudience is the audience asserted on a user JWT: WithExpectedJWTAudience
// when set, else WithExpectedAudience.
func (c *Client) jwtAudience() string {
	if c.expectedJWTAudience != "" {
		return c.expectedJWTAudience
	}
	return c.expectedAudience
}

// WithMaxRetries sets how many times a retryable request (idempotent GET, or
// any request returning 429/5xx) is retried with exponential backoff. 0 disables
// retries.
func WithMaxRetries(n int) Option {
	return func(c *Client) {
		if n < 0 {
			n = 0
		}
		c.maxRetries = n
	}
}

// WithBackoff configures the exponential backoff used between retries.
// base is the initial delay; max caps the per-attempt delay. The transport
// honors a Retry-After header on 429/503 responses when present.
func WithBackoff(base, max time.Duration) Option {
	return func(c *Client) {
		if base > 0 {
			c.backoffBase = base
		}
		if max > 0 {
			c.backoffMax = max
		}
	}
}

// ---- Client ----

// Client is a typed, isolated client for the auth service.
// It is safe for concurrent use.
type Client struct {
	baseURL          string
	apiKey           string
	expectedAudience string
	// expectedJWTAudience, when set, replaces expectedAudience for user JWTs
	// only (WithExpectedJWTAudience); API keys keep expectedAudience.
	expectedJWTAudience string
	userAgent           string
	http                *http.Client
	timeout             time.Duration
	maxRetries          int
	backoffBase         time.Duration
	backoffMax          time.Duration

	jwks *jwksCache

	// vcache, when non-nil, caches credential-validation decisions. Since v0.12.0
	// it is ON by default with per-question TTLs (newDefaultValidationCache);
	// WithValidationCache / WithValidationCacheOptions replace that, and a zero
	// TTL leaves it nil, meaning every validation is an HTTP call (the pre-v0.12.0
	// behaviour). See validationcache.go.
	vcache *validationCache
	// vcacheConfigured records that the consumer chose a cache configuration
	// (including "off"), so New does not install the default over it.
	vcacheConfigured bool

	// observer, when set, receives one RequestInfo per completed HTTP attempt.
	// See observe.go.
	observer Observer

	// TokenFor state (tokenfor.go): the app's OAuth client credentials, the
	// legacy actor-token exchange bridge, and the lazily created token cache.
	clientID       string
	clientSecret   string
	legacyExchange bool
	legacyAudience string
	tokenCacheSize int
	tokenMu        sync.Mutex
	tcache         *tokenCache
	authzEndpoint  string
}

// New constructs a Client. baseURL may be "" to use DefaultBaseURL.
func New(baseURL string, opts ...Option) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	c := &Client{
		baseURL:     strings.TrimRight(baseURL, "/"),
		userAgent:   defaultUserAgent,
		timeout:     defaultTimeout,
		maxRetries:  defaultMaxRetries,
		backoffBase: 200 * time.Millisecond,
		backoffMax:  5 * time.Second,
	}
	for _, o := range opts {
		o(c)
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: c.timeout}
	} else if c.http.Timeout == 0 && c.timeout > 0 {
		// Don't mutate a caller-supplied client; clone shallowly.
		cp := *c.http
		cp.Timeout = c.timeout
		c.http = &cp
	}
	c.jwks = newJWKSCache(c)
	if !c.vcacheConfigured {
		// Default-on validation cache (owner decision, v0.12.0). The consumer
		// said nothing, so it gets the per-question defaults; see
		// validationcache.go for the TTLs and the revocation latency they imply.
		c.vcache = newDefaultValidationCache()
	}
	return c
}

// BaseURL returns the configured base URL.
func (c *Client) BaseURL() string { return c.baseURL }
