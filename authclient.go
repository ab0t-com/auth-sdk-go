package authclient

import (
	"context"
	"net/http"
	"strings"
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

// WithAPIKey sets the service API key (prefix "ab0t_sk_") sent as a bearer
// token on calls that require service-to-service auth (e.g. CheckPermission).
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
func WithExpectedAudience(aud string) Option {
	return func(c *Client) { c.expectedAudience = aud }
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
	userAgent        string
	http             *http.Client
	timeout          time.Duration
	maxRetries       int
	backoffBase      time.Duration
	backoffMax       time.Duration

	jwks *jwksCache

	// observer, when set, receives one RequestInfo per completed HTTP attempt.
	// See observe.go.
	observer Observer
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
	return c
}

// BaseURL returns the configured base URL.
func (c *Client) BaseURL() string { return c.baseURL }
