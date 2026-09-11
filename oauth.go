package authclient

import (
	"context"
	"encoding/json"
	"net/url"
)

// This file covers the interactive OAuth2/OIDC surface used by CLI/device and
// end-user app clients (contract section 1 remaining ops, section 6 token
// refresh, section 7 OIDC discovery): the authorization endpoint, the token
// endpoint, Pushed Authorization Requests (PAR), RFC 7591 dynamic client
// registration, email verification, password reset, and discovery documents.

// ---- Models ----

// AuthorizationResponse is returned by GET /auth/authorize. For an interactive
// browser flow the service typically issues a redirect; when accessed
// programmatically it returns the location and any pending consent metadata.
type AuthorizationResponse struct {
	RedirectURI string         `json:"redirect_uri,omitempty"`
	Location    string         `json:"location,omitempty"`
	Code        string         `json:"code,omitempty"`
	State       string         `json:"state,omitempty"`
	ConsentURL  string         `json:"consent_url,omitempty"`
	Extra       map[string]any `json:"extra,omitempty"`
}

// PushedAuthorizationResponse is the RFC 9126 PAR result.
type PushedAuthorizationResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in,omitempty"`
}

// TokenResponse is the OAuth2 token-endpoint response (POST /auth/oauth/token,
// /token/refresh, provider callbacks). It mirrors the standard token payload.
type TokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// OAuthProviderAuthorizeResponse is returned by
// GET /auth/oauth/{provider}/authorize.
type OAuthProviderAuthorizeResponse struct {
	AuthorizationURL string `json:"authorization_url,omitempty"`
	Provider         string `json:"provider,omitempty"`
	State            string `json:"state,omitempty"`
}

// ClientRegistration is the body for RFC 7591 dynamic client registration. The
// server reads all of these (goauth internal/oauth/dcr.go:104-115), including the
// client_uri/tos_uri/software_id/software_version metadata that the RESPONSE
// already surfaced — previously readable but un-settable (read-write asymmetry).
type ClientRegistration struct {
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	TOSURI                  string   `json:"tos_uri,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
}

// ClientRegistrationResponse is the RFC 7591 registration result.
type ClientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	OrgID                   string   `json:"org_id,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	TOSURI                  string   `json:"tos_uri,omitempty"`
}

// VerifyEmailSendRequest is the body for POST /auth/verify-email/send.
type VerifyEmailSendRequest struct {
	Email string `json:"email,omitempty"`
	OrgID string `json:"org_id,omitempty"`
}

// VerifyEmailConfirmRequest is the body for POST /auth/verify-email/confirm.
type VerifyEmailConfirmRequest struct {
	Token string `json:"token"`
}

// OpenIDConfiguration is the OIDC discovery document.
type OpenIDConfiguration struct {
	Issuer                                     string          `json:"issuer"`
	AuthorizationEndpoint                      string          `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                              string          `json:"token_endpoint,omitempty"`
	UserinfoEndpoint                           string          `json:"userinfo_endpoint,omitempty"`
	JWKSURI                                    string          `json:"jwks_uri,omitempty"`
	RegistrationEndpoint                       string          `json:"registration_endpoint,omitempty"`
	ScopesSupported                            []string        `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                     []string        `json:"response_types_supported,omitempty"`
	GrantTypesSupported                        []string        `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported                      []string        `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported           []string        `json:"id_token_signing_alg_values_supported,omitempty"`
	TokenEndpointAuthMethodsSupported          []string        `json:"token_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported              []string        `json:"code_challenge_methods_supported,omitempty"`
	AuthorizationDetailsTypesSupported         []string        `json:"authorization_details_types_supported,omitempty"`
	ClaimsParameterSupported                   bool            `json:"claims_parameter_supported,omitempty"`
	ClaimsSupported                            []string        `json:"claims_supported,omitempty"`
	DPoPSigningAlgValuesSupported              []string        `json:"dpop_signing_alg_values_supported,omitempty"`
	Features                                   json.RawMessage `json:"features,omitempty"`
	IntrospectionEndpoint                      string          `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported  []string        `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	JWKSRefreshInterval                        int64           `json:"jwks_refresh_interval,omitempty"`
	JWKSSupportsProviderAggregation            bool            `json:"jwks_supports_provider_aggregation,omitempty"`
	KeyRotationInterval                        int64           `json:"key_rotation_interval,omitempty"`
	OpPolicyURI                                string          `json:"op_policy_uri,omitempty"`
	OpTOSURI                                   string          `json:"op_tos_uri,omitempty"`
	PushedAuthorizationRequestEndpoint         string          `json:"pushed_authorization_request_endpoint,omitempty"`
	RequestParameterSupported                  bool            `json:"request_parameter_supported,omitempty"`
	RequestURIParameterSupported               bool            `json:"request_uri_parameter_supported,omitempty"`
	RequirePushedAuthorizationRequests         bool            `json:"require_pushed_authorization_requests,omitempty"`
	RequireRequestURIRegistration              bool            `json:"require_request_uri_registration,omitempty"`
	ResponseModesSupported                     []string        `json:"response_modes_supported,omitempty"`
	RevocationEndpoint                         string          `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported     []string        `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	ServiceDocumentation                       string          `json:"service_documentation,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported []string        `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	UiLocalesSupported                         []string        `json:"ui_locales_supported,omitempty"`
}

// AuthorizationServerMetadata is the RFC 8414 OAuth metadata document.
type AuthorizationServerMetadata = OpenIDConfiguration

// ---- Operations ----

// OAuthAuthorize starts the interactive OAuth2 authorization flow for the
// current user. GET /auth/authorize. params are appended as query parameters.
// (The token-validation route-gating primitive is the separate Authorize
// method.)
func (c *Client) OAuthAuthorize(ctx context.Context, token string, params url.Values) (*AuthorizationResponse, error) {
	path := "/auth/authorize"
	if params != nil {
		if enc := params.Encode(); enc != "" {
			path += "?" + enc
		}
	}
	var out AuthorizationResponse
	if err := c.doGet(ctx, path, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// PushedAuthorizationRequest performs an RFC 9126 PAR, registering the
// authorization parameters and returning a request_uri. POST /auth/oauth/par.
func (c *Client) PushedAuthorizationRequest(ctx context.Context, params url.Values) (*PushedAuthorizationResponse, error) {
	var out PushedAuthorizationResponse
	if err := c.doForm(ctx, "/auth/oauth/par", params, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// ProviderAuthorizeInfo returns provider authorize metadata for a programmatic
// device/CLI flow. GET /auth/oauth/{provider}/authorize. Unlike
// OAuthAuthorizeURL this returns the typed discovery payload directly.
func (c *Client) ProviderAuthorizeInfo(ctx context.Context, provider string, params url.Values) (*OAuthProviderAuthorizeResponse, error) {
	if provider == "" {
		return nil, &APIError{StatusCode: 400, Method: "GET", Endpoint: "/auth/oauth/{provider}/authorize", Code: "invalid_request", Message: "provider is required"}
	}
	path := "/auth/oauth/" + url.PathEscape(provider) + "/authorize"
	if params != nil {
		if enc := params.Encode(); enc != "" {
			path += "?" + enc
		}
	}
	var out OAuthProviderAuthorizeResponse
	if err := c.doGet(ctx, path, &out, ""); err != nil {
		return nil, err
	}
	if out.Provider == "" {
		out.Provider = provider
	}
	return &out, nil
}

// OAuthToken exchanges credentials at the OAuth2 token endpoint. This is the
// device/CLI grant path (authorization_code, refresh_token, etc.).
// POST /auth/oauth/token (form-encoded).
func (c *Client) OAuthToken(ctx context.Context, form url.Values) (*TokenResponse, error) {
	var out TokenResponse
	if err := c.doForm(ctx, "/auth/oauth/token", form, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// RefreshTokenForm exchanges a refresh token via the form-encoded token
// endpoint. POST /token/refresh.
func (c *Client) RefreshTokenForm(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	var out TokenResponse
	if err := c.doForm(ctx, "/token/refresh", form, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- RFC 8693 token exchange (on-behalf-of / delegation) ----

// GrantTypeTokenExchange is the RFC 8693 grant_type URN for OAuth 2.0 Token
// Exchange — the on-behalf-of (OBO) / delegation flow in which app/agent A
// exchanges user U's token for one it can present to mesh service B as U.
const GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

// RFC 8693 §3 token-type identifiers. The exchange defaults both the
// subject_token_type and the requested_token_type to access_token.
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
)

// ExchangeOption customizes a token-exchange request built by TokenExchangeForm
// / ExchangeToken. Options are applied after the defaults, in order, so a
// With*TokenType option overrides the access_token default.
type ExchangeOption func(url.Values)

// WithScope requests a specific (space-delimited) scope for the exchanged token.
// The server narrows it fail-closed against the delegation-grant ceiling — it is
// never widened, and an empty resulting scope is denied. Omit to accept the
// grant's default scope. (See FINDINGS Q5 / permission_service.py:830-848.)
func WithScope(scope string) ExchangeOption {
	return func(v url.Values) { v.Set("scope", scope) }
}

// WithActorToken supplies the RFC 8693 actor_token (the party acting on the
// subject's behalf) for the delegation/composite case. Per RFC 8693 §2.1
// actor_token_type is required when actor_token is present, so this also sets
// actor_token_type to access_token.
func WithActorToken(actorToken string) ExchangeOption {
	return func(v url.Values) {
		v.Set("actor_token", actorToken)
		v.Set("actor_token_type", TokenTypeAccessToken)
	}
}

// WithSubjectTokenType overrides the subject_token_type (default: access_token).
func WithSubjectTokenType(tokenType string) ExchangeOption {
	return func(v url.Values) { v.Set("subject_token_type", tokenType) }
}

// WithRequestedTokenType overrides the requested_token_type (default: access_token).
func WithRequestedTokenType(tokenType string) ExchangeOption {
	return func(v url.Values) { v.Set("requested_token_type", tokenType) }
}

// ExchangeResponse is the RFC 8693 §2.2.1 token-exchange response. Unlike
// TokenResponse it surfaces issued_token_type — the type of the returned
// security token — which the plain token response silently drops.
type ExchangeResponse struct {
	AccessToken     string `json:"access_token,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
	TokenType       string `json:"token_type,omitempty"`
	ExpiresIn       int    `json:"expires_in,omitempty"`
	Scope           string `json:"scope,omitempty"`
}

// TokenExchangeForm builds the RFC 8693 token-exchange (on-behalf-of) form for
// POST /auth/oauth/token: grant_type is the token-exchange URN, subject_token is
// the token being exchanged (typically the end user's access token), and
// audience names the mesh service the exchanged token is minted for — which must
// be that org's registered service_audience or the server returns invalid_target.
// subject_token_type and requested_token_type both default to access_token;
// override with the With*TokenType options. Optional: WithScope, WithActorToken.
//
// It mirrors RefreshTokenForm — a typed builder for the raw OAuthToken form path.
func TokenExchangeForm(subjectToken, audience string, opts ...ExchangeOption) url.Values {
	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", TokenTypeAccessToken)
	form.Set("requested_token_type", TokenTypeAccessToken)
	if audience != "" {
		form.Set("audience", audience)
	}
	for _, opt := range opts {
		opt(form)
	}
	return form
}

// ExchangeToken performs an RFC 8693 token exchange (on-behalf-of): it exchanges
// subjectToken for a token minted for audience, using the SAME token endpoint,
// transport, and OAuth error-envelope mapping as OAuthToken, and decodes the
// §2.2.1 body (including issued_token_type) into an ExchangeResponse. It requires
// two provisioning prerequisites — audience registered as the org's
// service_audience and a read-only may_act delegation grant; see
// docs/OBO_TOKEN_EXCHANGE.md. POST /auth/oauth/token (form-encoded).
func (c *Client) ExchangeToken(ctx context.Context, subjectToken, audience string, opts ...ExchangeOption) (*ExchangeResponse, error) {
	var out ExchangeResponse
	if err := c.doForm(ctx, "/auth/oauth/token", TokenExchangeForm(subjectToken, audience, opts...), &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// RegisterClient performs RFC 7591 dynamic client registration.
// POST /auth/oauth/register.
func (c *Client) RegisterClient(ctx context.Context, req ClientRegistration) (*ClientRegistrationResponse, error) {
	var out ClientRegistrationResponse
	if err := c.doJSON(ctx, "POST", "/auth/oauth/register", req, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetClientRegistration reads a dynamically-registered client.
// GET /auth/oauth/register/{client_id}.
func (c *Client) GetClientRegistration(ctx context.Context, clientID string) (*ClientRegistrationResponse, error) {
	var out ClientRegistrationResponse
	if err := c.doGet(ctx, "/auth/oauth/register/"+url.PathEscape(clientID), &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateClientRegistration updates a dynamically-registered client.
// PUT /auth/oauth/register/{client_id}.
func (c *Client) UpdateClientRegistration(ctx context.Context, clientID string, req ClientRegistration) (*ClientRegistrationResponse, error) {
	var out ClientRegistrationResponse
	if err := c.doJSON(ctx, "PUT", "/auth/oauth/register/"+url.PathEscape(clientID), req, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteClientRegistration deletes a dynamically-registered client.
// DELETE /auth/oauth/register/{client_id}.
func (c *Client) DeleteClientRegistration(ctx context.Context, clientID string) error {
	return c.doJSON(ctx, "DELETE", "/auth/oauth/register/"+url.PathEscape(clientID), nil, nil, "")
}

// SendVerificationEmail triggers an email-verification message.
// POST /auth/verify-email/send.
func (c *Client) SendVerificationEmail(ctx context.Context, req VerifyEmailSendRequest) error {
	return c.doJSON(ctx, "POST", "/auth/verify-email/send", req, nil, "")
}

// ConfirmVerificationEmail confirms an email-verification token.
// POST /auth/verify-email/confirm.
func (c *Client) ConfirmVerificationEmail(ctx context.Context, token string) error {
	return c.doJSON(ctx, "POST", "/auth/verify-email/confirm", VerifyEmailConfirmRequest{Token: token}, nil, "")
}

// RequestPasswordResetAuth requests a password reset via the auth endpoint.
// POST /auth/password-reset.
func (c *Client) RequestPasswordResetAuth(ctx context.Context, req PasswordReset) (*PasswordResetResponse, error) {
	var out PasswordResetResponse
	if err := c.doJSON(ctx, "POST", "/auth/password-reset", req, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// ConfirmPasswordResetAuth confirms a password reset via the auth endpoint.
// POST /auth/password-reset/confirm.
func (c *Client) ConfirmPasswordResetAuth(ctx context.Context, req PasswordResetConfirm) (*PasswordResetConfirmResponse, error) {
	var out PasswordResetConfirmResponse
	if err := c.doJSON(ctx, "POST", "/auth/password-reset/confirm", req, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// ValidatePasswordResetToken validates a reset token before showing the form.
// GET /auth/password-reset/validate.
func (c *Client) ValidatePasswordResetToken(ctx context.Context, token string) (*PasswordResetValidateResponse, error) {
	q := url.Values{}
	q.Set("token", token)
	var out PasswordResetValidateResponse
	if err := c.doGet(ctx, "/auth/password-reset/validate?"+q.Encode(), &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// PasswordResetValidateResponse is the result of validating a reset token.
type PasswordResetValidateResponse struct {
	Valid   bool   `json:"valid"`
	Email   string `json:"email,omitempty"`
	Message string `json:"message,omitempty"`
}

// OpenIDConfiguration fetches the OIDC discovery document.
// GET /.well-known/openid-configuration.
func (c *Client) OpenIDConfiguration(ctx context.Context) (*OpenIDConfiguration, error) {
	var out OpenIDConfiguration
	if err := c.doGet(ctx, "/.well-known/openid-configuration", &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// AuthorizationServerMetadata fetches the RFC 8414 metadata document.
// GET /.well-known/oauth-authorization-server.
func (c *Client) AuthorizationServerMetadata(ctx context.Context) (*AuthorizationServerMetadata, error) {
	var out AuthorizationServerMetadata
	if err := c.doGet(ctx, "/.well-known/oauth-authorization-server", &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// JWKSHealth reports the health of the global JWKS endpoint.
// GET /.well-known/jwks.json/health.
func (c *Client) JWKSHealth(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.doGet(ctx, "/.well-known/jwks.json/health", &out, ""); err != nil {
		return nil, err
	}
	return out, nil
}
