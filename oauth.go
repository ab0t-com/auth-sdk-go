package authclient

import (
	"context"
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

// ClientRegistration is the body for RFC 7591 dynamic client registration.
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
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                     string   `json:"token_endpoint,omitempty"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	JWKSURI                           string   `json:"jwks_uri,omitempty"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported             []string `json:"subject_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
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
