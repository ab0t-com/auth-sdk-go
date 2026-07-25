package authclient

import (
	"context"
	"net/url"
)

// This file covers per-tenant hosted authentication (contract section 2:
// /organizations/{slug}/auth/*) and the hosted-login configuration, client
// listing and invite-acceptance surface (section 19). These serve the
// end-user app archetype against an org-scoped login experience and the
// admin archetype configuring it.

// ---- Shared message envelopes ----

// EnterpriseMessageResponse is the {message,...} envelope returned by the
// enterprise (passwordless/SAML/federation) endpoints.
type EnterpriseMessageResponse struct {
	Message string `json:"message,omitempty"`
	Success bool   `json:"success,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// HostedLoginMessageResponse is the message envelope returned by hosted-login
// auth endpoints (org-scoped logout / reset-password).
type HostedLoginMessageResponse struct {
	Message string `json:"message,omitempty"`
	Success bool   `json:"success,omitempty"`
}

// ---- Models: org-scoped auth ----

// OrgLoginRequest is the body for POST /organizations/{slug}/auth/login.
type OrgLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// OrgRegisterRequest is the body for POST /organizations/{slug}/auth/register.
type OrgRegisterRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	Name      string `json:"name,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

// OrgPasswordResetRequest is the body for
// POST /organizations/{slug}/auth/reset-password.
type OrgPasswordResetRequest struct {
	Email string `json:"email"`
}

// OrgProviderInfo is the safe provider metadata returned to a hosted login page.
type OrgProviderInfo struct {
	ID       string `json:"id"`
	Type     string `json:"type,omitempty"`
	Name     string `json:"name,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

// OrgProvidersResponse is the result of GET /organizations/{slug}/auth/providers.
type OrgProvidersResponse struct {
	Providers []OrgProviderInfo `json:"providers"`
}

// ---- Operations: org-scoped auth ----

// OrgLogin authenticates a user against a specific tenant's login endpoint.
// POST /organizations/{slug}/auth/login.
func (c *Client) OrgLogin(ctx context.Context, slug string, req OrgLoginRequest) (*TokenSet, error) {
	var out TokenSet
	if err := c.doJSON(ctx, "POST", "/organizations/"+url.PathEscape(slug)+"/auth/login", req, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// OrgRegister creates a user within a specific tenant.
// POST /organizations/{slug}/auth/register.
func (c *Client) OrgRegister(ctx context.Context, slug string, req OrgRegisterRequest) (*TokenSet, error) {
	var out TokenSet
	if err := c.doJSON(ctx, "POST", "/organizations/"+url.PathEscape(slug)+"/auth/register", req, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// OrgToken exchanges credentials at a tenant's token endpoint (form-encoded).
// POST /organizations/{slug}/auth/token.
func (c *Client) OrgToken(ctx context.Context, slug string, form url.Values) (*TokenResponse, error) {
	var out TokenResponse
	if err := c.doForm(ctx, "/organizations/"+url.PathEscape(slug)+"/auth/token", form, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// OrgRefresh refreshes a token against a tenant's refresh endpoint.
// POST /organizations/{slug}/auth/refresh.
func (c *Client) OrgRefresh(ctx context.Context, slug, refreshToken string) (*TokenResponse, error) {
	var out TokenResponse
	if err := c.doJSON(ctx, "POST", "/organizations/"+url.PathEscape(slug)+"/auth/refresh", RefreshRequest{RefreshToken: refreshToken}, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// OrgLogout logs out of a tenant session. POST /organizations/{slug}/auth/logout.
func (c *Client) OrgLogout(ctx context.Context, slug, token string) (*HostedLoginMessageResponse, error) {
	var out HostedLoginMessageResponse
	if err := c.doJSON(ctx, "POST", "/organizations/"+url.PathEscape(slug)+"/auth/logout", struct{}{}, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// OrgResetPassword requests a password reset within a tenant.
// POST /organizations/{slug}/auth/reset-password.
func (c *Client) OrgResetPassword(ctx context.Context, slug string, req OrgPasswordResetRequest) (*HostedLoginMessageResponse, error) {
	var out HostedLoginMessageResponse
	if err := c.doJSON(ctx, "POST", "/organizations/"+url.PathEscape(slug)+"/auth/reset-password", req, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// OrgAuthProviders lists the tenant's safe provider metadata for a hosted login
// page. GET /organizations/{slug}/auth/providers.
func (c *Client) OrgAuthProviders(ctx context.Context, slug string) (*OrgProvidersResponse, error) {
	var out OrgProvidersResponse
	if err := c.doGet(ctx, "/organizations/"+url.PathEscape(slug)+"/auth/providers", &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// OrgSSOInitiate begins an org-scoped SSO flow, returning the redirect target.
// GET /organizations/{slug}/auth/sso/initiate.
func (c *Client) OrgSSOInitiate(ctx context.Context, slug string, params url.Values) (map[string]any, error) {
	path := "/organizations/" + url.PathEscape(slug) + "/auth/sso/initiate"
	if params != nil {
		if enc := params.Encode(); enc != "" {
			path += "?" + enc
		}
	}
	var out map[string]any
	if err := c.doGet(ctx, path, &out, ""); err != nil {
		return nil, err
	}
	return out, nil
}

// OrgSSOCallback completes an org-scoped SSO flow (form-encoded callback).
// POST /organizations/{slug}/auth/sso/callback.
func (c *Client) OrgSSOCallback(ctx context.Context, slug string, form url.Values) (map[string]any, error) {
	var out map[string]any
	if err := c.doForm(ctx, "/organizations/"+url.PathEscape(slug)+"/auth/sso/callback", form, &out, ""); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- Models: hosted login config (section 19) ----

// LoginConfig describes a tenant's hosted-login branding and behaviour.
type LoginConfig struct {
	OrgID             string         `json:"org_id,omitempty"`
	LogoURL           string         `json:"logo_url,omitempty"`
	PrimaryColor      string         `json:"primary_color,omitempty"`
	BackgroundColor   string         `json:"background_color,omitempty"`
	AllowPassword     bool           `json:"allow_password,omitempty"`
	AllowSignup       bool           `json:"allow_signup,omitempty"`
	AllowPasswordless bool           `json:"allow_passwordless,omitempty"`
	TermsURL          string         `json:"terms_url,omitempty"`
	PrivacyURL        string         `json:"privacy_url,omitempty"`
	CustomCSS         string         `json:"custom_css,omitempty"`
	Settings          map[string]any `json:"settings,omitempty"`
}

// LoginConfigResponse wraps the tenant login configuration.
type LoginConfigResponse struct {
	Config LoginConfig `json:"config"`
}

// LoginConfigUpdate is the body for PUT /organizations/{org_id}/login-config.
type LoginConfigUpdate struct {
	LogoURL           *string         `json:"logo_url,omitempty"`
	PrimaryColor      *string         `json:"primary_color,omitempty"`
	BackgroundColor   *string         `json:"background_color,omitempty"`
	AllowPassword     *bool           `json:"allow_password,omitempty"`
	AllowSignup       *bool           `json:"allow_signup,omitempty"`
	AllowPasswordless *bool           `json:"allow_passwordless,omitempty"`
	TermsURL          *string         `json:"terms_url,omitempty"`
	PrivacyURL        *string         `json:"privacy_url,omitempty"`
	CustomCSS         *string         `json:"custom_css,omitempty"`
	Settings          *map[string]any `json:"settings,omitempty"`
}

// PublicLoginConfig is the public subset of a tenant's login config.
type PublicLoginConfig struct {
	OrgSlug           string            `json:"org_slug,omitempty"`
	OrgName           string            `json:"org_name,omitempty"`
	LogoURL           string            `json:"logo_url,omitempty"`
	PrimaryColor      string            `json:"primary_color,omitempty"`
	BackgroundColor   string            `json:"background_color,omitempty"`
	AllowPassword     bool              `json:"allow_password,omitempty"`
	AllowSignup       bool              `json:"allow_signup,omitempty"`
	AllowPasswordless bool              `json:"allow_passwordless,omitempty"`
	Providers         []OrgProviderInfo `json:"providers,omitempty"`
}

// OrgClientSafe is the safe (non-secret) view of an OAuth client in an org.
type OrgClientSafe struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name,omitempty"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	GrantTypes   []string `json:"grant_types,omitempty"`
	CreatedAt    string   `json:"created_at,omitempty"`
}

// OrgClientSafeResponse is the result of GET /organizations/{org_id}/clients.
type OrgClientSafeResponse struct {
	Clients []OrgClientSafe `json:"clients"`
	Total   int             `json:"total,omitempty"`
}

// ---- Operations: hosted login config ----

// GetLoginConfig returns a tenant's hosted-login configuration.
// GET /organizations/{org_id}/login-config.
func (c *Client) GetLoginConfig(ctx context.Context, orgID, callerToken string) (*LoginConfigResponse, error) {
	var out LoginConfigResponse
	if err := c.doGet(ctx, "/organizations/"+url.PathEscape(orgID)+"/login-config", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateLoginConfig updates a tenant's hosted-login configuration.
// PUT /organizations/{org_id}/login-config.
func (c *Client) UpdateLoginConfig(ctx context.Context, orgID string, req LoginConfigUpdate, callerToken string) (*LoginConfigResponse, error) {
	var out LoginConfigResponse
	if err := c.doJSON(ctx, "PUT", "/organizations/"+url.PathEscape(orgID)+"/login-config", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetPublicLoginConfig returns the public login config for a tenant slug.
// GET /organizations/{slug}/login-config/public.
func (c *Client) GetPublicLoginConfig(ctx context.Context, slug string) (*PublicLoginConfig, error) {
	var out PublicLoginConfig
	if err := c.doGet(ctx, "/organizations/"+url.PathEscape(slug)+"/login-config/public", &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListOrgClients lists the OAuth clients registered for a tenant (safe view).
// GET /organizations/{org_id}/clients.
func (c *Client) ListOrgClients(ctx context.Context, orgID, callerToken string) (*OrgClientSafeResponse, error) {
	var out OrgClientSafeResponse
	if err := c.doGet(ctx, "/organizations/"+url.PathEscape(orgID)+"/clients", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetHostedLoginPage fetches the hosted login page payload for a tenant slug.
// GET /login/{slug}. Returns the raw JSON the hosted page is rendered from.
func (c *Client) GetHostedLoginPage(ctx context.Context, slug string) (map[string]any, error) {
	var out map[string]any
	if err := c.doGet(ctx, "/login/"+url.PathEscape(slug), &out, ""); err != nil {
		return nil, err
	}
	return out, nil
}

// AcceptInvitePage fetches the invite-acceptance page payload for a tenant slug.
// GET /organizations/{slug}/accept-invite. token is the invite token query param.
func (c *Client) AcceptInvitePage(ctx context.Context, slug, inviteToken string) (map[string]any, error) {
	path := "/organizations/" + url.PathEscape(slug) + "/accept-invite"
	if inviteToken != "" {
		q := url.Values{}
		q.Set("token", inviteToken)
		path += "?" + q.Encode()
	}
	var out map[string]any
	if err := c.doGet(ctx, path, &out, ""); err != nil {
		return nil, err
	}
	return out, nil
}
