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
// Fields mirror the goauth orgRegisterRequest handler struct (orgauth/login.go:37-43).
type OrgRegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name,omitempty"`
	// ClientID associates the new user with the OAuth client driving the hosted
	// login (accepted by the org-scoped register handler).
	ClientID string `json:"client_id,omitempty"`
	// InvitationCode joins the tenant by invite (the org-scoped invite-join flow).
	InvitationCode string `json:"invitation_code,omitempty"`
	// NOTE: this endpoint does NOT accept first_name/last_name (only name). The
	// pre-v0.11.0 FirstName/LastName fields were phantom (ignored) and were removed.
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

// The org login-config MANAGEMENT API (GET/PUT
// /organizations/{org_id}/login-config) is organised into FIVE nested sections:
// branding, content, auth_methods, registration, security. GET returns the
// merged config as those sections at the TOP LEVEL (no {config} wrapper). PUT is
// a partial deep-merge and 400-REJECTS any unknown top-level key, so a PUT body
// MUST be nested by section (a flat {logo_url:...} body is rejected wholesale).
// Sections/fields mirror goauth loginConfigDefaults (orgs/loginconfig.go:163).
// Fields are pointers so a partial PUT can distinguish "unset" from a zero value.

// LoginConfigBranding is the "branding" section.
type LoginConfigBranding struct {
	LogoURL         *string        `json:"logo_url,omitempty"`
	PrimaryColor    *string        `json:"primary_color,omitempty"`
	BackgroundColor *string        `json:"background_color,omitempty"`
	PageTitle       *string        `json:"page_title,omitempty"`
	CustomCSS       *string        `json:"custom_css,omitempty"`
	HidePoweredBy   *bool          `json:"hide_powered_by,omitempty"`
	LoginTemplate   *string        `json:"login_template,omitempty"`
	SecurityBadge   map[string]any `json:"security_badge,omitempty"`
}

// LoginConfigContent is the "content" section.
type LoginConfigContent struct {
	WelcomeMessage    *string `json:"welcome_message,omitempty"`
	SignupMessage     *string `json:"signup_message,omitempty"`
	TermsURL          *string `json:"terms_url,omitempty"`
	PrivacyURL        *string `json:"privacy_url,omitempty"`
	SupportURL        *string `json:"support_url,omitempty"`
	FooterMessage     *string `json:"footer_message,omitempty"`
	TrustSectionLabel *string `json:"trust_section_label,omitempty"`
	TrustLogos        []any   `json:"trust_logos,omitempty"`
	FooterLinkPrefix  *string `json:"footer_link_prefix,omitempty"`
	FooterLinkText    *string `json:"footer_link_text,omitempty"`
	FooterLinkURL     *string `json:"footer_link_url,omitempty"`
}

// LoginConfigAuthMethods is the "auth_methods" section.
type LoginConfigAuthMethods struct {
	EmailPassword  *bool `json:"email_password,omitempty"`
	SignupEnabled  *bool `json:"signup_enabled,omitempty"`
	InvitationOnly *bool `json:"invitation_only,omitempty"`
}

// LoginConfigRegistration is the "registration" section.
type LoginConfigRegistration struct {
	DefaultRole              *string        `json:"default_role,omitempty"`
	DefaultTeam              *string        `json:"default_team,omitempty"`
	RequireEmailVerification *bool          `json:"require_email_verification,omitempty"`
	CollectName              *bool          `json:"collect_name,omitempty"`
	OrgStructure             map[string]any `json:"org_structure,omitempty"`
	// DefaultLanding selects the post-login landing org: "parent" (default) or
	// "workspace". The API 400-rejects any other value.
	DefaultLanding *string `json:"default_landing,omitempty"`
}

// LoginConfigSecurity is the "security" section.
type LoginConfigSecurity struct {
	PostLogoutRedirectURI      *string  `json:"post_logout_redirect_uri,omitempty"`
	RememberMeEnabled          *bool    `json:"remember_me_enabled,omitempty"`
	AcceptInviteURL            *string  `json:"accept_invite_url,omitempty"`
	AcceptInviteErrorURL       *string  `json:"accept_invite_error_url,omitempty"`
	AcceptInviteAllowedOrigins []string `json:"accept_invite_allowed_origins,omitempty"`
}

// LoginConfig is the merged org login-config: the shape GET returns (sections at
// the top level, no wrapper) and that a PUT echoes back. After the server's
// deep-merge onto defaults, every section is present on a GET.
type LoginConfig struct {
	Branding     *LoginConfigBranding     `json:"branding,omitempty"`
	Content      *LoginConfigContent      `json:"content,omitempty"`
	AuthMethods  *LoginConfigAuthMethods  `json:"auth_methods,omitempty"`
	Registration *LoginConfigRegistration `json:"registration,omitempty"`
	Security     *LoginConfigSecurity     `json:"security,omitempty"`
}

// LoginConfigUpdate is the partial body for PUT
// /organizations/{org_id}/login-config: send only the sections you want changed;
// each is deep-merged server-side. It is structurally the merged LoginConfig
// (unknown top-level keys are 400-rejected, so only these five sections apply).
type LoginConfigUpdate = LoginConfig

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

// OrgClientSafe is the safe (non-secret) view of an OAuth client in an org. Fields
// mirror the goauth orgClientSafe handler struct (orgs/clients.go:20-32).
type OrgClientSafe struct {
	ClientID      string   `json:"client_id,omitempty"`
	ClientName    string   `json:"client_name,omitempty"`
	ClientType    string   `json:"client_type,omitempty"`
	ClientURI     string   `json:"client_uri,omitempty"`
	LogoURI       string   `json:"logo_uri,omitempty"`
	RedirectURIs  []string `json:"redirect_uris,omitempty"`
	ResponseTypes []string `json:"response_types,omitempty"`
	GrantTypes    []string `json:"grant_types,omitempty"`
	Scope         string   `json:"scope,omitempty"`
	Status        string   `json:"status,omitempty"`
	CreatedAt     string   `json:"created_at,omitempty"`
	OrgID         string   `json:"org_id,omitempty"`
}

// ---- Operations: hosted login config ----

// GetLoginConfig returns a tenant's hosted-login configuration.
// GET /organizations/{org_id}/login-config.
//
// The API returns the merged sections at the TOP LEVEL, so this returns a
// *LoginConfig (BREAKING vs the pre-v0.11.0 *LoginConfigResponse{Config} wrapper,
// which decoded empty because the API never wraps in "config").
func (c *Client) GetLoginConfig(ctx context.Context, orgID, callerToken string) (*LoginConfig, error) {
	var out LoginConfig
	if err := c.doGet(ctx, "/organizations/"+url.PathEscape(orgID)+"/login-config", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateLoginConfig updates a tenant's hosted-login configuration.
// PUT /organizations/{org_id}/login-config. The body is a partial, section-nested
// deep-merge; it returns the full merged config.
func (c *Client) UpdateLoginConfig(ctx context.Context, orgID string, req LoginConfigUpdate, callerToken string) (*LoginConfig, error) {
	var out LoginConfig
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

// ListOrgClients lists the OAuth clients registered for a tenant (safe view, no
// secrets). GET /organizations/{org_id}/clients.
//
// The endpoint returns a BARE array of clients, so this returns []OrgClientSafe
// (BREAKING vs the pre-v0.11.0 *OrgClientSafeResponse{Clients,Total} envelope,
// which hard-errored decoding the array into a struct).
func (c *Client) ListOrgClients(ctx context.Context, orgID, callerToken string) ([]OrgClientSafe, error) {
	var out []OrgClientSafe
	if err := c.doGet(ctx, "/organizations/"+url.PathEscape(orgID)+"/clients", &out, callerToken); err != nil {
		return nil, err
	}
	return out, nil
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
