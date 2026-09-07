package authclient

import (
	"context"
	"encoding/json"
	"net/url"
)

// This file extends the SDK with the Providers / SSO connection config domain
// (contract section 13) and the Federation / SSO sessions / JIT / attribute
// mapping domain (contract section 5). Together these cover SSO and identity
// federation configuration for the admin/tenant-management client type.

// ===================== Models: providers =====================

// ProviderConfigCreate is the body for POST /providers/. Fields mirror the goauth
// createRequest handler (providerswire/handlers.go:125-134). The provider kind is
// provider_type (NOT type), and provider-specific settings (client_id,
// client_secret, issuer_url, domain, ...) go INSIDE Config — the API has no
// top-level fields for them, so the pre-v0.11.0 top-level ClientID/ClientSecret/
// IssuerURL/Domain were silently dropped. A new provider is active by default
// (there is no create-time is_active/enabled).
type ProviderConfigCreate struct {
	Name         string         `json:"name"`
	ProviderType string         `json:"provider_type"` // e.g. "oidc","saml","google","okta"
	Description  string         `json:"description,omitempty"`
	Config       map[string]any `json:"config,omitempty"`
	IsDefault    bool           `json:"is_default,omitempty"`
	Priority     int            `json:"priority,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// ProviderConfigUpdate is the body for PUT /providers/{provider_id}. Mirrors goauth
// updateRequest (:139-147). Enable/disable a provider via IsActive (the server
// field is is_active; the pre-v0.11.0 `enabled` was silently ignored, so toggling
// a provider did nothing). Provider-specific settings go inside Config.
type ProviderConfigUpdate struct {
	Name        *string        `json:"name,omitempty"`
	Description *string        `json:"description,omitempty"`
	Config      map[string]any `json:"config,omitempty"`
	IsActive    *bool          `json:"is_active,omitempty"`
	IsDefault   *bool          `json:"is_default,omitempty"`
	Priority    *int           `json:"priority,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// Provider is a provider configuration record. Fields mirror the goauth
// providerResponse (providerswire/handlers.go:152-166): the kind is provider_type,
// the enabled flag is is_active, and provider-specific settings are inside config
// (the API sends no top-level type/enabled/domain/issuer_url).
type Provider struct {
	ID           string          `json:"id"`
	OrgID        string          `json:"org_id,omitempty"`
	ProviderType string          `json:"provider_type,omitempty"`
	Name         string          `json:"name,omitempty"`
	Description  string          `json:"description,omitempty"`
	Config       map[string]any  `json:"config,omitempty"`
	IsActive     bool            `json:"is_active,omitempty"`
	IsDefault    bool            `json:"is_default,omitempty"`
	Priority     int             `json:"priority,omitempty"`
	Status       string          `json:"status,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
	CreatedAt    string          `json:"created_at,omitempty"`
	UpdatedAt    string          `json:"updated_at,omitempty"`
}

// ProviderTestRequest is the body for POST /providers/test.
type ProviderTestRequest struct {
	ProviderID string         `json:"provider_id,omitempty"`
	Type       string         `json:"type,omitempty"`
	Config     map[string]any `json:"config,omitempty"`
}

// ProviderTestResponse is the result of a provider connectivity test.
type ProviderTestResponse struct {
	Success        bool            `json:"success"`
	Message        string          `json:"message,omitempty"`
	Details        map[string]any  `json:"details,omitempty"`
	Error          string          `json:"error,omitempty"`
	Metadata       json.RawMessage `json:"metadata,omitempty"`
	ResponseTimeMs float64         `json:"response_time_ms,omitempty"`
}

// ===================== Models: federation =====================

// SSOSession is one federated SSO session.
type SSOSession struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id,omitempty"`
	Provider  string `json:"provider,omitempty"`
	Domain    string `json:"domain,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// SSOSessionListResponse is the result of GET /federation/sso/sessions.
type SSOSessionListResponse struct {
	Sessions []SSOSession `json:"sessions"`
	Total    int          `json:"total,omitempty"`
	Count    int64        `json:"count,omitempty"`
}

// SSOSessionCreateResponse is the result of POST /federation/sso/sessions.
type SSOSessionCreateResponse struct {
	Session    SSOSession `json:"session"`
	SessionID  string     `json:"session_id,omitempty"`
	CreatedAt  string     `json:"created_at,omitempty"`
	Domains    []string   `json:"domains,omitempty"`
	ExpiresIn  int64      `json:"expires_in,omitempty"`
	RememberMe bool       `json:"remember_me,omitempty"`
}

// SSOSessionDetailResponse is the result of GET /federation/sso/sessions/{id}.
type SSOSessionDetailResponse struct {
	Session    SSOSession `json:"session"`
	Active     bool       `json:"active,omitempty"`
	CreatedAt  string     `json:"created_at,omitempty"`
	Domains    []string   `json:"domains,omitempty"`
	ExpiresAt  string     `json:"expires_at,omitempty"`
	RememberMe bool       `json:"remember_me,omitempty"`
	SessionID  string     `json:"session_id,omitempty"`
	UserID     string     `json:"user_id,omitempty"`
}

// DomainTokenResponse is the result of POST /federation/sso/create-token.
type DomainTokenResponse struct {
	Token     string `json:"token"`
	Domain    string `json:"domain,omitempty"`
	ExpiresIn int    `json:"expires_in,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

// SSOPropagateResponse is the result of POST /federation/sso/propagate.
type SSOPropagateResponse struct {
	Success           bool     `json:"success,omitempty"`
	PropagatedTo      []string `json:"propagated_to,omitempty"`
	Message           string   `json:"message,omitempty"`
	PropagatedDomains []string `json:"propagated_domains,omitempty"`
	SessionID         string   `json:"session_id,omitempty"`
	Status            string   `json:"status,omitempty"`
}

// LogoutPropagationResponse is the result of POST /federation/sso/propagate-logout.
type LogoutPropagationResponse struct {
	Success     bool     `json:"success,omitempty"`
	LoggedOutOf []string `json:"logged_out_of,omitempty"`
	Message     string   `json:"message,omitempty"`
	SessionID   string   `json:"session_id,omitempty"`
	Status      string   `json:"status,omitempty"`
}

// SSOConfigResponse is the result of GET /federation/sso/config.
type SSOConfigResponse struct {
	Enabled            bool           `json:"enabled,omitempty"`
	Config             map[string]any `json:"config,omitempty"`
	AllowedDomains     []string       `json:"allowed_domains,omitempty"`
	CookieDomain       string         `json:"cookie_domain,omitempty"`
	MaxSessionDuration int64          `json:"max_session_duration,omitempty"`
	RequireMFA         bool           `json:"require_mfa,omitempty"`
	SessionTimeout     int64          `json:"session_timeout,omitempty"`
}

// SSOConfigUpdateResponse is the result of PUT /federation/sso/config.
type SSOConfigUpdateResponse struct {
	Message string         `json:"message,omitempty"`
	Config  map[string]any `json:"config,omitempty"`
}

// SSODomainConfigRequest is the body for POST/PUT /federation/sso/domains/{domain}.
type SSODomainConfigRequest struct {
	ProviderID string         `json:"provider_id,omitempty"`
	Enabled    bool           `json:"enabled,omitempty"`
	Config     map[string]any `json:"config,omitempty"`
}

// SSODomainConfigResponse is one domain's SSO configuration.
type SSODomainConfigResponse struct {
	Domain              string          `json:"domain"`
	ProviderID          string          `json:"provider_id,omitempty"`
	Enabled             bool            `json:"enabled,omitempty"`
	Config              map[string]any  `json:"config,omitempty"`
	Active              bool            `json:"active,omitempty"`
	AllowedAuthMethods  []string        `json:"allowed_auth_methods,omitempty"`
	AllowedRedirectUrls []string        `json:"allowed_redirect_urls,omitempty"`
	CreatedAt           string          `json:"created_at,omitempty"`
	DisplayName         string          `json:"display_name,omitempty"`
	EntityID            string          `json:"entity_id,omitempty"`
	ExpiresAt           string          `json:"expires_at,omitempty"`
	IPWhitelist         []string        `json:"ip_whitelist,omitempty"`
	LoginCallbackURL    string          `json:"login_callback_url,omitempty"`
	LogoutCallbackURL   string          `json:"logout_callback_url,omitempty"`
	Metadata            json.RawMessage `json:"metadata,omitempty"`
	RequireMFA          bool            `json:"require_mfa,omitempty"`
	SessionTimeout      int64           `json:"session_timeout,omitempty"`
	UpdatedAt           string          `json:"updated_at,omitempty"`
}

// SSODomainListResponse is the result of GET /federation/sso/domains.
type SSODomainListResponse struct {
	Domains  []SSODomainConfigResponse `json:"domains"`
	Total    int                       `json:"total,omitempty"`
	Page     int64                     `json:"page,omitempty"`
	PageSize int64                     `json:"page_size,omitempty"`
}

// AttributeMapping is one IdP attribute -> local attribute mapping.
type AttributeMapping struct {
	ID         string `json:"id,omitempty"`
	SourceAttr string `json:"source_attribute"`
	TargetAttr string `json:"target_attribute"`
	Transform  string `json:"transform,omitempty"`
	ProviderID string `json:"provider_id,omitempty"`
}

// AttributeMappingListResponse is the result of GET /federation/attribute-mappings.
type AttributeMappingListResponse struct {
	Mappings []AttributeMapping `json:"mappings"`
	Total    int                `json:"total,omitempty"`
	Count    int64              `json:"count,omitempty"`
}

// AttributeMappingCreateResponse is the result of POST /federation/attribute-mappings.
type AttributeMappingCreateResponse struct {
	Mapping   AttributeMapping `json:"mapping"`
	Message   string           `json:"message,omitempty"`
	MappingID string           `json:"mapping_id,omitempty"`
}

// JITConfigResponse is the result of GET /federation/jit/config (just-in-time provisioning).
type JITConfigResponse struct {
	Enabled        bool           `json:"enabled,omitempty"`
	DefaultRole    string         `json:"default_role,omitempty"`
	AllowedDomains []string       `json:"allowed_domains,omitempty"`
	Config         map[string]any `json:"config,omitempty"`
	AutoActivate   bool           `json:"auto_activate,omitempty"`
	SyncAttributes bool           `json:"sync_attributes,omitempty"`
}

// FederationStatsResponse is the result of GET /federation/stats.
type FederationStatsResponse struct {
	ActiveSessions int             `json:"active_sessions,omitempty"`
	Domains        int             `json:"domains,omitempty"`
	Providers      int             `json:"providers,omitempty"`
	Stats          map[string]any  `json:"stats,omitempty"`
	SAML           json.RawMessage `json:"saml,omitempty"`
	SSO            json.RawMessage `json:"sso,omitempty"`
	Webauthn       json.RawMessage `json:"webauthn,omitempty"`
}

// ===================== Providers =====================

// CreateProvider creates a provider/SSO connection (requires org.admin).
// POST /providers/.
func (c *Client) CreateProvider(ctx context.Context, req ProviderConfigCreate, callerToken string) (*Provider, error) {
	var out Provider
	if err := c.doJSON(ctx, "POST", "/providers/", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListProviders lists configured providers (requires org.read). GET /providers/.
func (c *Client) ListProviders(ctx context.Context, callerToken string) ([]Provider, error) {
	var out []Provider
	if err := c.doGet(ctx, "/providers/", &out, callerToken); err != nil {
		return nil, err
	}
	return out, nil
}

// GetProvider fetches a provider config (requires org.read).
// GET /providers/{provider_id}.
func (c *Client) GetProvider(ctx context.Context, providerID, callerToken string) (*Provider, error) {
	var out Provider
	if err := c.doGet(ctx, "/providers/"+url.PathEscape(providerID), &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateProvider updates a provider config (requires org.admin).
// PUT /providers/{provider_id}.
func (c *Client) UpdateProvider(ctx context.Context, providerID string, req ProviderConfigUpdate, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "PUT", "/providers/"+url.PathEscape(providerID), req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteProvider deletes a provider config (requires org.admin).
// DELETE /providers/{provider_id}.
func (c *Client) DeleteProvider(ctx context.Context, providerID, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "DELETE", "/providers/"+url.PathEscape(providerID), nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// TestProvider tests a provider's connectivity/config (requires org.admin).
// POST /providers/test.
func (c *Client) TestProvider(ctx context.Context, req ProviderTestRequest, callerToken string) (*ProviderTestResponse, error) {
	var out ProviderTestResponse
	if err := c.doJSON(ctx, "POST", "/providers/test", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// SupportedProviderTypes lists provider types the service supports.
// GET /providers/types/supported. PUBLIC.
func (c *Client) SupportedProviderTypes(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.doGet(ctx, "/providers/types/supported", &out, ""); err != nil {
		return nil, err
	}
	return out, nil
}

// ===================== Federation: SSO sessions =====================

// ListSSOSessions lists the caller's federated SSO sessions.
// GET /federation/sso/sessions.
func (c *Client) ListSSOSessions(ctx context.Context, token string) (*SSOSessionListResponse, error) {
	var out SSOSessionListResponse
	if err := c.doGet(ctx, "/federation/sso/sessions", &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateSSOSession creates a federated SSO session.
// POST /federation/sso/sessions.
func (c *Client) CreateSSOSession(ctx context.Context, token string) (*SSOSessionCreateResponse, error) {
	var out SSOSessionCreateResponse
	if err := c.doJSON(ctx, "POST", "/federation/sso/sessions", struct{}{}, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateDomainToken mints a domain-scoped SSO token.
// POST /federation/sso/create-token.
func (c *Client) CreateDomainToken(ctx context.Context, token string) (*DomainTokenResponse, error) {
	var out DomainTokenResponse
	if err := c.doJSON(ctx, "POST", "/federation/sso/create-token", struct{}{}, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetSSOSession fetches one of the caller's SSO sessions.
// GET /federation/sso/sessions/{session_id}.
func (c *Client) GetSSOSession(ctx context.Context, sessionID, token string) (*SSOSessionDetailResponse, error) {
	var out SSOSessionDetailResponse
	if err := c.doGet(ctx, "/federation/sso/sessions/"+url.PathEscape(sessionID), &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteSSOSession terminates one of the caller's SSO sessions.
// DELETE /federation/sso/sessions/{session_id}.
func (c *Client) DeleteSSOSession(ctx context.Context, sessionID, token string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "DELETE", "/federation/sso/sessions/"+url.PathEscape(sessionID), nil, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// PropagateSSO propagates an SSO session across domains (requires sso.admin).
// POST /federation/sso/propagate.
func (c *Client) PropagateSSO(ctx context.Context, callerToken string) (*SSOPropagateResponse, error) {
	var out SSOPropagateResponse
	if err := c.doJSON(ctx, "POST", "/federation/sso/propagate", struct{}{}, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// PropagateLogout propagates a logout across federated domains.
// POST /federation/sso/propagate-logout.
func (c *Client) PropagateLogout(ctx context.Context, token string) (*LogoutPropagationResponse, error) {
	var out LogoutPropagationResponse
	if err := c.doJSON(ctx, "POST", "/federation/sso/propagate-logout", struct{}{}, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// ===================== Federation: SSO config & domains =====================

// GetSSOConfig returns the org SSO configuration (requires org.admin).
// GET /federation/sso/config.
func (c *Client) GetSSOConfig(ctx context.Context, callerToken string) (*SSOConfigResponse, error) {
	var out SSOConfigResponse
	if err := c.doGet(ctx, "/federation/sso/config", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateSSOConfig updates the org SSO configuration (requires org.admin).
// PUT /federation/sso/config.
func (c *Client) UpdateSSOConfig(ctx context.Context, config map[string]any, callerToken string) (*SSOConfigUpdateResponse, error) {
	var out SSOConfigUpdateResponse
	if err := c.doJSON(ctx, "PUT", "/federation/sso/config", config, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListSSODomains lists configured SSO domains (requires org.admin).
// GET /federation/sso/domains.
func (c *Client) ListSSODomains(ctx context.Context, callerToken string) (*SSODomainListResponse, error) {
	var out SSODomainListResponse
	if err := c.doGet(ctx, "/federation/sso/domains", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetSSODomain fetches one SSO domain config (requires org.admin).
// GET /federation/sso/domains/{domain}.
func (c *Client) GetSSODomain(ctx context.Context, domain, callerToken string) (*SSODomainConfigResponse, error) {
	var out SSODomainConfigResponse
	if err := c.doGet(ctx, "/federation/sso/domains/"+url.PathEscape(domain), &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateSSODomain creates an SSO domain config (requires org.admin).
// POST /federation/sso/domains/{domain}.
func (c *Client) CreateSSODomain(ctx context.Context, domain string, req SSODomainConfigRequest, callerToken string) (*SSODomainConfigResponse, error) {
	var out SSODomainConfigResponse
	if err := c.doJSON(ctx, "POST", "/federation/sso/domains/"+url.PathEscape(domain), req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateSSODomain updates an SSO domain config (requires org.admin).
// PUT /federation/sso/domains/{domain}.
func (c *Client) UpdateSSODomain(ctx context.Context, domain string, req SSODomainConfigRequest, callerToken string) (*SSODomainConfigResponse, error) {
	var out SSODomainConfigResponse
	if err := c.doJSON(ctx, "PUT", "/federation/sso/domains/"+url.PathEscape(domain), req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteSSODomain removes an SSO domain config (requires org.admin).
// DELETE /federation/sso/domains/{domain}.
func (c *Client) DeleteSSODomain(ctx context.Context, domain, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "DELETE", "/federation/sso/domains/"+url.PathEscape(domain), nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ===================== Federation: attribute mappings, JIT, stats =====================

// ListAttributeMappings lists federation attribute mappings (requires system.admin).
// GET /federation/attribute-mappings.
func (c *Client) ListAttributeMappings(ctx context.Context, callerToken string) (*AttributeMappingListResponse, error) {
	var out AttributeMappingListResponse
	if err := c.doGet(ctx, "/federation/attribute-mappings", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateAttributeMapping creates a federation attribute mapping (requires system.admin).
// POST /federation/attribute-mappings.
func (c *Client) CreateAttributeMapping(ctx context.Context, req AttributeMapping, callerToken string) (*AttributeMappingCreateResponse, error) {
	var out AttributeMappingCreateResponse
	if err := c.doJSON(ctx, "POST", "/federation/attribute-mappings", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetJITConfig returns just-in-time provisioning config (requires org.admin).
// GET /federation/jit/config.
func (c *Client) GetJITConfig(ctx context.Context, callerToken string) (*JITConfigResponse, error) {
	var out JITConfigResponse
	if err := c.doGet(ctx, "/federation/jit/config", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateJITConfig updates just-in-time provisioning config (requires org.admin).
// PUT /federation/jit/config.
func (c *Client) UpdateJITConfig(ctx context.Context, config map[string]any, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "PUT", "/federation/jit/config", config, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// FederationStats returns federation usage statistics (requires system.admin).
// GET /federation/stats.
func (c *Client) FederationStats(ctx context.Context, callerToken string) (*FederationStatsResponse, error) {
	var out FederationStatsResponse
	if err := c.doGet(ctx, "/federation/stats", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}
