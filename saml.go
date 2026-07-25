package authclient

import (
	"context"
	"net/url"
)

// This file covers the SAML domain (contract section 4): IdP + SP flows
// (metadata, SSO, ACS, SLO), service-provider registration/management,
// attribute mappings, certificates and analytics. Browser-facing SSO/ACS/SLO
// endpoints exchange XML/form payloads, so those operations work with raw
// strings/forms while management endpoints use typed models. Admin operations
// require saml.admin / saml.read / system.admin scopes and accept either a
// BearerJWT or an ApiKeyBearer via callerToken.

// ---- Models ----

// SAMLAssertionResult is the result of the assertion-consumer service.
type SAMLAssertionResult struct {
	AccessToken  string         `json:"access_token,omitempty"`
	RefreshToken string         `json:"refresh_token,omitempty"`
	NameID       string         `json:"name_id,omitempty"`
	SessionIndex string         `json:"session_index,omitempty"`
	Attributes   map[string]any `json:"attributes,omitempty"`
	RelayState   string         `json:"relay_state,omitempty"`
}

// SAMLLogoutResult is the result of a SAML single-logout.
type SAMLLogoutResult struct {
	Success     bool   `json:"success,omitempty"`
	RedirectURL string `json:"redirect_url,omitempty"`
	Message     string `json:"message,omitempty"`
}

// SAMLServiceProviderConfig is the body for POST /saml/sp/register and the
// shape used to update a service provider.
type SAMLServiceProviderConfig struct {
	EntityID             string            `json:"entity_id"`
	Name                 string            `json:"name,omitempty"`
	ACSURL               string            `json:"acs_url,omitempty"`
	SLOURL               string            `json:"slo_url,omitempty"`
	MetadataURL          string            `json:"metadata_url,omitempty"`
	MetadataXML          string            `json:"metadata_xml,omitempty"`
	NameIDFormat         string            `json:"name_id_format,omitempty"`
	WantAssertionsSigned bool              `json:"want_assertions_signed,omitempty"`
	SignAuthnRequests    bool              `json:"sign_authn_requests,omitempty"`
	AllowedRedirectURLs  []string          `json:"allowed_redirect_urls,omitempty"`
	AttributeMapping     map[string]string `json:"attribute_mapping,omitempty"`
}

// SAMLSPRegistrationResponse is the result of registering a service provider.
type SAMLSPRegistrationResponse struct {
	SPID        string `json:"sp_id"`
	EntityID    string `json:"entity_id,omitempty"`
	MetadataURL string `json:"metadata_url,omitempty"`
	Message     string `json:"message,omitempty"`
}

// SAMLServiceProvider is a registered service provider (detail view).
type SAMLServiceProvider struct {
	SPID         string `json:"sp_id"`
	EntityID     string `json:"entity_id,omitempty"`
	Name         string `json:"name,omitempty"`
	ACSURL       string `json:"acs_url,omitempty"`
	SLOURL       string `json:"slo_url,omitempty"`
	NameIDFormat string `json:"name_id_format,omitempty"`
	Status       string `json:"status,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
}

// SAMLSPDetailResponse wraps a service-provider detail.
type SAMLSPDetailResponse struct {
	ServiceProvider SAMLServiceProvider `json:"service_provider"`
}

// SAMLSPListResponse lists registered service providers.
type SAMLSPListResponse struct {
	ServiceProviders []SAMLServiceProvider `json:"service_providers"`
	Total            int                   `json:"total,omitempty"`
}

// SAMLSPUpdateResponse is the result of updating a service provider.
type SAMLSPUpdateResponse struct {
	SPID    string `json:"sp_id,omitempty"`
	Message string `json:"message,omitempty"`
	Success bool   `json:"success,omitempty"`
}

// SAMLSession is one active SAML session.
type SAMLSession struct {
	SessionIndex string `json:"session_index,omitempty"`
	NameID       string `json:"name_id,omitempty"`
	SPEntityID   string `json:"sp_entity_id,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
}

// SAMLSessionListResponse lists active SAML sessions.
type SAMLSessionListResponse struct {
	Sessions []SAMLSession `json:"sessions"`
}

// SAMLAttributeMappingResponse is the SAML attribute-mapping configuration.
type SAMLAttributeMappingResponse struct {
	Mappings map[string]string `json:"mappings"`
}

// SAMLAttributeMappingUpdate is the body for PUT /saml/attributes/mappings.
type SAMLAttributeMappingUpdate struct {
	Mappings map[string]string `json:"mappings"`
}

// SAMLCertificate describes a signing/encryption certificate.
type SAMLCertificate struct {
	Use         string `json:"use,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	NotBefore   string `json:"not_before,omitempty"`
	NotAfter    string `json:"not_after,omitempty"`
	Active      bool   `json:"active,omitempty"`
}

// SAMLCertificateStatusResponse reports certificate status.
type SAMLCertificateStatusResponse struct {
	Certificates []SAMLCertificate `json:"certificates"`
}

// SAMLCertificateGenerateResponse is the result of generating a certificate.
type SAMLCertificateGenerateResponse struct {
	Certificate string `json:"certificate,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Message     string `json:"message,omitempty"`
}

// SAMLAnalyticsResponse reports SAML usage analytics.
type SAMLAnalyticsResponse struct {
	TotalLogins    int            `json:"total_logins,omitempty"`
	ActiveSessions int            `json:"active_sessions,omitempty"`
	Stats          map[string]any `json:"stats,omitempty"`
}

// ---- IdP / SP browser flows ----

// SAMLMetadata fetches the IdP metadata XML. GET /saml/metadata.
func (c *Client) SAMLMetadata(ctx context.Context) (string, error) {
	return c.getString(ctx, "/saml/metadata", "")
}

// SAMLSSORedirect performs an IdP-initiated/redirect-binding SSO GET, returning
// the raw response body (typically an HTML/redirect). GET /saml/sso.
func (c *Client) SAMLSSORedirect(ctx context.Context, params url.Values) (string, error) {
	path := "/saml/sso"
	if params != nil {
		if enc := params.Encode(); enc != "" {
			path += "?" + enc
		}
	}
	return c.getString(ctx, path, "")
}

// SAMLSSOPost performs a POST-binding SSO submission (form-encoded).
// POST /saml/sso.
func (c *Client) SAMLSSOPost(ctx context.Context, form url.Values) (string, error) {
	return c.postFormString(ctx, "/saml/sso", form)
}

// SAMLAssertionConsumer processes a SAML response at the ACS (form-encoded),
// returning the resulting assertion/token payload. POST /saml/acs.
func (c *Client) SAMLAssertionConsumer(ctx context.Context, form url.Values) (*SAMLAssertionResult, error) {
	var out SAMLAssertionResult
	if err := c.doForm(ctx, "/saml/acs", form, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// SAMLSingleLogout processes a single-logout request/response. POST /saml/slo.
func (c *Client) SAMLSingleLogout(ctx context.Context, form url.Values) (*SAMLLogoutResult, error) {
	var out SAMLLogoutResult
	if err := c.doForm(ctx, "/saml/slo", form, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// SAMLSPMetadata fetches a service provider's metadata XML.
// GET /saml/sp/{sp_id}/metadata.
func (c *Client) SAMLSPMetadata(ctx context.Context, spID string) (string, error) {
	return c.getString(ctx, "/saml/sp/"+url.PathEscape(spID)+"/metadata", "")
}

// ---- SP management ----

// RegisterSAMLSP registers a SAML service provider. POST /saml/sp/register.
// Requires saml.admin. callerToken may be a JWT or an API key.
func (c *Client) RegisterSAMLSP(ctx context.Context, req SAMLServiceProviderConfig, callerToken string) (*SAMLSPRegistrationResponse, error) {
	var out SAMLSPRegistrationResponse
	if err := c.doJSON(ctx, "POST", "/saml/sp/register", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListSAMLSessions lists the caller's active SAML sessions. GET /saml/sessions.
func (c *Client) ListSAMLSessions(ctx context.Context, token string) (*SAMLSessionListResponse, error) {
	var out SAMLSessionListResponse
	if err := c.doGet(ctx, "/saml/sessions", &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListSAMLSPs lists registered service providers. GET /saml/sp/list.
// Requires saml.read.
func (c *Client) ListSAMLSPs(ctx context.Context, callerToken string) (*SAMLSPListResponse, error) {
	var out SAMLSPListResponse
	if err := c.doGet(ctx, "/saml/sp/list", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetSAMLSP fetches a service provider by id. GET /saml/sp/{sp_id}.
func (c *Client) GetSAMLSP(ctx context.Context, spID, callerToken string) (*SAMLSPDetailResponse, error) {
	var out SAMLSPDetailResponse
	if err := c.doGet(ctx, "/saml/sp/"+url.PathEscape(spID), &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateSAMLSP updates a service provider. PUT /saml/sp/{sp_id}.
// Requires saml.admin.
func (c *Client) UpdateSAMLSP(ctx context.Context, spID string, req SAMLServiceProviderConfig, callerToken string) (*SAMLSPUpdateResponse, error) {
	var out SAMLSPUpdateResponse
	if err := c.doJSON(ctx, "PUT", "/saml/sp/"+url.PathEscape(spID), req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteSAMLSP deletes a service provider. DELETE /saml/sp/{sp_id}.
// Requires saml.admin / system.admin.
func (c *Client) DeleteSAMLSP(ctx context.Context, spID, callerToken string) (*EnterpriseMessageResponse, error) {
	var out EnterpriseMessageResponse
	if err := c.doJSON(ctx, "DELETE", "/saml/sp/"+url.PathEscape(spID), nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Attribute mappings / certificates / analytics ----

// GetSAMLAttributeMappings returns the SAML attribute mappings.
// GET /saml/attributes/mappings. Requires saml.read / system.admin.
func (c *Client) GetSAMLAttributeMappings(ctx context.Context, callerToken string) (*SAMLAttributeMappingResponse, error) {
	var out SAMLAttributeMappingResponse
	if err := c.doGet(ctx, "/saml/attributes/mappings", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateSAMLAttributeMappings updates the SAML attribute mappings.
// PUT /saml/attributes/mappings. Requires saml.admin / system.admin.
func (c *Client) UpdateSAMLAttributeMappings(ctx context.Context, req SAMLAttributeMappingUpdate, callerToken string) (*EnterpriseMessageResponse, error) {
	var out EnterpriseMessageResponse
	if err := c.doJSON(ctx, "PUT", "/saml/attributes/mappings", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetSAMLCertificates returns SAML certificate status.
// GET /saml/certificates. Requires saml.read / system.admin.
func (c *Client) GetSAMLCertificates(ctx context.Context, callerToken string) (*SAMLCertificateStatusResponse, error) {
	var out SAMLCertificateStatusResponse
	if err := c.doGet(ctx, "/saml/certificates", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GenerateSAMLCertificate generates a new SAML certificate.
// POST /saml/certificates/generate. Requires saml.admin / system.admin.
func (c *Client) GenerateSAMLCertificate(ctx context.Context, callerToken string) (*SAMLCertificateGenerateResponse, error) {
	var out SAMLCertificateGenerateResponse
	if err := c.doJSON(ctx, "POST", "/saml/certificates/generate", struct{}{}, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// SAMLAnalytics returns SAML usage analytics.
// GET /saml/analytics. Requires saml.read / system.admin.
func (c *Client) SAMLAnalytics(ctx context.Context, callerToken string) (*SAMLAnalyticsResponse, error) {
	var out SAMLAnalyticsResponse
	if err := c.doGet(ctx, "/saml/analytics", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}
