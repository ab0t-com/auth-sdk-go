package authclient

import (
	"context"
	"net/url"
)

// This file covers the passwordless domain (contract section 3): WebAuthn /
// passkeys, magic links, MFA recovery codes and device listing. These serve
// the end-user app archetype. WebAuthn register/authenticate ceremonies pass
// opaque option/credential blobs straight through (the relying-party JSON is
// browser-generated), so the SDK models them as map[string]any while keeping
// the typed result envelopes.

// ---- Models ----

// WebAuthnConfigResponse is the result of
// GET /auth/passwordless/webauthn/config.
type WebAuthnConfigResponse struct {
	RPID              string   `json:"rp_id,omitempty"`
	RPName            string   `json:"rp_name,omitempty"`
	Origin            string   `json:"origin,omitempty"`
	Origins           []string `json:"origins,omitempty"`
	AttestationFormat string   `json:"attestation,omitempty"`
	UserVerification  string   `json:"user_verification,omitempty"`
	Enabled           bool     `json:"enabled,omitempty"`
}

// WebAuthnRegistrationResult is returned when finishing a WebAuthn registration.
type WebAuthnRegistrationResult struct {
	CredentialID string `json:"credential_id,omitempty"`
	Success      bool   `json:"success,omitempty"`
	Message      string `json:"message,omitempty"`
}

// PasswordlessAuthResponse is the token payload returned by a successful
// passwordless authentication (WebAuthn, magic link or recovery code).
type PasswordlessAuthResponse struct {
	AccessToken  string         `json:"access_token,omitempty"`
	RefreshToken string         `json:"refresh_token,omitempty"`
	TokenType    string         `json:"token_type,omitempty"`
	ExpiresIn    int            `json:"expires_in,omitempty"`
	User         *TokenUserInfo `json:"user,omitempty"`
}

// WebAuthnCredential is a registered passkey/credential.
type WebAuthnCredential struct {
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"`
	DeviceType string `json:"device_type,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	BackedUp   bool   `json:"backed_up,omitempty"`
}

// WebAuthnCredentialListResponse lists a user's registered credentials.
type WebAuthnCredentialListResponse struct {
	Credentials []WebAuthnCredential `json:"credentials"`
}

// WebAuthnCredentialUpdate renames a credential.
type WebAuthnCredentialUpdate struct {
	Name string `json:"name"`
}

// MagicLinkSendResponse is the result of sending a magic link.
type MagicLinkSendResponse struct {
	Message   string `json:"message,omitempty"`
	Success   bool   `json:"success,omitempty"`
	ExpiresIn int    `json:"expires_in,omitempty"`
}

// MagicLinkConfigResponse is the result of GET .../magic-link/config.
type MagicLinkConfigResponse struct {
	Enabled    bool `json:"enabled,omitempty"`
	TTLSeconds int  `json:"ttl_seconds,omitempty"`
	MaxActive  int  `json:"max_active,omitempty"`
}

// ActiveMagicLink describes one outstanding magic link.
type ActiveMagicLink struct {
	Token     string `json:"token,omitempty"`
	Email     string `json:"email,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// ActiveMagicLinksResponse lists a user's active magic links.
type ActiveMagicLinksResponse struct {
	Links []ActiveMagicLink `json:"links"`
}

// MagicLinkAnalyticsResponse is the result of GET .../magic-link/analytics.
type MagicLinkAnalyticsResponse struct {
	Sent     int            `json:"sent,omitempty"`
	Verified int            `json:"verified,omitempty"`
	Expired  int            `json:"expired,omitempty"`
	Stats    map[string]any `json:"stats,omitempty"`
}

// RecoveryCodesResponse is the result of generating MFA recovery codes.
type RecoveryCodesResponse struct {
	Codes     []string `json:"codes"`
	Generated int      `json:"generated,omitempty"`
}

// Device is one entry returned by the device listing.
type Device struct {
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"`
	Type       string `json:"type,omitempty"`
	LastSeenAt string `json:"last_seen_at,omitempty"`
	Trusted    bool   `json:"trusted,omitempty"`
}

// DeviceListResponse lists a user's known devices.
type DeviceListResponse struct {
	Devices []Device `json:"devices"`
}

// ---- WebAuthn operations ----

// WebAuthnConfig returns the relying-party WebAuthn configuration.
// GET /auth/passwordless/webauthn/config.
func (c *Client) WebAuthnConfig(ctx context.Context) (*WebAuthnConfigResponse, error) {
	var out WebAuthnConfigResponse
	if err := c.doGet(ctx, "/auth/passwordless/webauthn/config", &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// WebAuthnRegisterStart begins a passkey registration, returning the creation
// options the authenticator needs. POST /auth/passwordless/webauthn/register/start.
func (c *Client) WebAuthnRegisterStart(ctx context.Context, token string, req map[string]any) (map[string]any, error) {
	var out map[string]any
	if err := c.doJSON(ctx, "POST", "/auth/passwordless/webauthn/register/start", reqOrEmpty(req), &out, token); err != nil {
		return nil, err
	}
	return out, nil
}

// WebAuthnRegisterFinish completes a passkey registration with the
// authenticator's attestation. POST /auth/passwordless/webauthn/register/finish.
func (c *Client) WebAuthnRegisterFinish(ctx context.Context, token string, credential map[string]any) (*WebAuthnRegistrationResult, error) {
	var out WebAuthnRegistrationResult
	if err := c.doJSON(ctx, "POST", "/auth/passwordless/webauthn/register/finish", reqOrEmpty(credential), &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// WebAuthnAuthenticateStart begins a passkey authentication, returning the
// request options. POST /auth/passwordless/webauthn/authenticate/start.
func (c *Client) WebAuthnAuthenticateStart(ctx context.Context, req map[string]any) (map[string]any, error) {
	var out map[string]any
	if err := c.doJSON(ctx, "POST", "/auth/passwordless/webauthn/authenticate/start", reqOrEmpty(req), &out, ""); err != nil {
		return nil, err
	}
	return out, nil
}

// WebAuthnAuthenticateFinish completes a passkey authentication and returns a
// token set. POST /auth/passwordless/webauthn/authenticate/finish.
func (c *Client) WebAuthnAuthenticateFinish(ctx context.Context, assertion map[string]any) (*PasswordlessAuthResponse, error) {
	var out PasswordlessAuthResponse
	if err := c.doJSON(ctx, "POST", "/auth/passwordless/webauthn/authenticate/finish", reqOrEmpty(assertion), &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListWebAuthnCredentials lists the caller's registered credentials.
// GET /auth/passwordless/webauthn/credentials.
func (c *Client) ListWebAuthnCredentials(ctx context.Context, token string) (*WebAuthnCredentialListResponse, error) {
	var out WebAuthnCredentialListResponse
	if err := c.doGet(ctx, "/auth/passwordless/webauthn/credentials", &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateWebAuthnCredential renames one of the caller's credentials.
// PUT /auth/passwordless/webauthn/credentials/{credential_id}.
func (c *Client) UpdateWebAuthnCredential(ctx context.Context, token, credentialID string, req WebAuthnCredentialUpdate) (*EnterpriseMessageResponse, error) {
	var out EnterpriseMessageResponse
	if err := c.doJSON(ctx, "PUT", "/auth/passwordless/webauthn/credentials/"+url.PathEscape(credentialID), req, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteWebAuthnCredential removes one of the caller's credentials.
// DELETE /auth/passwordless/webauthn/credentials/{credential_id}.
func (c *Client) DeleteWebAuthnCredential(ctx context.Context, token, credentialID string) (*EnterpriseMessageResponse, error) {
	var out EnterpriseMessageResponse
	if err := c.doJSON(ctx, "DELETE", "/auth/passwordless/webauthn/credentials/"+url.PathEscape(credentialID), nil, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Magic-link operations ----

// SendMagicLink sends a login magic link (form-encoded).
// POST /auth/passwordless/magic-link/send.
func (c *Client) SendMagicLink(ctx context.Context, form url.Values) (*MagicLinkSendResponse, error) {
	var out MagicLinkSendResponse
	if err := c.doForm(ctx, "/auth/passwordless/magic-link/send", form, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyMagicLink verifies a magic-link token and returns a token set
// (form-encoded). POST /auth/passwordless/magic-link/verify.
func (c *Client) VerifyMagicLink(ctx context.Context, form url.Values) (*PasswordlessAuthResponse, error) {
	var out PasswordlessAuthResponse
	if err := c.doForm(ctx, "/auth/passwordless/magic-link/verify", form, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListActiveMagicLinks lists the caller's outstanding magic links.
// GET /auth/passwordless/magic-link/active.
func (c *Client) ListActiveMagicLinks(ctx context.Context, token string) (*ActiveMagicLinksResponse, error) {
	var out ActiveMagicLinksResponse
	if err := c.doGet(ctx, "/auth/passwordless/magic-link/active", &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// RevokeMagicLink revokes a specific magic link by token.
// DELETE /auth/passwordless/magic-link/{token}.
func (c *Client) RevokeMagicLink(ctx context.Context, callerToken, linkToken string) (*EnterpriseMessageResponse, error) {
	var out EnterpriseMessageResponse
	if err := c.doJSON(ctx, "DELETE", "/auth/passwordless/magic-link/"+url.PathEscape(linkToken), nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// MagicLinkConfig returns the magic-link configuration.
// GET /auth/passwordless/magic-link/config.
func (c *Client) MagicLinkConfig(ctx context.Context) (*MagicLinkConfigResponse, error) {
	var out MagicLinkConfigResponse
	if err := c.doGet(ctx, "/auth/passwordless/magic-link/config", &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// MagicLinkAnalytics returns magic-link usage analytics for the caller.
// GET /auth/passwordless/magic-link/analytics.
func (c *Client) MagicLinkAnalytics(ctx context.Context, token string) (*MagicLinkAnalyticsResponse, error) {
	var out MagicLinkAnalyticsResponse
	if err := c.doGet(ctx, "/auth/passwordless/magic-link/analytics", &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Recovery codes ----

// GenerateRecoveryCodes generates a new set of MFA recovery codes for the
// caller. POST /auth/passwordless/recovery-codes/generate.
func (c *Client) GenerateRecoveryCodes(ctx context.Context, token string) (*RecoveryCodesResponse, error) {
	var out RecoveryCodesResponse
	if err := c.doJSON(ctx, "POST", "/auth/passwordless/recovery-codes/generate", struct{}{}, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyRecoveryCode authenticates using an MFA recovery code (form-encoded).
// POST /auth/passwordless/recovery-codes/verify.
func (c *Client) VerifyRecoveryCode(ctx context.Context, form url.Values) (*PasswordlessAuthResponse, error) {
	var out PasswordlessAuthResponse
	if err := c.doForm(ctx, "/auth/passwordless/recovery-codes/verify", form, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Devices ----

// ListDevices lists the caller's known passwordless devices.
// GET /auth/passwordless/devices.
func (c *Client) ListDevices(ctx context.Context, token string) (*DeviceListResponse, error) {
	var out DeviceListResponse
	if err := c.doGet(ctx, "/auth/passwordless/devices", &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// reqOrEmpty returns an empty JSON object body when m is nil so that POSTs to
// endpoints expecting a body still send `{}` rather than a null literal.
func reqOrEmpty(m map[string]any) any {
	if m == nil {
		return struct{}{}
	}
	return m
}
