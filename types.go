package authclient

import "time"

// ---- Authentication ----

// LoginRequest is the body for POST /auth/login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	// OrgID selects a specific organization for a multi-org user. Optional.
	OrgID string `json:"org_id,omitempty"`
	// ProviderType selects an auth provider (e.g. "internal", "google").
	// Defaults server-side to "internal".
	ProviderType string `json:"provider_type,omitempty"`
}

// TokenUserInfo is the embedded user summary returned with a token set.
type TokenUserInfo struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	Name        string `json:"name,omitempty"`
	OrgID       string `json:"org_id,omitempty"`
	IsDelegated bool   `json:"is_delegated,omitempty"`
}

// TokenSet is the result of Login / Refresh / SwitchOrganization
// (LoginResponse / TokenResponse in the API).
type TokenSet struct {
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	TokenType    string        `json:"token_type,omitempty"` // "bearer"
	ExpiresIn    int           `json:"expires_in,omitempty"` // seconds
	User         TokenUserInfo `json:"user"`
	Audience     []string      `json:"audience,omitempty"`
}

// RegisterRequest is the body for POST /auth/register.
type RegisterRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	Name         string `json:"name,omitempty"`
	OrgID        string `json:"org_id,omitempty"`
	ProviderType string `json:"provider_type,omitempty"`
}

// RefreshRequest is the body for POST /auth/refresh.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// ---- OAuth2 / OIDC ----

// OAuthAuthorizeParams configures the start of an OAuth2/OIDC authorization
// (GET /auth/oauth/{provider}/authorize). Fields map to standard OAuth2 query
// parameters; zero-valued fields are omitted.
type OAuthAuthorizeParams struct {
	// Provider is the upstream IdP identifier (e.g. "google", "okta").
	Provider string `json:"-"`
	// RedirectURI is where the IdP returns the user after consent.
	RedirectURI string `json:"redirect_uri,omitempty"`
	// State is an opaque CSRF token echoed back to the callback.
	State string `json:"state,omitempty"`
	// Scope is a space-delimited list of requested scopes.
	Scope string `json:"scope,omitempty"`
	// OrgID scopes the flow to a specific organization/tenant.
	OrgID string `json:"org_id,omitempty"`
	// CodeChallenge / CodeChallengeMethod enable PKCE.
	CodeChallenge       string `json:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`
	// LoginHint pre-fills the IdP login (e.g. an email).
	LoginHint string `json:"login_hint,omitempty"`
}

// OAuthAuthorize is the result of starting an OAuth/OIDC flow
// (OAuthProviderAuthorizeResponse). AuthorizationURL is where the caller should
// redirect the user-agent.
type OAuthAuthorize struct {
	AuthorizationURL string `json:"authorization_url"`
	State            string `json:"state,omitempty"`
	Provider         string `json:"provider,omitempty"`
	// CodeVerifier is returned only when the server generated PKCE on the
	// caller's behalf; otherwise empty.
	CodeVerifier string `json:"code_verifier,omitempty"`
}

// OAuthCallbackParams carries the values returned by the IdP to the callback
// endpoint (POST /auth/oauth/{provider}/callback). They are sent as form values.
type OAuthCallbackParams struct {
	Provider     string `json:"-"`
	Code         string `json:"code,omitempty"`
	State        string `json:"state,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	CodeVerifier string `json:"code_verifier,omitempty"`
	// Error / ErrorDescription are populated when the IdP denied the request.
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// SwitchOrganizationRequest is the body for POST /auth/switch-organization.
type SwitchOrganizationRequest struct {
	OrgID string `json:"org_id"`
}

// ---- Revocation / logout ----

// RevokeResult is the response from POST /auth/revoke and /token/revoke.
// Per RFC 7009 the revocation endpoint may return an empty body; in that case
// Revoked defaults to false but a nil error indicates success.
type RevokeResult struct {
	Revoked bool   `json:"revoked,omitempty"`
	Message string `json:"message,omitempty"`
}

// LogoutResult is the response from POST /auth/logout.
type LogoutResult struct {
	Success bool   `json:"success,omitempty"`
	Message string `json:"message,omitempty"`
}

// ---- Token validation / introspection (the authz surface) ----

// Resource is an optional fine-grained target for a permission decision.
// Zero value means "no specific resource".
type Resource struct {
	Type string
	ID   string
}

// IsZero reports whether no resource was specified.
func (r Resource) IsZero() bool { return r.Type == "" && r.ID == "" }

// TokenValidationRequest is the body for POST /auth/validate-token.
type TokenValidationRequest struct {
	Token               string   `json:"token"`
	RequiredPermissions []string `json:"required_permissions,omitempty"`
	ResourceType        string   `json:"resource_type,omitempty"`
	ResourceID          string   `json:"resource_id,omitempty"`
	ExpectedAudience    string   `json:"expected_audience,omitempty"`
	IncludePermissions  bool     `json:"include_permissions,omitempty"`
}

// Actor is the resolved identity behind a token (TokenValidationResponse).
// It is the canonical "who + tenant + capabilities" the server authorizes on.
type Actor struct {
	Valid       bool      `json:"valid"`
	UserID      string    `json:"user_id,omitempty"`
	OrgID       string    `json:"org_id,omitempty"`
	Email       string    `json:"email,omitempty"`
	Permissions []string  `json:"permissions,omitempty"`
	Audience    []string  `json:"audience,omitempty"`
	ExpiresAt   string    `json:"expires_at,omitempty"`
	Error       string    `json:"error,omitempty"`
	retrievedAt time.Time `json:"-"`
}

// HasPermission reports whether the actor's resolved permission list contains p.
// Note: this only reflects permissions the service chose to return (use
// IncludePermissions or RequiredPermissions when validating). Prefer
// Client.Authorize / Client.CheckPermission for authoritative decisions.
func (a Actor) HasPermission(p string) bool {
	for _, x := range a.Permissions {
		if x == p {
			return true
		}
	}
	return false
}

// ValidateAPIKeyRequest is the body for POST /auth/validate-api-key.
type ValidateAPIKeyRequest struct {
	APIKey              string   `json:"api_key"`
	RequiredPermissions []string `json:"required_permissions,omitempty"`
	ExpectedAudience    string   `json:"expected_audience,omitempty"`
}

// APIKeyValidation is the result of validating a service API key.
type APIKeyValidation struct {
	Valid       bool     `json:"valid"`
	UserID      string   `json:"user_id,omitempty"`
	OrgID       string   `json:"org_id,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Reason      string   `json:"reason,omitempty"`
}

// Introspection is the RFC 7662 response from POST /token/introspect.
type Introspection struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Subject   string `json:"sub,omitempty"`
	OrgID     string `json:"org_id,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	JTI       string `json:"jti,omitempty"`
	Audience  any    `json:"aud,omitempty"` // string or []string per RFC 7662
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
}

// ---- RBAC / permissions ----

// PermissionCheckRequest is the body for POST /permissions/check and
// POST /auth/check-permission.
type PermissionCheckRequest struct {
	UserID       string `json:"user_id"`
	Permission   string `json:"permission"`
	OrgID        string `json:"org_id,omitempty"`
	ResourceType string `json:"resource_type,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`
}

// PermissionDecision is the result of a permission check.
type PermissionDecision struct {
	Allowed              bool     `json:"allowed"`
	Reason               string   `json:"reason,omitempty"`
	Source               string   `json:"source,omitempty"`
	EffectivePermissions []string `json:"effective_permissions,omitempty"`
}

// UserPermissions is the result of GET /permissions/user/{user_id}.
type UserPermissions struct {
	UserID      string   `json:"user_id"`
	OrgID       string   `json:"org_id,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// RoleDefinition describes a role and the permissions it grants.
type RoleDefinition struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// RolesResponse is the result of GET /permissions/roles
// (map keyed by role name).
type RolesResponse struct {
	Roles map[string]RoleDefinition `json:"roles"`
}

// ---- Users / organizations ----

// User is the profile returned by GET /users/{user_id}, /users/me, /auth/me.
// Fields are a superset that tolerates both UserProfile and UserResponse.
type User struct {
	ID            string                 `json:"id"`
	Email         string                 `json:"email"`
	Name          string                 `json:"name,omitempty"`
	Status        string                 `json:"status,omitempty"`
	EmailVerified bool                   `json:"email_verified,omitempty"`
	Phone         string                 `json:"phone,omitempty"`
	AvatarURL     string                 `json:"avatar_url,omitempty"`
	Timezone      string                 `json:"timezone,omitempty"`
	Language      string                 `json:"language,omitempty"`
	ProviderType  string                 `json:"provider_type,omitempty"`
	OrgID         string                 `json:"org_id,omitempty"`        // UserResponse
	ActiveOrgID   string                 `json:"active_org_id,omitempty"` // UserProfile
	Organizations []UserOrganizationInfo `json:"organizations,omitempty"` // UserProfile
	Metadata      map[string]any         `json:"metadata,omitempty"`
}

// UserOrganizationInfo is one membership entry (GET /users/me/organizations).
type UserOrganizationInfo struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	Role          string   `json:"role"`
	IsPersonal    bool     `json:"is_personal"`
	IsDefault     bool     `json:"is_default"`
	JoinedAt      string   `json:"joined_at,omitempty"`
	Permissions   []string `json:"permissions"`
	ParentID      string   `json:"parent_id,omitempty"`
	WorkspaceType string   `json:"workspace_type,omitempty"`
}

// Organization is the result of GET /organizations/{org_id}.
type Organization struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Slug            string         `json:"slug,omitempty"`
	Domain          string         `json:"domain,omitempty"`
	ParentID        string         `json:"parent_id,omitempty"`
	ServiceAudience string         `json:"service_audience,omitempty"`
	BillingType     string         `json:"billing_type,omitempty"`
	Status          string         `json:"status,omitempty"`
	Timezone        string         `json:"timezone,omitempty"`
	Settings        map[string]any `json:"settings,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}
