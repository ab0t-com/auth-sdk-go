package authclient

import (
	"context"
	"net/url"
	"time"
)

// ===================== Authentication =====================

// Login authenticates a user and returns a token set. POST /auth/login.
func (c *Client) Login(ctx context.Context, req LoginRequest) (*TokenSet, error) {
	var out TokenSet
	if err := c.doJSON(ctx, "POST", "/auth/login", req, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// Refresh exchanges a refresh token for a new token set. POST /auth/refresh.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenSet, error) {
	var out TokenSet
	err := c.doJSON(ctx, "POST", "/auth/refresh", RefreshRequest{RefreshToken: refreshToken}, &out, "")
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Register creates a new user and returns a token set. POST /auth/register.
func (c *Client) Register(ctx context.Context, req RegisterRequest) (*TokenSet, error) {
	var out TokenSet
	if err := c.doJSON(ctx, "POST", "/auth/register", req, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// Logout invalidates the session for the given user token. POST /auth/logout.
func (c *Client) Logout(ctx context.Context, token string) (*LogoutResult, error) {
	var out LogoutResult
	if err := c.doJSON(ctx, "POST", "/auth/logout", struct{}{}, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// RevokeToken revokes a user-issued access or refresh token. POST /auth/revoke.
// The token to revoke is supplied in the body; the caller's own bearer token
// (callerToken) authenticates the request.
func (c *Client) RevokeToken(ctx context.Context, callerToken, tokenToRevoke, hint string) (*RevokeResult, error) {
	body := map[string]string{"token": tokenToRevoke}
	if hint != "" {
		body["token_type_hint"] = hint
	}
	var out RevokeResult
	if err := c.doJSON(ctx, "POST", "/auth/revoke", body, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// RevokeTokenPublic revokes a token via the RFC 7009 public endpoint
// POST /token/revoke (form-encoded, no caller auth required).
func (c *Client) RevokeTokenPublic(ctx context.Context, token, hint string) error {
	form := url.Values{}
	form.Set("token", token)
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	// Per RFC 7009 the body is typically empty; treat any 2xx as success.
	return c.doForm(ctx, "/token/revoke", form, nil, "")
}

// ===================== OAuth2 / OIDC =====================

// OAuthAuthorizeURL starts an OAuth2/OIDC authorization flow with the given
// provider and returns the authorization URL the user-agent should be
// redirected to. GET /auth/oauth/{provider}/authorize.
func (c *Client) OAuthAuthorizeURL(ctx context.Context, p OAuthAuthorizeParams) (*OAuthAuthorize, error) {
	if p.Provider == "" {
		return nil, &APIError{StatusCode: 400, Method: "GET", Endpoint: "/auth/oauth/{provider}/authorize", Code: "invalid_request", Message: "provider is required"}
	}
	q := url.Values{}
	setIf(q, "redirect_uri", p.RedirectURI)
	setIf(q, "state", p.State)
	setIf(q, "scope", p.Scope)
	setIf(q, "org_id", p.OrgID)
	setIf(q, "code_challenge", p.CodeChallenge)
	setIf(q, "code_challenge_method", p.CodeChallengeMethod)
	setIf(q, "login_hint", p.LoginHint)

	path := "/auth/oauth/" + url.PathEscape(p.Provider) + "/authorize"
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	var out OAuthAuthorize
	if err := c.doGet(ctx, path, &out, ""); err != nil {
		return nil, err
	}
	if out.Provider == "" {
		out.Provider = p.Provider
	}
	return &out, nil
}

// OAuthCallback completes an OAuth2/OIDC flow by exchanging the authorization
// code returned by the IdP for a token set.
// POST /auth/oauth/{provider}/callback.
func (c *Client) OAuthCallback(ctx context.Context, p OAuthCallbackParams) (*TokenSet, error) {
	if p.Provider == "" {
		return nil, &APIError{StatusCode: 400, Method: "POST", Endpoint: "/auth/oauth/{provider}/callback", Code: "invalid_request", Message: "provider is required"}
	}
	if p.Error != "" {
		return nil, &APIError{StatusCode: 400, Method: "POST", Endpoint: "/auth/oauth/" + p.Provider + "/callback", Code: p.Error, Message: p.ErrorDescription}
	}
	form := url.Values{}
	setIf(form, "code", p.Code)
	setIf(form, "state", p.State)
	setIf(form, "redirect_uri", p.RedirectURI)
	setIf(form, "code_verifier", p.CodeVerifier)

	path := "/auth/oauth/" + url.PathEscape(p.Provider) + "/callback"
	var out TokenSet
	if err := c.doForm(ctx, path, form, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

func setIf(v url.Values, key, val string) {
	if val != "" {
		v.Set(key, val)
	}
}

// SwitchOrganization re-issues tokens scoped to a different org/tenant.
// POST /auth/switch-organization. token must belong to a member of orgID.
func (c *Client) SwitchOrganization(ctx context.Context, token, orgID string) (*TokenSet, error) {
	var out TokenSet
	err := c.doJSON(ctx, "POST", "/auth/switch-organization",
		SwitchOrganizationRequest{OrgID: orgID}, &out, token)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Me returns the current user for a token. GET /auth/me.
func (c *Client) Me(ctx context.Context, token string) (*User, error) {
	var out User
	if err := c.doGet(ctx, "/auth/me", &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// ===================== Token validation / authorization =====================

// ValidateToken resolves a bearer credential to an Actor.
//
// The credential may be a user JWT or a service/agent API key (ab0t_sk_…). The
// auth service resolves these at DIFFERENT endpoints — JWTs at
// POST /auth/validate-token, API keys at POST /auth/validate-api-key (the
// token endpoint does not resolve API keys). ValidateToken detects an API key
// by its prefix (IsAPIKey) and routes accordingly, adapting the API-key
// validation result into the same Actor shape, so a caller (and the resource
// server's Authenticate middleware) can treat both credential types uniformly.
//
// The configured expected audience (WithExpectedAudience) is applied if set.
func (c *Client) ValidateToken(ctx context.Context, token string) (*Actor, error) {
	if IsAPIKey(token) {
		return c.apiKeyActor(ctx, token, nil)
	}
	return c.ValidateTokenWith(ctx, TokenValidationRequest{
		Token:            token,
		ExpectedAudience: c.expectedAudience,
	})
}

// apiKeyActor validates a service/agent API key via POST /auth/validate-api-key
// and adapts the result to an *Actor (so API keys and JWTs share one identity
// shape). requiredPerms, when non-nil, is checked by the auth service and a
// missing permission yields Valid=false. The configured expected audience is
// applied if set.
func (c *Client) apiKeyActor(ctx context.Context, key string, requiredPerms []string) (*Actor, error) {
	v, err := c.ValidateAPIKey(ctx, ValidateAPIKeyRequest{
		APIKey:              key,
		RequiredPermissions: requiredPerms,
		ExpectedAudience:    c.expectedAudience,
	})
	if err != nil {
		return nil, err
	}
	return &Actor{
		Valid:       v.Valid,
		UserID:      v.UserID,
		OrgID:       v.OrgID,
		Permissions: v.Permissions,
		Error:       v.Reason,
		retrievedAt: time.Now(),
	}, nil
}

// ValidateTokenWith performs a fully-specified validation, allowing inline
// permission and resource assertions. POST /auth/validate-token.
func (c *Client) ValidateTokenWith(ctx context.Context, req TokenValidationRequest) (*Actor, error) {
	if req.ExpectedAudience == "" {
		req.ExpectedAudience = c.expectedAudience
	}
	var out Actor
	if err := c.doJSON(ctx, "POST", "/auth/validate-token", req, &out, ""); err != nil {
		return nil, err
	}
	out.retrievedAt = time.Now()
	return &out, nil
}

// Authorize reports whether token may perform action on resource. It validates
// the token with an inline required-permission (and optional resource) check,
// so it needs no service privilege. This is the route-gating primitive.
//
// resource may be the zero Resource for non-resource-scoped actions.
//
// A credential may be a user JWT or a service/agent API key (ab0t_sk_…). API
// keys are resolved at POST /auth/validate-api-key (the validate-token endpoint
// does not resolve them), so Authorize routes an API-key credential there with
// the required permission; JWTs use the inline validate-token check below.
func (c *Client) Authorize(ctx context.Context, token, action string, resource Resource) (bool, error) {
	if IsAPIKey(token) {
		actor, err := c.apiKeyActor(ctx, token, []string{action})
		if err != nil {
			return false, err
		}
		return actor.Valid, nil
	}
	req := TokenValidationRequest{
		Token:               token,
		RequiredPermissions: []string{action},
		ExpectedAudience:    c.expectedAudience,
	}
	if !resource.IsZero() {
		req.ResourceType = resource.Type
		req.ResourceID = resource.ID
	}
	actor, err := c.ValidateTokenWith(ctx, req)
	if err != nil {
		return false, err
	}
	return actor.Valid, nil
}

// ValidateAPIKey validates a service API key. POST /auth/validate-api-key.
func (c *Client) ValidateAPIKey(ctx context.Context, req ValidateAPIKeyRequest) (*APIKeyValidation, error) {
	if req.ExpectedAudience == "" {
		req.ExpectedAudience = c.expectedAudience
	}
	var out APIKeyValidation
	if err := c.doJSON(ctx, "POST", "/auth/validate-api-key", req, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// Introspect performs RFC 7662 token introspection. POST /token/introspect.
// hint may be "" or "access_token"/"refresh_token". Always check Active.
func (c *Client) Introspect(ctx context.Context, token, hint string) (*Introspection, error) {
	form := url.Values{}
	form.Set("token", token)
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	var out Introspection
	if err := c.doForm(ctx, "/token/introspect", form, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// ===================== RBAC / permissions =====================

// CheckPermission performs an authoritative RBAC check for a specific user.
// POST /permissions/check. Requires the caller (service API key or a token with
// users.read) to be authorized; configure WithAPIKey or pass a privileged token
// via callerToken (use "" to fall back to the configured service API key).
func (c *Client) CheckPermission(ctx context.Context, req PermissionCheckRequest, callerToken string) (*PermissionDecision, error) {
	var out PermissionDecision
	if err := c.doJSON(ctx, "POST", "/permissions/check", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetUserPermissions lists a user's effective permissions.
// GET /permissions/user/{user_id}.
func (c *Client) GetUserPermissions(ctx context.Context, userID, callerToken string) (*UserPermissions, error) {
	var out UserPermissions
	if err := c.doGet(ctx, "/permissions/user/"+url.PathEscape(userID), &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetRoles returns the available roles and their permissions.
// GET /permissions/roles.
func (c *Client) GetRoles(ctx context.Context, callerToken string) (map[string]RoleDefinition, error) {
	var out RolesResponse
	if err := c.doGet(ctx, "/permissions/roles", &out, callerToken); err != nil {
		return nil, err
	}
	return out.Roles, nil
}

// ===================== Users / organizations =====================

// GetUser fetches a user by id. GET /users/{user_id}.
// callerToken may be a user JWT or "" to use the service API key.
func (c *Client) GetUser(ctx context.Context, userID, callerToken string) (*User, error) {
	var out User
	if err := c.doGet(ctx, "/users/"+url.PathEscape(userID), &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetMyOrganizations lists organizations the token's user belongs to.
// GET /users/me/organizations.
func (c *Client) GetMyOrganizations(ctx context.Context, token string) ([]UserOrganizationInfo, error) {
	var out []UserOrganizationInfo
	if err := c.doGet(ctx, "/users/me/organizations", &out, token); err != nil {
		return nil, err
	}
	return out, nil
}

// GetOrganization fetches an organization/tenant. GET /organizations/{org_id}.
func (c *Client) GetOrganization(ctx context.Context, orgID, callerToken string) (*Organization, error) {
	var out Organization
	if err := c.doGet(ctx, "/organizations/"+url.PathEscape(orgID), &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ===================== JWKS =====================

// JWKS returns the service's signing key set, using a TTL cache (10m) with
// single-flight refresh. GET /.well-known/jwks.json. Use RefreshJWKS to force
// a fetch (e.g. on an unknown kid).
func (c *Client) JWKS(ctx context.Context) (JWKS, error) {
	return c.jwks.get(ctx, "/.well-known/jwks.json", false)
}

// RefreshJWKS forces a refetch of the global key set, bypassing the cache.
func (c *Client) RefreshJWKS(ctx context.Context) (JWKS, error) {
	return c.jwks.get(ctx, "/.well-known/jwks.json", true)
}

// OrgJWKS returns an organization's signing key set, cached per org.
// GET /organizations/{org_id}/.well-known/jwks.json.
func (c *Client) OrgJWKS(ctx context.Context, orgID string) (JWKS, error) {
	path := "/organizations/" + url.PathEscape(orgID) + "/.well-known/jwks.json"
	return c.jwks.get(ctx, path, false)
}

// SigningKey returns the cached signing key with the given kid, transparently
// refreshing the key set once if the kid is not found (handles key rotation).
func (c *Client) SigningKey(ctx context.Context, kid string) (JWK, error) {
	set, err := c.JWKS(ctx)
	if err != nil {
		return JWK{}, err
	}
	if k, ok := set.Key(kid); ok {
		return k, nil
	}
	set, err = c.RefreshJWKS(ctx)
	if err != nil {
		return JWK{}, err
	}
	if k, ok := set.Key(kid); ok {
		return k, nil
	}
	return JWK{}, &APIError{StatusCode: 404, Method: "GET", Endpoint: "/.well-known/jwks.json", Code: "key_not_found", Message: "no signing key with kid " + kid}
}
