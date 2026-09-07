package authclient

import (
	"context"
	"net/url"
)

// This file extends the SDK with the API Keys + Service Accounts domain
// (contract section 14) and the Delegation domain (contract section 15:
// act-as / impersonation grants). API keys are the service/machine caller's
// own credential lifecycle; delegation lets a principal act on behalf of
// another within the permissions they hold.

// ===================== Models: API keys =====================

// APIKeyCreate is the body for POST /api-keys/. Fields mirror the goauth
// createRequest handler struct (apikeyshttp.go:94-99): {name, permissions,
// rate_limit, expires_at}. The server ignores anything else, so org_id/audience
// (which it never read) were removed — they gave a false "scoped the key" signal.
type APIKeyCreate struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions,omitempty"`
	// RateLimit sets the key's requests-per-window limit AT CREATE (previously only
	// settable on update, so a key was born with the default until a second call).
	RateLimit *int64 `json:"rate_limit,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// APIKeyUpdate is the body for PUT /api-keys/{key_id}.
type APIKeyUpdate struct {
	Name        *string   `json:"name,omitempty"`
	Permissions *[]string `json:"permissions,omitempty"`
	// IsActive enables/disables the key. The server field is `is_active`; an
	// earlier revision sent `enabled`, which the server ignored — so toggling a
	// key through the SDK silently did nothing.
	IsActive  *bool  `json:"is_active,omitempty"`
	RateLimit *int64 `json:"rate_limit,omitempty"`
	// ExpiresAt is not in the server's update schema (kept for compatibility;
	// the server ignores it — update expiry is not currently supported). This is a
	// KNOWN, allow-listed over-exposure: it is documented here so callers aren't
	// misled, but the field is retained to avoid churn. See contract gate allow-list.
	ExpiresAt *string `json:"expires_at,omitempty"`
}

// APIKey is the metadata for a key (no secret). APIKeyResponse in the API.
type APIKey struct {
	ID          string   `json:"id"`
	Name        string   `json:"name,omitempty"`
	Prefix      string   `json:"prefix,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	OrgID       string   `json:"org_id,omitempty"`
	CreatedAt   string   `json:"created_at,omitempty"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
	// IsActive/LastUsed/RateLimit are the fields the server actually sends
	// (APIKeyResponse marks them required). They replace the earlier `enabled`
	// and `last_used_at`, which the server never sent — those were always zero.
	IsActive  bool   `json:"is_active,omitempty"`
	LastUsed  string `json:"last_used,omitempty"`
	RateLimit int64  `json:"rate_limit,omitempty"`
}

// APIKeyWithToken is the create response, which includes the secret exactly
// once. It embeds APIKey (id, name, permissions, created_at, expires_at,
// rate_limit) and adds the secret.
type APIKeyWithToken struct {
	APIKey
	// Token is the secret key (prefix "ab0t_sk_"), returned exactly once at
	// creation. The wire field is `key` — the service does not send `token`, so an
	// earlier revision that tagged this `json:"token"` never populated it.
	Token string `json:"key,omitempty"`
}

// ===================== Models: delegation =====================

// DelegationGrant is the body for POST /delegation/grant.
// DelegationGrant is the body for POST /delegation/grant. The target is the
// AUTHENTICATED caller (you grant an actor the right to act as YOU), so it is not
// in the body. (G-04) An earlier revision sent `permissions`/`target_user_id`/
// `expires_at`/`reason` — none of which the server's request schema has; the
// server requires `scope` (the permission set) and, on goauth, `expires_in_hours`.
// So GrantDelegation could not succeed as-shipped (422). Fixed here.
type DelegationGrant struct {
	ActorID string   `json:"actor_id"` // who may act (on the caller's behalf)
	Scope   []string `json:"scope"`    // the permission set the actor may use — REQUIRED
	// ExpiresInHours bounds the grant. REQUIRED by goauth; optional on Python.
	// Set it, or the goauth backend rejects the grant (422).
	ExpiresInHours *int `json:"expires_in_hours,omitempty"`
}

// DelegationResponse is the result of POST /delegation/grant.
type DelegationResponse struct {
	ID           string   `json:"id,omitempty"`
	ActorID      string   `json:"actor_id,omitempty"`
	TargetUserID string   `json:"target_user_id,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
	Message      string   `json:"message,omitempty"`
	Success      bool     `json:"success,omitempty"`
}

// DelegationCheckResponse is the result of GET /delegation/check/{target_user_id}.
type DelegationCheckResponse struct {
	CanDelegate bool     `json:"can_delegate"`
	Permissions []string `json:"permissions,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	Allowed     bool     `json:"allowed,omitempty"`
	Scope       []string `json:"scope,omitempty"`
}

// DelegationEntry is one delegation grant from GET /delegation/list/{user_id}.
type DelegationEntry struct {
	ID           string   `json:"id"`
	ActorID      string   `json:"actor_id,omitempty"`
	TargetUserID string   `json:"target_user_id,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
	CreatedAt    string   `json:"created_at,omitempty"`
}

// DelegateTokenRequest is the body for POST /auth/delegate (mint an act-as token).
type DelegateTokenRequest struct {
	TargetUserID string   `json:"target_user_id"`
	Permissions  []string `json:"permissions,omitempty"`
	OrgID        string   `json:"org_id,omitempty"`
}

// ===================== API keys =====================

// ListAPIKeys lists the caller's API keys. GET /api-keys/.
func (c *Client) ListAPIKeys(ctx context.Context, callerToken string) ([]APIKey, error) {
	var out []APIKey
	if err := c.doGet(ctx, "/api-keys/", &out, callerToken); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateAPIKey mints a new API key. The secret token is returned exactly once.
// POST /api-keys/. Requires a user JWT (BearerJWT).
func (c *Client) CreateAPIKey(ctx context.Context, req APIKeyCreate, token string) (*APIKeyWithToken, error) {
	var out APIKeyWithToken
	if err := c.doJSON(ctx, "POST", "/api-keys/", req, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetAPIKey fetches one API key's metadata. GET /api-keys/{key_id}.
func (c *Client) GetAPIKey(ctx context.Context, keyID, token string) (*APIKey, error) {
	var out APIKey
	if err := c.doGet(ctx, "/api-keys/"+url.PathEscape(keyID), &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateAPIKey updates an API key's metadata/permissions.
// PUT /api-keys/{key_id}.
func (c *Client) UpdateAPIKey(ctx context.Context, keyID string, req APIKeyUpdate, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "PUT", "/api-keys/"+url.PathEscape(keyID), req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteAPIKey revokes an API key. DELETE /api-keys/{key_id}.
func (c *Client) DeleteAPIKey(ctx context.Context, keyID, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "DELETE", "/api-keys/"+url.PathEscape(keyID), nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ===================== Delegation =====================

// GrantDelegation grants act-as rights to an actor (you can only delegate
// permissions you hold). POST /delegation/grant.
func (c *Client) GrantDelegation(ctx context.Context, req DelegationGrant, token string) (*DelegationResponse, error) {
	var out DelegationResponse
	if err := c.doJSON(ctx, "POST", "/delegation/grant", req, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// RevokeDelegation revokes an actor's delegation. DELETE /delegation/revoke/{actor_id}.
func (c *Client) RevokeDelegation(ctx context.Context, actorID, token string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "DELETE", "/delegation/revoke/"+url.PathEscape(actorID), nil, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// CheckDelegation reports whether the caller may act on behalf of a target user.
// GET /delegation/check/{target_user_id}.
func (c *Client) CheckDelegation(ctx context.Context, targetUserID, token string) (*DelegationCheckResponse, error) {
	var out DelegationCheckResponse
	if err := c.doGet(ctx, "/delegation/check/"+url.PathEscape(targetUserID), &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListDelegations lists a user's delegations (own unless admin).
// GET /delegation/list/{user_id}.
func (c *Client) ListDelegations(ctx context.Context, userID, token string) ([]DelegationEntry, error) {
	var out []DelegationEntry
	if err := c.doGet(ctx, "/delegation/list/"+url.PathEscape(userID), &out, token); err != nil {
		return nil, err
	}
	return out, nil
}

// Delegate mints a delegated (act-as) token for the target user, scoped to the
// permissions the caller holds. POST /auth/delegate.
func (c *Client) Delegate(ctx context.Context, req DelegateTokenRequest, token string) (*TokenSet, error) {
	var out TokenSet
	if err := c.doJSON(ctx, "POST", "/auth/delegate", req, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}
