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

// APIKeyCreate is the body for POST /api-keys/.
type APIKeyCreate struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions,omitempty"`
	OrgID       string   `json:"org_id,omitempty"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
	Audience    []string `json:"audience,omitempty"`
}

// APIKeyUpdate is the body for PUT /api-keys/{key_id}.
type APIKeyUpdate struct {
	Name        *string   `json:"name,omitempty"`
	Permissions *[]string `json:"permissions,omitempty"`
	Enabled     *bool     `json:"enabled,omitempty"`
	ExpiresAt   *string   `json:"expires_at,omitempty"`
}

// APIKey is the metadata for a key (no secret). APIKeyResponse in the API.
type APIKey struct {
	ID          string   `json:"id"`
	Name        string   `json:"name,omitempty"`
	Prefix      string   `json:"prefix,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	OrgID       string   `json:"org_id,omitempty"`
	Enabled     bool     `json:"enabled,omitempty"`
	CreatedAt   string   `json:"created_at,omitempty"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
	LastUsedAt  string   `json:"last_used_at,omitempty"`
}

// APIKeyWithToken is the create response, which includes the secret exactly
// once (APIKeyWithToken in the API). Token has the "ab0t_sk_" prefix.
type APIKeyWithToken struct {
	APIKey
	Token string `json:"token"`
}

// ===================== Models: delegation =====================

// DelegationGrant is the body for POST /delegation/grant.
type DelegationGrant struct {
	ActorID      string   `json:"actor_id"`       // who may act
	TargetUserID string   `json:"target_user_id"` // on whose behalf
	Permissions  []string `json:"permissions,omitempty"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
	Reason       string   `json:"reason,omitempty"`
}

// DelegationResponse is the result of POST /delegation/grant.
type DelegationResponse struct {
	ID           string   `json:"id,omitempty"`
	ActorID      string   `json:"actor_id,omitempty"`
	TargetUserID string   `json:"target_user_id,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
	Message      string   `json:"message,omitempty"`
}

// DelegationCheckResponse is the result of GET /delegation/check/{target_user_id}.
type DelegationCheckResponse struct {
	CanDelegate bool     `json:"can_delegate"`
	Permissions []string `json:"permissions,omitempty"`
	Reason      string   `json:"reason,omitempty"`
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
