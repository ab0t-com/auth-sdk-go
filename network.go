package authclient

import (
	"context"
	"net/url"
)

// This file covers the network-access-control domain (contract section 21):
// IP policies, emergency overrides, temporary allowlists and violation
// reporting. These serve the admin / tenant-management archetype (org.admin
// for mutating policy; reads are membership-scoped).

// ---- Models ----

// NetworkPolicy is an IP/network access policy.
type NetworkPolicy struct {
	ID          string   `json:"id"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Mode        string   `json:"mode,omitempty"` // allowlist | blocklist
	CIDRs       []string `json:"cidrs,omitempty"`
	Enabled     bool     `json:"enabled,omitempty"`
	Priority    int      `json:"priority,omitempty"`
	CreatedAt   string   `json:"created_at,omitempty"`
}

// CreateNetworkPolicyRequest is the body for POST /network-policy/.
type CreateNetworkPolicyRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	CIDRs       []string `json:"cidrs"`
	Enabled     bool     `json:"enabled,omitempty"`
	Priority    int      `json:"priority,omitempty"`
}

// UpdateNetworkPolicyRequest is the body for PUT /network-policy/{policy_id}.
type UpdateNetworkPolicyRequest struct {
	Name        *string   `json:"name,omitempty"`
	Description *string   `json:"description,omitempty"`
	Mode        *string   `json:"mode,omitempty"`
	CIDRs       *[]string `json:"cidrs,omitempty"`
	Enabled     *bool     `json:"enabled,omitempty"`
	Priority    *int      `json:"priority,omitempty"`
}

// NetworkPolicyCreateResponse is the result of creating a network policy.
type NetworkPolicyCreateResponse struct {
	PolicyID string `json:"policy_id"`
	Message  string `json:"message,omitempty"`
}

// NetworkPolicyListResponse lists network policies.
type NetworkPolicyListResponse struct {
	Policies []NetworkPolicy `json:"policies"`
	Total    int             `json:"total,omitempty"`
}

// NetworkPolicyStatusResponse is the generic status envelope for
// update/delete/override/allowlist mutations.
type NetworkPolicyStatusResponse struct {
	Success bool   `json:"success,omitempty"`
	Message string `json:"message,omitempty"`
	Status  string `json:"status,omitempty"`
}

// PolicyEvaluationResult is the result of GET /network-policy/evaluate.
type PolicyEvaluationResult struct {
	Allowed   bool   `json:"allowed"`
	IP        string `json:"ip,omitempty"`
	MatchedID string `json:"matched_policy_id,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// EmergencyOverrideRequest is the body for POST /network-policy/emergency-override.
type EmergencyOverrideRequest struct {
	IP         string `json:"ip"`
	Reason     string `json:"reason,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
}

// EmergencyOverrideCreateResponse is the result of creating an override.
type EmergencyOverrideCreateResponse struct {
	OverrideID string `json:"override_id"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	Message    string `json:"message,omitempty"`
}

// NetworkOverride is one emergency override entry.
type NetworkOverride struct {
	ID        string `json:"id"`
	IP        string `json:"ip,omitempty"`
	Reason    string `json:"reason,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// OverrideListResponse lists emergency overrides.
type OverrideListResponse struct {
	Overrides []NetworkOverride `json:"overrides"`
}

// TempAllowlistRequest is the body for POST /network-policy/temp-allowlist.
type TempAllowlistRequest struct {
	IP         string `json:"ip"`
	Reason     string `json:"reason,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
}

// TempAllowlistCreateResponse is the result of creating a temp allowlist entry.
type TempAllowlistCreateResponse struct {
	EntryID   string `json:"entry_id"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Message   string `json:"message,omitempty"`
}

// TempAllowlistEntry is one temporary allowlist entry.
type TempAllowlistEntry struct {
	ID        string `json:"id"`
	IP        string `json:"ip,omitempty"`
	Reason    string `json:"reason,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// TempAllowlistListResponse lists temporary allowlist entries.
type TempAllowlistListResponse struct {
	Entries []TempAllowlistEntry `json:"entries"`
}

// NetworkViolation is one recorded access violation.
type NetworkViolation struct {
	IP        string `json:"ip,omitempty"`
	PolicyID  string `json:"policy_id,omitempty"`
	Path      string `json:"path,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// ViolationListResponse lists access violations.
type ViolationListResponse struct {
	Violations []NetworkViolation `json:"violations"`
	Total      int                `json:"total,omitempty"`
}

// ---- Operations ----

// CreateNetworkPolicy creates an IP/network access policy.
// POST /network-policy/. Requires org.admin.
func (c *Client) CreateNetworkPolicy(ctx context.Context, req CreateNetworkPolicyRequest, callerToken string) (*NetworkPolicyCreateResponse, error) {
	var out NetworkPolicyCreateResponse
	if err := c.doJSON(ctx, "POST", "/network-policy/", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListNetworkPolicies lists network policies. GET /network-policy/.
func (c *Client) ListNetworkPolicies(ctx context.Context, callerToken string) (*NetworkPolicyListResponse, error) {
	var out NetworkPolicyListResponse
	if err := c.doGet(ctx, "/network-policy/", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetNetworkPolicy fetches a network policy. GET /network-policy/{policy_id}.
func (c *Client) GetNetworkPolicy(ctx context.Context, policyID, callerToken string) (*NetworkPolicy, error) {
	var out NetworkPolicy
	if err := c.doGet(ctx, "/network-policy/"+url.PathEscape(policyID), &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateNetworkPolicy updates a network policy. PUT /network-policy/{policy_id}.
func (c *Client) UpdateNetworkPolicy(ctx context.Context, policyID string, req UpdateNetworkPolicyRequest, callerToken string) (*NetworkPolicyStatusResponse, error) {
	var out NetworkPolicyStatusResponse
	if err := c.doJSON(ctx, "PUT", "/network-policy/"+url.PathEscape(policyID), req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteNetworkPolicy deletes a network policy. DELETE /network-policy/{policy_id}.
func (c *Client) DeleteNetworkPolicy(ctx context.Context, policyID, callerToken string) (*NetworkPolicyStatusResponse, error) {
	var out NetworkPolicyStatusResponse
	if err := c.doJSON(ctx, "DELETE", "/network-policy/"+url.PathEscape(policyID), nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// EvaluateNetworkPolicy evaluates whether an IP is allowed (public).
// GET /network-policy/evaluate. ip is supplied as the `ip` query parameter.
func (c *Client) EvaluateNetworkPolicy(ctx context.Context, ip string) (*PolicyEvaluationResult, error) {
	q := url.Values{}
	if ip != "" {
		q.Set("ip", ip)
	}
	path := "/network-policy/evaluate"
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	var out PolicyEvaluationResult
	if err := c.doGet(ctx, path, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateEmergencyOverride creates an emergency network override.
// POST /network-policy/emergency-override. Requires org.admin.
func (c *Client) CreateEmergencyOverride(ctx context.Context, req EmergencyOverrideRequest, callerToken string) (*EmergencyOverrideCreateResponse, error) {
	var out EmergencyOverrideCreateResponse
	if err := c.doJSON(ctx, "POST", "/network-policy/emergency-override", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListNetworkOverrides lists emergency overrides. GET /network-policy/overrides.
func (c *Client) ListNetworkOverrides(ctx context.Context, callerToken string) (*OverrideListResponse, error) {
	var out OverrideListResponse
	if err := c.doGet(ctx, "/network-policy/overrides", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteNetworkOverride deletes an emergency override.
// DELETE /network-policy/overrides/{override_id}.
func (c *Client) DeleteNetworkOverride(ctx context.Context, overrideID, callerToken string) (*NetworkPolicyStatusResponse, error) {
	var out NetworkPolicyStatusResponse
	if err := c.doJSON(ctx, "DELETE", "/network-policy/overrides/"+url.PathEscape(overrideID), nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateTempAllowlist adds a temporary IP allowlist entry.
// POST /network-policy/temp-allowlist.
func (c *Client) CreateTempAllowlist(ctx context.Context, req TempAllowlistRequest, callerToken string) (*TempAllowlistCreateResponse, error) {
	var out TempAllowlistCreateResponse
	if err := c.doJSON(ctx, "POST", "/network-policy/temp-allowlist", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListTempAllowlist lists temporary allowlist entries.
// GET /network-policy/temp-allowlist.
func (c *Client) ListTempAllowlist(ctx context.Context, callerToken string) (*TempAllowlistListResponse, error) {
	var out TempAllowlistListResponse
	if err := c.doGet(ctx, "/network-policy/temp-allowlist", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteTempAllowlist removes a temporary allowlist entry.
// DELETE /network-policy/temp-allowlist/{entry_id}.
func (c *Client) DeleteTempAllowlist(ctx context.Context, entryID, callerToken string) (*NetworkPolicyStatusResponse, error) {
	var out NetworkPolicyStatusResponse
	if err := c.doJSON(ctx, "DELETE", "/network-policy/temp-allowlist/"+url.PathEscape(entryID), nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListNetworkViolations lists recorded access violations.
// GET /network-policy/violations.
func (c *Client) ListNetworkViolations(ctx context.Context, callerToken string) (*ViolationListResponse, error) {
	var out ViolationListResponse
	if err := c.doGet(ctx, "/network-policy/violations", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}
