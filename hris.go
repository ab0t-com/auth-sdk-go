package authclient

import (
	"context"
	"net/url"
)

// This file covers HR-system (HRIS) directory integration and SCIM connection
// management for an organization. Requires an auth-service deployment that
// provides these surfaces; the endpoints return 404 where they are not enabled.

// ---- Models ----

// HRISConnectionStatus is the state of an org's HRIS directory connection.
type HRISConnectionStatus struct {
	Provider   string `json:"provider"`
	Configured bool   `json:"configured"`
	Active     bool   `json:"active"`
	BaseURL    string `json:"base_url"`
	CreatedAt  string `json:"created_at,omitempty"`
	LastSyncAt string `json:"last_sync_at,omitempty"`
}

// HRISConfigureRequest configures an org's HRIS connection.
type HRISConfigureRequest struct {
	Provider string `json:"provider"`
	BaseURL  string `json:"base_url"`
	APIKey   string `json:"api_key"`
}

// HRISSyncResult reports the outcome of a directory sync.
type HRISSyncResult struct {
	Provider      string   `json:"provider"`
	RosterSize    int64    `json:"roster_size"`
	Provisioned   int64    `json:"provisioned"`
	Deprovisioned int64    `json:"deprovisioned"`
	Unchanged     int64    `json:"unchanged"`
	Errors        []string `json:"errors,omitempty"`
}

// DeleteResult is a simple {deleted: bool} response.
type DeleteResult struct {
	Deleted bool `json:"deleted"`
}

// SCIMConnection is an org's SCIM provisioning connection (the endpoint a SCIM
// client provisions against, plus its bearer token).
type SCIMConnection struct {
	OrgID       string `json:"org_id"`
	Configured  bool   `json:"configured"`
	Active      bool   `json:"active"`
	SCIMBaseURL string `json:"scim_base_url"`
	Token       string `json:"token,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	RotatedAt   string `json:"rotated_at,omitempty"`
}

func orgPath(orgID, suffix string) string {
	return "/organizations/" + url.PathEscape(orgID) + suffix
}

// ---- HRIS ----

// GetHRISConnection returns an org's HRIS connection status.
// GET /organizations/{org_id}/hris/connection.
func (c *Client) GetHRISConnection(ctx context.Context, orgID, callerToken string) (*HRISConnectionStatus, error) {
	var out HRISConnectionStatus
	if err := c.doGet(ctx, orgPath(orgID, "/hris/connection"), &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ConfigureHRISConnection configures (or updates) an org's HRIS connection.
// POST /organizations/{org_id}/hris/connection. Requires org.admin.
func (c *Client) ConfigureHRISConnection(ctx context.Context, orgID string, req HRISConfigureRequest, callerToken string) (*HRISConnectionStatus, error) {
	var out HRISConnectionStatus
	if err := c.doJSON(ctx, "POST", orgPath(orgID, "/hris/connection"), req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteHRISConnection removes an org's HRIS connection.
// DELETE /organizations/{org_id}/hris/connection. Requires org.admin.
func (c *Client) DeleteHRISConnection(ctx context.Context, orgID, callerToken string) (*DeleteResult, error) {
	var out DeleteResult
	if err := c.doJSON(ctx, "DELETE", orgPath(orgID, "/hris/connection"), nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// SyncHRIS triggers a directory sync for an org's HRIS connection.
// POST /organizations/{org_id}/hris/sync. Requires org.admin.
func (c *Client) SyncHRIS(ctx context.Context, orgID, callerToken string) (*HRISSyncResult, error) {
	var out HRISSyncResult
	if err := c.doJSON(ctx, "POST", orgPath(orgID, "/hris/sync"), nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- SCIM connection management ----

// GetSCIMConnection returns an org's SCIM provisioning connection.
// GET /organizations/{org_id}/scim/connection.
func (c *Client) GetSCIMConnection(ctx context.Context, orgID, callerToken string) (*SCIMConnection, error) {
	var out SCIMConnection
	if err := c.doGet(ctx, orgPath(orgID, "/scim/connection"), &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// EnableSCIMConnection enables SCIM provisioning for an org and returns the
// connection (including its bearer token). POST /organizations/{org_id}/scim/connection.
// Requires org.admin.
func (c *Client) EnableSCIMConnection(ctx context.Context, orgID, callerToken string) (*SCIMConnection, error) {
	var out SCIMConnection
	if err := c.doJSON(ctx, "POST", orgPath(orgID, "/scim/connection"), nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteSCIMConnection disables SCIM provisioning for an org.
// DELETE /organizations/{org_id}/scim/connection. Requires org.admin.
func (c *Client) DeleteSCIMConnection(ctx context.Context, orgID, callerToken string) error {
	return c.doJSON(ctx, "DELETE", orgPath(orgID, "/scim/connection"), nil, nil, callerToken)
}
