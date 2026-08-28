package authclient

import (
	"context"
	"net/url"
)

// This file covers the quotas/tiers (contract section 23), reports/abuse
// (section 24) and metrics/health/discovery (section 25) domains. Quotas serve
// the end-user/service archetypes (own usage + tier discovery); reports serve
// public abuse submission plus admin triage; metrics/health/discovery serve
// the resource-server and admin archetypes.

// ===================== Quotas / tiers =====================

// QuotaUsageItem is usage for one resource type.
//
// Deprecated: /quotas/my-usage does not return an array of these. The server
// returns object maps keyed by resource type (see QuotaUsageResponse). Retained
// for source compatibility; no endpoint decodes into it.
type QuotaUsageItem struct {
	ResourceType string  `json:"resource_type"`
	Used         int64   `json:"used"`
	Limit        int64   `json:"limit"`
	Remaining    int64   `json:"remaining,omitempty"`
	Percent      float64 `json:"percent,omitempty"`
}

// QuotaUsageResponse is the result of GET /quotas/my-usage. The server returns
// object MAPS keyed by resource type (not arrays); an earlier revision modeled
// `usage` as a slice, so the real object body failed to decode entirely.
type QuotaUsageResponse struct {
	UserID string `json:"user_id,omitempty"`
	Tier   string `json:"tier,omitempty"`
	// Usage/Limits/Percentages are keyed by resource type.
	Usage       map[string]int64   `json:"usage,omitempty"`
	Limits      map[string]int64   `json:"limits,omitempty"`
	Percentages map[string]float64 `json:"percentages,omitempty"`
}

// QuotaCheckResponse is the result of GET /quotas/check/{resource_type}.
type QuotaCheckResponse struct {
	ResourceType string `json:"resource_type,omitempty"`
	Allowed      bool   `json:"allowed"`
	Used         int64  `json:"used,omitempty"`
	Limit        int64  `json:"limit,omitempty"`
	Remaining    int64  `json:"remaining,omitempty"`
	CurrentUsage int64  `json:"current_usage,omitempty"`
	Message      string `json:"message,omitempty"`
	Tier         string `json:"tier,omitempty"`
}

// QuotaTier describes one subscription tier.
type QuotaTier struct {
	Name   string           `json:"name"`
	Limits map[string]int64 `json:"limits,omitempty"`
	Price  string           `json:"price,omitempty"`
}

// QuotaTierLimits is the per-tier limit set the server returns as the value of
// each entry in QuotaTiersResponse.Tiers.
type QuotaTierLimits struct {
	MaxOrganizationsPerUser int64 `json:"max_organizations_per_user,omitempty"`
	MaxUsersPerOrg          int64 `json:"max_users_per_org,omitempty"`
	MaxTeamsPerOrg          int64 `json:"max_teams_per_org,omitempty"`
	MaxAPIKeysPerOrg        int64 `json:"max_api_keys_per_org,omitempty"`
	MaxPermissionsPerUser   int64 `json:"max_permissions_per_user,omitempty"`
	MaxDelegationsPerUser   int64 `json:"max_delegations_per_user,omitempty"`
	StorageQuotaMB          int64 `json:"storage_quota_mb,omitempty"`
	APIRateLimitPerHour     int64 `json:"api_rate_limit_per_hour,omitempty"`
}

// QuotaTiersResponse is the result of GET /quotas/tiers. `tiers` is an object
// keyed by tier name (not an array); an earlier revision modeled it as a slice,
// so the real object body failed to decode entirely.
type QuotaTiersResponse struct {
	Tiers      map[string]QuotaTierLimits `json:"tiers,omitempty"`
	UpgradeURL string                     `json:"upgrade_url,omitempty"`
}

// MyQuotaUsage returns the caller's quota usage. GET /quotas/my-usage.
func (c *Client) MyQuotaUsage(ctx context.Context, token string) (*QuotaUsageResponse, error) {
	var out QuotaUsageResponse
	if err := c.doGet(ctx, "/quotas/my-usage", &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// CheckQuota checks the caller's quota for a resource type.
// GET /quotas/check/{resource_type}.
func (c *Client) CheckQuota(ctx context.Context, resourceType, token string) (*QuotaCheckResponse, error) {
	var out QuotaCheckResponse
	if err := c.doGet(ctx, "/quotas/check/"+url.PathEscape(resourceType), &out, token); err != nil {
		return nil, err
	}
	if out.ResourceType == "" {
		out.ResourceType = resourceType
	}
	return &out, nil
}

// QuotaTiers lists the available subscription tiers. GET /quotas/tiers (public).
func (c *Client) QuotaTiers(ctx context.Context) (*QuotaTiersResponse, error) {
	var out QuotaTiersResponse
	if err := c.doGet(ctx, "/quotas/tiers", &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// ===================== Reports / abuse =====================

// LeakReportSubmission is the body for POST /reports.
type LeakReportSubmission struct {
	Type          string         `json:"type,omitempty"`
	Description   string         `json:"description,omitempty"`
	URL           string         `json:"url,omitempty"`
	Evidence      string         `json:"evidence,omitempty"`
	ReporterEmail string         `json:"reporter_email,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

// LeakReportSubmissionResponse is the result of submitting an abuse report.
type LeakReportSubmissionResponse struct {
	ReportID string `json:"report_id"`
	Message  string `json:"message,omitempty"`
	Status   string `json:"status,omitempty"`
}

// LeakReport is one abuse report entry.
type LeakReport struct {
	ID          string `json:"id"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
}

// LeakReportListResponse lists abuse reports.
type LeakReportListResponse struct {
	Reports []LeakReport `json:"reports"`
	Total   int          `json:"total,omitempty"`
}

// LeakReportActionResponse is the result of dismiss/resolve.
type LeakReportActionResponse struct {
	ReportID string `json:"report_id,omitempty"`
	Status   string `json:"status,omitempty"`
	Message  string `json:"message,omitempty"`
}

// SubmitReport submits an abuse/leak report. POST /reports (public).
func (c *Client) SubmitReport(ctx context.Context, req LeakReportSubmission) (*LeakReportSubmissionResponse, error) {
	var out LeakReportSubmissionResponse
	if err := c.doJSON(ctx, "POST", "/reports", req, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListReports lists abuse/leak reports. GET /reports. Requires org.admin.
func (c *Client) ListReports(ctx context.Context, callerToken string) (*LeakReportListResponse, error) {
	var out LeakReportListResponse
	if err := c.doGet(ctx, "/reports", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// DismissReport dismisses an abuse report. POST /reports/{report_id}/dismiss.
// Requires org.admin.
func (c *Client) DismissReport(ctx context.Context, reportID, callerToken string) (*LeakReportActionResponse, error) {
	var out LeakReportActionResponse
	if err := c.doJSON(ctx, "POST", "/reports/"+url.PathEscape(reportID)+"/dismiss", struct{}{}, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ResolveReport resolves an abuse report. POST /reports/{report_id}/resolve.
// Requires org.admin.
func (c *Client) ResolveReport(ctx context.Context, reportID, callerToken string) (*LeakReportActionResponse, error) {
	var out LeakReportActionResponse
	if err := c.doJSON(ctx, "POST", "/reports/"+url.PathEscape(reportID)+"/resolve", struct{}{}, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}
