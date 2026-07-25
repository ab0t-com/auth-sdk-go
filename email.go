package authclient

import (
	"context"
	"net/url"
)

// This file covers the email-admin domain (contract section 18): system-level
// email history/stats/config/template-types, and per-organisation email
// configuration, templates, previews and test sends. These serve the admin /
// tenant-management archetype (system.admin or org.admin scopes).

// ---- Models ----

// EmailHistoryEntry is one sent-email record.
type EmailHistoryEntry struct {
	ID       string `json:"id,omitempty"`
	To       string `json:"to,omitempty"`
	Template string `json:"template,omitempty"`
	Status   string `json:"status,omitempty"`
	Subject  string `json:"subject,omitempty"`
	SentAt   string `json:"sent_at,omitempty"`
	Provider string `json:"provider,omitempty"`
	Error    string `json:"error,omitempty"`
}

// EmailHistoryResponse lists sent emails.
type EmailHistoryResponse struct {
	Emails []EmailHistoryEntry `json:"emails"`
	Total  int                 `json:"total,omitempty"`
}

// EmailStatsResponse reports aggregate email statistics.
type EmailStatsResponse struct {
	Sent      int            `json:"sent,omitempty"`
	Delivered int            `json:"delivered,omitempty"`
	Failed    int            `json:"failed,omitempty"`
	Bounced   int            `json:"bounced,omitempty"`
	Stats     map[string]any `json:"stats,omitempty"`
}

// GlobalEmailConfigResponse is the system-wide email configuration.
type GlobalEmailConfigResponse struct {
	Provider    string         `json:"provider,omitempty"`
	FromAddress string         `json:"from_address,omitempty"`
	FromName    string         `json:"from_name,omitempty"`
	Configured  bool           `json:"configured,omitempty"`
	Settings    map[string]any `json:"settings,omitempty"`
}

// TemplateTypeInfo describes one available email template type.
type TemplateTypeInfo struct {
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Variables   []string `json:"variables,omitempty"`
}

// TemplateTypesResponse lists available template types.
type TemplateTypesResponse struct {
	TemplateTypes []TemplateTypeInfo `json:"template_types"`
}

// OrgEmailConfig is a per-organisation email configuration.
type OrgEmailConfig struct {
	Provider    string         `json:"provider,omitempty"`
	FromAddress string         `json:"from_address,omitempty"`
	FromName    string         `json:"from_name,omitempty"`
	ReplyTo     string         `json:"reply_to,omitempty"`
	Settings    map[string]any `json:"settings,omitempty"`
}

// OrgEmailConfigResponse wraps an org's email configuration.
type OrgEmailConfigResponse struct {
	Config OrgEmailConfig `json:"config"`
}

// OrgEmailConfigUpdate is the body for PUT /organizations/{org_id}/emails/config.
type OrgEmailConfigUpdate struct {
	Provider    *string         `json:"provider,omitempty"`
	FromAddress *string         `json:"from_address,omitempty"`
	FromName    *string         `json:"from_name,omitempty"`
	ReplyTo     *string         `json:"reply_to,omitempty"`
	APIKey      *string         `json:"api_key,omitempty"`
	Settings    *map[string]any `json:"settings,omitempty"`
}

// EmailConfigDeleteResponse is the result of deleting an org email config.
type EmailConfigDeleteResponse struct {
	Message string `json:"message,omitempty"`
	Success bool   `json:"success,omitempty"`
}

// OrgEmailTemplate is a per-organisation email template.
type OrgEmailTemplate struct {
	Type     string `json:"type,omitempty"`
	Subject  string `json:"subject,omitempty"`
	HTMLBody string `json:"html_body,omitempty"`
	TextBody string `json:"text_body,omitempty"`
	Enabled  bool   `json:"enabled,omitempty"`
}

// OrgEmailTemplateResponse wraps one or more org email templates.
type OrgEmailTemplateResponse struct {
	Template  *OrgEmailTemplate  `json:"template,omitempty"`
	Templates []OrgEmailTemplate `json:"templates,omitempty"`
}

// OrgEmailTemplateUpdate is the body for updating an org email template.
type OrgEmailTemplateUpdate struct {
	Subject  *string `json:"subject,omitempty"`
	HTMLBody *string `json:"html_body,omitempty"`
	TextBody *string `json:"text_body,omitempty"`
	Enabled  *bool   `json:"enabled,omitempty"`
}

// EmailTemplateDeleteResponse is the result of deleting an org email template.
type EmailTemplateDeleteResponse struct {
	Message string `json:"message,omitempty"`
	Success bool   `json:"success,omitempty"`
}

// TemplatePreviewResponse is the rendered preview of an email template.
type TemplatePreviewResponse struct {
	Subject  string `json:"subject,omitempty"`
	HTMLBody string `json:"html_body,omitempty"`
	TextBody string `json:"text_body,omitempty"`
}

// TestEmailRequest is the body for POST /organizations/{org_id}/emails/test.
type TestEmailRequest struct {
	To       string `json:"to"`
	Template string `json:"template,omitempty"`
}

// TestEmailSentResponse is the result of sending a test email.
type TestEmailSentResponse struct {
	Message string `json:"message,omitempty"`
	Success bool   `json:"success,omitempty"`
	EmailID string `json:"email_id,omitempty"`
}

// ---- System email operations ----

// EmailHistory returns the system-wide sent-email history.
// GET /admin/emails/history. Requires system.admin.
func (c *Client) EmailHistory(ctx context.Context, callerToken string) (*EmailHistoryResponse, error) {
	var out EmailHistoryResponse
	if err := c.doGet(ctx, "/admin/emails/history", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// EmailStats returns system-wide email statistics.
// GET /admin/emails/stats. Requires system.admin.
func (c *Client) EmailStats(ctx context.Context, callerToken string) (*EmailStatsResponse, error) {
	var out EmailStatsResponse
	if err := c.doGet(ctx, "/admin/emails/stats", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GlobalEmailConfig returns the system-wide email configuration.
// GET /admin/emails/config. Requires system.admin.
func (c *Client) GlobalEmailConfig(ctx context.Context, callerToken string) (*GlobalEmailConfigResponse, error) {
	var out GlobalEmailConfigResponse
	if err := c.doGet(ctx, "/admin/emails/config", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// EmailTemplateTypes lists the available email template types.
// GET /admin/emails/template-types. Requires system.admin.
func (c *Client) EmailTemplateTypes(ctx context.Context, callerToken string) (*TemplateTypesResponse, error) {
	var out TemplateTypesResponse
	if err := c.doGet(ctx, "/admin/emails/template-types", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Org email operations ----

// OrgEmailHistory returns an org's sent-email history.
// GET /organizations/{org_id}/emails/history. Requires org.admin.
func (c *Client) OrgEmailHistory(ctx context.Context, orgID, callerToken string) (*EmailHistoryResponse, error) {
	var out EmailHistoryResponse
	if err := c.doGet(ctx, "/organizations/"+url.PathEscape(orgID)+"/emails/history", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetOrgEmailConfig returns an org's email configuration.
// GET /organizations/{org_id}/emails/config. Requires org.admin.
func (c *Client) GetOrgEmailConfig(ctx context.Context, orgID, callerToken string) (*OrgEmailConfigResponse, error) {
	var out OrgEmailConfigResponse
	if err := c.doGet(ctx, "/organizations/"+url.PathEscape(orgID)+"/emails/config", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateOrgEmailConfig updates an org's email configuration.
// PUT /organizations/{org_id}/emails/config. Requires org.admin.
func (c *Client) UpdateOrgEmailConfig(ctx context.Context, orgID string, req OrgEmailConfigUpdate, callerToken string) (*OrgEmailConfigResponse, error) {
	var out OrgEmailConfigResponse
	if err := c.doJSON(ctx, "PUT", "/organizations/"+url.PathEscape(orgID)+"/emails/config", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteOrgEmailConfig deletes an org's email configuration.
// DELETE /organizations/{org_id}/emails/config. Requires org.admin.
func (c *Client) DeleteOrgEmailConfig(ctx context.Context, orgID, callerToken string) (*EmailConfigDeleteResponse, error) {
	var out EmailConfigDeleteResponse
	if err := c.doJSON(ctx, "DELETE", "/organizations/"+url.PathEscape(orgID)+"/emails/config", nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListOrgEmailTemplates lists an org's email templates.
// GET /organizations/{org_id}/emails/templates. Requires org.admin.
func (c *Client) ListOrgEmailTemplates(ctx context.Context, orgID, callerToken string) (*OrgEmailTemplateResponse, error) {
	var out OrgEmailTemplateResponse
	if err := c.doGet(ctx, "/organizations/"+url.PathEscape(orgID)+"/emails/templates", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetOrgEmailTemplate fetches one of an org's email templates.
// GET /organizations/{org_id}/emails/templates/{template_type}. Requires org.admin.
func (c *Client) GetOrgEmailTemplate(ctx context.Context, orgID, templateType, callerToken string) (*OrgEmailTemplateResponse, error) {
	var out OrgEmailTemplateResponse
	if err := c.doGet(ctx, "/organizations/"+url.PathEscape(orgID)+"/emails/templates/"+url.PathEscape(templateType), &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateOrgEmailTemplate updates one of an org's email templates.
// PUT /organizations/{org_id}/emails/templates/{template_type}. Requires org.admin.
func (c *Client) UpdateOrgEmailTemplate(ctx context.Context, orgID, templateType string, req OrgEmailTemplateUpdate, callerToken string) (*OrgEmailTemplateResponse, error) {
	var out OrgEmailTemplateResponse
	if err := c.doJSON(ctx, "PUT", "/organizations/"+url.PathEscape(orgID)+"/emails/templates/"+url.PathEscape(templateType), req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteOrgEmailTemplate deletes one of an org's email templates.
// DELETE /organizations/{org_id}/emails/templates/{template_type}. Requires org.admin.
func (c *Client) DeleteOrgEmailTemplate(ctx context.Context, orgID, templateType, callerToken string) (*EmailTemplateDeleteResponse, error) {
	var out EmailTemplateDeleteResponse
	if err := c.doJSON(ctx, "DELETE", "/organizations/"+url.PathEscape(orgID)+"/emails/templates/"+url.PathEscape(templateType), nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// PreviewOrgEmailTemplate renders a preview of an org's email template.
// POST /organizations/{org_id}/emails/templates/{template_type}/preview. Requires org.admin.
func (c *Client) PreviewOrgEmailTemplate(ctx context.Context, orgID, templateType string, vars map[string]any, callerToken string) (*TemplatePreviewResponse, error) {
	var out TemplatePreviewResponse
	body := map[string]any{}
	if vars != nil {
		body["variables"] = vars
	}
	if err := c.doJSON(ctx, "POST", "/organizations/"+url.PathEscape(orgID)+"/emails/templates/"+url.PathEscape(templateType)+"/preview", body, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// SendTestEmail sends a test email using an org's configuration.
// POST /organizations/{org_id}/emails/test. Requires org.admin.
func (c *Client) SendTestEmail(ctx context.Context, orgID string, req TestEmailRequest, callerToken string) (*TestEmailSentResponse, error) {
	var out TestEmailSentResponse
	if err := c.doJSON(ctx, "POST", "/organizations/"+url.PathEscape(orgID)+"/emails/test", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}
