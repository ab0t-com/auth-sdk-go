package authclient

import (
	"context"
	"net/url"
)

// This file extends the SDK with the platform Admin domain (contract section
// 16: password policy, JWKS rotation/revocation, circuit breakers, service
// accounts, privilege elevation, audit, emergency API-key revoke, provider
// status) and the Super-Admin domain (contract section 17: time-bound elevated
// grants with approval + audit). These are gated by admin.* / system.admin
// dot-permissions and serve the admin/tenant-management client archetype.

// ===================== Models: password policy =====================

// PasswordPolicyRequest is the body for POST /admin/password-policy.
type PasswordPolicyRequest struct {
	OrgID            string `json:"org_id,omitempty"`
	MinLength        int    `json:"min_length,omitempty"`
	RequireUppercase bool   `json:"require_uppercase,omitempty"`
	RequireLowercase bool   `json:"require_lowercase,omitempty"`
	RequireNumbers   bool   `json:"require_numbers,omitempty"`
	RequireSymbols   bool   `json:"require_symbols,omitempty"`
	MaxAgeDays       int    `json:"max_age_days,omitempty"`
	HistoryCount     int    `json:"history_count,omitempty"`
}

// PasswordPolicySetResponse is the result of setting a password policy.
type PasswordPolicySetResponse struct {
	Message string                 `json:"message,omitempty"`
	Policy  *PasswordPolicyRequest `json:"policy,omitempty"`
}

// PasswordPolicyGetResponse is the result of GET /admin/password-policy/{org_id}.
type PasswordPolicyGetResponse struct {
	OrgID  string                 `json:"org_id,omitempty"`
	Policy *PasswordPolicyRequest `json:"policy,omitempty"`
}

// ForcePasswordResetRequest is the body for POST /admin/password-policy/force-reset.
type ForcePasswordResetRequest struct {
	OrgID    string   `json:"org_id,omitempty"`
	UserIDs  []string `json:"user_ids,omitempty"`
	AllUsers bool     `json:"all_users,omitempty"`
}

// ForcePasswordResetResponse is the result of forcing password resets.
type ForcePasswordResetResponse struct {
	Message       string `json:"message,omitempty"`
	AffectedCount int    `json:"affected_count,omitempty"`
}

// PasswordComplianceResponse is the result of GET /admin/reports/password-compliance.
type PasswordComplianceResponse struct {
	Compliant    int            `json:"compliant,omitempty"`
	NonCompliant int            `json:"non_compliant,omitempty"`
	Details      map[string]any `json:"details,omitempty"`
}

// PasswordAgeUpdate is the body for POST /admin/users/password-age (test helper).
type PasswordAgeUpdate struct {
	UserID  string `json:"user_id"`
	AgeDays int    `json:"age_days"`
}

// PasswordAgeUpdateResponse is the result of POST /admin/users/password-age.
type PasswordAgeUpdateResponse struct {
	Message string `json:"message,omitempty"`
	UserID  string `json:"user_id,omitempty"`
}

// PasswordAuditEventsResponse is the result of GET /admin/audit/password-events.
type PasswordAuditEventsResponse struct {
	Events []map[string]any `json:"events"`
	Total  int              `json:"total,omitempty"`
}

// ===================== Models: JWKS admin =====================

// KeyRevocationRequest is the body for POST /admin/jwks/revoke/{kid}.
type KeyRevocationRequest struct {
	Reason string `json:"reason,omitempty"`
}

// KeyRevocationResponse is the result of revoking a signing key.
type KeyRevocationResponse struct {
	Kid     string `json:"kid,omitempty"`
	Revoked bool   `json:"revoked,omitempty"`
	Message string `json:"message,omitempty"`
}

// RevokedKeysListResponse is the result of GET /admin/jwks/revoked.
type RevokedKeysListResponse struct {
	RevokedKeys []map[string]any `json:"revoked_keys"`
	Total       int              `json:"total,omitempty"`
}

// KeyRotationRequest is the body for POST /admin/jwks/rotate.
type KeyRotationRequest struct {
	Algorithm string `json:"algorithm,omitempty"`
	Force     bool   `json:"force,omitempty"`
}

// KeyRotationResponse is the result of rotating signing keys.
type KeyRotationResponse struct {
	NewKid  string `json:"new_kid,omitempty"`
	Message string `json:"message,omitempty"`
}

// RotationStatusResponse is the result of GET /admin/jwks/rotation-status.
type RotationStatusResponse struct {
	Rotating    bool   `json:"rotating,omitempty"`
	CurrentKid  string `json:"current_kid,omitempty"`
	LastRotated string `json:"last_rotated,omitempty"`
}

// NextRotationResponse is the result of GET /admin/jwks/next-rotation.
type NextRotationResponse struct {
	NextRotation string `json:"next_rotation,omitempty"`
}

// KeyGenerationRequest is the body for POST /admin/jwks/generate.
type KeyGenerationRequest struct {
	Algorithm string `json:"algorithm,omitempty"`
	Activate  bool   `json:"activate,omitempty"`
}

// KeyGenerateResponse is the result of generating a key.
type KeyGenerateResponse struct {
	Kid     string `json:"kid,omitempty"`
	Message string `json:"message,omitempty"`
}

// KeyActivateResponse is the result of POST /admin/jwks/activate/{kid}.
type KeyActivateResponse struct {
	Kid     string `json:"kid,omitempty"`
	Active  bool   `json:"active,omitempty"`
	Message string `json:"message,omitempty"`
}

// KeyCleanupRequest is the body for POST /admin/jwks/cleanup.
type KeyCleanupRequest struct {
	OlderThanDays int  `json:"older_than_days,omitempty"`
	DryRun        bool `json:"dry_run,omitempty"`
}

// KeyCleanupResponse is the result of cleaning up old keys.
type KeyCleanupResponse struct {
	RemovedCount int      `json:"removed_count,omitempty"`
	RemovedKids  []string `json:"removed_kids,omitempty"`
	Message      string   `json:"message,omitempty"`
}

// ===================== Models: service accounts / elevation =====================

// ServiceAccountCreate is the body for POST /admin/users/create-service-account.
type ServiceAccountCreate struct {
	Name        string   `json:"name"`
	OrgID       string   `json:"org_id,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Description string   `json:"description,omitempty"`
}

// ServiceAccountResponse is the result of creating a service account.
type ServiceAccountResponse struct {
	UserID      string   `json:"user_id,omitempty"`
	Name        string   `json:"name,omitempty"`
	APIKey      string   `json:"api_key,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Message     string   `json:"message,omitempty"`
}

// ElevatePrivilegesRequest is the body for POST /admin/users/elevate-privileges.
type ElevatePrivilegesRequest struct {
	UserID          string   `json:"user_id"`
	Permissions     []string `json:"permissions"`
	DurationSeconds int      `json:"duration_seconds,omitempty"`
	Reason          string   `json:"reason,omitempty"`
}

// ElevatePrivilegesResponse is the result of elevating a user's privileges.
type ElevatePrivilegesResponse struct {
	UserID    string   `json:"user_id,omitempty"`
	Granted   []string `json:"granted,omitempty"`
	ExpiresAt string   `json:"expires_at,omitempty"`
	Message   string   `json:"message,omitempty"`
}

// ===================== Models: circuit breakers / audit / emergency =====================

// CircuitBreakerStatusResponse is the result of GET /admin/circuit-breakers/status.
type CircuitBreakerStatusResponse struct {
	Breakers map[string]any `json:"breakers,omitempty"`
}

// CircuitBreakerResetResponse is the result of resetting one breaker.
type CircuitBreakerResetResponse struct {
	Name    string `json:"name,omitempty"`
	Reset   bool   `json:"reset,omitempty"`
	Message string `json:"message,omitempty"`
}

// CircuitBreakerResetAllResponse is the result of resetting all breakers.
type CircuitBreakerResetAllResponse struct {
	ResetCount int    `json:"reset_count,omitempty"`
	Message    string `json:"message,omitempty"`
}

// RevocationAuditEntry is one entry from GET /admin/audit/revocations.
type RevocationAuditEntry struct {
	ID        string `json:"id,omitempty"`
	Type      string `json:"type,omitempty"`
	Subject   string `json:"subject,omitempty"`
	Actor     string `json:"actor,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

// EmergencyRevokeRequest is the body for POST /admin/api-keys/emergency-revoke.
type EmergencyRevokeRequest struct {
	KeyIDs  []string `json:"key_ids,omitempty"`
	OrgID   string   `json:"org_id,omitempty"`
	AllKeys bool     `json:"all_keys,omitempty"`
	Reason  string   `json:"reason,omitempty"`
}

// EmergencyRevokeResponse is the result of emergency API-key revocation.
type EmergencyRevokeResponse struct {
	RevokedCount int    `json:"revoked_count,omitempty"`
	Message      string `json:"message,omitempty"`
}

// ProviderStatusUpdateRequest is the body for POST /admin/providers/status.
type ProviderStatusUpdateRequest struct {
	ProviderID string `json:"provider_id"`
	Enabled    bool   `json:"enabled"`
	Reason     string `json:"reason,omitempty"`
}

// ProviderStatusUpdateResponse is the result of updating provider status.
type ProviderStatusUpdateResponse struct {
	ProviderID string `json:"provider_id,omitempty"`
	Enabled    bool   `json:"enabled,omitempty"`
	Message    string `json:"message,omitempty"`
}

// ===================== Models: super-admin =====================

// SuperAdminGrantRequestModel is the body for POST /super-admin/grant.
type SuperAdminGrantRequestModel struct {
	UserID           string   `json:"user_id"`
	Permissions      []string `json:"permissions"`
	DurationSeconds  int      `json:"duration_seconds,omitempty"`
	Reason           string   `json:"reason,omitempty"`
	RequiresApproval bool     `json:"requires_approval,omitempty"`
}

// SuperAdminGrantResponse is the result of POST /super-admin/grant.
type SuperAdminGrantResponse struct {
	GrantID   string `json:"grant_id,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	Status    string `json:"status,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Message   string `json:"message,omitempty"`
}

// SuperAdminRevokeRequestModel is the body for POST /super-admin/revoke.
type SuperAdminRevokeRequestModel struct {
	GrantID string `json:"grant_id,omitempty"`
	UserID  string `json:"user_id,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// SuperAdminRevokeResponse is the result of POST /super-admin/revoke.
type SuperAdminRevokeResponse struct {
	GrantID string `json:"grant_id,omitempty"`
	Revoked bool   `json:"revoked,omitempty"`
	Message string `json:"message,omitempty"`
}

// SuperAdminExtendRequestModel is the body for POST /super-admin/extend.
type SuperAdminExtendRequestModel struct {
	GrantID           string `json:"grant_id"`
	AdditionalSeconds int    `json:"additional_seconds,omitempty"`
	Reason            string `json:"reason,omitempty"`
}

// SuperAdminExtendResponse is the result of POST /super-admin/extend.
type SuperAdminExtendResponse struct {
	GrantID   string `json:"grant_id,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Message   string `json:"message,omitempty"`
}

// SuperAdminActiveGrantsResponse is the result of GET /super-admin/active-grants.
type SuperAdminActiveGrantsResponse struct {
	Grants []map[string]any `json:"grants"`
	Total  int              `json:"total,omitempty"`
}

// ApprovalRequestModel is the body for POST /super-admin/approve.
type ApprovalRequestModel struct {
	GrantID string `json:"grant_id"`
	Approve bool   `json:"approve"`
	Comment string `json:"comment,omitempty"`
}

// SuperAdminCleanupResponse is the result of POST /super-admin/cleanup-expired.
type SuperAdminCleanupResponse struct {
	CleanedCount int    `json:"cleaned_count,omitempty"`
	Message      string `json:"message,omitempty"`
}

// ===================== Admin: password policy =====================

// SetPasswordPolicy sets a password policy. POST /admin/password-policy.
func (c *Client) SetPasswordPolicy(ctx context.Context, req PasswordPolicyRequest, callerToken string) (*PasswordPolicySetResponse, error) {
	var out PasswordPolicySetResponse
	if err := c.doJSON(ctx, "POST", "/admin/password-policy", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetPasswordPolicy fetches an org's password policy.
// GET /admin/password-policy/{org_id}.
func (c *Client) GetPasswordPolicy(ctx context.Context, orgID, callerToken string) (*PasswordPolicyGetResponse, error) {
	var out PasswordPolicyGetResponse
	if err := c.doGet(ctx, "/admin/password-policy/"+url.PathEscape(orgID), &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ForcePasswordReset forces password resets for users.
// POST /admin/password-policy/force-reset.
func (c *Client) ForcePasswordReset(ctx context.Context, req ForcePasswordResetRequest, callerToken string) (*ForcePasswordResetResponse, error) {
	var out ForcePasswordResetResponse
	if err := c.doJSON(ctx, "POST", "/admin/password-policy/force-reset", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// PasswordComplianceReport returns password-compliance stats.
// GET /admin/reports/password-compliance.
func (c *Client) PasswordComplianceReport(ctx context.Context, callerToken string) (*PasswordComplianceResponse, error) {
	var out PasswordComplianceResponse
	if err := c.doGet(ctx, "/admin/reports/password-compliance", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdatePasswordAge sets a user's password age (test/admin helper).
// POST /admin/users/password-age.
func (c *Client) UpdatePasswordAge(ctx context.Context, req PasswordAgeUpdate, callerToken string) (*PasswordAgeUpdateResponse, error) {
	var out PasswordAgeUpdateResponse
	if err := c.doJSON(ctx, "POST", "/admin/users/password-age", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// PasswordAuditEvents returns password-related audit events.
// GET /admin/audit/password-events.
func (c *Client) PasswordAuditEvents(ctx context.Context, callerToken string) (*PasswordAuditEventsResponse, error) {
	var out PasswordAuditEventsResponse
	if err := c.doGet(ctx, "/admin/audit/password-events", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ===================== Admin: JWKS lifecycle =====================

// RevokeSigningKey revokes a signing key by kid. POST /admin/jwks/revoke/{kid}.
func (c *Client) RevokeSigningKey(ctx context.Context, kid string, req KeyRevocationRequest, callerToken string) (*KeyRevocationResponse, error) {
	var out KeyRevocationResponse
	if err := c.doJSON(ctx, "POST", "/admin/jwks/revoke/"+url.PathEscape(kid), req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListRevokedKeys lists revoked signing keys. GET /admin/jwks/revoked.
func (c *Client) ListRevokedKeys(ctx context.Context, callerToken string) (*RevokedKeysListResponse, error) {
	var out RevokedKeysListResponse
	if err := c.doGet(ctx, "/admin/jwks/revoked", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// RotateSigningKeys rotates the signing key set. POST /admin/jwks/rotate.
func (c *Client) RotateSigningKeys(ctx context.Context, req KeyRotationRequest, callerToken string) (*KeyRotationResponse, error) {
	var out KeyRotationResponse
	if err := c.doJSON(ctx, "POST", "/admin/jwks/rotate", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// JWKSRotationStatus returns current rotation status. GET /admin/jwks/rotation-status.
func (c *Client) JWKSRotationStatus(ctx context.Context, callerToken string) (*RotationStatusResponse, error) {
	var out RotationStatusResponse
	if err := c.doGet(ctx, "/admin/jwks/rotation-status", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// JWKSNextRotation returns the next scheduled rotation. GET /admin/jwks/next-rotation.
func (c *Client) JWKSNextRotation(ctx context.Context, callerToken string) (*NextRotationResponse, error) {
	var out NextRotationResponse
	if err := c.doGet(ctx, "/admin/jwks/next-rotation", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GenerateSigningKey generates a new signing key. POST /admin/jwks/generate.
func (c *Client) GenerateSigningKey(ctx context.Context, req KeyGenerationRequest, callerToken string) (*KeyGenerateResponse, error) {
	var out KeyGenerateResponse
	if err := c.doJSON(ctx, "POST", "/admin/jwks/generate", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ActivateSigningKey activates a signing key by kid. POST /admin/jwks/activate/{kid}.
func (c *Client) ActivateSigningKey(ctx context.Context, kid, callerToken string) (*KeyActivateResponse, error) {
	var out KeyActivateResponse
	if err := c.doJSON(ctx, "POST", "/admin/jwks/activate/"+url.PathEscape(kid), struct{}{}, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// CleanupSigningKeys removes old signing keys. POST /admin/jwks/cleanup.
func (c *Client) CleanupSigningKeys(ctx context.Context, req KeyCleanupRequest, callerToken string) (*KeyCleanupResponse, error) {
	var out KeyCleanupResponse
	if err := c.doJSON(ctx, "POST", "/admin/jwks/cleanup", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ===================== Admin: service accounts / elevation =====================

// CreateServiceAccount creates a service account (machine identity).
// POST /admin/users/create-service-account.
func (c *Client) CreateServiceAccount(ctx context.Context, req ServiceAccountCreate, callerToken string) (*ServiceAccountResponse, error) {
	var out ServiceAccountResponse
	if err := c.doJSON(ctx, "POST", "/admin/users/create-service-account", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ElevatePrivileges grants elevated privileges to a user.
// POST /admin/users/elevate-privileges.
func (c *Client) ElevatePrivileges(ctx context.Context, req ElevatePrivilegesRequest, callerToken string) (*ElevatePrivilegesResponse, error) {
	var out ElevatePrivilegesResponse
	if err := c.doJSON(ctx, "POST", "/admin/users/elevate-privileges", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ===================== Admin: circuit breakers =====================

// CircuitBreakerStatus returns the status of all circuit breakers.
// GET /admin/circuit-breakers/status.
func (c *Client) CircuitBreakerStatus(ctx context.Context, callerToken string) (*CircuitBreakerStatusResponse, error) {
	var out CircuitBreakerStatusResponse
	if err := c.doGet(ctx, "/admin/circuit-breakers/status", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ResetCircuitBreaker resets one circuit breaker.
// POST /admin/circuit-breakers/{breaker_name}/reset.
func (c *Client) ResetCircuitBreaker(ctx context.Context, name, callerToken string) (*CircuitBreakerResetResponse, error) {
	var out CircuitBreakerResetResponse
	if err := c.doJSON(ctx, "POST", "/admin/circuit-breakers/"+url.PathEscape(name)+"/reset", struct{}{}, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ResetAllCircuitBreakers resets all circuit breakers.
// POST /admin/circuit-breakers/reset-all.
func (c *Client) ResetAllCircuitBreakers(ctx context.Context, callerToken string) (*CircuitBreakerResetAllResponse, error) {
	var out CircuitBreakerResetAllResponse
	if err := c.doJSON(ctx, "POST", "/admin/circuit-breakers/reset-all", struct{}{}, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ===================== Admin: audit / emergency / provider status =====================

// RevocationAuditLog lists revocation audit entries. GET /admin/audit/revocations.
func (c *Client) RevocationAuditLog(ctx context.Context, callerToken string) ([]RevocationAuditEntry, error) {
	var out []RevocationAuditEntry
	if err := c.doGet(ctx, "/admin/audit/revocations", &out, callerToken); err != nil {
		return nil, err
	}
	return out, nil
}

// EmergencyRevokeAPIKeys emergency-revokes API keys (requires org.admin).
// POST /admin/api-keys/emergency-revoke.
func (c *Client) EmergencyRevokeAPIKeys(ctx context.Context, req EmergencyRevokeRequest, callerToken string) (*EmergencyRevokeResponse, error) {
	var out EmergencyRevokeResponse
	if err := c.doJSON(ctx, "POST", "/admin/api-keys/emergency-revoke", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateProviderStatus enables/disables a provider (requires org.admin).
// POST /admin/providers/status.
func (c *Client) UpdateProviderStatus(ctx context.Context, req ProviderStatusUpdateRequest, callerToken string) (*ProviderStatusUpdateResponse, error) {
	var out ProviderStatusUpdateResponse
	if err := c.doJSON(ctx, "POST", "/admin/providers/status", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ===================== Super-Admin =====================

// SuperAdminGrant creates a time-bound elevated grant (requires system.admin).
// POST /super-admin/grant.
func (c *Client) SuperAdminGrant(ctx context.Context, req SuperAdminGrantRequestModel, callerToken string) (*SuperAdminGrantResponse, error) {
	var out SuperAdminGrantResponse
	if err := c.doJSON(ctx, "POST", "/super-admin/grant", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// SuperAdminRevoke revokes an elevated grant (requires system.admin).
// POST /super-admin/revoke.
func (c *Client) SuperAdminRevoke(ctx context.Context, req SuperAdminRevokeRequestModel, callerToken string) (*SuperAdminRevokeResponse, error) {
	var out SuperAdminRevokeResponse
	if err := c.doJSON(ctx, "POST", "/super-admin/revoke", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// SuperAdminExtend extends an elevated grant's expiry (requires system.admin).
// POST /super-admin/extend.
func (c *Client) SuperAdminExtend(ctx context.Context, req SuperAdminExtendRequestModel, callerToken string) (*SuperAdminExtendResponse, error) {
	var out SuperAdminExtendResponse
	if err := c.doJSON(ctx, "POST", "/super-admin/extend", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// SuperAdminActiveGrants lists active elevated grants (requires system.admin).
// GET /super-admin/active-grants.
func (c *Client) SuperAdminActiveGrants(ctx context.Context, callerToken string) (*SuperAdminActiveGrantsResponse, error) {
	var out SuperAdminActiveGrantsResponse
	if err := c.doGet(ctx, "/super-admin/active-grants", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// SuperAdminApprove approves/denies a pending grant (must be a different admin
// than the requester). POST /super-admin/approve.
func (c *Client) SuperAdminApprove(ctx context.Context, req ApprovalRequestModel, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "POST", "/super-admin/approve", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// SuperAdminCleanupExpired purges expired grants (requires system.admin).
// POST /super-admin/cleanup-expired.
func (c *Client) SuperAdminCleanupExpired(ctx context.Context, callerToken string) (*SuperAdminCleanupResponse, error) {
	var out SuperAdminCleanupResponse
	if err := c.doJSON(ctx, "POST", "/super-admin/cleanup-expired", struct{}{}, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// SuperAdminAuditLog returns the super-admin audit log (requires system.admin).
// GET /super-admin/audit-log.
func (c *Client) SuperAdminAuditLog(ctx context.Context, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doGet(ctx, "/super-admin/audit-log", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}
