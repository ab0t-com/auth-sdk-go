package authclient

import (
	"context"
	"net/url"
)

// This file extends the SDK with the remaining Roles + Permissions registry
// operations (contract section 11). The core GetRoles, CheckPermission and
// GetUserPermissions operations live in operations.go; the grant/revoke and
// permission-registry operations are added here.

// ---- Models ----

// RegisteredService describes a service that has registered permissions.
type RegisteredService struct {
	Service     string   `json:"service"`
	Permissions []string `json:"permissions,omitempty"`
	Description string   `json:"description,omitempty"`
}

// RegisteredServicesResponse is the result of GET /permissions/registry/services.
type RegisteredServicesResponse struct {
	Services []RegisteredService `json:"services"`
	Total    int                 `json:"total,omitempty"`
}

// ValidPermissionsResponse is the result of GET /permissions/registry/valid-permissions.
type ValidPermissionsResponse struct {
	Permissions []string `json:"permissions"`
	Total       int      `json:"total,omitempty"`
}

// PermissionValidationRequest is the body for POST /permissions/registry/validate.
type PermissionValidationRequest struct {
	Permissions []string `json:"permissions"`
}

// PermissionValidationResponse is the result of validating permission strings.
type PermissionValidationResponse struct {
	Valid   bool            `json:"valid"`
	Results map[string]bool `json:"results,omitempty"`
	Invalid []string        `json:"invalid,omitempty"`
}

// RegistryStatsResponse is the result of GET /permissions/registry/stats.
type RegistryStatsResponse struct {
	TotalServices    int `json:"total_services,omitempty"`
	TotalPermissions int `json:"total_permissions,omitempty"`
}

// ServicePermissionRegister is the body for POST /permissions/registry/register.
type ServicePermissionRegister struct {
	Service     string   `json:"service"`
	Permissions []string `json:"permissions"`
	Description string   `json:"description,omitempty"`
}

// ServicePermissionResponse is the result of registering service permissions.
type ServicePermissionResponse struct {
	Service     string   `json:"service,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Message     string   `json:"message,omitempty"`
}

// ---- Grant / revoke (RBAC) ----

// GrantPermission grants an explicit permission to a user.
// POST /permissions/grant. Requires org.admin / users.write (or api.*).
//
// Per the auth service OpenAPI (verified 2026-07-12) this endpoint takes its
// arguments as REQUIRED query parameters (user_id, org_id, permission), NOT a
// request body.
func (c *Client) GrantPermission(ctx context.Context, userID, orgID, permission, callerToken string) (*MessageResponse, error) {
	return c.grantOrRevoke(ctx, "/permissions/grant", userID, orgID, permission, callerToken)
}

// RevokePermission revokes an explicitly-granted permission (not role-inherited).
// POST /permissions/revoke. Requires users.write. Like GrantPermission, the
// server reads user_id, org_id and permission from REQUIRED query parameters.
func (c *Client) RevokePermission(ctx context.Context, userID, orgID, permission, callerToken string) (*MessageResponse, error) {
	return c.grantOrRevoke(ctx, "/permissions/revoke", userID, orgID, permission, callerToken)
}

func (c *Client) grantOrRevoke(ctx context.Context, path, userID, orgID, permission, callerToken string) (*MessageResponse, error) {
	q := url.Values{"user_id": {userID}, "org_id": {orgID}, "permission": {permission}}
	var out MessageResponse
	if err := c.doJSON(ctx, "POST", path+"?"+q.Encode(), struct{}{}, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Permission registry ----

// ListRegisteredServices lists services that have registered permissions.
// GET /permissions/registry/services.
func (c *Client) ListRegisteredServices(ctx context.Context, callerToken string) (*RegisteredServicesResponse, error) {
	var out RegisteredServicesResponse
	if err := c.doGet(ctx, "/permissions/registry/services", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListValidPermissions returns all permission strings the registry knows about.
// GET /permissions/registry/valid-permissions. PUBLIC.
func (c *Client) ListValidPermissions(ctx context.Context) (*ValidPermissionsResponse, error) {
	var out ValidPermissionsResponse
	if err := c.doGet(ctx, "/permissions/registry/valid-permissions", &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// ValidatePermissions checks whether permission strings are registered/valid.
// POST /permissions/registry/validate. PUBLIC.
func (c *Client) ValidatePermissions(ctx context.Context, perms []string) (*PermissionValidationResponse, error) {
	var out PermissionValidationResponse
	if err := c.doJSON(ctx, "POST", "/permissions/registry/validate", PermissionValidationRequest{Permissions: perms}, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// RegistryStats returns aggregate permission-registry counters.
// GET /permissions/registry/stats. PUBLIC.
func (c *Client) RegistryStats(ctx context.Context) (*RegistryStatsResponse, error) {
	var out RegistryStatsResponse
	if err := c.doGet(ctx, "/permissions/registry/stats", &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// RegisterServicePermissions registers a service's permission vocabulary.
// POST /permissions/registry/register. Requires permissions.register.
func (c *Client) RegisterServicePermissions(ctx context.Context, req ServicePermissionRegister, callerToken string) (*ServicePermissionResponse, error) {
	var out ServicePermissionResponse
	if err := c.doJSON(ctx, "POST", "/permissions/registry/register", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}
