package authclient

import (
	"context"
	"net/url"
)

// This file extends the SDK with the Organisations/Tenants domain (contract
// section 9: org lifecycle, hierarchy, membership, invitations, sessions) and
// the Teams/Groups domain (section 10: team lifecycle, membership, team
// permissions). GetOrganization lives in operations.go.

// ===================== Models: organisations =====================

// OrganizationCreate is the body for POST /organizations/.
type OrganizationCreate struct {
	Name            string         `json:"name"`
	Slug            string         `json:"slug,omitempty"`
	Domain          string         `json:"domain,omitempty"`
	ParentID        string         `json:"parent_id,omitempty"`
	BillingType     string         `json:"billing_type,omitempty"`
	ServiceAudience string         `json:"service_audience,omitempty"`
	Timezone        string         `json:"timezone,omitempty"`
	Settings        map[string]any `json:"settings,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

// OrganizationUpdate is the body for PUT /organizations/{org_id}.
type OrganizationUpdate struct {
	Name        *string         `json:"name,omitempty"`
	Domain      *string         `json:"domain,omitempty"`
	BillingType *string         `json:"billing_type,omitempty"`
	Status      *string         `json:"status,omitempty"`
	Timezone    *string         `json:"timezone,omitempty"`
	Settings    *map[string]any `json:"settings,omitempty"`
	Metadata    *map[string]any `json:"metadata,omitempty"`
}

// OrgHierarchyNode is a node in an organization tree.
type OrgHierarchyNode struct {
	ID       string             `json:"id"`
	Name     string             `json:"name"`
	Slug     string             `json:"slug,omitempty"`
	ParentID string             `json:"parent_id,omitempty"`
	Type     string             `json:"type,omitempty"`
	Children []OrgHierarchyNode `json:"children,omitempty"`
}

// OrgHierarchyResponse is the result of GET /organizations/{org_id}/hierarchy.
type OrgHierarchyResponse struct {
	Root          *OrgHierarchyNode  `json:"root,omitempty"`
	Organizations []OrgHierarchyNode `json:"organizations,omitempty"`
}

// OrgMember is one organization membership entry.
type OrgMember struct {
	UserID      string   `json:"user_id"`
	Email       string   `json:"email,omitempty"`
	Name        string   `json:"name,omitempty"`
	Role        string   `json:"role,omitempty"`
	Status      string   `json:"status,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	JoinedAt    string   `json:"joined_at,omitempty"`
}

// OrgUserResponse is the result of GET /organizations/{org_id}/users.
type OrgUserResponse struct {
	Users []OrgMember `json:"users"`
	Total int         `json:"total,omitempty"`
}

// RoleUpdateResponse is the result of changing a member's role.
type RoleUpdateResponse struct {
	Message string `json:"message,omitempty"`
	UserID  string `json:"user_id,omitempty"`
	Role    string `json:"role,omitempty"`
}

// OrgRoleUpdate is the body for PUT /organizations/{org_id}/users/{user_id}.
type OrgRoleUpdate struct {
	Role        string   `json:"role,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// OrganizationInvite is the body for POST /organizations/{org_id}/invite.
type OrganizationInvite struct {
	Email   string   `json:"email"`
	Role    string   `json:"role,omitempty"`
	TeamIDs []string `json:"team_ids,omitempty"`
	Message string   `json:"message,omitempty"`
	Resend  bool     `json:"resend,omitempty"`
}

// InvitationListItem is one entry from GET /organizations/{org_id}/invitations.
type InvitationListItem struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role,omitempty"`
	Status    string `json:"status,omitempty"`
	InvitedBy string `json:"invited_by,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// OrgSession is one active session row.
type OrgSession struct {
	ID         string `json:"id"`
	UserID     string `json:"user_id"`
	IPAddress  string `json:"ip_address,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
	LastSeenAt string `json:"last_seen_at,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

// OrgSessionsResponse is the result of GET /organizations/{org_id}/sessions.
type OrgSessionsResponse struct {
	Sessions []OrgSession `json:"sessions"`
	Total    int          `json:"total,omitempty"`
}

// SessionRevokeResponse is the result of revoking a user's sessions.
type SessionRevokeResponse struct {
	Message      string `json:"message,omitempty"`
	RevokedCount int    `json:"revoked_count,omitempty"`
}

// ===================== Models: teams =====================

// Team is a team/group within an organization.
type Team struct {
	ID          string         `json:"id"`
	OrgID       string         `json:"org_id,omitempty"`
	Name        string         `json:"name"`
	Slug        string         `json:"slug,omitempty"`
	Description string         `json:"description,omitempty"`
	ParentID    string         `json:"parent_id,omitempty"`
	MemberCount int            `json:"member_count,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	CreatedAt   string         `json:"created_at,omitempty"`
}

// TeamCreate is the body for POST /organizations/{org_id}/teams.
type TeamCreate struct {
	Name        string         `json:"name"`
	Slug        string         `json:"slug,omitempty"`
	Description string         `json:"description,omitempty"`
	ParentID    string         `json:"parent_id,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// TeamUpdate is the body for PUT /teams/{team_id}.
type TeamUpdate struct {
	Name        *string         `json:"name,omitempty"`
	Description *string         `json:"description,omitempty"`
	Metadata    *map[string]any `json:"metadata,omitempty"`
}

// TeamMember is one team member entry.
type TeamMember struct {
	UserID  string `json:"user_id"`
	Email   string `json:"email,omitempty"`
	Name    string `json:"name,omitempty"`
	Role    string `json:"role,omitempty"`
	AddedAt string `json:"added_at,omitempty"`
}

// TeamMemberAdd is the body for POST /teams/{team_id}/members.
type TeamMemberAdd struct {
	UserID string `json:"user_id"`
	Role   string `json:"role,omitempty"`
}

// TeamMemberRoleUpdate is the body for PUT /teams/{team_id}/members/{user_id}.
type TeamMemberRoleUpdate struct {
	Role string `json:"role"`
}

// TeamPermissionsResponse is the result of GET /teams/{team_id}/permissions.
type TeamPermissionsResponse struct {
	TeamID      string   `json:"team_id,omitempty"`
	Permissions []string `json:"permissions"`
}

// ===================== Organisations =====================

// CreateOrganization creates a new organization/tenant.
// POST /organizations/.
func (c *Client) CreateOrganization(ctx context.Context, req OrganizationCreate, token string) (*Organization, error) {
	var out Organization
	if err := c.doJSON(ctx, "POST", "/organizations/", req, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateOrganization updates an organization. PUT /organizations/{org_id}.
func (c *Client) UpdateOrganization(ctx context.Context, orgID string, req OrganizationUpdate, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "PUT", "/organizations/"+url.PathEscape(orgID), req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteOrganization deletes an organization (requires org.admin).
// DELETE /organizations/{org_id}.
func (c *Client) DeleteOrganization(ctx context.Context, orgID, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "DELETE", "/organizations/"+url.PathEscape(orgID), nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetOrgHierarchy returns the org's sub-tree. GET /organizations/{org_id}/hierarchy.
func (c *Client) GetOrgHierarchy(ctx context.Context, orgID, callerToken string) (*OrgHierarchyResponse, error) {
	var out OrgHierarchyResponse
	if err := c.doGet(ctx, "/organizations/"+url.PathEscape(orgID)+"/hierarchy", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListOrgUsers lists members of an organization (requires users.read).
// GET /organizations/{org_id}/users.
func (c *Client) ListOrgUsers(ctx context.Context, orgID, callerToken string) (*OrgUserResponse, error) {
	var out OrgUserResponse
	if err := c.doGet(ctx, "/organizations/"+url.PathEscape(orgID)+"/users", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateOrgUserRole changes a member's role/permissions (requires users.write).
// PUT /organizations/{org_id}/users/{user_id}.
func (c *Client) UpdateOrgUserRole(ctx context.Context, orgID, userID string, req OrgRoleUpdate, callerToken string) (*RoleUpdateResponse, error) {
	var out RoleUpdateResponse
	path := "/organizations/" + url.PathEscape(orgID) + "/users/" + url.PathEscape(userID)
	if err := c.doJSON(ctx, "PUT", path, req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// RemoveOrgUser removes a member from an organization (requires users.write).
// DELETE /organizations/{org_id}/users/{user_id}.
func (c *Client) RemoveOrgUser(ctx context.Context, orgID, userID, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	path := "/organizations/" + url.PathEscape(orgID) + "/users/" + url.PathEscape(userID)
	if err := c.doJSON(ctx, "DELETE", path, nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// InviteToOrganization invites a user by email (requires users.invite).
// POST /organizations/{org_id}/invite.
func (c *Client) InviteToOrganization(ctx context.Context, orgID string, req OrganizationInvite, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "POST", "/organizations/"+url.PathEscape(orgID)+"/invite", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListInvitations lists pending invitations. GET /organizations/{org_id}/invitations.
func (c *Client) ListInvitations(ctx context.Context, orgID, callerToken string) ([]InvitationListItem, error) {
	var out []InvitationListItem
	if err := c.doGet(ctx, "/organizations/"+url.PathEscape(orgID)+"/invitations", &out, callerToken); err != nil {
		return nil, err
	}
	return out, nil
}

// RevokeInvitation cancels a pending invitation.
// DELETE /organizations/{org_id}/invitations/{invitation_id}.
func (c *Client) RevokeInvitation(ctx context.Context, orgID, invitationID, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	path := "/organizations/" + url.PathEscape(orgID) + "/invitations/" + url.PathEscape(invitationID)
	if err := c.doJSON(ctx, "DELETE", path, nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListOrgSessions lists active sessions in an organization.
// GET /organizations/{org_id}/sessions.
func (c *Client) ListOrgSessions(ctx context.Context, orgID, callerToken string) (*OrgSessionsResponse, error) {
	var out OrgSessionsResponse
	if err := c.doGet(ctx, "/organizations/"+url.PathEscape(orgID)+"/sessions", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// RevokeOrgSessions revokes ALL sessions in an organization (requires org.admin).
// DELETE /organizations/{org_id}/sessions.
func (c *Client) RevokeOrgSessions(ctx context.Context, orgID, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "DELETE", "/organizations/"+url.PathEscape(orgID)+"/sessions", nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// RevokeUserSessions revokes a single user's sessions (requires org.admin).
// DELETE /organizations/{org_id}/users/{user_id}/sessions.
func (c *Client) RevokeUserSessions(ctx context.Context, orgID, userID, callerToken string) (*SessionRevokeResponse, error) {
	var out SessionRevokeResponse
	path := "/organizations/" + url.PathEscape(orgID) + "/users/" + url.PathEscape(userID) + "/sessions"
	if err := c.doJSON(ctx, "DELETE", path, nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ===================== Org-scoped teams =====================

// CreateTeam creates a team in an organization (requires teams.write).
// POST /organizations/{org_id}/teams.
func (c *Client) CreateTeam(ctx context.Context, orgID string, req TeamCreate, callerToken string) (*Team, error) {
	var out Team
	if err := c.doJSON(ctx, "POST", "/organizations/"+url.PathEscape(orgID)+"/teams", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListTeams lists teams in an organization (requires teams.read).
// GET /organizations/{org_id}/teams.
func (c *Client) ListTeams(ctx context.Context, orgID, callerToken string) ([]Team, error) {
	var out []Team
	if err := c.doGet(ctx, "/organizations/"+url.PathEscape(orgID)+"/teams", &out, callerToken); err != nil {
		return nil, err
	}
	return out, nil
}

// ===================== Teams / groups =====================

// GetTeam fetches a team by id (requires teams.read). GET /teams/{team_id}.
func (c *Client) GetTeam(ctx context.Context, teamID, callerToken string) (*Team, error) {
	var out Team
	if err := c.doGet(ctx, "/teams/"+url.PathEscape(teamID), &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateTeam updates a team (requires teams.write). PUT /teams/{team_id}.
func (c *Client) UpdateTeam(ctx context.Context, teamID string, req TeamUpdate, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "PUT", "/teams/"+url.PathEscape(teamID), req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteTeam deletes a team (requires teams.write). DELETE /teams/{team_id}.
func (c *Client) DeleteTeam(ctx context.Context, teamID, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "DELETE", "/teams/"+url.PathEscape(teamID), nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// AddTeamMember adds a member to a team (requires teams.write).
// POST /teams/{team_id}/members.
func (c *Client) AddTeamMember(ctx context.Context, teamID string, req TeamMemberAdd, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	if err := c.doJSON(ctx, "POST", "/teams/"+url.PathEscape(teamID)+"/members", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListTeamMembers lists a team's members (requires teams.read).
// GET /teams/{team_id}/members.
func (c *Client) ListTeamMembers(ctx context.Context, teamID, callerToken string) ([]TeamMember, error) {
	var out []TeamMember
	if err := c.doGet(ctx, "/teams/"+url.PathEscape(teamID)+"/members", &out, callerToken); err != nil {
		return nil, err
	}
	return out, nil
}

// RemoveTeamMember removes a member from a team (requires teams.write).
// DELETE /teams/{team_id}/members/{user_id}.
func (c *Client) RemoveTeamMember(ctx context.Context, teamID, userID, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	path := "/teams/" + url.PathEscape(teamID) + "/members/" + url.PathEscape(userID)
	if err := c.doJSON(ctx, "DELETE", path, nil, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateTeamMemberRole changes a team member's role (requires teams.write).
// PUT /teams/{team_id}/members/{user_id}.
func (c *Client) UpdateTeamMemberRole(ctx context.Context, teamID, userID string, req TeamMemberRoleUpdate, callerToken string) (*MessageResponse, error) {
	var out MessageResponse
	path := "/teams/" + url.PathEscape(teamID) + "/members/" + url.PathEscape(userID)
	if err := c.doJSON(ctx, "PUT", path, req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetTeamPermissions returns a team's effective permissions (requires teams.read).
// GET /teams/{team_id}/permissions.
func (c *Client) GetTeamPermissions(ctx context.Context, teamID, callerToken string) (*TeamPermissionsResponse, error) {
	var out TeamPermissionsResponse
	if err := c.doGet(ctx, "/teams/"+url.PathEscape(teamID)+"/permissions", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}
