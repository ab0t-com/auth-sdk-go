package authclient

import (
	"context"
	"encoding/json"
	"net/url"
)

// This file extends the SDK with the Organisations/Tenants domain (contract
// section 9: org lifecycle, hierarchy, membership, invitations, sessions) and
// the Teams/Groups domain (section 10: team lifecycle, membership, team
// permissions). GetOrganization lives in operations.go.

// ===================== Models: organisations =====================

// OrganizationCreate is the body for POST /organizations/. Fields mirror the goauth
// createOrgRequest handler struct (orgs/create.go:19-32), adding the org-profile
// fields (logo_url, website, industry, size). NOTE: billing_type is NOT settable on
// this endpoint — the handler forces the PREPAID default (create.go:43-46), so the
// pre-v0.11.0 BillingType field was silently ignored and has been removed. See the
// FEATURE QUESTION in the work_log about where caller-set billing_type should live.
type OrganizationCreate struct {
	Name            string         `json:"name"`
	Slug            string         `json:"slug,omitempty"`
	Domain          string         `json:"domain,omitempty"`
	ParentID        string         `json:"parent_id,omitempty"`
	ServiceAudience string         `json:"service_audience,omitempty"`
	LogoURL         string         `json:"logo_url,omitempty"`
	Website         string         `json:"website,omitempty"`
	Industry        string         `json:"industry,omitempty"`
	Size            string         `json:"size,omitempty"`
	Timezone        string         `json:"timezone,omitempty"`
	Settings        map[string]any `json:"settings,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

// OrganizationUpdate is the body for PUT /organizations/{org_id}. Fields mirror the
// goauth updateOrgRequest handler struct (orgs/detail.go:35-48): the SDK can now
// rename the slug and re-parent (parent_id), and set the profile fields. NOTE:
//   - billing_type is NOT accepted here — the handler 400-REJECTS the whole request
//     if it is present (detail.go:70-73), so BillingType was removed (a stray value
//     would otherwise fail an unrelated update). FEATURE QUESTION filed in work_log.
//   - status is NOT in the update schema (silently ignored), so Status was removed.
type OrganizationUpdate struct {
	Name     *string         `json:"name,omitempty"`
	Slug     *string         `json:"slug,omitempty"`
	Domain   *string         `json:"domain,omitempty"`
	ParentID *string         `json:"parent_id,omitempty"`
	LogoURL  *string         `json:"logo_url,omitempty"`
	Website  *string         `json:"website,omitempty"`
	Industry *string         `json:"industry,omitempty"`
	Size     *string         `json:"size,omitempty"`
	Timezone *string         `json:"timezone,omitempty"`
	Settings *map[string]any `json:"settings,omitempty"`
	Metadata *map[string]any `json:"metadata,omitempty"`
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

// OrgInfo describes one organization in a hierarchy response.
//
// ParentID is the nesting primitive: organizations form a TREE. A company can own
// sub-companies, each with their own teams and users. Nothing in this SDK exposed
// that before, so consumers modelled a flat tenancy the service never had.
type OrgInfo struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	Slug     string `json:"slug,omitempty"`
	ParentID string `json:"parent_id,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Status   string `json:"status,omitempty"`

	BillingType string `json:"billing_type,omitempty"`
	Industry    string `json:"industry,omitempty"`
	Size        string `json:"size,omitempty"`
	Timezone    string `json:"timezone,omitempty"`
	Website     string `json:"website,omitempty"`
	LogoURL     string `json:"logo_url,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

// OrgHierarchyResponse is the result of GET /organizations/{org_id}/hierarchy.
//
// CONTRACT NOTE: an earlier release of this SDK declared this as
// {root, organizations}, which no version of the service has ever returned — the
// spec defines {organization, teams, children, user_count, team_count} with
// `organization` required. Every field would have decoded to its zero value, and
// silently: JSON decoding does not complain about names it does not recognise, so
// a caller got an empty tree rather than an error. This is the same class of
// defect as the bulk-check mismatch fixed in v0.2.0, and the reason `make drift`
// exists.
//
// Children are the SUB-ORGANIZATIONS: this is how companies-of-companies are
// represented on the wire.
type OrgHierarchyResponse struct {
	Organization *OrgInfo            `json:"organization"`
	Teams        []HierarchyTeam     `json:"teams,omitempty"`
	Children     []OrgHierarchyChild `json:"children,omitempty"`
	UserCount    int                 `json:"user_count,omitempty"`
	TeamCount    int                 `json:"team_count,omitempty"`
}

// OrgHierarchyChild is one sub-organization node in a hierarchy response. IMPORTANT:
// unlike the ROOT (which nests the org under an "organization" key alongside teams
// and counts), a child carries the org's fields INLINE (flattened) plus its own
// recursive `children`. Modelling children as OrgHierarchyResponse (the pre-v0.11.0
// bug) dropped every child's org fields, since they were looked for under a
// non-existent "organization" sub-key. Mirrors goauth childOrgOut
// (orgs/hierarchy.go:24-27: embedded orgResponse + children).
type OrgHierarchyChild struct {
	OrgInfo
	Children []OrgHierarchyChild `json:"children,omitempty"`
}

// HierarchyTeam is one team inside an organization in a hierarchy response.
type HierarchyTeam struct {
	ID      string          `json:"id,omitempty"`
	Type    string          `json:"type,omitempty"`
	Members []HierarchyUser `json:"members,omitempty"`
}

// HierarchyUser is one user inside a team in a hierarchy response.
type HierarchyUser struct {
	ID   string `json:"id,omitempty"`
	Type string `json:"type,omitempty"`
	Role string `json:"role,omitempty"`
}

// WalkOrgTree visits every organization in the hierarchy depth-first, including
// the root (depth 0), calling fn with that node's OrgInfo and its depth.
//
// Provided because "how many companies are under this one" and "flatten the tree
// for an audit" are the two things every caller does with this response, and both
// are recursive — which is exactly the code people get subtly wrong. The callback
// receives *OrgInfo (uniform across root and children) — the root's Organization
// and each child's inline org — since the root and child wire shapes differ.
func (r *OrgHierarchyResponse) WalkOrgTree(fn func(org *OrgInfo, depth int)) {
	if r == nil {
		return
	}
	fn(r.Organization, 0)
	var walk func(kids []OrgHierarchyChild, depth int)
	walk = func(kids []OrgHierarchyChild, depth int) {
		for i := range kids {
			fn(&kids[i].OrgInfo, depth)
			walk(kids[i].Children, depth+1)
		}
	}
	walk(r.Children, 1)
}

// OrgMember is one organization membership entry as returned by
// GET /organizations/{org_id}/users. The endpoint returns a BARE JSON array of
// these objects (not an envelope), so ListOrgUsers decodes into []OrgMember.
// Fields mirror the goauth orgUserResponse handler struct
// (goauth/internal/httpapi/orgs/members.go). Note the member-scoped grants are
// carried on org_permissions (NOT permissions).
type OrgMember struct {
	ID             string         `json:"id,omitempty"`
	UserID         string         `json:"user_id"`
	Email          string         `json:"email,omitempty"`
	Name           string         `json:"name,omitempty"`
	ProviderType   string         `json:"provider_type,omitempty"`
	Role           string         `json:"role,omitempty"`
	Status         string         `json:"status,omitempty"`
	EmailVerified  bool           `json:"email_verified,omitempty"`
	Phone          string         `json:"phone,omitempty"`
	AvatarURL      string         `json:"avatar_url,omitempty"`
	Timezone       string         `json:"timezone,omitempty"`
	Language       string         `json:"language,omitempty"`
	LastLogin      string         `json:"last_login,omitempty"`
	CreatedAt      string         `json:"created_at,omitempty"`
	UpdatedAt      string         `json:"updated_at,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	OrgID          string         `json:"org_id,omitempty"`
	TeamID         string         `json:"team_id,omitempty"`
	JoinedAt       string         `json:"joined_at,omitempty"`
	OrgPermissions []string       `json:"org_permissions,omitempty"`
}

// RoleUpdateResponse is the result of changing a member's role.
type RoleUpdateResponse struct {
	Message string `json:"message,omitempty"`
	UserID  string `json:"user_id,omitempty"`
	Role    string `json:"role,omitempty"`
}

// OrgRoleUpdate is the body for PUT /organizations/{org_id}/users/{user_id}. The
// handler reads ONLY role (goauth updateRoleRequest, orgs/members.go:133-135), so
// the pre-v0.11.0 Permissions field was silently ignored (a member's permissions
// are set via the invite or team, not this role update) and has been removed.
type OrgRoleUpdate struct {
	Role string `json:"role,omitempty"`
}

// OrganizationInvite is the body for POST /organizations/{org_id}/invite. Fields
// mirror the goauth inviteRequest handler struct (orgs/invitations.go:25-31): a
// SINGLE team_id (not team_ids), plus per-invite permissions. The API accepts no
// `resend` flag (re-sends are deduped server-side), so it was removed.
type OrganizationInvite struct {
	Email string `json:"email"`
	Role  string `json:"role,omitempty"`
	// TeamID assigns the invitee to a team on join (the API applies exactly one).
	TeamID string `json:"team_id,omitempty"`
	// Permissions grants member-scoped permissions on join.
	Permissions []string `json:"permissions,omitempty"`
	Message     string   `json:"message,omitempty"`
}

// InviteResult is the result of POST /organizations/{org_id}/invite. The endpoint
// returns one of two shapes: for a NEW invitee, {message, invitation_id,
// invitation_code, expires_at} — InvitationCode is what the invitee redeems via
// RegisterRequest.InvitationCode; for an EXISTING user (added directly), {message,
// user_id}. Both are folded here (unset fields stay empty).
type InviteResult struct {
	Message        string `json:"message,omitempty"`
	InvitationID   string `json:"invitation_id,omitempty"`
	InvitationCode string `json:"invitation_code,omitempty"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	UserID         string `json:"user_id,omitempty"`
}

// InvitationListItem is one entry from GET /organizations/{org_id}/invitations.
type InvitationListItem struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	Role        string   `json:"role,omitempty"`
	Status      string   `json:"status,omitempty"`
	InvitedBy   string   `json:"invited_by,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	TeamID      string   `json:"team_id,omitempty"`
	CreatedAt   string   `json:"created_at,omitempty"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
	UsedAt      string   `json:"used_at,omitempty"`
	CancelledAt string   `json:"cancelled_at,omitempty"`
}

// OrgSession is one active session row. Field names mirror the goauth orgSession
// handler struct (orgs/sessions.go:31-41): the id is on session_id (NOT id), the
// last-activity time is last_accessed (NOT last_seen_at), and the API does NOT
// return an expiry on this listing. It also carries the user's email/name.
type OrgSession struct {
	SessionID    string `json:"session_id"`
	UserID       string `json:"user_id"`
	UserEmail    string `json:"user_email,omitempty"`
	UserName     string `json:"user_name,omitempty"`
	IPAddress    string `json:"ip_address,omitempty"`
	UserAgent    string `json:"user_agent,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
	LastAccessed string `json:"last_accessed,omitempty"`
}

// OrgSessionsResponse is the result of GET /organizations/{org_id}/sessions.
// The count is on total_sessions (NOT total), and the org id is echoed.
type OrgSessionsResponse struct {
	OrganizationID string       `json:"organization_id,omitempty"`
	Sessions       []OrgSession `json:"sessions"`
	TotalSessions  int          `json:"total_sessions,omitempty"`
}

// SessionRevokeResponse is the result of revoking a user's org sessions. The count
// is on sessions_revoked (goauth sessionRevokeResponse, orgs/sessions.go:121-124).
type SessionRevokeResponse struct {
	Message         string `json:"message,omitempty"`
	SessionsRevoked int    `json:"sessions_revoked,omitempty"`
}

// ===================== Models: teams =====================

// Team is a team/group within an organization.
type Team struct {
	ID           string          `json:"id"`
	OrgID        string          `json:"org_id,omitempty"`
	Name         string          `json:"name"`
	Slug         string          `json:"slug,omitempty"`
	Description  string          `json:"description,omitempty"`
	ParentID     string          `json:"parent_id,omitempty"`
	MemberCount  int             `json:"member_count,omitempty"`
	Metadata     map[string]any  `json:"metadata,omitempty"`
	CreatedAt    string          `json:"created_at,omitempty"`
	ParentTeamID string          `json:"parent_team_id,omitempty"`
	Permissions  []string        `json:"permissions,omitempty"`
	Settings     json.RawMessage `json:"settings,omitempty"`
	UpdatedAt    string          `json:"updated_at,omitempty"`
}

// TeamCreate is the body for POST /organizations/{org_id}/teams.
type TeamCreate struct {
	Name        string         `json:"name"`
	Slug        string         `json:"slug,omitempty"`
	Description string         `json:"description,omitempty"`
	ParentID    string         `json:"parent_id,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	// Permissions sets the team's computed permissions AT CREATE — the API accepts
	// them on POST (teamCreateRequest.Permissions), so a caller need not do a
	// create-then-grant loop (impractical under the grant rate limit for large sets).
	// Read them back via GetTeamPermissions / Team.Permissions.
	Permissions []string `json:"permissions,omitempty"`
}

// TeamUpdate is the body for PUT /teams/{team_id}.
type TeamUpdate struct {
	Name        *string         `json:"name,omitempty"`
	Description *string         `json:"description,omitempty"`
	Metadata    *map[string]any `json:"metadata,omitempty"`
	// Permissions replaces the team's computed permissions (pointer: nil = leave as-is,
	// non-nil = set to exactly this set). Matches teamUpdateRequest.Permissions server-side.
	Permissions *[]string `json:"permissions,omitempty"`
}

// TeamMember is one team member entry from GET /teams/{team_id}/members. Fields
// mirror the goauth teamMemberResponse handler struct (teams/teams.go:272-278):
// {user_id, team_id, role, permissions, joined_at}. The endpoint does NOT return
// email/name (those phantom fields were dropped), the join time is joined_at (not
// added_at), and per-member permissions/team_id are now exposed.
type TeamMember struct {
	UserID      string   `json:"user_id"`
	TeamID      string   `json:"team_id,omitempty"`
	Role        string   `json:"role,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	JoinedAt    string   `json:"joined_at,omitempty"`
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
// InheritedPermissions is the union of ancestor teams' permissions (walked up the
// parent_team_id chain server-side); enterprise callers must union it with
// Permissions to compute a member's effective grants. Mirrors goauth
// teamPermissionsResponse (teams/teams.go:281-285).
type TeamPermissionsResponse struct {
	TeamID               string   `json:"team_id,omitempty"`
	Permissions          []string `json:"permissions"`
	InheritedPermissions []string `json:"inherited_permissions,omitempty"`
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
//
// The endpoint returns a BARE JSON array of member objects, so this returns a
// []OrgMember (BREAKING vs the pre-v0.11.0 *OrgUserResponse envelope, which
// hard-errored decoding the array into a struct). Supports server-side ?role=
// and ?limit= filters via optional query args on the caller's own path today;
// this convenience method fetches the full list.
func (c *Client) ListOrgUsers(ctx context.Context, orgID, callerToken string) ([]OrgMember, error) {
	var out []OrgMember
	if err := c.doGet(ctx, "/organizations/"+url.PathEscape(orgID)+"/users", &out, callerToken); err != nil {
		return nil, err
	}
	return out, nil
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
// POST /organizations/{org_id}/invite. Returns an InviteResult carrying the
// invitation_code for a new invitee (BREAKING vs the pre-v0.11.0 *MessageResponse,
// which dropped the code the invitee needs to register).
func (c *Client) InviteToOrganization(ctx context.Context, orgID string, req OrganizationInvite, callerToken string) (*InviteResult, error) {
	var out InviteResult
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

// GetInvitation fetches one pending invitation.
// GET /organizations/{org_id}/invitations/{invitation_id}.
func (c *Client) GetInvitation(ctx context.Context, orgID, invitationID, callerToken string) (*InvitationListItem, error) {
	var out InvitationListItem
	if err := c.doGet(ctx, "/organizations/"+url.PathEscape(orgID)+"/invitations/"+url.PathEscape(invitationID), &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}
