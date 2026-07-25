package authclient

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// This file implements the Zanzibar ReBAC surface of the auth service
// (/zanzibar/stores/{store_id}/...): relationship tuples, check/expand/list,
// namespaces, hierarchy, team membership, visualization, migration, watch, plus
// the public /auth/check-permission endpoint.
//
// CONTRACT (source of truth: the live auth service OpenAPI 3.1 at
// https://auth.service.ab0t.com/openapi.json, verified 2026-07-12): the Zanzibar
// wire model uses COMBINED typed-string ids — `object` / `subject` like
// "calendar:123", "user:bob" — and `relation` (for tuples) / `permission` (for
// checks). RelationshipRequest is a SINGLE tuple, NOT a {relationships:[...]}
// batch, and reads return RelationshipEntry / RelationshipsResponse. Do NOT
// confuse this with the account/RBAC surface (/permissions/check,
// PermissionCheckRequest{user_id,...}) — that is a different user/resource model.

// Object builds a combined Zanzibar object/subject id ("type:id"), e.g.
// Object("calendar", "123") == "calendar:123". Subject is an alias for the same
// shape (e.g. Subject("user", "bob") == "user:bob").
func Object(typ, id string) string { return typ + ":" + id }

// Subject builds a combined Zanzibar subject id ("type:id"), e.g.
// Subject("user", "bob") == "user:bob". Userset subjects append "#relation"
// yourself, e.g. Subject("group", "eng")+"#member".
func Subject(typ, id string) string { return typ + ":" + id }

// ---- Zanzibar relationship tuple ----

// RelationshipRequest is a SINGLE relationship tuple: object#relation@subject.
// Body for POST/DELETE /zanzibar/stores/{store_id}/relationships.
//
// Matches OpenAPI schema RelationshipRequest (required: object, relation,
// subject). Object/Subject are combined typed strings ("doc:123", "user:alice");
// build them with Object()/Subject().
type RelationshipRequest struct {
	Object    string         `json:"object"`
	Relation  string         `json:"relation"`
	Subject   string         `json:"subject"`
	Context   map[string]any `json:"context,omitempty"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
}

// RelationshipEntry is a stored relationship tuple as returned by reads.
// Matches OpenAPI schema RelationshipEntry (required: relation, subject).
// CreatedAt/ExpiresAt are left as raw strings because the server's OpenAPI types
// them as anyOf[str, date-time, null] — a plain string is a valid value.
type RelationshipEntry struct {
	Relation  string         `json:"relation"`
	Subject   string         `json:"subject"`
	Context   map[string]any `json:"context,omitempty"`
	CreatedAt string         `json:"created_at,omitempty"`
	ExpiresAt string         `json:"expires_at,omitempty"`
}

// WriteOperationResponse is the result of a tuple write/delete/grant/revoke.
// Matches OpenAPI schema WriteOperationResponse (required: success, message).
type WriteOperationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	// ConsistencyToken (a "zookie") identifies the revision this write produced.
	// Feed it back as CheckPermissionRequest.ConsistencyToken (or the *Request
	// consistency_token fields) to get a read-after-write consistent read. Empty
	// if the server issues none.
	ConsistencyToken string `json:"consistency_token,omitempty"`
}

// RelationshipsResponse lists the tuples for an object.
// Matches OpenAPI schema RelationshipsResponse (required: object).
type RelationshipsResponse struct {
	Object        string              `json:"object"`
	Relationships []RelationshipEntry `json:"relationships,omitempty"`
}

// ---- Check / expand / list ----

// CheckPermissionRequest is the body for POST /zanzibar/stores/{store_id}/check
// (and the elements of a BulkCheckRequest). Matches OpenAPI schema
// CheckPermissionRequest (required: subject, permission, object).
type CheckPermissionRequest struct {
	Subject    string         `json:"subject"`
	Permission string         `json:"permission"`
	Object     string         `json:"object"`
	OrgID      string         `json:"org_id,omitempty"`
	Context    map[string]any `json:"context,omitempty"`
	// ConsistencyToken requests a read at least as fresh as the write that
	// produced it (read-after-write). Maps to `consistency_token`.
	ConsistencyToken string `json:"consistency_token,omitempty"`
}

// CheckPermissionResponse is the result of a Zanzibar check.
// Matches OpenAPI schema CheckPermissionResponse (required: allowed).
type CheckPermissionResponse struct {
	Allowed     bool     `json:"allowed"`
	Reason      string   `json:"reason,omitempty"`
	Path        []string `json:"path,omitempty"`
	Cached      bool     `json:"cached,omitempty"`
	CheckTimeMS float64  `json:"check_time_ms,omitempty"`
}

// BulkCheckRequest is the body for POST /zanzibar/stores/{store_id}/check/bulk.
// Matches OpenAPI schema BulkCheckRequest (required: checks).
type BulkCheckRequest struct {
	Checks []CheckPermissionRequest `json:"checks"`
}

// BulkCheckResults is the result of a bulk check: one CheckPermissionResponse
// per element of the BulkCheckRequest.Checks slice, IN THE SAME ORDER.
//
// The wire shape is a bare JSON array (OpenAPI: `type: array, items:
// CheckPermissionResponse`, verified against the live spec 2026-07-25), not an
// object. An earlier release of this SDK decoded it into a struct with a
// `results` map — a documented best-effort guess made while the server had no
// declared response schema. The server has since declared one and the guess was
// wrong, which made EVERY successful bulk check return a
// json.UnmarshalTypeError to the caller. If you are upgrading from that release,
// this type and ZanzibarCheckBulk's return type both changed.
type BulkCheckResults []CheckPermissionResponse

// Allowed reports the decision for the i'th check in the request. It returns
// false for an out-of-range index rather than panicking: a short response from
// the server must fail CLOSED, never allow.
func (b BulkCheckResults) Allowed(i int) bool {
	if i < 0 || i >= len(b) {
		return false
	}
	return b[i].Allowed
}

// AllAllowed reports whether every check was allowed. An empty result set
// returns false — "nothing was checked" is not "everything is permitted".
func (b BulkCheckResults) AllAllowed() bool {
	if len(b) == 0 {
		return false
	}
	for _, r := range b {
		if !r.Allowed {
			return false
		}
	}
	return true
}

// WildcardCheckResponse is the result of GET
// /zanzibar/stores/{store_id}/check/wildcard. Matches OpenAPI schema
// WildcardCheckResponse (required: allowed).
type WildcardCheckResponse struct {
	Allowed bool `json:"allowed"`
}

// ExpandRequest is the body for POST /zanzibar/stores/{store_id}/expand.
// Matches OpenAPI schema ExpandRequest (required: permission, object).
type ExpandRequest struct {
	Permission string `json:"permission"`
	Object     string `json:"object"`
	OrgID      string `json:"org_id,omitempty"`
	MaxDepth   int    `json:"max_depth,omitempty"`
}

// ExpandResponse is the result of expanding a permission into its userset tree.
// Matches OpenAPI schema ExpandResponse (required: object, permission).
type ExpandResponse struct {
	Object      string         `json:"object"`
	Permission  string         `json:"permission"`
	Subjects    []string       `json:"subjects,omitempty"`
	UsersetTree map[string]any `json:"userset_tree,omitempty"`
}

// ListObjectsRequest is the body for POST /zanzibar/stores/{store_id}/list-objects.
// Matches OpenAPI schema ListObjectsRequest (required: subject, permission,
// object_type). MaxResults caps the result set (1..1000, server default 1000).
type ListObjectsRequest struct {
	Subject          string `json:"subject"`
	Permission       string `json:"permission"`
	ObjectType       string `json:"object_type"`
	OrgID            string `json:"org_id,omitempty"`
	MaxResults       int    `json:"max_results,omitempty"`
	ConsistencyToken string `json:"consistency_token,omitempty"`
}

// ListObjectsResponse lists the object ids a subject can access.
// Matches OpenAPI schema ListObjectsResponse (required: subject, permission,
// object_type).
type ListObjectsResponse struct {
	Objects     []string `json:"objects,omitempty"`
	Subject     string   `json:"subject"`
	Permission  string   `json:"permission"`
	ObjectType  string   `json:"object_type"`
	ResultCount int      `json:"result_count,omitempty"`
	// ContinuationToken is reserved for future use by the server (currently always
	// empty); it is NOT accepted on the request side.
	ContinuationToken string `json:"continuation_token,omitempty"`
}

// ListUsersRequest is the body for POST /zanzibar/stores/{store_id}/list-users.
// Matches OpenAPI schema ListUsersRequest (required: object, permission).
// ExpandGroups defaults to true server-side; leave nil to accept that default.
type ListUsersRequest struct {
	Object           string `json:"object"`
	Permission       string `json:"permission"`
	OrgID            string `json:"org_id,omitempty"`
	MaxResults       int    `json:"max_results,omitempty"`
	ExpandGroups     *bool  `json:"expand_groups,omitempty"`
	ConsistencyToken string `json:"consistency_token,omitempty"`
}

// ListUsersResponse lists the subject ids that can access an object.
// Matches OpenAPI schema ListUsersResponse (required: object, permission).
type ListUsersResponse struct {
	Users       []string `json:"users,omitempty"`
	Object      string   `json:"object"`
	Permission  string   `json:"permission"`
	ResultCount int      `json:"result_count,omitempty"`
	// ContinuationToken is reserved for future use (currently always empty).
	ContinuationToken string `json:"continuation_token,omitempty"`
}

// ---- Namespaces ----

// NamespaceRequest is the body for POST /zanzibar/stores/{store_id}/namespaces.
// Matches OpenAPI schema NamespaceRequest (required: name, relations,
// permissions). Relations and Permissions are the namespace's relation and
// permission (userset-rewrite) definitions.
type NamespaceRequest struct {
	Name            string         `json:"name"`
	Relations       map[string]any `json:"relations"`
	Permissions     map[string]any `json:"permissions"`
	ParentNamespace string         `json:"parent_namespace,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

// NamespaceSummary is one entry of a namespace listing.
// Matches OpenAPI schema NamespaceSummary (required: name).
type NamespaceSummary struct {
	Name            string   `json:"name"`
	Relations       []string `json:"relations,omitempty"`
	Permissions     []string `json:"permissions,omitempty"`
	ParentNamespace string   `json:"parent_namespace,omitempty"`
	Version         *int     `json:"version,omitempty"`
}

// NamespaceListResponse lists the namespaces in a store.
// Matches OpenAPI schema NamespaceListResponse.
type NamespaceListResponse struct {
	Namespaces []NamespaceSummary `json:"namespaces,omitempty"`
}

// NamespaceDetailResponse is one namespace's full definition.
// Matches OpenAPI schema NamespaceDetailResponse (required: name).
type NamespaceDetailResponse struct {
	Name            string         `json:"name"`
	Relations       map[string]any `json:"relations,omitempty"`
	Permissions     map[string]any `json:"permissions,omitempty"`
	ParentNamespace string         `json:"parent_namespace,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	Version         *int           `json:"version,omitempty"`
}

// ZanzibarMessageResponse is the generic Zanzibar message envelope.
// Matches OpenAPI schema ZanzibarMessageResponse (required: message).
type ZanzibarMessageResponse struct {
	Message string `json:"message"`
}

// ---- Zanzibar grant / revoke ----

// PermissionGrantRequest is the body for POST/DELETE
// /zanzibar/stores/{store_id}/permissions/{grant,revoke}. Matches OpenAPI schema
// PermissionGrantRequest (required: subject, permission, resource). Subject and
// Resource are combined typed strings ("user:alice", "doc:123").
//
// NOTE: this is the ZANZIBAR grant shape. The account/RBAC grant/revoke
// (/permissions/{grant,revoke}) take query parameters, not this body — see
// GrantPermission/RevokePermission in roles.go.
type PermissionGrantRequest struct {
	Subject    string         `json:"subject"`
	Permission string         `json:"permission"`
	Resource   string         `json:"resource"`
	ExpiresAt  *time.Time     `json:"expires_at,omitempty"`
	Conditions map[string]any `json:"conditions,omitempty"`
}

// ---- Hierarchy / team membership / visualization ----

// OrgHierarchyRequest is the body for POST
// /zanzibar/stores/{store_id}/hierarchy/setup. Matches OpenAPI schema
// OrgHierarchyRequest (required: org_id).
type OrgHierarchyRequest struct {
	OrgID       string `json:"org_id"`
	ParentOrgID string `json:"parent_org_id,omitempty"`
	WorkspaceID string `json:"workspace_id,omitempty"`
}

// TeamMembershipRequest is the body for POST
// /zanzibar/stores/{store_id}/teams/membership. Matches OpenAPI schema
// TeamMembershipRequest (required: user_id, team_id) — a SINGLE membership, not
// a batch.
type TeamMembershipRequest struct {
	UserID string `json:"user_id"`
	TeamID string `json:"team_id"`
	Role   string `json:"role,omitempty"`
}

// VisualizationRequest is the body for POST
// /zanzibar/stores/{store_id}/visualize/hierarchy. Matches OpenAPI schema
// VisualizationRequest (required: org_id).
type VisualizationRequest struct {
	OrgID              string `json:"org_id"`
	IncludeUsers       bool   `json:"include_users,omitempty"`
	IncludeTeams       bool   `json:"include_teams,omitempty"`
	IncludePermissions bool   `json:"include_permissions,omitempty"`
	MaxDepth           int    `json:"max_depth,omitempty"`
}

// HierarchyVisualizationResponse is a hierarchy tree node.
// Matches OpenAPI schema HierarchyVisualizationResponse (required: id). Children
// and Permissions are left generic because the OpenAPI leaves their item schema
// untyped; Users/Teams are objects.
type HierarchyVisualizationResponse struct {
	ID          string           `json:"id"`
	Type        string           `json:"type,omitempty"`
	Children    []any            `json:"children,omitempty"`
	Users       []map[string]any `json:"users,omitempty"`
	Teams       []map[string]any `json:"teams,omitempty"`
	Permissions []any            `json:"permissions,omitempty"`
}

// PermissionsVisualizationResponse is a user's permission graph.
// Matches OpenAPI schema PermissionsVisualizationResponse (required: user_id).
type PermissionsVisualizationResponse struct {
	UserID            string           `json:"user_id"`
	DirectPermissions []map[string]any `json:"direct_permissions,omitempty"`
	InheritedFrom     []map[string]any `json:"inherited_from,omitempty"`
}

// WatchStatusResponse is the result of GET
// /zanzibar/stores/{store_id}/watch/status. Matches OpenAPI schema
// WatchStatusResponse (required: available, message).
type WatchStatusResponse struct {
	Available bool   `json:"available"`
	Channel   string `json:"channel,omitempty"`
	Message   string `json:"message"`
}

// ---- Public RBAC check (auth router) ----

// CheckPermissionPublic performs a permission check via the public
// POST /auth/check-permission endpoint (no caller auth required). This is the
// account/RBAC surface: it takes PermissionCheckRequest{user_id,...}, NOT a
// Zanzibar tuple.
func (c *Client) CheckPermissionPublic(ctx context.Context, req PermissionCheckRequest) (*PermissionDecision, error) {
	var out PermissionDecision
	if err := c.doJSON(ctx, "POST", "/auth/check-permission", req, &out, ""); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Zanzibar check / expand / list ----

func zanzibarBase(storeID string) string {
	return "/zanzibar/stores/" + url.PathEscape(storeID)
}

// ZanzibarCheck performs a single permission check.
// POST /zanzibar/stores/{store_id}/check.
func (c *Client) ZanzibarCheck(ctx context.Context, storeID string, req CheckPermissionRequest, callerToken string) (*CheckPermissionResponse, error) {
	if err := req.checkTypedIDs(); err != nil {
		return nil, err
	}
	var out CheckPermissionResponse
	if err := c.doJSON(ctx, "POST", zanzibarBase(storeID)+"/check", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ZanzibarCheckBulk performs multiple checks in one call.
// POST /zanzibar/stores/{store_id}/check/bulk.
// The results are returned IN REQUEST ORDER, one per element of req.Checks;
// index them with the same offset you built the request with, or use
// BulkCheckResults.Allowed(i).
func (c *Client) ZanzibarCheckBulk(ctx context.Context, storeID string, req BulkCheckRequest, callerToken string) (BulkCheckResults, error) {
	for i, chk := range req.Checks {
		if err := chk.checkTypedIDs(); err != nil {
			// Name the offending element: a bulk request is built in a loop and
			// "check 7 is wrong" is the difference between a one-minute fix and
			// an afternoon.
			return nil, fmt.Errorf("check %d: %w", i, err)
		}
	}
	var out BulkCheckResults
	if err := c.doJSON(ctx, "POST", zanzibarBase(storeID)+"/check/bulk", req, &out, callerToken); err != nil {
		return nil, err
	}
	return out, nil
}

// ZanzibarCheckWildcard evaluates a wildcard permission check.
// GET /zanzibar/stores/{store_id}/check/wildcard. The server reads the check
// parameters from the query string (e.g. user_id, permission).
func (c *Client) ZanzibarCheckWildcard(ctx context.Context, storeID string, q url.Values, callerToken string) (*WildcardCheckResponse, error) {
	path := zanzibarBase(storeID) + "/check/wildcard"
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	var out WildcardCheckResponse
	if err := c.doGet(ctx, path, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ZanzibarExpand expands a permission into its userset tree.
// POST /zanzibar/stores/{store_id}/expand.
func (c *Client) ZanzibarExpand(ctx context.Context, storeID string, req ExpandRequest, callerToken string) (*ExpandResponse, error) {
	var out ExpandResponse
	if err := c.doJSON(ctx, "POST", zanzibarBase(storeID)+"/expand", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ZanzibarListObjects lists objects a subject can access via a permission.
// POST /zanzibar/stores/{store_id}/list-objects.
func (c *Client) ZanzibarListObjects(ctx context.Context, storeID string, req ListObjectsRequest, callerToken string) (*ListObjectsResponse, error) {
	var out ListObjectsResponse
	if err := c.doJSON(ctx, "POST", zanzibarBase(storeID)+"/list-objects", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ZanzibarListUsers lists subjects with a permission on an object.
// POST /zanzibar/stores/{store_id}/list-users.
func (c *Client) ZanzibarListUsers(ctx context.Context, storeID string, req ListUsersRequest, callerToken string) (*ListUsersResponse, error) {
	var out ListUsersResponse
	if err := c.doJSON(ctx, "POST", zanzibarBase(storeID)+"/list-users", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Tuple writes (zanzibar.admin) ----

// WriteRelationships writes a single relationship tuple (requires zanzibar.admin).
// POST /zanzibar/stores/{store_id}/relationships.
func (c *Client) WriteRelationships(ctx context.Context, storeID string, req RelationshipRequest, token string) (*WriteOperationResponse, error) {
	var out WriteOperationResponse
	if err := c.doJSON(ctx, "POST", zanzibarBase(storeID)+"/relationships", req, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteRelationships deletes a single relationship tuple (requires zanzibar.admin).
// DELETE /zanzibar/stores/{store_id}/relationships.
func (c *Client) DeleteRelationships(ctx context.Context, storeID string, req RelationshipRequest, token string) (*WriteOperationResponse, error) {
	var out WriteOperationResponse
	if err := c.doJSON(ctx, "DELETE", zanzibarBase(storeID)+"/relationships", req, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListRelationships lists the tuples for an object, optionally filtered by
// relation (pass "" for all).
// GET /zanzibar/stores/{store_id}/relationships/{object_type}/{object_id}.
func (c *Client) ListRelationships(ctx context.Context, storeID, objectType, objectID, relation, callerToken string) (*RelationshipsResponse, error) {
	path := zanzibarBase(storeID) + "/relationships/" + url.PathEscape(objectType) + "/" + url.PathEscape(objectID)
	if relation != "" {
		path += "?" + url.Values{"relation": {relation}}.Encode()
	}
	var out RelationshipsResponse
	if err := c.doGet(ctx, path, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Namespaces ----

// CreateNamespace defines a namespace (requires zanzibar.admin).
// POST /zanzibar/stores/{store_id}/namespaces.
func (c *Client) CreateNamespace(ctx context.Context, storeID string, req NamespaceRequest, callerToken string) (*ZanzibarMessageResponse, error) {
	var out ZanzibarMessageResponse
	if err := c.doJSON(ctx, "POST", zanzibarBase(storeID)+"/namespaces", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListNamespaces lists namespaces in a store.
// GET /zanzibar/stores/{store_id}/namespaces.
func (c *Client) ListNamespaces(ctx context.Context, storeID, callerToken string) (*NamespaceListResponse, error) {
	var out NamespaceListResponse
	if err := c.doGet(ctx, zanzibarBase(storeID)+"/namespaces", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetNamespace fetches one namespace definition.
// GET /zanzibar/stores/{store_id}/namespaces/{namespace_name}.
func (c *Client) GetNamespace(ctx context.Context, storeID, name, callerToken string) (*NamespaceDetailResponse, error) {
	var out NamespaceDetailResponse
	if err := c.doGet(ctx, zanzibarBase(storeID)+"/namespaces/"+url.PathEscape(name), &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Zanzibar grant / revoke ----

// ZanzibarGrant grants a permission via a relationship tuple (requires zanzibar.admin).
// POST /zanzibar/stores/{store_id}/permissions/grant.
func (c *Client) ZanzibarGrant(ctx context.Context, storeID string, req PermissionGrantRequest, callerToken string) (*WriteOperationResponse, error) {
	var out WriteOperationResponse
	if err := c.doJSON(ctx, "POST", zanzibarBase(storeID)+"/permissions/grant", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ZanzibarRevoke revokes a permission relationship (requires zanzibar.admin).
// DELETE /zanzibar/stores/{store_id}/permissions/revoke.
func (c *Client) ZanzibarRevoke(ctx context.Context, storeID string, req PermissionGrantRequest, callerToken string) (*WriteOperationResponse, error) {
	var out WriteOperationResponse
	if err := c.doJSON(ctx, "DELETE", zanzibarBase(storeID)+"/permissions/revoke", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Hierarchy / membership ----

// SetupOrgHierarchy configures org hierarchy tuples (requires zanzibar.admin).
// POST /zanzibar/stores/{store_id}/hierarchy/setup.
func (c *Client) SetupOrgHierarchy(ctx context.Context, storeID string, req OrgHierarchyRequest, callerToken string) (*ZanzibarMessageResponse, error) {
	var out ZanzibarMessageResponse
	if err := c.doJSON(ctx, "POST", zanzibarBase(storeID)+"/hierarchy/setup", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetupTeamMembership writes a team-membership tuple (requires zanzibar.admin).
// POST /zanzibar/stores/{store_id}/teams/membership.
func (c *Client) SetupTeamMembership(ctx context.Context, storeID string, req TeamMembershipRequest, callerToken string) (*ZanzibarMessageResponse, error) {
	var out ZanzibarMessageResponse
	if err := c.doJSON(ctx, "POST", zanzibarBase(storeID)+"/teams/membership", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Visualization / migration / watch ----

// VisualizeHierarchy renders an org/relationship hierarchy graph.
// POST /zanzibar/stores/{store_id}/visualize/hierarchy.
func (c *Client) VisualizeHierarchy(ctx context.Context, storeID string, req VisualizationRequest, callerToken string) (*HierarchyVisualizationResponse, error) {
	var out HierarchyVisualizationResponse
	if err := c.doJSON(ctx, "POST", zanzibarBase(storeID)+"/visualize/hierarchy", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// VisualizePermissions renders a user's permissions graph. The target user is
// passed as the `user_id` query parameter (required by the server).
// POST /zanzibar/stores/{store_id}/visualize/permissions.
func (c *Client) VisualizePermissions(ctx context.Context, storeID, userID, callerToken string) (*PermissionsVisualizationResponse, error) {
	path := zanzibarBase(storeID) + "/visualize/permissions"
	if userID != "" {
		path += "?" + url.Values{"user_id": {userID}}.Encode()
	}
	var out PermissionsVisualizationResponse
	if err := c.doJSON(ctx, "POST", path, struct{}{}, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// MigrateSetupDefaults installs default namespaces/relations (requires zanzibar.admin).
// POST /zanzibar/stores/{store_id}/migrate/setup-defaults.
func (c *Client) MigrateSetupDefaults(ctx context.Context, storeID, callerToken string) (*ZanzibarMessageResponse, error) {
	var out ZanzibarMessageResponse
	if err := c.doJSON(ctx, "POST", zanzibarBase(storeID)+"/migrate/setup-defaults", struct{}{}, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// MigratePermissions migrates a user's legacy RBAC permissions into Zanzibar
// tuples (requires zanzibar.admin). The user id and permission list are passed
// as `user_id` and repeated `permissions` query parameters (required by the
// server). POST /zanzibar/stores/{store_id}/migrate/permissions.
func (c *Client) MigratePermissions(ctx context.Context, storeID, userID string, permissions []string, callerToken string) (*ZanzibarMessageResponse, error) {
	q := url.Values{}
	if userID != "" {
		q.Set("user_id", userID)
	}
	for _, p := range permissions {
		q.Add("permissions", p)
	}
	path := zanzibarBase(storeID) + "/migrate/permissions"
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	var out ZanzibarMessageResponse
	if err := c.doJSON(ctx, "POST", path, struct{}{}, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// WatchStatus returns the change-stream/watch status for a store.
// GET /zanzibar/stores/{store_id}/watch/status.
func (c *Client) WatchStatus(ctx context.Context, storeID, callerToken string) (*WatchStatusResponse, error) {
	var out WatchStatusResponse
	if err := c.doGet(ctx, zanzibarBase(storeID)+"/watch/status", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Typed-id validation ----
//
// The Zanzibar wire model uses COMBINED typed ids — "user:alice", "doc:123" — but
// every field carrying one is a plain Go string. Nothing stops a caller passing a
// bare "alice", and the server cannot tell that apart from a legitimate id it has
// simply never seen: it answers `allowed:false` and the caller reads a deny.
//
// That is a silent, wrong DENY, and it is the exact ambiguity behind the incident
// this SDK's Zanzibar surface was rewritten to fix — the earlier model split ids
// into object_type/object_id fields, and reconciling it against the live spec was
// what surfaced how easy the untyped form is to get wrong.
//
// So the client checks before it asks. A missing type prefix is always a bug, and
// an error naming it costs one round trip less than a false deny costs to debug.

// ErrUntypedID reports an id that is missing its "type:" prefix. Build ids with
// Object() / Subject() rather than concatenating strings.
type ErrUntypedID struct {
	Field string // which request field ("subject", "object", …)
	Value string
}

func (e *ErrUntypedID) Error() string {
	return "authclient: " + e.Field + " " + strconv.Quote(e.Value) +
		` is not a typed Zanzibar id — it needs a "type:id" form such as "user:alice"; build it with Subject()/Object()`
}

// validTypedID reports whether s looks like "type:id" (and tolerates the userset
// form "group:eng#member"). It deliberately does NOT validate the type or id
// beyond non-emptiness — the server owns that vocabulary, not this client.
func validTypedID(s string) bool {
	typ, rest, ok := strings.Cut(s, ":")
	return ok && typ != "" && rest != ""
}

// checkTypedIDs validates the combined-id fields of a check request.
func (r CheckPermissionRequest) checkTypedIDs() error {
	if !validTypedID(r.Subject) {
		return &ErrUntypedID{Field: "subject", Value: r.Subject}
	}
	if !validTypedID(r.Object) {
		return &ErrUntypedID{Field: "object", Value: r.Object}
	}
	return nil
}
