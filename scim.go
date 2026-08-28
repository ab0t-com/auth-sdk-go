package authclient

import (
	"context"
	"encoding/json"
	"net/url"
)

// This file covers SCIM 2.0 (RFC 7643/7644) user and group provisioning.
// Requires an auth-service deployment that provides the SCIM surface; these
// endpoints return 404 where SCIM is not enabled. SCIM requests/responses use
// the SCIM schema shapes below (sent as application/json).

// ---- SCIM models ----

// ScimName is the SCIM name sub-attribute.
type ScimName struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
}

// ScimEmail is one entry in a SCIM user's emails.
type ScimEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// ScimMeta is the SCIM resource metadata block.
type ScimMeta struct {
	ResourceType string `json:"resourceType,omitempty"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
	Version      string `json:"version,omitempty"`
}

// ScimUser is a SCIM 2.0 User resource.
type ScimUser struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id,omitempty"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	Active      bool        `json:"active"`
	DisplayName string      `json:"displayName,omitempty"`
	Name        *ScimName   `json:"name,omitempty"`
	Emails      []ScimEmail `json:"emails,omitempty"`
	Meta        *ScimMeta   `json:"meta,omitempty"`
}

// ScimGroupMember is one member reference in a SCIM group.
type ScimGroupMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// ScimGroup is a SCIM 2.0 Group resource.
type ScimGroup struct {
	Schemas     []string          `json:"schemas"`
	ID          string            `json:"id,omitempty"`
	ExternalID  string            `json:"externalId,omitempty"`
	DisplayName string            `json:"displayName"`
	Members     []ScimGroupMember `json:"members,omitempty"`
	Meta        *ScimMeta         `json:"meta,omitempty"`
}

// ScimPatchOperation is one operation in a SCIM PatchOp (op is add/remove/replace).
type ScimPatchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value,omitempty"`
}

// ScimPatchRequest is a SCIM PatchOp body (urn:ietf:params:scim:api:messages:2.0:PatchOp).
type ScimPatchRequest struct {
	Schemas    []string             `json:"schemas"`
	Operations []ScimPatchOperation `json:"Operations"`
}

// ScimListResponse is a SCIM ListResponse. Resources is left as raw JSON so the
// caller decodes it into the concrete resource type (ScimUser/ScimGroup/...).
type ScimListResponse struct {
	Schemas      []string        `json:"schemas"`
	TotalResults int             `json:"totalResults"`
	StartIndex   int             `json:"startIndex"`
	ItemsPerPage int             `json:"itemsPerPage"`
	Resources    json.RawMessage `json:"Resources"`
}

// ---- SCIM users ----

// ListScimUsers lists SCIM users. GET /scim/v2/Users.
func (c *Client) ListScimUsers(ctx context.Context, callerToken string) (*ScimListResponse, error) {
	var out ScimListResponse
	if err := c.doGet(ctx, "/scim/v2/Users", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateScimUser provisions a SCIM user. POST /scim/v2/Users.
func (c *Client) CreateScimUser(ctx context.Context, u ScimUser, callerToken string) (*ScimUser, error) {
	var out ScimUser
	if err := c.doJSON(ctx, "POST", "/scim/v2/Users", u, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetScimUser fetches one SCIM user. GET /scim/v2/Users/{id}.
func (c *Client) GetScimUser(ctx context.Context, id, callerToken string) (*ScimUser, error) {
	var out ScimUser
	if err := c.doGet(ctx, "/scim/v2/Users/"+url.PathEscape(id), &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ReplaceScimUser replaces a SCIM user (PUT semantics). PUT /scim/v2/Users/{id}.
func (c *Client) ReplaceScimUser(ctx context.Context, id string, u ScimUser, callerToken string) (*ScimUser, error) {
	var out ScimUser
	if err := c.doJSON(ctx, "PUT", "/scim/v2/Users/"+url.PathEscape(id), u, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// PatchScimUser applies a SCIM PatchOp to a user. PATCH /scim/v2/Users/{id}.
func (c *Client) PatchScimUser(ctx context.Context, id string, req ScimPatchRequest, callerToken string) (*ScimUser, error) {
	var out ScimUser
	if err := c.doJSON(ctx, "PATCH", "/scim/v2/Users/"+url.PathEscape(id), req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteScimUser deprovisions a SCIM user. DELETE /scim/v2/Users/{id} (204).
func (c *Client) DeleteScimUser(ctx context.Context, id, callerToken string) error {
	return c.doJSON(ctx, "DELETE", "/scim/v2/Users/"+url.PathEscape(id), nil, nil, callerToken)
}

// ---- SCIM groups ----

// ListScimGroups lists SCIM groups. GET /scim/v2/Groups.
func (c *Client) ListScimGroups(ctx context.Context, callerToken string) (*ScimListResponse, error) {
	var out ScimListResponse
	if err := c.doGet(ctx, "/scim/v2/Groups", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateScimGroup provisions a SCIM group. POST /scim/v2/Groups.
func (c *Client) CreateScimGroup(ctx context.Context, g ScimGroup, callerToken string) (*ScimGroup, error) {
	var out ScimGroup
	if err := c.doJSON(ctx, "POST", "/scim/v2/Groups", g, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetScimGroup fetches one SCIM group. GET /scim/v2/Groups/{id}.
func (c *Client) GetScimGroup(ctx context.Context, id, callerToken string) (*ScimGroup, error) {
	var out ScimGroup
	if err := c.doGet(ctx, "/scim/v2/Groups/"+url.PathEscape(id), &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ReplaceScimGroup replaces a SCIM group. PUT /scim/v2/Groups/{id}.
func (c *Client) ReplaceScimGroup(ctx context.Context, id string, g ScimGroup, callerToken string) (*ScimGroup, error) {
	var out ScimGroup
	if err := c.doJSON(ctx, "PUT", "/scim/v2/Groups/"+url.PathEscape(id), g, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// PatchScimGroup applies a SCIM PatchOp to a group. PATCH /scim/v2/Groups/{id}.
func (c *Client) PatchScimGroup(ctx context.Context, id string, req ScimPatchRequest, callerToken string) (*ScimGroup, error) {
	var out ScimGroup
	if err := c.doJSON(ctx, "PATCH", "/scim/v2/Groups/"+url.PathEscape(id), req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteScimGroup deletes a SCIM group. DELETE /scim/v2/Groups/{id} (204).
func (c *Client) DeleteScimGroup(ctx context.Context, id, callerToken string) error {
	return c.doJSON(ctx, "DELETE", "/scim/v2/Groups/"+url.PathEscape(id), nil, nil, callerToken)
}

// ---- SCIM discovery ----

// ScimSchemas returns the supported SCIM schemas. GET /scim/v2/Schemas.
func (c *Client) ScimSchemas(ctx context.Context, callerToken string) (*ScimListResponse, error) {
	var out ScimListResponse
	if err := c.doGet(ctx, "/scim/v2/Schemas", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ScimResourceTypes returns the SCIM resource types. GET /scim/v2/ResourceTypes.
func (c *Client) ScimResourceTypes(ctx context.Context, callerToken string) (*ScimListResponse, error) {
	var out ScimListResponse
	if err := c.doGet(ctx, "/scim/v2/ResourceTypes", &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ScimServiceProviderConfig returns the SCIM ServiceProviderConfig document.
// GET /scim/v2/ServiceProviderConfig. Shape is deployment-defined, so it is
// returned as raw JSON.
func (c *Client) ScimServiceProviderConfig(ctx context.Context, callerToken string) (json.RawMessage, error) {
	var out json.RawMessage
	if err := c.doGet(ctx, "/scim/v2/ServiceProviderConfig", &out, callerToken); err != nil {
		return nil, err
	}
	return out, nil
}
