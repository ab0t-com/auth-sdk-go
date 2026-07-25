package authclient

// mesh.go implements the /mesh service-discovery surface: the public directory
// where a service publishes itself as an ab0t mesh provider (what it is, where to
// register, which permission tiers it offers) and where a consumer discovers what
// is available.
//
// Contract source: the live ab0t Auth Service OpenAPI 3.1 at
// https://auth.service.ab0t.com/openapi.json.
//
//	GET  /mesh/providers               -> MeshProvidersListResponse
//	POST /mesh/providers               -> MeshProviderPublishResponse
//	GET  /mesh/providers/{service_id}  -> MeshProvider

import (
	"context"
	"net/url"
)

// ---- Models ----

// MeshProviderTier is one named permission tier a provider offers, as returned
// by a read. Matches OpenAPI schema MeshProviderTier (required: name).
type MeshProviderTier struct {
	Name string `json:"name"`
	// Default marks the tier a consumer gets if it does not choose one.
	Default bool `json:"default,omitempty"`
	// PermissionCount is server-computed; it is not settable on publish.
	PermissionCount int      `json:"permission_count,omitempty"`
	Permissions     []string `json:"permissions,omitempty"`
	// PrivilegedAck records that the publisher explicitly acknowledged that this
	// tier grants privileged permissions.
	PrivilegedAck bool `json:"privileged_ack,omitempty"`
}

// MeshProviderTierInput is a tier as supplied on publish. It is deliberately a
// separate type from MeshProviderTier: PermissionCount is server-computed and
// sending it is meaningless.
type MeshProviderTierInput struct {
	Name          string   `json:"name"`
	Default       bool     `json:"default,omitempty"`
	Permissions   []string `json:"permissions,omitempty"`
	PrivilegedAck bool     `json:"privileged_ack,omitempty"`
}

// MeshConsumerRegistration describes how a consumer signs up to a provider.
type MeshConsumerRegistration struct {
	Enabled     bool               `json:"enabled,omitempty"`
	OrgSlug     string             `json:"org_slug,omitempty"`
	RegisterURL string             `json:"register_url,omitempty"`
	Tiers       []MeshProviderTier `json:"tiers,omitempty"`
}

// MeshProvider is a published provider entry in the mesh directory.
// Matches OpenAPI schema MeshProvider (no required fields — the server may
// return a sparse entry, so treat every field as optional).
type MeshProvider struct {
	ServiceID            string                    `json:"service_id,omitempty"`
	DisplayName          string                    `json:"display_name,omitempty"`
	ConsumerRegistration *MeshConsumerRegistration `json:"consumer_registration,omitempty"`
	DocsURL              string                    `json:"docs_url,omitempty"`
	// ConnectPrompt is the natural-language instruction an agent can follow to
	// connect to this provider.
	ConnectPrompt string `json:"connect_prompt,omitempty"`
	SchemaURL     string `json:"schema_url,omitempty"`
	// LLMsTxtURL points at the provider's llms.txt (agent-facing description).
	LLMsTxtURL    string `json:"llms_txt_url,omitempty"`
	SupportURL    string `json:"support_url,omitempty"`
	QuickstartURL string `json:"quickstart_url,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
}

// MeshProvidersListResponse is the result of GET /mesh/providers.
type MeshProvidersListResponse struct {
	Providers []MeshProvider `json:"providers,omitempty"`
}

// MeshProviderPublishRequest is the body for POST /mesh/providers.
// Matches OpenAPI schema MeshProviderPublishRequest
// (required: service_id, display_name, register_url, org_slug).
type MeshProviderPublishRequest struct {
	ServiceID   string `json:"service_id"`
	DisplayName string `json:"display_name"`
	// RegisterURL is where a consumer goes to sign up.
	RegisterURL string `json:"register_url"`
	OrgSlug     string `json:"org_slug"`

	Tiers         []MeshProviderTierInput `json:"tiers,omitempty"`
	SignupEnabled bool                    `json:"signup_enabled,omitempty"`

	DocsURL       string `json:"docs_url,omitempty"`
	ConnectPrompt string `json:"connect_prompt,omitempty"`
	SchemaURL     string `json:"schema_url,omitempty"`
	LLMsTxtURL    string `json:"llms_txt_url,omitempty"`
	SupportURL    string `json:"support_url,omitempty"`
	QuickstartURL string `json:"quickstart_url,omitempty"`

	// PublicMesh lists the provider in the PUBLIC directory. Leaving it false
	// publishes privately.
	PublicMesh bool `json:"public_mesh,omitempty"`
	// PrivilegedPerms declares permissions the publisher knows are privileged.
	PrivilegedPerms []string `json:"privileged_perms,omitempty"`
}

// MeshProviderPublishResponse is the result of POST /mesh/providers.
// Matches OpenAPI schema MeshProviderPublishResponse (required: valid).
//
// NOTE the shape of the contract: a 200 does NOT mean "published". Valid reports
// whether the submission was accepted and Listed whether it actually appears in
// the directory; Reason carries the explanation when it does not. Always check
// Valid and Listed rather than relying on the absence of an error.
type MeshProviderPublishResponse struct {
	Valid     bool   `json:"valid"`
	ServiceID string `json:"service_id,omitempty"`
	Listed    bool   `json:"listed,omitempty"`
	Reason    string `json:"reason,omitempty"`

	// DocsURLWarning reports that the docs URL looked unreachable or malformed.
	DocsURLWarning bool `json:"docs_url_warning,omitempty"`
	// PrivilegeWarning reports that a declared tier grants privileged
	// permissions; PrivilegeViolations names them.
	PrivilegeWarning    bool     `json:"privilege_warning,omitempty"`
	PrivilegeViolations []string `json:"privilege_violations,omitempty"`
}

// ---- Operations ----

// ListMeshProviders lists providers in the mesh directory.
// GET /mesh/providers. Pass an empty callerToken for the public directory.
//
// q may carry server-supported filters; pass nil for none.
func (c *Client) ListMeshProviders(ctx context.Context, q url.Values, callerToken string) (*MeshProvidersListResponse, error) {
	path := "/mesh/providers"
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	var out MeshProvidersListResponse
	if err := c.doGet(ctx, path, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetMeshProvider fetches one provider entry by its service id.
// GET /mesh/providers/{service_id}.
func (c *Client) GetMeshProvider(ctx context.Context, serviceID, callerToken string) (*MeshProvider, error) {
	var out MeshProvider
	if err := c.doGet(ctx, "/mesh/providers/"+url.PathEscape(serviceID), &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// PublishMeshProvider publishes (or updates) this service's mesh directory entry.
// POST /mesh/providers.
//
// Check the returned Valid and Listed fields: a nil error means the request was
// accepted, NOT that the provider is listed.
func (c *Client) PublishMeshProvider(ctx context.Context, req MeshProviderPublishRequest, callerToken string) (*MeshProviderPublishResponse, error) {
	var out MeshProviderPublishResponse
	if err := c.doJSON(ctx, "POST", "/mesh/providers", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}
