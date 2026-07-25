package authclient

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"strings"
)

// This file extends the Zanzibar/ReBAC surface (see permissions.go) with
// authorization-model management, atomic write+delete transactions, cursored
// listing, and cleanup helpers. Every operation here is a generic
// Zanzibar/OpenFGA-style primitive: it makes no assumptions about any
// particular application's object types or relations. Routes follow the same
// /zanzibar/stores/{store_id}/... convention as permissions.go; where a route
// is not fixed by an existing method it uses the OpenFGA-canonical path.
//
// SERVER-GAP SUMMARY (verified against the live auth service OpenAPI on
// 2026-07-12 — https://auth.service.ab0t.com/openapi.json):
//
// The auth service exposes NO authorization-MODEL management and NO atomic
// write+delete transaction endpoint. The REAL schema-management surface is
// per-namespace: POST/GET /zanzibar/stores/{store_id}/namespaces[/{name}] (see
// CreateNamespace/ListNamespaces/GetNamespace in permissions.go), plus
// /hierarchy/setup and /migrate/setup-defaults. An "authorization model" here is
// a whole-store schema (a COLLECTION of namespaces + a DSL), which does not map
// 1:1 onto the single-namespace endpoints, so the model-management methods below
// are kept as forward-looking SERVER-GAPs rather than being re-pointed at
// /namespaces. Each is marked SERVER-GAP on its godoc and must not be relied on
// until the server implements it:
//   - WriteAuthorizationModel   (POST   .../authorization-models)            — no such path
//   - ReadAuthorizationModel    (GET    .../authorization-models/{id})       — no such path
//   - ListAuthorizationModels   (GET    .../authorization-models)            — no such path
//   - WriteAndDeleteRelationships (POST  .../relationships/transact)         — no such path
//   - EnsureAuthorizationModel  (Read+Write model helper)                    — depends on the above
//
// The list-relationships pagination is also a SERVER-GAP: the real GET
// .../relationships/{object_type}/{object_id} accepts only a `relation` query
// filter and returns {object, relationships:[]RelationshipEntry} — it has no
// page_size/continuation_token and returns no cursor. See ListRelationshipsPaged.
//
// ListObjectsPaged maps to a REAL route (POST .../list-objects) but the server
// caps results with `max_results` (not `page_size`) and has no request-side
// continuation token; see the notes on ListObjectsRequest in permissions.go.

// ---- Authorization model (type + relation + userset-rewrite schema) ----

// AuthorizationModel is a versioned authorization schema: the object types,
// their relations, and the userset rewrites (unions, computed usersets such as
// "viewer from parent", wildcards, subject-relation subjects) that checks
// evaluate against. Provide EITHER DSL (the OpenFGA/Zanzibar model text) OR
// TypeDefinitions (the equivalent structured form); the server parses whichever
// is supplied and returns the canonical form plus a version id.
//
// SERVER-GAP: authorization-model management is not part of the auth service
// OpenAPI as of 2026-07-12; these types describe a forward-looking contract.
type AuthorizationModel struct {
	// SchemaVersion is the model schema language version (e.g. "1.1").
	SchemaVersion string `json:"schema_version,omitempty"`
	// DSL is the model expressed as OpenFGA/Zanzibar model text.
	DSL string `json:"dsl,omitempty"`
	// TypeDefinitions is the structured form of the model (type -> relations ->
	// rewrites). Left generic (untyped) so any server schema shape is expressible.
	TypeDefinitions []map[string]any `json:"type_definitions,omitempty"`
}

// WriteAuthorizationModelRequest is the body for POST .../authorization-models.
type WriteAuthorizationModelRequest struct {
	Model AuthorizationModel `json:"model"`
}

// WriteAuthorizationModelResponse returns the immutable, versioned model id that
// subsequent checks and writes may pin to.
type WriteAuthorizationModelResponse struct {
	AuthorizationModelID string `json:"authorization_model_id"`
	Message              string `json:"message,omitempty"`
}

// AuthorizationModelResponse is one stored model version (read / list item).
type AuthorizationModelResponse struct {
	AuthorizationModelID string           `json:"authorization_model_id"`
	SchemaVersion        string           `json:"schema_version,omitempty"`
	TypeDefinitions      []map[string]any `json:"type_definitions,omitempty"`
	DSL                  string           `json:"dsl,omitempty"`
	CreatedAt            string           `json:"created_at,omitempty"`
}

// ListAuthorizationModelsResponse lists model versions, newest first.
type ListAuthorizationModelsResponse struct {
	Models            []AuthorizationModelResponse `json:"models"`
	ContinuationToken string                       `json:"continuation_token,omitempty"`
}

// WriteAuthorizationModel registers an authorization model (object types,
// relations, userset rewrites, wildcards) as a new immutable version and returns
// its id. Requires zanzibar.admin.
// POST /zanzibar/stores/{store_id}/authorization-models.
//
// SERVER-GAP: this endpoint does NOT exist in the auth service OpenAPI as of
// 2026-07-12 — the service has no authorization-model management (it uses
// /zanzibar/stores/{store_id}/namespaces instead). Forward-looking; will 404
// until the server implements it.
func (c *Client) WriteAuthorizationModel(ctx context.Context, storeID string, req WriteAuthorizationModelRequest, callerToken string) (*WriteAuthorizationModelResponse, error) {
	var out WriteAuthorizationModelResponse
	if err := c.doJSON(ctx, "POST", zanzibarBase(storeID)+"/authorization-models", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ReadAuthorizationModel fetches a single model version. Pass modelID == "" (or
// "latest") to read the store's latest model.
// GET /zanzibar/stores/{store_id}/authorization-models/{authorization_model_id}.
//
// SERVER-GAP: this endpoint does NOT exist in the auth service OpenAPI as of
// 2026-07-12 (no authorization-model management). Forward-looking; will 404
// until the server implements it.
func (c *Client) ReadAuthorizationModel(ctx context.Context, storeID, modelID, callerToken string) (*AuthorizationModelResponse, error) {
	if modelID == "" {
		modelID = "latest"
	}
	path := zanzibarBase(storeID) + "/authorization-models/" + url.PathEscape(modelID)
	var out AuthorizationModelResponse
	if err := c.doGet(ctx, path, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListAuthorizationModels lists a store's model versions (newest first). Pass
// pageToken == "" for the first page and the response's ContinuationToken to
// continue.
// GET /zanzibar/stores/{store_id}/authorization-models.
//
// SERVER-GAP: this endpoint does NOT exist in the auth service OpenAPI as of
// 2026-07-12 (no authorization-model management). Forward-looking; will 404
// until the server implements it.
func (c *Client) ListAuthorizationModels(ctx context.Context, storeID, pageToken, callerToken string) (*ListAuthorizationModelsResponse, error) {
	path := zanzibarBase(storeID) + "/authorization-models"
	if pageToken != "" {
		path += "?" + url.Values{"continuation_token": {pageToken}}.Encode()
	}
	var out ListAuthorizationModelsResponse
	if err := c.doGet(ctx, path, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Atomic write + delete ----

// TransactRelationshipsRequest writes and deletes tuples in ONE atomic
// (all-or-nothing) transaction — e.g. re-parenting an object requires deleting
// the old edge and writing the new one together. Each write/delete is a single
// RelationshipRequest tuple (combined `object`/`subject` strings).
type TransactRelationshipsRequest struct {
	Writes  []RelationshipRequest `json:"writes,omitempty"`
	Deletes []RelationshipRequest `json:"deletes,omitempty"`
}

// WriteAndDeleteRelationships applies writes and deletes atomically and returns
// the resulting consistency token (WriteOperationResponse.ConsistencyToken) for
// read-after-write. Requires zanzibar.admin.
// POST /zanzibar/stores/{store_id}/relationships/transact.
//
// SERVER-GAP: this endpoint does NOT exist in the auth service OpenAPI as of
// 2026-07-12 — the server exposes only separate POST and DELETE on
// /zanzibar/stores/{store_id}/relationships (no atomic combined transaction).
// Forward-looking; will 404 until the server implements it. Until then, use
// WriteRelationships + DeleteRelationships (non-atomic).
func (c *Client) WriteAndDeleteRelationships(ctx context.Context, storeID string, req TransactRelationshipsRequest, token string) (*WriteOperationResponse, error) {
	var out WriteOperationResponse
	if err := c.doJSON(ctx, "POST", zanzibarBase(storeID)+"/relationships/transact", req, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Cursored listing ----

// RelationshipsPage is the (nominally cursored) form of RelationshipsResponse.
//
// SERVER-GAP (pagination): the auth service does NOT paginate list-relationships
// (see ListRelationshipsPaged). ContinuationToken is forward-looking and always
// comes back empty from the current server. It matches RelationshipsResponse on
// the wire: {object, relationships:[]RelationshipEntry}.
type RelationshipsPage struct {
	Object            string              `json:"object"`
	Relationships     []RelationshipEntry `json:"relationships,omitempty"`
	ContinuationToken string              `json:"continuation_token,omitempty"`
}

// ListRelationshipsPaged lists the tuples whose object == (objectType, objectID),
// optionally filtered by relation (pass "" for all).
// GET /zanzibar/stores/{store_id}/relationships/{object_type}/{object_id}.
//
// SERVER-GAP (pagination): the auth service OpenAPI (verified 2026-07-12) accepts
// ONLY a `relation` query filter on this route — it does NOT accept
// page_size/continuation_token and returns the FULL (unpaged) result set
// {object, relationships:[]RelationshipEntry} with no cursor. This method is
// therefore a thin wrapper over ListRelationships; RelationshipsPage's
// ContinuationToken is always empty.
func (c *Client) ListRelationshipsPaged(ctx context.Context, storeID, objectType, objectID, relation, callerToken string) (*RelationshipsPage, error) {
	path := zanzibarBase(storeID) + "/relationships/" + url.PathEscape(objectType) + "/" + url.PathEscape(objectID)
	if relation != "" {
		path += "?" + url.Values{"relation": {relation}}.Encode()
	}
	var out RelationshipsPage
	if err := c.doGet(ctx, path, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListObjectsPaged lists the object ids a subject relates to. Set req.MaxResults
// (1..1000) to cap the result set.
// POST /zanzibar/stores/{store_id}/list-objects.
//
// SERVER-GAP (pagination): the route is REAL, but the auth service OpenAPI
// (verified 2026-07-12) caps results with `max_results` and has NO request-side
// continuation token. The response's ContinuationToken is documented as
// "reserved for future use" and currently always empty, so this method returns
// at most one (capped) page. It is retained as an alias of ZanzibarListObjects
// for callers that want the pagination-shaped name.
func (c *Client) ListObjectsPaged(ctx context.Context, storeID string, req ListObjectsRequest, callerToken string) (*ListObjectsResponse, error) {
	var out ListObjectsResponse
	if err := c.doJSON(ctx, "POST", zanzibarBase(storeID)+"/list-objects", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Bulk cleanup ----

// DeleteAllRelationshipsForObject removes EVERY tuple whose object ==
// (objectType, objectID) — the generic cleanup primitive for deleting a
// resource or erasing its relationships. It is implemented client-side as a
// ListRelationships -> DeleteRelationships loop (there is no bulk server route
// today), deleting one tuple per call because the server's
// DELETE .../relationships accepts a SINGLE tuple. It re-lists from the start
// after draining a batch, so it is idempotent and safe to retry. Requires
// zanzibar.admin. Returns the total number of tuples deleted.
func (c *Client) DeleteAllRelationshipsForObject(ctx context.Context, storeID, objectType, objectID, token string) (int, error) {
	object := Object(objectType, objectID)
	total := 0
	for {
		page, err := c.ListRelationships(ctx, storeID, objectType, objectID, "", token)
		if err != nil {
			return total, err
		}
		if len(page.Relationships) == 0 {
			return total, nil
		}
		for _, e := range page.Relationships {
			req := RelationshipRequest{Object: object, Relation: e.Relation, Subject: e.Subject}
			if _, err := c.DeleteRelationships(ctx, storeID, req, token); err != nil {
				return total, err
			}
			total++
		}
	}
}

// ---- Idempotent model apply ----

// EnsureAuthorizationModel registers model only if the store's latest model is
// not already equivalent, and returns the effective (existing-or-newly-written)
// model id. It is idempotent and safe to run on every deploy: an unchanged model
// is a no-op (changed == false), a new or differing model is written (changed ==
// true). Requires zanzibar.admin.
//
// SERVER-GAP: this helper composes ReadAuthorizationModel + WriteAuthorizationModel,
// NEITHER of which exists in the auth service OpenAPI as of 2026-07-12 (no
// authorization-model management). Forward-looking; both underlying calls will
// 404 until the server implements model management.
func (c *Client) EnsureAuthorizationModel(ctx context.Context, storeID string, model AuthorizationModel, callerToken string) (modelID string, changed bool, err error) {
	latest, rerr := c.ReadAuthorizationModel(ctx, storeID, "latest", callerToken)
	if rerr != nil && !IsNotFound(rerr) {
		return "", false, rerr
	}
	if rerr == nil && authorizationModelEquivalent(model, latest) {
		return latest.AuthorizationModelID, false, nil
	}
	written, werr := c.WriteAuthorizationModel(ctx, storeID, WriteAuthorizationModelRequest{Model: model}, callerToken)
	if werr != nil {
		return "", false, werr
	}
	return written.AuthorizationModelID, true, nil
}

// authorizationModelEquivalent reports whether want describes the same model as
// the stored have. It compares the DSL text when want provides one, otherwise
// the structured type definitions; schema versions, when both set, must match.
func authorizationModelEquivalent(want AuthorizationModel, have *AuthorizationModelResponse) bool {
	if have == nil {
		return false
	}
	if want.SchemaVersion != "" && have.SchemaVersion != "" && want.SchemaVersion != have.SchemaVersion {
		return false
	}
	if want.DSL != "" {
		return strings.TrimSpace(want.DSL) == strings.TrimSpace(have.DSL)
	}
	if len(want.TypeDefinitions) > 0 {
		wb, _ := json.Marshal(want.TypeDefinitions)
		hb, _ := json.Marshal(have.TypeDefinitions)
		return bytes.Equal(wb, hb)
	}
	return false
}
