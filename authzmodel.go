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
// SERVER STATUS (re-verified against goauth
// internal/httpapi/zanzibarhttp/authmodels.go + zanzibarhttp.go:160-162 on
// 2026-09-07):
//
// Authorization-MODEL management IS now implemented by the auth service (ticket
// 20260901_zanzibar_surface_completion) at:
//   - CreateAuthModel  POST /zanzibar/stores/{store_id}/authorization-models
//   - ListAuthModels   GET  /zanzibar/stores/{store_id}/authorization-models
//   - GetAuthModel     GET  /zanzibar/stores/{store_id}/authorization-models/{id}
//
// The wire shapes are TYPE-DEFINITION based (no DSL): the POST body is a FLAT
// {schema_version, type_definitions} (NOT wrapped in "model"); the GET-one
// response nests the model under "authorization_model"; the list response keys on
// "authorization_models" (summaries: id/schema_version/created_at, no
// type_definitions). The methods below match those shapes. The DSL field on
// AuthorizationModel is retained for callers that author in DSL, but this endpoint
// neither accepts nor returns DSL today — supply TypeDefinitions.
//
// Atomic write+delete: WriteAndDeleteRelationships now targets the REAL batch route
// POST .../write with the {writes,deletes} of {object,relation,subject} body (goauth
// zanzibarhttp/transact.go); the old .../relationships/transact path never existed.
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
// evaluate against. Supply TypeDefinitions: the server stores/returns the
// structured form and derives a version id. DSL is retained for callers that
// author in OpenFGA text, but the authorization-models endpoint neither accepts
// nor returns DSL today — a DSL-only model (empty TypeDefinitions) is rejected
// 400 "type_definitions is required".
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
// It carries a Model for caller ergonomics, but marshals to the FLAT wire shape
// the server decodes ({schema_version, type_definitions}) — NOT a {model:{...}}
// envelope (the pre-v0.11.0 wrapper made the server see empty type_definitions
// and 400 "type_definitions is required"). DSL is not sent (the endpoint is
// type_definitions-only today).
type WriteAuthorizationModelRequest struct {
	Model AuthorizationModel `json:"-"`
}

// MarshalJSON flattens the request to the server's decode shape.
func (r WriteAuthorizationModelRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SchemaVersion   string           `json:"schema_version,omitempty"`
		TypeDefinitions []map[string]any `json:"type_definitions"`
	}{
		SchemaVersion:   r.Model.SchemaVersion,
		TypeDefinitions: r.Model.TypeDefinitions,
	})
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

// ListAuthorizationModelsResponse lists model versions, newest first. The server
// returns SUMMARIES (id / schema_version / created_at — no type_definitions) under
// the "authorization_models" key, and does NOT paginate (no continuation token).
type ListAuthorizationModelsResponse struct {
	Models []AuthorizationModelResponse `json:"authorization_models"`
}

// WriteAuthorizationModel registers an authorization model (object types,
// relations, userset rewrites, wildcards) as a new immutable version and returns
// its id. Requires zanzibar.admin. Supply req.Model.TypeDefinitions (the endpoint
// is type_definitions-only; a DSL-only model is 400-rejected).
// POST /zanzibar/stores/{store_id}/authorization-models  (201 Created).
func (c *Client) WriteAuthorizationModel(ctx context.Context, storeID string, req WriteAuthorizationModelRequest, callerToken string) (*WriteAuthorizationModelResponse, error) {
	var out WriteAuthorizationModelResponse
	if err := c.doJSON(ctx, "POST", zanzibarBase(storeID)+"/authorization-models", req, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ReadAuthorizationModel fetches a single model version by id, with its full
// type_definitions. Pass modelID == "" or "latest" to resolve the store's newest
// model (the server has no "latest" alias, so this lists newest-first and reads
// the top id). Returns an ErrNotFound-typed error when the store has no models.
// GET /zanzibar/stores/{store_id}/authorization-models/{authorization_model_id}.
func (c *Client) ReadAuthorizationModel(ctx context.Context, storeID, modelID, callerToken string) (*AuthorizationModelResponse, error) {
	if modelID == "" || modelID == "latest" {
		list, err := c.ListAuthorizationModels(ctx, storeID, "", callerToken)
		if err != nil {
			return nil, err
		}
		if len(list.Models) == 0 {
			return nil, &APIError{StatusCode: 404, Method: "GET",
				Endpoint: zanzibarBase(storeID) + "/authorization-models",
				Message:  "no authorization models in store"}
		}
		modelID = list.Models[0].AuthorizationModelID // newest-first
	}
	path := zanzibarBase(storeID) + "/authorization-models/" + url.PathEscape(modelID)
	// The server nests the model under "authorization_model".
	var wrapper struct {
		AuthorizationModel AuthorizationModelResponse `json:"authorization_model"`
	}
	if err := c.doGet(ctx, path, &wrapper, callerToken); err != nil {
		return nil, err
	}
	return &wrapper.AuthorizationModel, nil
}

// ListAuthorizationModels lists a store's model versions (newest first). The
// pageToken arg is accepted for forward-compatibility but the server does not
// paginate this endpoint today (it returns the full summary list).
// GET /zanzibar/stores/{store_id}/authorization-models.
func (c *Client) ListAuthorizationModels(ctx context.Context, storeID, pageToken, callerToken string) (*ListAuthorizationModelsResponse, error) {
	path := zanzibarBase(storeID) + "/authorization-models"
	var out ListAuthorizationModelsResponse
	if err := c.doGet(ctx, path, &out, callerToken); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Authorization-model assertions (model testing) ----
//
// Assertions pin expected Check outcomes to a model version so a schema change can
// be regression-tested (OpenFGA-style). Wire shapes mirror goauth
// zanzibarhttp/assertions.go:39-70.

// AssertionTupleKey is the (object, relation, user) a model assertion checks.
type AssertionTupleKey struct {
	Object   string `json:"object"`
	Relation string `json:"relation"`
	User     string `json:"user"`
}

// ModelAssertion is one stored assertion: the tuple and the expected Check result.
type ModelAssertion struct {
	TupleKey    AssertionTupleKey `json:"tuple_key"`
	Expectation bool              `json:"expectation"`
}

// PutAssertionsRequest is the body for PUT .../assertions/{model_id}.
type PutAssertionsRequest struct {
	Assertions []ModelAssertion `json:"assertions"`
}

// AssertionsResponse is the result of GET .../assertions/{model_id}.
type AssertionsResponse struct {
	AuthorizationModelID string           `json:"authorization_model_id"`
	Assertions           []ModelAssertion `json:"assertions"`
}

// AssertionResult is one assertion's outcome after running it through Check.
type AssertionResult struct {
	TupleKey    AssertionTupleKey `json:"tuple_key"`
	Expectation bool              `json:"expectation"`
	Got         bool              `json:"got"`
	Passed      bool              `json:"passed"`
	Reason      string            `json:"reason,omitempty"`
}

// AssertionsRunResponse is the result of POST .../assertions/{model_id}/run:
// Passed is the AND of every result's Passed.
type AssertionsRunResponse struct {
	AuthorizationModelID string            `json:"authorization_model_id"`
	Passed               bool              `json:"passed"`
	Results              []AssertionResult `json:"results"`
}

// PutModelAssertions stores the assertion set for a model version (replaces any
// existing set). Requires zanzibar.admin.
// PUT /zanzibar/stores/{store_id}/assertions/{model_id}.
func (c *Client) PutModelAssertions(ctx context.Context, storeID, modelID string, req PutAssertionsRequest, token string) (*MessageResponse, error) {
	var out MessageResponse
	path := zanzibarBase(storeID) + "/assertions/" + url.PathEscape(modelID)
	if err := c.doJSON(ctx, "PUT", path, req, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetModelAssertions returns the stored assertions for a model version.
// GET /zanzibar/stores/{store_id}/assertions/{model_id}.
func (c *Client) GetModelAssertions(ctx context.Context, storeID, modelID, token string) (*AssertionsResponse, error) {
	var out AssertionsResponse
	path := zanzibarBase(storeID) + "/assertions/" + url.PathEscape(modelID)
	if err := c.doGet(ctx, path, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// RunModelAssertions evaluates every stored assertion through Check and returns
// pass/fail per assertion (Passed is true only if all pass).
// POST /zanzibar/stores/{store_id}/assertions/{model_id}/run.
func (c *Client) RunModelAssertions(ctx context.Context, storeID, modelID, token string) (*AssertionsRunResponse, error) {
	var out AssertionsRunResponse
	path := zanzibarBase(storeID) + "/assertions/" + url.PathEscape(modelID) + "/run"
	if err := c.doJSON(ctx, "POST", path, nil, &out, token); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Atomic write + delete ----

// TransactRelationshipsRequest writes and deletes tuples in ONE atomic
// (all-or-nothing) transaction — e.g. re-parenting an object requires deleting the
// old edge and writing the new one together. Each tuple is a RelationshipRequest
// for ergonomic consistency with the single-write API, but the transact endpoint's
// wire tuple is ONLY {object, relation, subject}: RelationshipRequest.Context and
// .ExpiresAt are NOT supported on a transact write (they are dropped on the wire by
// this type's MarshalJSON, so they can never be silently half-applied) — use
// WriteRelationships for an expiring or contextual grant.
type TransactRelationshipsRequest struct {
	Writes  []RelationshipRequest `json:"writes,omitempty"`
	Deletes []RelationshipRequest `json:"deletes,omitempty"`
}

// MarshalJSON emits the exact transact wire shape (goauth transactRequestBody /
// transactTupleWire, zanzibarhttp/transact.go:27-35): writes/deletes of
// {object, relation, subject} only.
func (r TransactRelationshipsRequest) MarshalJSON() ([]byte, error) {
	type tuple struct {
		Object   string `json:"object"`
		Relation string `json:"relation"`
		Subject  string `json:"subject"`
	}
	conv := func(in []RelationshipRequest) []tuple {
		out := make([]tuple, len(in))
		for i, t := range in {
			out[i] = tuple{Object: t.Object, Relation: t.Relation, Subject: t.Subject}
		}
		return out
	}
	return json.Marshal(struct {
		Writes  []tuple `json:"writes"`
		Deletes []tuple `json:"deletes"`
	}{Writes: conv(r.Writes), Deletes: conv(r.Deletes)})
}

// TransactResponse is the result of the atomic write+delete (goauth transactResponse,
// zanzibarhttp/transact.go:38-43): how many tuples were written/deleted plus the
// consistency token for read-after-write.
type TransactResponse struct {
	Success          bool   `json:"success"`
	Message          string `json:"message,omitempty"`
	Written          int    `json:"written"`
	Deleted          int    `json:"deleted"`
	ConsistencyToken string `json:"consistency_token,omitempty"`
}

// WriteAndDeleteRelationships applies writes and deletes atomically and returns the
// counts + consistency token (TransactResponse.ConsistencyToken) for read-after-write.
// Requires zanzibar write-authority on each targeted object.
// POST /zanzibar/stores/{store_id}/write.
//
// (BREAKING vs pre-v0.11.0: the method used to POST to a NON-EXISTENT
// .../relationships/transact path — which 404'd — and returned WriteOperationResponse.)
func (c *Client) WriteAndDeleteRelationships(ctx context.Context, storeID string, req TransactRelationshipsRequest, token string) (*TransactResponse, error) {
	var out TransactResponse
	if err := c.doJSON(ctx, "POST", zanzibarBase(storeID)+"/write", req, &out, token); err != nil {
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

// readTupleKey filters a POST .../read by any combination of object, relation,
// and user (subject); an empty field is omitted so the server applies no filter
// on it. This is the by-subject/by-object tuple index the CLI's `read` verb uses.
type readTupleKey struct {
	Object   string `json:"object,omitempty"`
	Relation string `json:"relation,omitempty"`
	User     string `json:"user,omitempty"`
}

// readTuplesRequest is the body for POST .../read: a filter plus optional cursor.
type readTuplesRequest struct {
	TupleKey          readTupleKey `json:"tuple_key"`
	PageSize          int          `json:"page_size,omitempty"`
	ContinuationToken string       `json:"continuation_token,omitempty"`
}

// subjectTuple is one stored tuple (object#relation@user) returned by a read,
// including the grant's optional created/expiry timestamps.
type subjectTuple struct {
	Object    string
	Relation  string
	User      string
	CreatedAt string
	ExpiresAt string
}

// SubjectRelationship is one tuple a subject holds, as returned by
// ReadRelationshipsForSubject. ExpiresAt (empty when the grant never lapses) lets
// break-glass / GDPR-offboarding audits see WHEN each grant expires — consistent
// with RelationshipEntry.ExpiresAt on the by-object read path.
type SubjectRelationship struct {
	Object    string `json:"object"`
	Relation  string `json:"relation"`
	Subject   string `json:"user"`
	CreatedAt string `json:"created_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// readTuplesResponse is the wire shape of POST .../read: a page of tuples plus a
// continuation_token (empty on the last page). Each tuple carries the grant's
// timestamp (created) and expires_at (goauth readTupleEntry, zanzibarhttp/read.go:56-63).
type readTuplesResponse struct {
	Tuples []struct {
		Key struct {
			Object   string `json:"object"`
			Relation string `json:"relation"`
			User     string `json:"user"`
		} `json:"key"`
		Timestamp *string `json:"timestamp"`
		ExpiresAt *string `json:"expires_at"`
	} `json:"tuples"`
	ContinuationToken string `json:"continuation_token"`
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ReadRelationshipsForSubject returns EVERY tuple whose subject == (subjectType,
// subjectID), across all pages, including each grant's expires_at — the read
// primitive for auditing what a user/agent can do before offboarding them
// (GDPR erasure, employee departure, break-glass review). Requires zanzibar.read.
// POST /zanzibar/stores/{store_id}/read (filtered to user == subject).
func (c *Client) ReadRelationshipsForSubject(ctx context.Context, storeID, subjectType, subjectID, token string) ([]SubjectRelationship, error) {
	tuples, err := c.readAllTuplesForSubject(ctx, storeID, Subject(subjectType, subjectID), token)
	if err != nil {
		return nil, err
	}
	out := make([]SubjectRelationship, 0, len(tuples))
	for _, t := range tuples {
		out = append(out, SubjectRelationship{
			Object: t.Object, Relation: t.Relation, Subject: t.User,
			CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
		})
	}
	return out, nil
}

// readAllTuplesForSubject cursor-paginates POST .../read filtered to user ==
// subject, collecting every tuple the subject appears in across all pages.
func (c *Client) readAllTuplesForSubject(ctx context.Context, storeID, subject, token string) ([]subjectTuple, error) {
	var all []subjectTuple
	cursor := ""
	for {
		req := readTuplesRequest{TupleKey: readTupleKey{User: subject}, ContinuationToken: cursor}
		var resp readTuplesResponse
		if err := c.doJSON(ctx, "POST", zanzibarBase(storeID)+"/read", req, &resp, token); err != nil {
			return all, err
		}
		for _, t := range resp.Tuples {
			all = append(all, subjectTuple{
				Object: t.Key.Object, Relation: t.Key.Relation, User: t.Key.User,
				CreatedAt: derefStr(t.Timestamp), ExpiresAt: derefStr(t.ExpiresAt),
			})
		}
		if resp.ContinuationToken == "" {
			return all, nil
		}
		cursor = resp.ContinuationToken
	}
}

// DeleteAllRelationshipsForSubject removes EVERY tuple whose subject ==
// (subjectType, subjectID) — the generic cleanup primitive for offboarding a
// user or agent (GDPR erasure, employee departure, tenant teardown): it erases
// every grant the subject holds across all objects. Like
// DeleteAllRelationshipsForObject it is implemented client-side (there is no
// bulk delete-by-subject server route today): it cursor-paginates POST .../read
// (filtered to user == subject) to collect the subject's tuples, deletes each
// one via DeleteRelationships — one tuple per call, because the server's
// DELETE .../relationships accepts a SINGLE tuple — then re-reads from the start
// after draining, so it is idempotent and safe to retry. Requires
// zanzibar.admin. Returns the total number of tuples deleted.
func (c *Client) DeleteAllRelationshipsForSubject(ctx context.Context, storeID, subjectType, subjectID, token string) (int, error) {
	subject := Subject(subjectType, subjectID)
	total := 0
	for {
		tuples, err := c.readAllTuplesForSubject(ctx, storeID, subject, token)
		if err != nil {
			return total, err
		}
		if len(tuples) == 0 {
			return total, nil
		}
		for _, t := range tuples {
			req := RelationshipRequest{Object: t.Object, Relation: t.Relation, Subject: t.User}
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
// Provide model.TypeDefinitions: the endpoint is type_definitions-only, so a
// DSL-only model cannot be written (400) and cannot be compared for equivalence
// (the server never returns DSL) — such a model is always treated as changed.
// Use TypeDefinitions for reliable idempotency.
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
