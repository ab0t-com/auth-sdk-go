package authclient

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---- Authorization model management ----

// sampleTypeDefs is a realistic structured type_definitions payload.
func sampleTypeDefs() []map[string]any {
	return []map[string]any{
		{"type": "document", "relations": map[string]any{
			"viewer": map[string]any{"allowed_subject_types": []any{"user"}},
		}},
	}
}

func TestWriteAuthorizationModel(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/zanzibar/stores/store1/authorization-models" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		// The body MUST be FLAT: {schema_version, type_definitions}. A {model:{...}}
		// wrapper (the old bug) would make the server see empty type_definitions.
		var body map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if _, wrapped := body["model"]; wrapped {
			t.Errorf("body must not wrap in 'model': %v", body)
		}
		if _, ok := body["type_definitions"]; !ok {
			t.Errorf("body missing top-level type_definitions: %v", body)
		}
		if _, dsl := body["dsl"]; dsl {
			t.Errorf("body must not send phantom dsl: %v", body)
		}
		// Server returns 201 with just the id.
		writeJSON(w, 201, WriteAuthorizationModelResponse{AuthorizationModelID: "m123"})
	})
	out, err := c.WriteAuthorizationModel(context.Background(), "store1", WriteAuthorizationModelRequest{
		Model: AuthorizationModel{SchemaVersion: "1.1", TypeDefinitions: sampleTypeDefs()},
	}, "admin")
	if err != nil {
		t.Fatalf("WriteAuthorizationModel: %v", err)
	}
	if out.AuthorizationModelID != "m123" {
		t.Errorf("model id = %q", out.AuthorizationModelID)
	}
}

func TestReadAuthorizationModel(t *testing.T) {
	t.Run("explicit id (nested under authorization_model)", func(t *testing.T) {
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/zanzibar/stores/store1/authorization-models/m123" {
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			}
			// Server nests the model under "authorization_model".
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"authorization_model":{"authorization_model_id":"m123","schema_version":"1.1","type_definitions":[{"type":"document"}]}}`))
		})
		out, err := c.ReadAuthorizationModel(context.Background(), "store1", "m123", "tok")
		if err != nil {
			t.Fatalf("ReadAuthorizationModel: %v", err)
		}
		if out.AuthorizationModelID != "m123" || out.SchemaVersion != "1.1" || len(out.TypeDefinitions) != 1 {
			t.Errorf("unexpected (nested body not unwrapped?): %+v", out)
		}
	})
	t.Run("empty id resolves to latest via list->get", func(t *testing.T) {
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.URL.Path == "/zanzibar/stores/store1/authorization-models" && r.Method == http.MethodGet:
				// newest-first summaries
				_, _ = w.Write([]byte(`{"authorization_models":[{"authorization_model_id":"m2"},{"authorization_model_id":"m1"}]}`))
			case r.URL.Path == "/zanzibar/stores/store1/authorization-models/m2":
				_, _ = w.Write([]byte(`{"authorization_model":{"authorization_model_id":"m2"}}`))
			default:
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			}
		})
		out, err := c.ReadAuthorizationModel(context.Background(), "store1", "", "tok")
		if err != nil {
			t.Fatalf("ReadAuthorizationModel: %v", err)
		}
		if out.AuthorizationModelID != "m2" {
			t.Errorf("id = %q (want newest m2)", out.AuthorizationModelID)
		}
	})
}

func TestListAuthorizationModels(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zanzibar/stores/store1/authorization-models" {
			t.Errorf("path = %s", r.URL.Path)
		}
		// Server keys on "authorization_models" (NOT "models") and does not paginate.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_models":[{"authorization_model_id":"m2"},{"authorization_model_id":"m1"}]}`))
	})
	out, err := c.ListAuthorizationModels(context.Background(), "store1", "", "tok")
	if err != nil {
		t.Fatalf("ListAuthorizationModels: %v", err)
	}
	if len(out.Models) != 2 || out.Models[0].AuthorizationModelID != "m2" {
		t.Errorf("unexpected (wrong envelope key?): %+v", out)
	}
}

// ---- Atomic write + delete ----

func TestWriteAndDeleteRelationships(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		// Real route is POST .../write (NOT .../relationships/transact).
		if r.Method != http.MethodPost || r.URL.Path != "/zanzibar/stores/store1/write" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		// Wire tuple is {object, relation, subject} only — no expires_at/context leak.
		var body struct {
			Writes  []map[string]json.RawMessage `json:"writes"`
			Deletes []map[string]json.RawMessage `json:"deletes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(body.Writes) != 1 || len(body.Deletes) != 1 {
			t.Errorf("writes/deletes = %d/%d", len(body.Writes), len(body.Deletes))
		}
		for _, forbidden := range []string{"expires_at", "context"} {
			if _, bad := body.Writes[0][forbidden]; bad {
				t.Errorf("transact write leaked %q (unsupported on this endpoint)", forbidden)
			}
		}
		writeJSON(w, 200, TransactResponse{Success: true, Message: "ok", Written: 1, Deleted: 1, ConsistencyToken: "zk-42"})
	})
	future := time.Now().Add(time.Hour)
	out, err := c.WriteAndDeleteRelationships(context.Background(), "store1", TransactRelationshipsRequest{
		// ExpiresAt is set but MUST be dropped on the wire (transact doesn't support it).
		Writes:  []RelationshipRequest{{Object: "doc:new", Relation: "parent", Subject: "folder:b", ExpiresAt: &future}},
		Deletes: []RelationshipRequest{{Object: "doc:old", Relation: "parent", Subject: "folder:a"}},
	}, "admin")
	if err != nil {
		t.Fatalf("WriteAndDeleteRelationships: %v", err)
	}
	if !out.Success || out.ConsistencyToken != "zk-42" || out.Written != 1 || out.Deleted != 1 {
		t.Errorf("unexpected: %+v", out)
	}
}

// ---- Cursored listing ----

func TestListRelationshipsPaged(t *testing.T) {
	// SERVER-GAP: the route accepts only a `relation` filter and returns the full
	// (unpaged) set with no cursor.
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/zanzibar/stores/store1/relationships/doc/d1" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.URL.Query().Get("relation"); got != "viewer" {
			t.Errorf("relation = %q", got)
		}
		writeJSON(w, 200, RelationshipsPage{
			Object:        "doc:d1",
			Relationships: []RelationshipEntry{{Relation: "viewer", Subject: "user:u1"}},
		})
	})
	out, err := c.ListRelationshipsPaged(context.Background(), "store1", "doc", "d1", "viewer", "tok")
	if err != nil {
		t.Fatalf("ListRelationshipsPaged: %v", err)
	}
	if len(out.Relationships) != 1 || out.Object != "doc:d1" {
		t.Errorf("unexpected: %+v", out)
	}
}

func TestListRelationshipsPagedNoRelationFilter(t *testing.T) {
	// An empty relation filter should send no query string.
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Errorf("expected no query, got %q", r.URL.RawQuery)
		}
		writeJSON(w, 200, RelationshipsPage{Object: "doc:d1"})
	})
	if _, err := c.ListRelationshipsPaged(context.Background(), "store1", "doc", "d1", "", "tok"); err != nil {
		t.Fatalf("ListRelationshipsPaged: %v", err)
	}
}

func TestListObjectsPaged(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/zanzibar/stores/store1/list-objects" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var req ListObjectsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if req.Subject != "user:u1" || req.Permission != "read" || req.ObjectType != "doc" || req.MaxResults != 25 {
			t.Errorf("request not forwarded: %+v", req)
		}
		writeJSON(w, 200, ListObjectsResponse{Objects: []string{"doc:1", "doc:2"}, Subject: "user:u1", Permission: "read", ObjectType: "doc", ResultCount: 2})
	})
	out, err := c.ListObjectsPaged(context.Background(), "store1", ListObjectsRequest{
		Subject: "user:u1", Permission: "read", ObjectType: "doc", MaxResults: 25,
	}, "tok")
	if err != nil {
		t.Fatalf("ListObjectsPaged: %v", err)
	}
	if len(out.Objects) != 2 || out.ResultCount != 2 {
		t.Errorf("unexpected: %+v", out)
	}
}

// ---- Cascade delete (list + delete loop) ----

func TestDeleteAllRelationshipsForObject(t *testing.T) {
	// The server's DELETE .../relationships removes ONE tuple per call, so the
	// helper lists the full set, deletes each entry, then re-lists (empty).
	var listCalls, deleteCalls int
	remaining := 3
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			listCalls++
			if r.URL.Path != "/zanzibar/stores/store1/relationships/doc/d1" {
				t.Errorf("list path = %s", r.URL.Path)
			}
			var entries []RelationshipEntry
			for i := 0; i < remaining; i++ {
				entries = append(entries, RelationshipEntry{Relation: "viewer", Subject: "user:u" + strconv.Itoa(i)})
			}
			writeJSON(w, 200, RelationshipsResponse{Object: "doc:d1", Relationships: entries})
		case r.Method == http.MethodDelete:
			deleteCalls++
			if r.URL.Path != "/zanzibar/stores/store1/relationships" {
				t.Errorf("delete path = %s", r.URL.Path)
			}
			var req RelationshipRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if req.Object != "doc:d1" {
				t.Errorf("delete object = %q", req.Object)
			}
			if remaining > 0 {
				remaining--
			}
			writeJSON(w, 200, WriteOperationResponse{Success: true, Message: "deleted"})
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	})
	total, err := c.DeleteAllRelationshipsForObject(context.Background(), "store1", "doc", "d1", "admin")
	if err != nil {
		t.Fatalf("DeleteAllRelationshipsForObject: %v", err)
	}
	if total != 3 {
		t.Errorf("total deleted = %d want 3", total)
	}
	// 3 tuples => 3 delete calls; 2 list calls (full set, then empty).
	if deleteCalls != 3 {
		t.Errorf("delete calls = %d want 3", deleteCalls)
	}
	if listCalls != 2 {
		t.Errorf("list calls = %d want 2", listCalls)
	}
}

func TestDeleteAllRelationshipsForSubject(t *testing.T) {
	// The subject appears in 3 tuples across different objects. The helper reads
	// the full set (one page, no cursor), deletes each tuple one at a time, then
	// re-reads (now empty) and stops.
	var readCalls, deleteCalls int
	remaining := 3
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/zanzibar/stores/store1/read":
			readCalls++
			var req readTuplesRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode read: %v", err)
			}
			if req.TupleKey.User != "user:erin" {
				t.Errorf("read filter user = %q want user:erin", req.TupleKey.User)
			}
			var tuples []map[string]any
			for i := 0; i < remaining; i++ {
				tuples = append(tuples, map[string]any{
					"key": map[string]any{"object": "doc:d" + strconv.Itoa(i), "relation": "viewer", "user": "user:erin"},
				})
			}
			writeJSON(w, 200, map[string]any{"tuples": tuples})
		case r.Method == http.MethodDelete && r.URL.Path == "/zanzibar/stores/store1/relationships":
			deleteCalls++
			var req RelationshipRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode delete: %v", err)
			}
			if req.Subject != "user:erin" {
				t.Errorf("delete subject = %q want user:erin", req.Subject)
			}
			if remaining > 0 {
				remaining--
			}
			writeJSON(w, 200, WriteOperationResponse{Success: true, Message: "deleted"})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})
	total, err := c.DeleteAllRelationshipsForSubject(context.Background(), "store1", "user", "erin", "admin")
	if err != nil {
		t.Fatalf("DeleteAllRelationshipsForSubject: %v", err)
	}
	if total != 3 {
		t.Errorf("total deleted = %d want 3", total)
	}
	// 3 tuples => 3 delete calls; 2 read calls (full set, then empty).
	if deleteCalls != 3 {
		t.Errorf("delete calls = %d want 3", deleteCalls)
	}
	if readCalls != 2 {
		t.Errorf("read calls = %d want 2", readCalls)
	}
}

// ---- Idempotent EnsureAuthorizationModel ----

// writeLatestModel serves the read-latest path (list newest-first -> get-by-id
// nested) for a store whose latest model is id with the given type_definitions.
func writeLatestModel(t *testing.T, w http.ResponseWriter, r *http.Request, id string, tds []map[string]any) bool {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/zanzibar/stores/store1/authorization-models" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"authorization_models": []map[string]any{{"authorization_model_id": id}}})
		return true
	case r.URL.Path == "/zanzibar/stores/store1/authorization-models/"+id && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"authorization_model": map[string]any{
			"authorization_model_id": id, "schema_version": "1.1", "type_definitions": tds}})
		return true
	}
	return false
}

func TestEnsureAuthorizationModelNoChangeWhenEquivalent(t *testing.T) {
	var wroteModel bool
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if writeLatestModel(t, w, r, "m1", sampleTypeDefs()) {
			return
		}
		if r.Method == http.MethodPost {
			wroteModel = true
			writeJSON(w, 201, WriteAuthorizationModelResponse{AuthorizationModelID: "m2"})
			return
		}
		t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
	})
	// Identical type_definitions -> equivalent, no write.
	id, changed, err := c.EnsureAuthorizationModel(context.Background(), "store1",
		AuthorizationModel{SchemaVersion: "1.1", TypeDefinitions: sampleTypeDefs()}, "admin")
	if err != nil {
		t.Fatalf("EnsureAuthorizationModel: %v", err)
	}
	if changed || wroteModel {
		t.Errorf("expected no write; changed=%v wrote=%v", changed, wroteModel)
	}
	if id != "m1" {
		t.Errorf("id = %q want m1", id)
	}
}

func TestEnsureAuthorizationModelWritesWhenDifferent(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if writeLatestModel(t, w, r, "m1", sampleTypeDefs()) {
			return
		}
		if r.Method == http.MethodPost {
			writeJSON(w, 201, WriteAuthorizationModelResponse{AuthorizationModelID: "m2"})
			return
		}
		t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
	})
	different := []map[string]any{{"type": "folder", "relations": map[string]any{
		"editor": map[string]any{"allowed_subject_types": []any{"user"}}}}}
	id, changed, err := c.EnsureAuthorizationModel(context.Background(), "store1",
		AuthorizationModel{SchemaVersion: "1.1", TypeDefinitions: different}, "admin")
	if err != nil {
		t.Fatalf("EnsureAuthorizationModel: %v", err)
	}
	if !changed || id != "m2" {
		t.Errorf("expected write to m2; changed=%v id=%q", changed, id)
	}
}

func TestEnsureAuthorizationModelWritesWhenAbsent(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet:
			// Empty store: no models -> read-latest yields a 404-typed error.
			writeJSON(w, 200, map[string]any{"authorization_models": []any{}})
		case r.Method == http.MethodPost:
			writeJSON(w, 201, WriteAuthorizationModelResponse{AuthorizationModelID: "m-first"})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}, WithMaxRetries(0))
	id, changed, err := c.EnsureAuthorizationModel(context.Background(), "store1",
		AuthorizationModel{SchemaVersion: "1.1", TypeDefinitions: sampleTypeDefs()}, "admin")
	if err != nil {
		t.Fatalf("EnsureAuthorizationModel: %v", err)
	}
	if !changed || id != "m-first" {
		t.Errorf("expected initial write; changed=%v id=%q", changed, id)
	}
}

// ---- Spec-shape marshaling behavior ----

func TestCheckRequestSpecShape(t *testing.T) {
	// A minimal CheckPermissionRequest emits only the required combined-string
	// fields; org_id/context/consistency_token are omitted when unset.
	b, err := json.Marshal(CheckPermissionRequest{Subject: "user:alice", Permission: "read", Object: "doc:123"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, k := range []string{`"subject":"user:alice"`, `"permission":"read"`, `"object":"doc:123"`} {
		if !strings.Contains(s, k) {
			t.Errorf("expected %s in %s", k, s)
		}
	}
	for _, k := range []string{"org_id", "context", "consistency_token", "object_type", "subject_type", "relation"} {
		if strings.Contains(s, k) {
			t.Errorf("expected %q omitted from %s", k, s)
		}
	}

	// When set, org_id and consistency_token appear under their spec names.
	b2, _ := json.Marshal(CheckPermissionRequest{Subject: "user:alice", Permission: "read", Object: "doc:123", OrgID: "org1", ConsistencyToken: "zk-1"})
	for _, k := range []string{`"org_id":"org1"`, `"consistency_token":"zk-1"`} {
		if !strings.Contains(string(b2), k) {
			t.Errorf("expected %s in %s", k, b2)
		}
	}
}

func TestWriteResponseConsistencyTokenOmitempty(t *testing.T) {
	b, _ := json.Marshal(WriteOperationResponse{Success: true, Message: "ok"})
	if strings.Contains(string(b), "consistency_token") {
		t.Errorf("consistency_token should be omitted: %s", b)
	}
	b2, _ := json.Marshal(WriteOperationResponse{Success: true, Message: "ok", ConsistencyToken: "zk"})
	if !strings.Contains(string(b2), `"consistency_token":"zk"`) {
		t.Errorf("consistency_token missing: %s", b2)
	}
}

func TestListObjectsRequestSpecShape(t *testing.T) {
	b, _ := json.Marshal(ListObjectsRequest{Subject: "user:alice", Permission: "read", ObjectType: "doc"})
	s := string(b)
	for _, k := range []string{`"subject":"user:alice"`, `"permission":"read"`, `"object_type":"doc"`} {
		if !strings.Contains(s, k) {
			t.Errorf("expected %s in %s", k, s)
		}
	}
	for _, k := range []string{"max_results", "org_id", "consistency_token", "page_size", "continuation_token"} {
		if strings.Contains(s, k) {
			t.Errorf("field %q should be omitted: %s", k, s)
		}
	}
}
