package authclient

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// ---- Authorization model management ----

func TestWriteAuthorizationModel(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/zanzibar/stores/store1/authorization-models" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer admin" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		var req WriteAuthorizationModelRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if req.Model.SchemaVersion != "1.1" || !strings.Contains(req.Model.DSL, "type document") {
			t.Errorf("bad model body: %+v", req.Model)
		}
		writeJSON(w, 200, WriteAuthorizationModelResponse{AuthorizationModelID: "m123", Message: "ok"})
	})
	out, err := c.WriteAuthorizationModel(context.Background(), "store1", WriteAuthorizationModelRequest{
		Model: AuthorizationModel{SchemaVersion: "1.1", DSL: "type document\n  relations\n    define viewer: [user]"},
	}, "admin")
	if err != nil {
		t.Fatalf("WriteAuthorizationModel: %v", err)
	}
	if out.AuthorizationModelID != "m123" {
		t.Errorf("model id = %q", out.AuthorizationModelID)
	}
}

func TestReadAuthorizationModel(t *testing.T) {
	t.Run("explicit id", func(t *testing.T) {
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/zanzibar/stores/store1/authorization-models/m123" {
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			}
			writeJSON(w, 200, AuthorizationModelResponse{AuthorizationModelID: "m123", SchemaVersion: "1.1", DSL: "type document"})
		})
		out, err := c.ReadAuthorizationModel(context.Background(), "store1", "m123", "tok")
		if err != nil {
			t.Fatalf("ReadAuthorizationModel: %v", err)
		}
		if out.AuthorizationModelID != "m123" || out.SchemaVersion != "1.1" {
			t.Errorf("unexpected: %+v", out)
		}
	})
	t.Run("empty id resolves to latest", func(t *testing.T) {
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/zanzibar/stores/store1/authorization-models/latest" {
				t.Errorf("path = %s", r.URL.Path)
			}
			writeJSON(w, 200, AuthorizationModelResponse{AuthorizationModelID: "mLatest"})
		})
		out, err := c.ReadAuthorizationModel(context.Background(), "store1", "", "tok")
		if err != nil {
			t.Fatalf("ReadAuthorizationModel: %v", err)
		}
		if out.AuthorizationModelID != "mLatest" {
			t.Errorf("id = %q", out.AuthorizationModelID)
		}
	})
}

func TestListAuthorizationModels(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zanzibar/stores/store1/authorization-models" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("continuation_token"); got != "cur1" {
			t.Errorf("continuation_token = %q", got)
		}
		writeJSON(w, 200, ListAuthorizationModelsResponse{
			Models:            []AuthorizationModelResponse{{AuthorizationModelID: "m2"}, {AuthorizationModelID: "m1"}},
			ContinuationToken: "cur2",
		})
	})
	out, err := c.ListAuthorizationModels(context.Background(), "store1", "cur1", "tok")
	if err != nil {
		t.Fatalf("ListAuthorizationModels: %v", err)
	}
	if len(out.Models) != 2 || out.ContinuationToken != "cur2" {
		t.Errorf("unexpected: %+v", out)
	}
}

// ---- Atomic write + delete ----

func TestWriteAndDeleteRelationships(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/zanzibar/stores/store1/relationships/transact" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var req TransactRelationshipsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(req.Writes) != 1 || len(req.Deletes) != 1 {
			t.Errorf("writes/deletes = %d/%d", len(req.Writes), len(req.Deletes))
		}
		if req.Writes[0].Object != "doc:new" || req.Deletes[0].Object != "doc:old" {
			t.Errorf("bad tuples: %+v", req)
		}
		writeJSON(w, 200, WriteOperationResponse{Success: true, Message: "ok", ConsistencyToken: "zk-42"})
	})
	out, err := c.WriteAndDeleteRelationships(context.Background(), "store1", TransactRelationshipsRequest{
		Writes:  []RelationshipRequest{{Object: "doc:new", Relation: "parent", Subject: "folder:b"}},
		Deletes: []RelationshipRequest{{Object: "doc:old", Relation: "parent", Subject: "folder:a"}},
	}, "admin")
	if err != nil {
		t.Fatalf("WriteAndDeleteRelationships: %v", err)
	}
	if !out.Success || out.ConsistencyToken != "zk-42" {
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

// ---- Idempotent EnsureAuthorizationModel ----

func TestEnsureAuthorizationModelNoChangeWhenEquivalent(t *testing.T) {
	var wroteModel bool
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zanzibar/stores/store1/authorization-models/latest":
			writeJSON(w, 200, AuthorizationModelResponse{AuthorizationModelID: "m1", SchemaVersion: "1.1", DSL: "type document\n"})
		case r.Method == http.MethodPost:
			wroteModel = true
			writeJSON(w, 200, WriteAuthorizationModelResponse{AuthorizationModelID: "m2"})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	// DSL differs only by trailing whitespace -> treated as equivalent, no write.
	id, changed, err := c.EnsureAuthorizationModel(context.Background(), "store1", AuthorizationModel{SchemaVersion: "1.1", DSL: "type document"}, "admin")
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
		switch {
		case r.Method == http.MethodGet:
			writeJSON(w, 200, AuthorizationModelResponse{AuthorizationModelID: "m1", SchemaVersion: "1.1", DSL: "type document"})
		case r.Method == http.MethodPost:
			writeJSON(w, 200, WriteAuthorizationModelResponse{AuthorizationModelID: "m2"})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})
	id, changed, err := c.EnsureAuthorizationModel(context.Background(), "store1", AuthorizationModel{SchemaVersion: "1.1", DSL: "type document\n  relations\n    define editor: [user]"}, "admin")
	if err != nil {
		t.Fatalf("EnsureAuthorizationModel: %v", err)
	}
	if !changed || id != "m2" {
		t.Errorf("expected write to m2; changed=%v id=%q", changed, id)
	}
}

func TestEnsureAuthorizationModelWritesWhenAbsent(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			writeJSON(w, 404, map[string]any{"detail": "no model yet"})
		case r.Method == http.MethodPost:
			writeJSON(w, 200, WriteAuthorizationModelResponse{AuthorizationModelID: "m-first"})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}, WithMaxRetries(0))
	id, changed, err := c.EnsureAuthorizationModel(context.Background(), "store1", AuthorizationModel{DSL: "type document"}, "admin")
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
