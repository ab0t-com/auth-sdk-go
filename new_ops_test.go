package authclient

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// F-03: SCIM user provisioning round-trips (real SCIM shape).
func TestSCIM_UserAndList(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/scim/v2/Users":
			if r.Method == "POST" {
				writeJSON(w, 201, ScimUser{Schemas: []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
					ID: "u1", UserName: "a@b", Active: true, Name: &ScimName{GivenName: "A", FamilyName: "B"},
					Emails: []ScimEmail{{Value: "a@b", Primary: true}}})
				return
			}
			writeJSON(w, 200, ScimListResponse{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
				TotalResults: 1, StartIndex: 1, ItemsPerPage: 1, Resources: json.RawMessage(`[{"id":"u1","userName":"a@b","active":true}]`)})
		case "/scim/v2/Users/u1":
			writeJSON(w, 204, nil)
		default:
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()
	u, err := c.CreateScimUser(ctx, ScimUser{Schemas: []string{"x"}, UserName: "a@b", Active: true}, "t")
	if err != nil || u.ID != "u1" || !u.Active || u.Name.GivenName != "A" || len(u.Emails) != 1 {
		t.Fatalf("CreateScimUser: %+v err=%v", u, err)
	}
	lst, err := c.ListScimUsers(ctx, "t")
	if err != nil || lst.TotalResults != 1 || len(lst.Resources) == 0 {
		t.Fatalf("ListScimUsers: %+v err=%v", lst, err)
	}
	var res []ScimUser
	if err := json.Unmarshal(lst.Resources, &res); err != nil || res[0].UserName != "a@b" {
		t.Fatalf("Resources decode: %v %+v", err, res)
	}
	if err := c.DeleteScimUser(ctx, "u1", "t"); err != nil { // 204, no body
		t.Fatalf("DeleteScimUser (204): %v", err)
	}
}

// F-03: HRIS sync result + connection decode with real numeric fields.
func TestHRIS_SyncAndConnection(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/organizations/o1/hris/connection":
			writeJSON(w, 200, HRISConnectionStatus{Provider: "workday", Configured: true, Active: true, BaseURL: "https://x"})
		case "/organizations/o1/hris/sync":
			writeJSON(w, 200, HRISSyncResult{Provider: "workday", RosterSize: 100, Provisioned: 3, Deprovisioned: 1, Unchanged: 96})
		default:
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()
	st, err := c.GetHRISConnection(ctx, "o1", "t")
	if err != nil || st.Provider != "workday" || !st.Active {
		t.Fatalf("GetHRISConnection: %+v err=%v", st, err)
	}
	sr, err := c.SyncHRIS(ctx, "o1", "t")
	if err != nil || sr.RosterSize != 100 || sr.Provisioned != 3 || sr.Unchanged != 96 {
		t.Fatalf("SyncHRIS: %+v err=%v", sr, err)
	}
}

// F-03: tail — access-check, get-invitation, delete-relationship-by-object.
func TestTailOps(t *testing.T) {
	var delBody map[string]any
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/network-policy/access-check":
			writeJSON(w, 200, AccessCheckResponse{Status: "allow", Enforced: true, NetworkZone: "corp"})
		case r.URL.Path == "/organizations/o1/invitations/i1":
			writeJSON(w, 200, InvitationListItem{ID: "i1", Email: "x@y", Status: "pending", Role: "member"})
		case r.Method == "DELETE" && r.URL.Path == "/zanzibar/stores/s1/relationships/doc/d1":
			_ = json.NewDecoder(r.Body).Decode(&delBody)
			writeJSON(w, 200, WriteOperationResponse{Success: true})
		default:
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()
	ac, err := c.NetworkAccessCheck(ctx, "t")
	if err != nil || ac.Status != "allow" || !ac.Enforced {
		t.Fatalf("NetworkAccessCheck: %+v err=%v", ac, err)
	}
	inv, err := c.GetInvitation(ctx, "o1", "i1", "t")
	if err != nil || inv.ID != "i1" || inv.Status != "pending" {
		t.Fatalf("GetInvitation: %+v err=%v", inv, err)
	}
	wr, err := c.DeleteRelationshipByObject(ctx, "s1", "doc", "d1", "viewer", "user:alice", "t")
	if err != nil || !wr.Success {
		t.Fatalf("DeleteRelationshipByObject: %+v err=%v", wr, err)
	}
	if delBody["relation"] != "viewer" || delBody["subject"] != "user:alice" {
		t.Fatalf("delete body wrong: %v", delBody)
	}
}
